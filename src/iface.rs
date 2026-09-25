//! Figure out which interface and subnet to scan, and where the gateway is.

use crate::platform;
use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

/// Largest subnet we sweep in full. Anything bigger gets narrowed to the
/// local /24 so a default run stays fast.
const MAX_PREFIX: u8 = 22;

/// What macOS reports instead of the real address when it withholds it.
const HIDDEN_MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 0);

pub struct Iface {
    pub iface: NetworkInterface,
    pub ip: Ipv4Addr,
    /// None when the OS hides it from us (recent macOS does, for unsigned binaries).
    pub mac: Option<MacAddr>,
    /// The network actually being scanned (may be narrower than the interface's).
    pub net: Ipv4Network,
    /// Set when the interface's real network was too large and got narrowed.
    pub narrowed_from: Option<Ipv4Network>,
    pub gateway: Option<Ipv4Addr>,
    /// Addresses on any of this machine's interfaces (a Mac on Wi-Fi and
    /// Ethernet at once shows up twice on the same LAN).
    pub own_ips: Vec<Ipv4Addr>,
}

impl Iface {
    /// Every address worth probing: all hosts except network, broadcast and ourselves.
    pub fn targets(&self) -> Vec<Ipv4Addr> {
        let (network, broadcast) = (self.net.network(), self.net.broadcast());
        self.net
            .iter()
            .filter(|&a| a != network && a != broadcast && a != self.ip)
            .collect()
    }
}

pub fn detect(name: Option<&str>) -> Result<Iface, String> {
    let all = datalink::interfaces();
    let own_ips = all
        .iter()
        .flat_map(|i| &i.ips)
        .filter_map(|n| match n.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .collect();
    let iface = match name {
        Some(n) => all
            .into_iter()
            .find(|i| i.name == n)
            .ok_or_else(|| format!("no interface named '{n}'"))?,
        None => pick(all, outbound_ip())
            .ok_or("couldn't find an active network interface (try --interface)")?,
    };

    let v4 = iface
        .ips
        .iter()
        .find_map(|n| match n {
            IpNetwork::V4(v4) => Some(*v4),
            _ => None,
        })
        .ok_or_else(|| format!("{} has no IPv4 address", iface.name))?;
    let mac = iface.mac.filter(|&m| m != MacAddr::zero() && m != HIDDEN_MAC);

    let full = Ipv4Network::new(v4.network(), v4.prefix()).expect("valid network");
    let (net, narrowed_from) = if v4.prefix() < MAX_PREFIX {
        let local = Ipv4Network::new(v4.ip(), 24).expect("valid prefix");
        (Ipv4Network::new(local.network(), 24).expect("valid prefix"), Some(full))
    } else {
        (full, None)
    };

    Ok(Iface {
        gateway: platform::default_gateway(&iface.name),
        ip: v4.ip(),
        mac,
        net,
        narrowed_from,
        own_ips,
        iface,
    })
}

/// The local address the OS would use to reach the internet. Connecting a UDP
/// socket only does a route lookup; no packets are sent.
fn outbound_ip() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:53").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

fn pick(all: Vec<NetworkInterface>, preferred: Option<Ipv4Addr>) -> Option<NetworkInterface> {
    let usable = |i: &NetworkInterface| {
        i.is_up()
            && !i.is_loopback()
            && i.mac.is_some_and(|m| m != MacAddr::zero())
            && i.ips.iter().any(|n| n.is_ipv4())
    };
    if let Some(ip) = preferred
        && let Some(i) = all
            .iter()
            .find(|i| usable(i) && i.ips.iter().any(|n| n.ip() == IpAddr::V4(ip)))
        {
            return Some(i.clone());
        }
    // Outbound traffic goes through a VPN or similar; fall back to the first real LAN interface.
    all.into_iter().find(|i| usable(i))
}
