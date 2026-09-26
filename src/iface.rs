//! Figure out which interface and subnet to scan, and where the gateway is.

use crate::platform::{self, Adapter};
use ipnetwork::Ipv4Network;
use pnet_base::MacAddr;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

/// Largest subnet we sweep in full. Anything bigger gets narrowed to the
/// local /24 so a default run stays fast.
const MAX_PREFIX: u8 = 22;

/// What macOS reports instead of the real address when it withholds it.
const HIDDEN_MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 0);

pub struct Iface {
    pub iface: Adapter,
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
    let all = platform::adapters();
    let own_ips = all.iter().flat_map(|a| &a.ips).map(|n| n.ip()).collect();
    let iface = match name {
        // Windows adapter names ("Wi-Fi") are case-insensitive.
        Some(n) => all
            .into_iter()
            .find(|a| a.name == n || (cfg!(windows) && a.name.eq_ignore_ascii_case(n)))
            .ok_or_else(|| format!("no interface named '{n}'"))?,
        None => pick(all, outbound_ip())
            .ok_or("couldn't find an active network interface (try --interface)")?,
    };

    let v4 = *iface.ips.first().ok_or_else(|| format!("{} has no IPv4 address", iface.name))?;
    let mac = iface.mac.filter(|&m| m != MacAddr::zero() && m != HIDDEN_MAC);

    let full = Ipv4Network::new(v4.network(), v4.prefix()).expect("valid network");
    let (net, narrowed_from) = if v4.prefix() < MAX_PREFIX {
        let local = Ipv4Network::new(v4.ip(), 24).expect("valid prefix");
        (Ipv4Network::new(local.network(), 24).expect("valid prefix"), Some(full))
    } else {
        (full, None)
    };

    Ok(Iface {
        gateway: platform::default_gateway(&iface),
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

fn pick(all: Vec<Adapter>, preferred: Option<Ipv4Addr>) -> Option<Adapter> {
    let usable = |a: &&Adapter| {
        a.up && !a.loopback && a.mac.is_some_and(|m| m != MacAddr::zero()) && !a.ips.is_empty()
    };
    if let Some(ip) = preferred
        && let Some(a) = all.iter().filter(usable).find(|a| a.ips.iter().any(|n| n.ip() == ip))
    {
        return Some(a.clone());
    }
    // Outbound traffic goes through a VPN or similar; fall back to the first
    // real LAN interface, passing over virtual switches (Hyper-V, WSL).
    let mut usable = all.into_iter().filter(|a| usable(&a));
    let first = usable.next()?;
    if first.physical {
        return Some(first);
    }
    Some(usable.find(|a| a.physical).unwrap_or(first))
}
