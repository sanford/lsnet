//! Figure out which interface and subnet to scan, and where the gateway is.

use crate::platform::{self, Adapter};
use ipnetwork::Ipv4Network;
use pnet_base::MacAddr;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

/// Largest subnet we sweep in full. Anything bigger gets narrowed to the
/// local /24 so a default run stays fast.
const MAX_PREFIX: u8 = 22;

/// Largest network `--net` will scan: a /16, 65,534 addresses.
pub const MAX_NET_PREFIX: u8 = 16;

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
    /// The interface's own network: the addresses ARP, mDNS and SSDP can reach.
    pub link: Ipv4Network,
    pub gateway: Option<Ipv4Addr>,
    /// Addresses on any of this machine's interfaces (a Mac on Wi-Fi and
    /// Ethernet at once shows up twice on the same LAN).
    pub own_ips: Vec<Ipv4Addr>,
}

impl Iface {
    /// Every address worth probing: all hosts except network, broadcast and
    /// ourselves. A /31 or /32 has no network or broadcast address.
    pub fn targets(&self) -> Vec<Ipv4Addr> {
        let (network, broadcast) = (self.net.network(), self.net.broadcast());
        let ends = self.net.prefix() < 31;
        self.net
            .iter()
            .filter(|&a| !(ends && (a == network || a == broadcast)) && a != self.ip)
            .collect()
    }

    /// Whether any of the scanned network is on this interface's own link.
    pub fn on_link(&self) -> bool {
        overlap(self.net, self.link)
    }
}

/// `--net`: a network in CIDR form, no larger than a /16. Host bits are
/// dropped, so 192.168.1.7/24 means 192.168.1.0/24.
pub fn parse_net(s: &str) -> Result<Ipv4Network, String> {
    let Some((ip, prefix)) = s.split_once('/') else {
        return Err(format!("give the size too, like {s}/24"));
    };
    let ip: Ipv4Addr = ip
        .parse()
        .map_err(|_| format!("'{ip}' isn't an IPv4 address"))?;
    let prefix: u8 = prefix
        .parse()
        .ok()
        .filter(|p| *p <= 32)
        .ok_or_else(|| format!("'{prefix}' isn't a prefix length from 0 to 32"))?;
    if prefix < MAX_NET_PREFIX {
        return Err(format!(
            "a /{prefix} is too large; lsnet scans at most a /{MAX_NET_PREFIX} (65,536 addresses)"
        ));
    }
    let net = Ipv4Network::new(ip, prefix).expect("valid prefix");
    Ok(Ipv4Network::new(net.network(), prefix).expect("valid prefix"))
}

fn overlap(a: Ipv4Network, b: Ipv4Network) -> bool {
    a.contains(b.network()) || b.contains(a.network())
}

/// The interface to scan and the network to scan on it: `net` if given,
/// otherwise the interface's own (narrowed to the local /24 when large).
pub fn detect(name: Option<&str>, net: Option<Ipv4Network>) -> Result<Iface, String> {
    let all = platform::adapters();
    let own_ips = all.iter().flat_map(|a| &a.ips).map(|n| n.ip()).collect();
    let on_net = net.and_then(|n| all.iter().flat_map(|a| &a.ips).find(|a| overlap(**a, n)));
    let on_net = on_net.map(|a| a.ip());
    let iface = match name {
        // Windows adapter names ("Wi-Fi") are case-insensitive.
        Some(n) => all
            .into_iter()
            .find(|a| a.name == n || (cfg!(windows) && a.name.eq_ignore_ascii_case(n)))
            .ok_or_else(|| format!("no interface named '{n}'"))?,
        // Prefer the interface that's on the network being scanned, so ARP,
        // mDNS and SSDP can reach it.
        None => pick(all, on_net.or_else(outbound_ip))
            .ok_or("couldn't find an active network interface (try --interface)")?,
    };

    let v4 = *net
        .and_then(|n| iface.ips.iter().find(|a| overlap(**a, n)))
        .or(iface.ips.first())
        .ok_or_else(|| format!("{} has no IPv4 address", iface.name))?;
    let mac = iface
        .mac
        .filter(|&m| m != MacAddr::zero() && m != HIDDEN_MAC);

    let full = Ipv4Network::new(v4.network(), v4.prefix()).expect("valid network");
    let (net, narrowed_from) = if let Some(net) = net {
        (net, None)
    } else if v4.prefix() < MAX_PREFIX {
        let local = Ipv4Network::new(v4.ip(), 24).expect("valid prefix");
        (
            Ipv4Network::new(local.network(), 24).expect("valid prefix"),
            Some(full),
        )
    } else {
        (full, None)
    };

    Ok(Iface {
        gateway: platform::default_gateway(&iface),
        ip: v4.ip(),
        mac,
        net,
        narrowed_from,
        link: full,
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
        && let Some(a) = all
            .iter()
            .filter(usable)
            .find(|a| a.ips.iter().any(|n| n.ip() == ip))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(ip: &str, net: &str) -> Iface {
        Iface {
            iface: Adapter {
                name: "en0".into(),
                index: 0,
                mac: None,
                ips: Vec::new(),
                up: true,
                loopback: false,
                physical: true,
                gateway: None,
            },
            ip: ip.parse().unwrap(),
            mac: None,
            net: net.parse().unwrap(),
            narrowed_from: None,
            link: "192.168.1.0/24".parse().unwrap(),
            gateway: None,
            own_ips: Vec::new(),
        }
    }

    #[test]
    fn net_takes_cidr_up_to_a_slash_16() {
        assert_eq!(parse_net("10.0.0.0/16").unwrap().to_string(), "10.0.0.0/16");
        // Host bits are dropped.
        assert_eq!(
            parse_net("192.168.1.77/24").unwrap().to_string(),
            "192.168.1.0/24"
        );
        assert!(parse_net("10.0.0.0/8").unwrap_err().contains("too large"));
        assert!(
            parse_net("192.168.1.0")
                .unwrap_err()
                .contains("192.168.1.0/24")
        );
        assert!(parse_net("192.168.1.0/33").is_err());
        assert!(
            parse_net("nonsense/24")
                .unwrap_err()
                .contains("IPv4 address")
        );
        assert!(parse_net("/24").unwrap_err().contains("IPv4 address"));
    }

    #[test]
    fn targets_skip_network_broadcast_and_self() {
        let t = iface("192.168.1.5", "192.168.1.0/24").targets();
        assert_eq!(t.len(), 253);
        assert!(!t.contains(&"192.168.1.0".parse().unwrap()));
        assert!(!t.contains(&"192.168.1.255".parse().unwrap()));
        // A /31 and a /32 have no network or broadcast address to skip.
        assert_eq!(iface("192.168.1.5", "10.0.0.0/31").targets().len(), 2);
        assert_eq!(iface("192.168.1.5", "10.0.0.9/32").targets().len(), 1);
    }

    #[test]
    fn on_link_when_the_networks_overlap() {
        assert!(iface("192.168.1.5", "192.168.1.128/25").on_link());
        assert!(iface("192.168.1.5", "192.168.0.0/16").on_link());
        assert!(!iface("192.168.1.5", "10.0.0.0/24").on_link());
    }
}
