//! IPv6 neighbors. One echo request to the all-nodes address (`ff02::1`)
//! reaches every device on the link at once, and most answer from their
//! link-local address: Macs, iPhones, Linux and much of what's built on it.
//! Windows doesn't, and plenty of smart-home gear has no IPv6 at all.
//!
//! lsnet lists devices by their IPv4 address, so a neighbor is matched to
//! one by its MAC address, which the kernel's neighbor cache has by the time
//! the answer arrives, and which an address made from a MAC (EUI-64) says
//! outright. Bonjour pairs the two addresses as well, with no MAC needed.
//!
//! Uses an ICMPv6 datagram socket, which macOS allows for everyone and Linux
//! for the groups in `net.ipv4.ping_group_range`. Windows has none.

use crate::Device;
use crate::platform::{self, Adapter};
use pnet_base::MacAddr;
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::time::{Duration, Instant};

const ECHO_REQUEST: u8 = 128;
const ECHO_REPLY: u8 = 129;
/// What our echo requests carry, to tell their replies from anyone else's.
const MARK: &[u8; 8] = b"lsnet\0\0\0";
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Each neighbor's link-local address, and its MAC where that's known.
pub type Neighbors = HashMap<Ipv6Addr, Option<MacAddr>>;

/// Everything on `adapter`'s link that answers an echo request to all of it
/// within `wait`.
pub fn discover(adapter: &Adapter, wait: Duration) -> Neighbors {
    let Some(sock) = open() else {
        return Neighbors::new();
    };
    let everyone = SocketAddr::V6(SocketAddrV6::new(ALL_NODES, 0, 0, adapter.index));
    let start = Instant::now();
    let end = start + wait;
    // Again a third of the way in, as Bonjour and Kasa do, for Wi-Fi clients
    // that dozed through the first.
    let mut again = Some(start + wait / 3);
    let _ = sock.send_to(&echo_request(0), everyone);
    let mut heard = Vec::new();
    let mut buf = [0u8; 1500];
    loop {
        let until = again.unwrap_or(end);
        let Some(left) = until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            if again.take().is_none() {
                break;
            }
            let _ = sock.send_to(&echo_request(1), everyone);
            continue;
        };
        let _ = sock.set_read_timeout(Some(left));
        if let Ok((n, SocketAddr::V6(from))) = sock.recv_from(&mut buf)
            && is_our_reply(&buf[..n])
            && is_link_local(*from.ip())
            && !heard.contains(from.ip())
        {
            heard.push(*from.ip());
        }
    }
    if heard.is_empty() {
        return Neighbors::new();
    }
    // To answer, each had to ask for our MAC, which told the kernel theirs.
    let cache: HashMap<Ipv6Addr, MacAddr> = platform::neighbor_cache().into_iter().collect();
    heard
        .into_iter()
        .map(|ip| (ip, cache.get(&ip).copied().or_else(|| eui64_mac(ip))))
        .collect()
}

/// An ICMPv6 datagram socket, wrapped in `UdpSocket` for its safe
/// `send_to`/`recv_from` (the port in the address is ignored).
#[cfg(unix)]
fn open() -> Option<UdpSocket> {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_ICMPV6) };
    (fd >= 0).then(|| unsafe { UdpSocket::from_raw_fd(fd) })
}

#[cfg(windows)]
fn open() -> Option<UdpSocket> {
    None
}

/// The kernel fills in the checksum, which covers addresses we don't know.
fn echo_request(seq: u16) -> [u8; 16] {
    let mut pkt = [0u8; 16];
    pkt[0] = ECHO_REQUEST;
    pkt[4..6].copy_from_slice(&(std::process::id() as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt[8..].copy_from_slice(MARK);
    pkt
}

/// Not our own request, looped back, or the neighbor advertisements that
/// macOS hands the same socket.
fn is_our_reply(pkt: &[u8]) -> bool {
    pkt.first() == Some(&ECHO_REPLY) && pkt.get(8..16) == Some(MARK)
}

fn is_link_local(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// The MAC an address was made from, if it's one of those: the MAC's halves
/// around `ff:fe`, with one bit of its first byte flipped.
pub fn eui64_mac(ip: Ipv6Addr) -> Option<MacAddr> {
    let o = ip.octets();
    (o[11] == 0xff && o[12] == 0xfe)
        .then(|| MacAddr::new(o[8] ^ 0x02, o[9], o[10], o[13], o[14], o[15]))
}

/// Give `d` its link-local addresses: the ones Bonjour lists for it, and
/// any neighbor's with its MAC. A device without a MAC gets one from them.
pub fn assign(d: &mut Device, neighbors: &Neighbors) {
    let mut ips: Vec<Ipv6Addr> = d.mdns.iter().flat_map(|m| m.ipv6.clone()).collect();
    let macs: Vec<MacAddr> = (d.mac.iter().chain(&d.other_macs))
        .filter_map(|m| m.parse().ok())
        .collect();
    let theirs = |mac: &Option<MacAddr>| mac.is_some_and(|m| macs.contains(&m));
    ips.extend(
        neighbors
            .iter()
            .filter(|(_, m)| theirs(m))
            .map(|(ip, _)| ip),
    );
    ips.sort_unstable();
    ips.dedup();
    if d.mac.is_none() {
        let mac = ips.iter().find_map(|ip| {
            neighbors
                .get(ip)
                .copied()
                .flatten()
                .or_else(|| eui64_mac(*ip))
        });
        d.mac = mac.map(|m| m.to_string());
    }
    d.ipv6 = ips;
}

/// The neighbors that are none of `devices`, nor this machine (`own`): on
/// the link, but found no other way. Only those whose MAC is known, since
/// that's all there is to tell them from the devices by.
pub fn strangers(
    neighbors: &Neighbors,
    devices: &[Device],
    own: &[MacAddr],
) -> Vec<(Ipv6Addr, MacAddr)> {
    let known: Vec<MacAddr> = devices
        .iter()
        .flat_map(|d| d.mac.iter().chain(&d.other_macs))
        .filter_map(|m| m.parse().ok())
        .collect();
    let mut out: Vec<(Ipv6Addr, MacAddr)> = neighbors
        .iter()
        .filter_map(|(ip, mac)| Some((*ip, (*mac)?)))
        .filter(|(_, mac)| !known.contains(mac) && !own.contains(mac))
        .filter(|(ip, _)| !devices.iter().any(|d| d.ipv6.contains(ip)))
        .collect();
    out.sort_unstable();
    out
}

/// One line for under the results, naming each stranger and its maker.
pub fn strangers_note(strangers: &[(Ipv6Addr, MacAddr)]) -> Option<String> {
    let who: Vec<String> = strangers
        .iter()
        .map(|(ip, mac)| match crate::oui::vendor(*mac) {
            Some(vendor) => format!("{ip} ({mac}, {vendor})"),
            None => format!("{ip} ({mac})"),
        })
        .collect();
    let (count, verb) = match who.len() {
        0 => return None,
        1 => ("1 more device".to_string(), "answers"),
        n => (format!("{n} more devices"), "answer"),
    };
    Some(format!("{count} {verb} over IPv6 only: {}", who.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdns::MdnsInfo;

    fn ip(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    fn device(last: u8, mac: Option<&str>) -> Device {
        let mut d = Device::new(std::net::Ipv4Addr::new(192, 168, 1, last));
        d.mac = mac.map(String::from);
        d
    }

    #[test]
    fn tells_our_replies_from_the_rest() {
        let mut pkt = echo_request(1);
        assert!(!is_our_reply(&pkt), "our own request, looped back");
        pkt[0] = ECHO_REPLY;
        assert!(is_our_reply(&pkt));
        pkt[9] = b'x';
        assert!(!is_our_reply(&pkt), "someone else's ping");
        // A neighbor advertisement, and a reply cut short.
        assert!(!is_our_reply(&[136, 0, 0, 0, 0x60, 0, 0, 0]));
        assert!(!is_our_reply(&[ECHO_REPLY, 0, 0, 0]));
        assert!(is_link_local(ip("fe80::1")));
        assert!(!is_link_local(ip("2001:db8::1")));
    }

    #[test]
    fn some_addresses_are_made_from_the_mac() {
        assert_eq!(
            eui64_mac(ip("fe80::211:32ff:fe66:d871")),
            Some(mac("00:11:32:66:d8:71"))
        );
        // A private one says nothing.
        assert_eq!(eui64_mac(ip("fe80::1084:3533:b1b:c41b")), None);
    }

    #[test]
    fn neighbors_go_to_the_device_with_their_mac() {
        let neighbors = Neighbors::from([
            (
                ip("fe80::1084:3533:b1b:c41b"),
                Some(mac("f0:18:98:3c:62:8d")),
            ),
            (
                ip("fe80::211:32ff:fe66:d871"),
                Some(mac("00:11:32:66:d8:71")),
            ),
            (ip("fe80::9"), None),
        ]);
        let mut tv = device(52, Some("f0:18:98:3c:62:8d"));
        assign(&mut tv, &neighbors);
        assert_eq!(tv.ipv6, [ip("fe80::1084:3533:b1b:c41b")]);

        // Without a MAC, Bonjour's word for its address, which gives it one.
        let mut nas = device(14, None);
        nas.mdns = Some(MdnsInfo {
            ipv6: vec![ip("fe80::211:32ff:fe66:d871")],
            ..Default::default()
        });
        assign(&mut nas, &neighbors);
        assert_eq!(nas.ipv6, [ip("fe80::211:32ff:fe66:d871")]);
        assert_eq!(nas.mac.as_deref(), Some("00:11:32:66:d8:71"));

        let mut other = device(60, Some("6c:4a:85:0b:77:21"));
        assign(&mut other, &neighbors);
        assert!(other.ipv6.is_empty());
    }

    #[test]
    fn strangers_are_neighbors_no_device_accounts_for() {
        let neighbors = Neighbors::from([
            (
                ip("fe80::1084:3533:b1b:c41b"),
                Some(mac("f0:18:98:3c:62:8d")),
            ),
            (ip("fe80::2"), Some(mac("b8:27:eb:5a:11:c4"))),
            (ip("fe80::3"), Some(mac("f0:18:98:a1:b2:c3"))),
            (ip("fe80::9"), None),
        ]);
        let mut tv = device(52, Some("f0:18:98:3c:62:8d"));
        assign(&mut tv, &neighbors);
        let own = [mac("f0:18:98:a1:b2:c3")];
        let found = strangers(&neighbors, &[tv], &own);
        assert_eq!(found, [(ip("fe80::2"), mac("b8:27:eb:5a:11:c4"))]);
        assert_eq!(
            strangers_note(&found).as_deref(),
            Some("1 more device answers over IPv6 only: fe80::2 (b8:27:eb:5a:11:c4, Raspberry Pi)")
        );
        assert_eq!(strangers_note(&[]), None);
    }
}
