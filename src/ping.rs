//! Unprivileged ICMP echo sweep. Finds hosts that drop every TCP port we
//! probe but still answer ping, which matters most on macOS, where without
//! root we can neither send ARP nor read the ARP cache.
//!
//! Uses an ICMP datagram socket, which macOS allows for everyone.
//!
//! Skipped on Linux: its ARP cache, which we can read without root, already
//! lists every host that would answer a ping. Worse, pings to empty addresses
//! sit in the send buffer while ARP for them fails, stalling the sweep for
//! seconds.
//!
//! Skipped on Windows too: its ARP sweep needs no privileges, so it already
//! finds every host that would answer a ping.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;

/// Hosts among `targets` that answered an echo request.
pub fn sweep(targets: &[Ipv4Addr], wait: Duration) -> HashSet<Ipv4Addr> {
    let mut alive = HashSet::new();
    if cfg!(any(target_os = "linux", windows)) {
        return alive;
    }
    let Some(sock) = open() else { return alive };
    let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let id = std::process::id() as u16;

    // Two rounds, like the ARP sweep: Wi-Fi clients in power-save often miss the first.
    for round in 0..2u16 {
        for (i, &ip) in targets.iter().filter(|ip| !alive.contains(*ip)).enumerate() {
            let _ = sock.send_to(&echo_request(id, round), SocketAddr::new(IpAddr::V4(ip), 0));
            if i % 64 == 63 {
                thread::sleep(Duration::from_millis(2)); // don't overrun the send buffer
            }
        }
        let end = Instant::now() + wait / 2;
        let mut buf = [0u8; 1500];
        while let Some(left) = end.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) {
            let _ = sock.set_read_timeout(Some(left));
            let Ok((n, SocketAddr::V4(from))) = sock.recv_from(&mut buf) else { continue };
            // Any echo reply proves the sender is alive, even one meant for another
            // process's ping, so there's no need to match the identifier (which
            // Linux rewrites anyway).
            if is_echo_reply(&buf[..n]) && wanted.contains(from.ip()) {
                alive.insert(*from.ip());
            }
        }
    }
    alive
}

/// An ICMP datagram socket, wrapped in `UdpSocket` for its safe
/// `send_to`/`recv_from` (the port in the address is ignored).
#[cfg(unix)]
fn open() -> Option<UdpSocket> {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    (fd >= 0).then(|| unsafe { UdpSocket::from_raw_fd(fd) })
}

/// Windows has no ICMP datagram sockets.
#[cfg(windows)]
fn open() -> Option<UdpSocket> {
    None
}

fn echo_request(id: u16, seq: u16) -> [u8; 16] {
    let mut pkt = [0u8; 16];
    pkt[0] = ECHO_REQUEST;
    pkt[4..6].copy_from_slice(&id.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt[8..].copy_from_slice(b"lsnet\0\0\0");
    let sum = checksum(&pkt);
    pkt[2..4].copy_from_slice(&sum.to_be_bytes());
    pkt
}

/// macOS includes the IP header before the ICMP message; Linux doesn't.
fn is_echo_reply(pkt: &[u8]) -> bool {
    let icmp = match pkt.first() {
        Some(b) if b >> 4 == 4 => pkt.get(usize::from(b & 0x0f) * 4..),
        _ => Some(pkt),
    };
    icmp.and_then(|m| m.first()) == Some(&ECHO_REPLY)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_checksum_verifies() {
        // A correct checksum makes the whole message sum to zero.
        assert_eq!(checksum(&echo_request(0x1234, 1)), 0);
    }

    #[test]
    fn replies_with_and_without_ip_header() {
        let icmp = [ECHO_REPLY, 0, 0, 0, 0, 0, 0, 1];
        assert!(is_echo_reply(&icmp));
        let mut with_ip = vec![0x45; 1];
        with_ip.extend([0u8; 19]);
        with_ip.extend(icmp);
        assert!(is_echo_reply(&with_ip));
        assert!(!is_echo_reply(&[ECHO_REQUEST, 0, 0, 0]));
        assert!(!is_echo_reply(&[0x45, 0, 0]));
    }
}
