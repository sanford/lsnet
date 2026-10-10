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
//!
//! Every system times the devices found, though (`times`): they've answered
//! something already, so there's no ARP to wait for.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;
/// What our echo requests carry, before the time each was sent.
const MARK: &[u8; 8] = b"lsnet\0\0\0";
/// How many times `times` asks each device.
const ROUNDS: u32 = 3;

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
            let _ = sock.send_to(
                &echo_request(id, round, 0),
                SocketAddr::new(IpAddr::V4(ip), 0),
            );
            if i % 64 == 63 {
                thread::sleep(Duration::from_millis(2)); // don't overrun the send buffer
            }
        }
        let end = Instant::now() + wait / 2;
        let mut buf = [0u8; 1500];
        while let Some(left) = end
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        {
            let _ = sock.set_read_timeout(Some(left));
            let Ok((n, SocketAddr::V4(from))) = sock.recv_from(&mut buf) else {
                continue;
            };
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

/// How long each of `targets` takes to answer a ping: the best of three
/// round trips, for those that answer within `wait`. Empty where the system
/// has no ICMP sockets for us (Linux, when `ping_group_range` leaves us out).
#[cfg(unix)]
pub fn times(targets: &[Ipv4Addr], wait: Duration) -> HashMap<Ipv4Addr, Duration> {
    let mut best = HashMap::new();
    if targets.is_empty() || wait.is_zero() {
        return best;
    }
    let Some(sock) = open() else { return best };
    let Ok(listener) = sock.try_clone() else {
        return best;
    };
    let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let id = std::process::id() as u16;
    // Each request carries when it was sent, on this clock, and the reply
    // brings it back. Listening on a thread of its own keeps the sending
    // from holding up the clock.
    let clock = Instant::now();
    let end = clock + wait;
    thread::scope(|s| {
        let listening = s.spawn(|| {
            let mut best: HashMap<Ipv4Addr, Duration> = HashMap::new();
            let mut buf = [0u8; 1500];
            while let Some(left) = end
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
            {
                let _ = listener.set_read_timeout(Some(left));
                let Ok((n, SocketAddr::V4(from))) = listener.recv_from(&mut buf) else {
                    continue;
                };
                let now = clock.elapsed();
                let Some(sent) = echoed_time(&buf[..n]).filter(|sent| *sent <= now) else {
                    continue;
                };
                if wanted.contains(from.ip()) {
                    let took = now - sent;
                    let entry = best.entry(*from.ip()).or_insert(took);
                    *entry = took.min(*entry);
                }
            }
            best
        });
        // The last round leaves half the wait for its answers.
        for round in 0..ROUNDS {
            for (i, &ip) in targets.iter().enumerate() {
                let sent = clock.elapsed().as_nanos() as u64;
                let _ = sock.send_to(
                    &echo_request(id, round as u16, sent),
                    SocketAddr::new(IpAddr::V4(ip), 0),
                );
                if i % 64 == 63 {
                    thread::sleep(Duration::from_millis(2)); // don't overrun the send buffer
                }
            }
            if round + 1 < ROUNDS {
                thread::sleep(wait / (2 * (ROUNDS - 1)));
            }
        }
        best = listening.join().expect("ping listener");
    });
    best
}

/// Windows pings for anyone who asks, but one address at a time, each call
/// blocking until the answer or the timeout: so, as for its ARP sweep, every
/// address gets a thread, and we stop listening at the deadline.
#[cfg(windows)]
pub fn times(targets: &[Ipv4Addr], wait: Duration) -> HashMap<Ipv4Addr, Duration> {
    use std::sync::mpsc;

    let mut best = HashMap::new();
    if targets.is_empty() || wait.is_zero() || targets.len() > 1024 {
        return best;
    }
    let end = Instant::now() + wait;
    let (tx, rx) = mpsc::channel();
    for &ip in targets {
        let tx = tx.clone();
        thread::spawn(move || {
            for _ in 0..ROUNDS {
                if let Some(took) = crate::platform::ping(ip, wait / ROUNDS) {
                    let _ = tx.send((ip, took));
                }
            }
        });
    }
    drop(tx);
    while let Some(left) = end.checked_duration_since(Instant::now()) {
        let Ok((ip, took)) = rx.recv_timeout(left) else {
            break;
        };
        let entry = best.entry(ip).or_insert(took);
        *entry = took.min(*entry);
    }
    best
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

/// An echo request carrying `sent`, when it was sent on the sender's clock.
fn echo_request(id: u16, seq: u16, sent: u64) -> [u8; 24] {
    let mut pkt = [0u8; 24];
    pkt[0] = ECHO_REQUEST;
    pkt[4..6].copy_from_slice(&id.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt[8..16].copy_from_slice(MARK);
    pkt[16..].copy_from_slice(&sent.to_be_bytes());
    let sum = checksum(&pkt);
    pkt[2..4].copy_from_slice(&sum.to_be_bytes());
    pkt
}

/// The ICMP message in `pkt`. macOS includes the IP header before it; Linux
/// doesn't.
fn icmp(pkt: &[u8]) -> Option<&[u8]> {
    match pkt.first() {
        Some(b) if b >> 4 == 4 => pkt.get(usize::from(b & 0x0f) * 4..),
        _ => Some(pkt),
    }
}

fn is_echo_reply(pkt: &[u8]) -> bool {
    icmp(pkt).and_then(|m| m.first()) == Some(&ECHO_REPLY)
}

/// When the request this reply answers was sent, if it was one of ours.
#[cfg(any(unix, test))]
fn echoed_time(pkt: &[u8]) -> Option<Duration> {
    let m = icmp(pkt)?;
    if m.first() != Some(&ECHO_REPLY) || m.get(8..16)? != MARK {
        return None;
    }
    let sent = u64::from_be_bytes(m.get(16..24)?.try_into().ok()?);
    Some(Duration::from_nanos(sent))
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
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
        assert_eq!(checksum(&echo_request(0x1234, 1, 987_654_321)), 0);
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

    #[test]
    fn a_reply_brings_back_when_its_request_was_sent() {
        let mut reply = echo_request(7, 2, 1_500_000);
        assert_eq!(echoed_time(&reply), None, "a request isn't a reply");
        reply[0] = ECHO_REPLY;
        assert_eq!(echoed_time(&reply), Some(Duration::from_micros(1500)));
        // Behind an IP header, as macOS hands it over.
        let mut with_ip = vec![0x45];
        with_ip.extend([0u8; 19]);
        with_ip.extend(reply);
        assert_eq!(echoed_time(&with_ip), Some(Duration::from_micros(1500)));
        // Someone else's ping, and one cut short.
        reply[8] = b'x';
        assert_eq!(echoed_time(&reply), None);
        assert_eq!(echoed_time(&[ECHO_REPLY, 0, 0, 0, 0, 0, 0, 1]), None);
    }
}
