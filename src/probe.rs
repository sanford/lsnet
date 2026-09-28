//! Unprivileged liveness check: try a handful of common TCP ports on every
//! address at once. A completed handshake *or* a refusal (RST) proves a host
//! is there; silence or "host down" doesn't. Hosts that answer then get the
//! longer list of service ports, and open ports double as a hint about what
//! the device is.

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};

/// Probed on every address. Chosen because common devices answer on at least one of them:
/// web UIs, SSH, SMB, iPhone sync (62078), AirPlay (7000), Chromecast (8008), printers (9100).
const LIVENESS: &[u16] = &[80, 443, 22, 445, 62078, 7000, 8008, 9100];

/// Probed only on hosts known to be alive, so a /24 sweep doesn't grow
/// fivefold. Common server ports (after Vaverka's list, minus UDP-only
/// SNMP) plus homelab apps that give themselves away by port.
const SERVICES: &[u16] = &[
    21, 25, 53, 110, 111, 135, 139, 143, 993, 995, 1433, 1521, 1883, 3306, 3389, 5001, 5060, 5432,
    5672, 6379, 8000, 8001, 8006, 8080, 8081, 8096, 8123, 8443, 8888, 9090, 9091, 9443, 27017,
    32400,
];

/// How long to wait on the ports of a host that just proved it's awake,
/// whether by answering near the deadline or by answering something other
/// than TCP. Handshakes on a LAN take milliseconds.
pub const AWAKE_WAIT: Duration = Duration::from_millis(250);

/// Live hosts and which ports they have open: `LIVENESS` on every target,
/// then `SERVICES` on each host as soon as it answers. Up to a /22 every
/// check starts at once; beyond that they start as earlier ones finish.
pub async fn scan(targets: &[Ipv4Addr], wait: Duration) -> HashMap<Ipv4Addr, Vec<u16>> {
    let deadline = Instant::now() + wait;
    let mut liveness = targets
        .iter()
        .flat_map(|&ip| LIVENESS.iter().map(move |&port| (ip, port)));
    // Live hosts' service ports go ahead of the addresses still unchecked.
    let mut services: VecDeque<(Ipv4Addr, u16, Duration)> = VecDeque::new();
    let mut set = JoinSet::new();
    let mut alive: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();
    loop {
        while set.len() < max_in_flight() {
            if let Some((ip, port, left)) = services.pop_front() {
                set.spawn(check(ip, port, left));
            } else if let Some((ip, port)) = liveness.next() {
                set.spawn(check(ip, port, wait));
            } else {
                break;
            }
        }
        let Some(joined) = set.join_next().await else {
            break;
        };
        let Ok((ip, port, Some(open))) = joined else {
            continue;
        };
        if !alive.contains_key(&ip) {
            let left = deadline
                .saturating_duration_since(Instant::now())
                .max(AWAKE_WAIT);
            services.extend(SERVICES.iter().map(|&port| (ip, port, left)));
        }
        let ports = alive.entry(ip).or_default();
        if open {
            ports.push(port);
        }
    }
    for ports in alive.values_mut() {
        ports.sort_unstable();
    }
    alive
}

/// Every port on one host found some other way (ARP, ping, mDNS, SSDP), for
/// devices that ignored the liveness ports or woke up late.
pub async fn all_ports(ip: Ipv4Addr, wait: Duration) -> Vec<u16> {
    let mut set = JoinSet::new();
    for &port in LIVENESS.iter().chain(SERVICES) {
        set.spawn(check(ip, port, wait));
    }
    let mut open = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((_, port, Some(true))) = joined {
            open.push(port);
        }
    }
    open.sort_unstable();
    open
}

/// Some(true) if the port is open, Some(false) if refused (the host is
/// there), None if we heard nothing. The wait starts once there's a socket
/// to spare.
async fn check(ip: Ipv4Addr, port: u16, wait: Duration) -> (Ipv4Addr, u16, Option<bool>) {
    let _permit = sockets().acquire().await.expect("never closed");
    let open = match timeout(wait, connect(ip, port)).await {
        Ok(Ok(_)) => Some(true),
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => Some(false),
        _ => None,
    };
    (ip, port, open)
}

#[cfg(not(windows))]
async fn connect(ip: Ipv4Addr, port: u16) -> std::io::Result<TcpStream> {
    TcpStream::connect((ip, port)).await
}

/// Windows retries a refused connection for two seconds unless told not to.
#[cfg(windows)]
async fn connect(ip: Ipv4Addr, port: u16) -> std::io::Result<TcpStream> {
    let sock = tokio::net::TcpSocket::new_v4()?;
    crate::platform::fail_fast_on_refusal(&sock);
    sock.connect((ip, port).into()).await
}

/// Connection attempts in flight at once, across every probe.
fn sockets() -> &'static Semaphore {
    static SOCKETS: OnceLock<Semaphore> = OnceLock::new();
    SOCKETS.get_or_init(|| Semaphore::new(max_in_flight()))
}

/// How many connections to attempt at once: enough for a /22 in one go,
/// leaving descriptors spare for everything else (web banners, mDNS, SSDP).
fn max_in_flight() -> usize {
    static MAX: OnceLock<usize> = OnceLock::new();
    *MAX.get_or_init(|| {
        #[cfg(unix)]
        let limit = unsafe {
            let mut lim: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
                lim.rlim_cur as usize
            } else {
                256
            }
        };
        #[cfg(windows)]
        let limit: usize = 10_240;
        limit.saturating_sub(512).clamp(128, 8_192)
    })
}

/// A /24 sweep opens ~2000 sockets at once, and a /22 ~8000; macOS
/// defaults to 256 descriptors. Windows has no such limit. Call this before
/// probing, since the probes size themselves to the limit it leaves.
pub fn raise_fd_limit() {
    #[cfg(unix)]
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
            lim.rlim_cur = lim.rlim_max.min(10_240);
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refusals_come_back_at_once() {
        // A port that was just free, so connecting to it is refused.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let start = std::time::Instant::now();
        let (_, _, open) = check(Ipv4Addr::LOCALHOST, port, Duration::from_secs(5)).await;
        assert_eq!(open, Some(false));
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "took {:?}",
            start.elapsed()
        );
    }
}
