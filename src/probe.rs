//! Unprivileged liveness check: try a handful of common TCP ports on every
//! address at once. A completed handshake *or* a refusal (RST) proves a host
//! is there; silence or "host down" doesn't. Hosts that answer then get the
//! longer list of service ports, and open ports double as a hint about what
//! the device is.

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
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
/// SNMP) plus homelab apps that give themselves away by port, and the
/// admin pages of Synology's (5000, 5001) and UGREEN's (9443, 9999) NAS.
const SERVICES: &[u16] = &[
    21, 25, 53, 110, 111, 135, 139, 143, 993, 995, 1433, 1521, 1883, 3306, 3389, 5000, 5001, 5060,
    5432, 5672, 6379, 8000, 8001, 8006, 8080, 8081, 8096, 8123, 8443, 8888, 9090, 9091, 9443, 9999,
    27017, 32400,
];

/// How long to wait on the ports of a host that just proved it's awake,
/// whether by answering near the deadline or by answering something other
/// than TCP. Handshakes on a LAN take milliseconds.
pub const AWAKE_WAIT: Duration = Duration::from_millis(250);

/// Live hosts and which ports they have open: `LIVENESS` on every target,
/// then `SERVICES` and `extra` (`--ports`) on each host as soon as it answers. Up to a /22 every
/// check starts at once; beyond that they start as earlier ones finish.
/// `checked` counts the liveness checks done, of `liveness_checks(targets)`.
pub async fn scan(
    targets: &[Ipv4Addr],
    extra: &[u16],
    wait: Duration,
    checked: &AtomicUsize,
) -> HashMap<Ipv4Addr, Vec<u16>> {
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
                set.spawn(async move { (false, check(ip, port, left).await) });
            } else if let Some((ip, port)) = liveness.next() {
                set.spawn(async move { (true, check(ip, port, wait).await) });
            } else {
                break;
            }
        }
        let Some(joined) = set.join_next().await else {
            break;
        };
        let Ok((is_liveness, (ip, port, open))) = joined else {
            continue;
        };
        if is_liveness {
            checked.fetch_add(1, Ordering::Relaxed);
        }
        let Some(open) = open else {
            continue;
        };
        if !alive.contains_key(&ip) {
            let left = deadline
                .saturating_duration_since(Instant::now())
                .max(AWAKE_WAIT);
            services.extend(service_ports(extra).map(|port| (ip, port, left)));
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

/// How many liveness checks `scan` makes of `targets`.
pub fn liveness_checks(targets: &[Ipv4Addr]) -> usize {
    targets.len() * LIVENESS.len()
}

/// Every port on one host found some other way (ARP, ping, mDNS, SSDP), for
/// devices that ignored the liveness ports or woke up late.
pub async fn all_ports(ip: Ipv4Addr, extra: &[u16], wait: Duration) -> Vec<u16> {
    let mut set = JoinSet::new();
    for port in LIVENESS.iter().copied().chain(service_ports(extra)) {
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

/// `SERVICES`, then whichever of `extra` aren't checked already.
fn service_ports(extra: &[u16]) -> impl Iterator<Item = u16> {
    let known = |p: &u16| LIVENESS.contains(p) || SERVICES.contains(p);
    let extra = extra.iter().copied().filter(move |p| !known(p));
    SERVICES.iter().copied().chain(extra)
}

/// The most ports `--ports` takes. Each is tried on every device found, and
/// past this it's a port scan, which nmap does better.
pub const MAX_EXTRA: usize = 1000;

/// One item of `--ports`: a port, or a range like 8000-8100.
pub fn parse_ports(s: &str) -> Result<RangeInclusive<u16>, String> {
    let port = |p: &str| {
        p.trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("'{p}' isn't a port from 1 to 65535"))
    };
    let (first, last) = match s.split_once('-') {
        Some((first, last)) => (port(first)?, port(last)?),
        None => (port(s)?, port(s)?),
    };
    if first > last {
        return Err(format!("{s} runs backwards; did you mean {last}-{first}?"));
    }
    Ok(first..=last)
}

/// Every port `--ports` named, once each, in order.
pub fn extra_ports(ranges: &[RangeInclusive<u16>]) -> Result<Vec<u16>, String> {
    let named: usize = ranges.iter().map(|r| r.len()).sum();
    if named > MAX_EXTRA {
        return Err(format!(
            "--ports takes up to {MAX_EXTRA} ports, and that's {named}; nmap is the tool for a port scan"
        ));
    }
    let mut ports: Vec<u16> = ranges.iter().cloned().flatten().collect();
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
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

    #[test]
    fn ports_takes_ports_and_ranges() {
        assert_eq!(parse_ports("2049"), Ok(2049..=2049));
        assert_eq!(parse_ports("8200-8210"), Ok(8200..=8210));
        assert!(parse_ports("0").unwrap_err().contains("1 to 65535"));
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("http").is_err());
        assert!(parse_ports("90-80").unwrap_err().contains("80-90"));
        // Named twice, or checked anyway: once each.
        let ports = extra_ports(&[9000..=9002, 9001..=9001, 22..=22]).unwrap();
        assert_eq!(ports, [22, 9000, 9001, 9002]);
        assert_eq!(service_ports(&ports).filter(|p| *p == 22).count(), 0);
        assert_eq!(service_ports(&ports).count(), SERVICES.len() + 3);
        assert!(
            extra_ports(&[1..=600, 8000..=8999])
                .unwrap_err()
                .contains("nmap")
        );
    }

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
