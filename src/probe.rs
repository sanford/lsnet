//! Unprivileged liveness check: try a handful of common TCP ports on every
//! address at once. A completed handshake *or* a refusal (RST) proves a host
//! is there; silence or "host down" doesn't. Open ports double as a first
//! hint about what the device is.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// Ports chosen because common devices answer on at least one of them:
/// web UIs, SSH, SMB, iPhone sync (62078), AirPlay (7000), Chromecast (8008), printers (9100).
const PORTS: &[u16] = &[80, 443, 22, 445, 62078, 7000, 8008, 9100];

/// Live hosts and whichever of `PORTS` they have open.
pub async fn scan(targets: &[Ipv4Addr], wait: Duration) -> HashMap<Ipv4Addr, Vec<u16>> {
    let mut set = JoinSet::new();
    for &ip in targets {
        for &port in PORTS {
            set.spawn(async move {
                let open = match timeout(wait, TcpStream::connect((ip, port))).await {
                    Ok(Ok(_)) => Some(true),
                    Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => Some(false),
                    _ => None,
                };
                (ip, port, open)
            });
        }
    }
    let mut alive: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();
    while let Some(Ok((ip, port, open))) = set.join_next().await {
        if let Some(open) = open {
            let ports = alive.entry(ip).or_default();
            if open {
                ports.push(port);
            }
        }
    }
    for ports in alive.values_mut() {
        ports.sort_unstable();
    }
    alive
}

/// A /24 sweep opens ~2000 sockets at once; macOS defaults to 256 descriptors.
pub fn raise_fd_limit() {
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
            lim.rlim_cur = lim.rlim_max.min(10_240);
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }
}
