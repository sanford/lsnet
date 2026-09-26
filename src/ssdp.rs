//! SSDP / UPnP discovery. Routers, TVs, media players and NASes answer an
//! M-SEARCH with the URL of an XML description that names their maker and model.

use crate::http;
use ipnetwork::Ipv4Network;
use serde::Serialize;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};

const SSDP: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 255, 255, 250), 1900);
const SEARCH: &str = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
    MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";

#[derive(Default, Clone, Serialize)]
pub struct SsdpInfo {
    pub server: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub device_type: Option<String>,
}

/// Collect responses for `wait`, fetching each device's description as soon
/// as it answers, then allow `fetch_grace` for the last fetches to finish.
pub async fn discover(
    local_ip: Ipv4Addr,
    net: Ipv4Network,
    own_ips: &[Ipv4Addr],
    wait: Duration,
    fetch_grace: Duration,
) -> HashMap<Ipv4Addr, SsdpInfo> {
    let Ok(sock) = UdpSocket::bind((local_ip, 0)).await else {
        return HashMap::new();
    };
    let _ = sock.send_to(SEARCH.as_bytes(), SSDP).await;

    let deadline = Instant::now() + wait;
    let resend_at = Instant::now() + wait / 3;
    let mut resent = false;
    let mut seen: HashMap<Ipv4Addr, Option<String>> = HashMap::new();
    let mut fetches = JoinSet::new();
    let mut buf = vec![0u8; 4096];

    loop {
        let until = if resent { deadline } else { resend_at };
        match timeout_at(until, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, SocketAddr::V4(src)))) => {
                let ip = *src.ip();
                if !net.contains(ip) || seen.contains_key(&ip) {
                    continue;
                }
                let resp = String::from_utf8_lossy(&buf[..n]).to_string();
                let header = |name: &str| {
                    resp.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.trim()
                            .eq_ignore_ascii_case(name)
                            .then(|| v.trim().to_string())
                    })
                };
                seen.insert(ip, header("server"));
                if let Some((host, port, path)) =
                    header("location").and_then(|l| description_url(&l, ip, own_ips))
                {
                    fetches.spawn(async move {
                        (ip, http::get(host, port, &path, wait + fetch_grace).await)
                    });
                }
            }
            Ok(_) => {}
            Err(_) if !resent => {
                resent = true;
                let _ = sock.send_to(SEARCH.as_bytes(), SSDP).await;
            }
            Err(_) => break,
        }
    }

    let mut out: HashMap<Ipv4Addr, SsdpInfo> = seen
        .into_iter()
        .map(|(ip, server)| {
            (
                ip,
                SsdpInfo {
                    server,
                    ..Default::default()
                },
            )
        })
        .collect();

    let grace_end = Instant::now() + fetch_grace;
    while let Ok(Some(joined)) = timeout_at(grace_end, fetches.join_next()).await {
        let Ok((ip, Some(resp))) = joined else {
            continue;
        };
        let info = out.entry(ip).or_default();
        let x = &resp.body;
        info.friendly_name = http::tag(x, "friendlyName");
        info.manufacturer = http::tag(x, "manufacturer");
        info.model_name = http::tag(x, "modelName");
        info.model_number = http::tag(x, "modelNumber");
        info.device_type = http::tag(x, "deviceType");
    }
    out
}

/// Where to fetch a responder's description, if its LOCATION is safe to follow.
///
/// Only the device that answered is asked, and never this machine; otherwise
/// anyone on the LAN could point us at 127.0.0.1 or the internet. Queries are
/// refused too: description URLs don't have them, but "do something on GET"
/// endpoints usually take their parameters that way.
fn description_url(
    location: &str,
    responder: Ipv4Addr,
    own_ips: &[Ipv4Addr],
) -> Option<(Ipv4Addr, u16, String)> {
    let (host, port, path) = http::parse_url(location)?;
    (host == responder && !own_ips.contains(&host) && !path.contains('?'))
        .then_some((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_only_safe_locations() {
        let dev: Ipv4Addr = "192.168.1.57".parse().unwrap();
        let me: Ipv4Addr = "192.168.1.179".parse().unwrap();
        let ok = |l: &str, from: Ipv4Addr| description_url(l, from, &[me]).is_some();

        assert!(ok("http://192.168.1.57:49152/description.xml", dev));
        assert!(!ok("http://127.0.0.1:8080/description.xml", dev));
        assert!(!ok("http://192.168.1.1/description.xml", dev));
        assert!(!ok("http://192.168.1.57/cgi-bin/reboot?now=1", dev));
        assert!(!ok("http://192.168.1.179/description.xml", me));
    }
}
