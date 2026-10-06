//! SSDP / UPnP discovery. Routers, TVs, media players and NASes answer an
//! M-SEARCH with the URL of an XML description that names their maker and model.

use crate::http;
use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};

const SSDP: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 255, 255, 250), 1900);
const SEARCH: &str = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
    MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SsdpInfo {
    pub server: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub device_type: Option<String>,
    /// The device's permanent UPnP identifier, e.g. `uuid:4d696e69-…`. A
    /// router's tells its network apart from others with the same addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udn: Option<String>,
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
    let start = Instant::now();
    collect(
        &sock,
        net,
        own_ips,
        start + wait,
        Some(start + wait / 3),
        start + wait + fetch_grace,
    )
    .await
}

/// Search each of `targets` directly, for devices whose answers to the
/// multicast search were lost: Wi-Fi access points often filter multicast,
/// and a unicast search gets through. Everything, description fetches
/// included, finishes within `wait`.
pub async fn query(
    local_ip: Ipv4Addr,
    net: Ipv4Network,
    own_ips: &[Ipv4Addr],
    targets: &[Ipv4Addr],
    wait: Duration,
) -> HashMap<Ipv4Addr, SsdpInfo> {
    if targets.is_empty() {
        return HashMap::new();
    }
    let Ok(sock) = UdpSocket::bind((local_ip, 0)).await else {
        return HashMap::new();
    };
    for &ip in targets {
        let _ = sock
            .send_to(unicast_search(ip).as_bytes(), (ip, 1900))
            .await;
    }
    let end = Instant::now() + wait;
    collect(&sock, net, own_ips, end, None, end).await
}

/// An M-SEARCH addressed to one device. Unicast searches are answered at
/// once, so MX only matters to devices that ignore that rule.
fn unicast_search(ip: Ipv4Addr) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {ip}:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n"
    )
}

/// Read search responses until `listen_end`, repeating the multicast search
/// at `resend_at` if given, and fetch each responder's description as soon as
/// it answers. Descriptions still arriving at `fetch_end` are dropped.
async fn collect(
    sock: &UdpSocket,
    net: Ipv4Network,
    own_ips: &[Ipv4Addr],
    listen_end: Instant,
    mut resend_at: Option<Instant>,
    fetch_end: Instant,
) -> HashMap<Ipv4Addr, SsdpInfo> {
    let mut seen: HashMap<Ipv4Addr, Option<String>> = HashMap::new();
    let mut fetches = JoinSet::new();
    let mut buf = vec![0u8; 4096];

    loop {
        let until = resend_at.unwrap_or(listen_end);
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
                    let wait = fetch_end.saturating_duration_since(Instant::now());
                    fetches.spawn(async move { (ip, http::get(host, port, &path, wait).await) });
                }
            }
            Ok(_) => {}
            Err(_) if resend_at.is_some() => {
                resend_at = None;
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

    while let Ok(Some(joined)) = timeout_at(fetch_end, fetches.join_next()).await {
        let Ok((ip, Some(resp))) = joined else {
            continue;
        };
        let info = out.entry(ip).or_default();
        *info = SsdpInfo {
            server: info.server.take(),
            ..parse_description(&resp.body)
        };
    }
    out
}

/// What a UPnP description says about the device. A root device describes
/// itself first, before any embedded devices, so the first of each tag is its own.
fn parse_description(xml: &str) -> SsdpInfo {
    SsdpInfo {
        server: None,
        friendly_name: http::tag(xml, "friendlyName"),
        manufacturer: http::tag(xml, "manufacturer"),
        model_name: http::tag(xml, "modelName"),
        model_number: http::tag(xml, "modelNumber"),
        device_type: http::tag(xml, "deviceType"),
        udn: http::tag(xml, "UDN"),
    }
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
    fn unicast_search_names_its_target() {
        let s = unicast_search("192.168.1.57".parse().unwrap());
        assert!(s.starts_with("M-SEARCH * HTTP/1.1\r\nHOST: 192.168.1.57:1900\r\n"));
        assert!(s.ends_with("ST: upnp:rootdevice\r\n\r\n"));
    }

    #[test]
    fn reads_the_root_device_from_a_description() {
        // A router's description, trimmed: the root device, then an embedded one.
        let xml = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Home Router</friendlyName>
    <manufacturer>NETGEAR</manufacturer>
    <modelName>RAX50</modelName>
    <modelNumber>v2</modelNumber>
    <UDN>uuid:4d696e69-444c-164e-9d41-001ec92f0001</UDN>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <friendlyName>WANDevice</friendlyName>
      </device>
    </deviceList>
  </device>
</root>"#;
        let info = parse_description(xml);
        assert_eq!(info.friendly_name.as_deref(), Some("Home Router"));
        assert_eq!(info.manufacturer.as_deref(), Some("NETGEAR"));
        assert_eq!(info.model_name.as_deref(), Some("RAX50"));
        assert_eq!(info.model_number.as_deref(), Some("v2"));
        assert_eq!(
            info.device_type.as_deref(),
            Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
        );
        assert_eq!(
            info.udn.as_deref(),
            Some("uuid:4d696e69-444c-164e-9d41-001ec92f0001")
        );
        assert_eq!(parse_description("<html>404</html>").manufacturer, None);
    }

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
