//! The services view: every server running on the network, one row per
//! address and port, from open ports and from what devices advertise over
//! Bonjour (which finds web UIs on ports we never probe).

use crate::Device;
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// Open ports that are how a device talks to its owner's phone, not servers.
const DEVICE_PROTOCOLS: &[u16] = &[7000, 8008, 62078];

pub struct Service {
    /// Index into the scan's devices.
    pub device: usize,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub name: Option<&'static str>,
}

impl Service {
    pub fn address(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }

    /// The page a browser would open for this service, if it's a web UI.
    pub fn url(&self) -> Option<String> {
        let scheme = match self.name? {
            "HTTPS" | "WebDAVS" | "Proxmox" => "https",
            "HTTP" | "HTTP alt" | "WebDAV" | "Home Assistant" | "ESPHome" | "OctoPrint"
            | "Umbrel" | "Plex" | "Jellyfin" | "Prometheus" => "http",
            _ => return None,
        };
        let host = match (scheme, self.port) {
            ("http", 80) | ("https", 443) => self.ip.to_string(),
            _ => self.address(),
        };
        // Plex's own page is a server's API; its web app is under /web.
        let path = if self.name == Some("Plex") {
            "/web"
        } else {
            "/"
        };
        Some(format!("{scheme}://{host}{path}"))
    }
}

#[derive(Serialize)]
pub struct Json {
    ip: Ipv4Addr,
    port: u16,
    service: Option<&'static str>,
    host: Option<String>,
}

impl Json {
    pub fn new(s: &Service, devices: &[Device]) -> Self {
        let d = &devices[s.device];
        let host = d.name.clone().or_else(|| d.hostname.clone());
        Json {
            ip: s.ip,
            port: s.port,
            service: s.name,
            host,
        }
    }
}

/// Every service on `devices` (except this machine, whose ports we don't
/// probe), sorted by address and then port.
pub fn list(devices: &[Device]) -> Vec<Service> {
    let mut found: BTreeMap<(Ipv4Addr, u16), (usize, Option<&'static str>)> = BTreeMap::new();
    for (i, d) in devices.iter().enumerate().filter(|(_, d)| !d.this_device) {
        for &port in d
            .open_ports
            .iter()
            .filter(|p| !DEVICE_PROTOCOLS.contains(p))
        {
            found.insert((d.ip, port), (i, port_name(port)));
        }
        let advertised = d.mdns.iter().flat_map(|m| &m.ports);
        for (name, &port) in
            advertised.filter_map(|(svc, port)| Some((advertised_name(svc)?, port)))
        {
            // An app's own port (Plex, Home Assistant) beats a generic advertised
            // name like HTTP, which beats a guess from the port number.
            let slot = found.entry((d.ip, port)).or_insert((i, None));
            if matches!(slot.1, None | Some("HTTP alt")) {
                slot.1 = Some(name);
            }
        }
    }
    found
        .into_iter()
        .map(|((ip, port), (device, name))| Service {
            device,
            ip,
            port,
            name,
        })
        .collect()
}

/// Where some makers' NAS keep their admin page, in order of preference,
/// when it isn't on port 80: Synology's DSM, UGREEN's UGOS and QNAP's QTS.
const ADMIN_PORTS: &[(&str, &[u16])] = &[
    ("synology", &[5001, 5000]),
    ("ugreen", &[9443, 9999]),
    ("qnap", &[443, 8080]),
];

/// The web page to open for `devices[device]`: its maker's admin page if
/// it's one of `ADMIN_PORTS`' and it's open, or else its first web UI by port.
pub fn device_url(services: &[Service], devices: &[Device], device: usize) -> Option<String> {
    let d = &devices[device];
    let ssdp = d.ssdp.iter().flat_map(|s| [&s.manufacturer, &s.model_name]);
    let maker = [d.vendor.map(String::from), d.model.clone()]
        .into_iter()
        .chain(ssdp.cloned())
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let theirs: Vec<&Service> = services.iter().filter(|s| s.device == device).collect();
    let admin = ADMIN_PORTS
        .iter()
        .filter(|(name, _)| maker.contains(name))
        .flat_map(|(_, ports)| ports.iter())
        .find_map(|&port| theirs.iter().find(|s| s.port == port)?.url());
    admin.or_else(|| theirs.iter().find_map(|s| s.url()))
}

/// Bonjour service types that are servers someone would want to reach.
fn advertised_name(service: &str) -> Option<&'static str> {
    Some(match service {
        "http" => "HTTP",
        "https" => "HTTPS",
        "ssh" => "SSH",
        "sftp-ssh" => "SFTP",
        "smb" => "SMB",
        "afpovertcp" => "AFP",
        "nfs" => "NFS",
        "ftp" => "FTP",
        "rfb" => "VNC",
        "webdav" => "WebDAV",
        "webdavs" => "WebDAVS",
        "home-assistant" => "Home Assistant",
        "esphomelib" => "ESPHome",
        "octoprint" => "OctoPrint",
        "umbrel" => "Umbrel",
        "plexmediasvr" => "Plex",
        _ => return None,
    })
}

/// What the ports `probe` checks usually mean.
pub fn port_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "FTP",
        22 => "SSH",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPC",
        135 => "Windows RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        // Also Synology DSM's (5001) and UGREEN NAS's or Portainer's (9443) web UIs.
        443 | 5001 | 8443 | 9443 => "HTTPS",
        445 => "SMB",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "SQL Server",
        1521 => "Oracle",
        1883 => "MQTT",
        3306 => "MySQL",
        3389 => "RDP",
        5060 => "SIP",
        5432 => "PostgreSQL",
        5672 => "AMQP",
        6379 => "Redis",
        7000 => "AirPlay",
        8000 | 8001 | 8080 | 8081 | 8888 => "HTTP alt",
        8006 => "Proxmox",
        8008 => "Cast",
        8096 => "Jellyfin",
        8123 => "Home Assistant",
        9090 => "Prometheus",
        9100 => "printing",
        27017 => "MongoDB",
        32400 => "Plex",
        62078 => "iOS sync",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdns::MdnsInfo;

    #[test]
    fn web_uis_have_urls() {
        let url = |port, name| {
            let s = Service {
                device: 0,
                ip: Ipv4Addr::new(192, 168, 1, 14),
                port,
                name,
            };
            s.url()
        };
        assert_eq!(
            url(80, Some("HTTP")).as_deref(),
            Some("http://192.168.1.14/")
        );
        assert_eq!(
            url(443, Some("HTTPS")).as_deref(),
            Some("https://192.168.1.14/")
        );
        assert_eq!(
            url(5001, Some("HTTPS")).as_deref(),
            Some("https://192.168.1.14:5001/")
        );
        assert_eq!(
            url(8006, Some("Proxmox")).as_deref(),
            Some("https://192.168.1.14:8006/")
        );
        assert_eq!(
            url(32400, Some("Plex")).as_deref(),
            Some("http://192.168.1.14:32400/web")
        );
        assert_eq!(url(22, Some("SSH")), None);
        assert_eq!(url(445, Some("SMB")), None);
        assert_eq!(url(12345, None), None);
    }

    #[test]
    fn a_nas_opens_its_admin_page() {
        let nas = |vendor: &'static str, ports: Vec<u16>| {
            let mut d = Device::new(Ipv4Addr::new(192, 168, 1, 14));
            d.vendor = Some(vendor);
            d.open_ports = ports;
            let devices = vec![d];
            device_url(&list(&devices), &devices, 0)
        };
        assert_eq!(
            nas("Synology", vec![80, 443, 5001]).as_deref(),
            Some("https://192.168.1.14:5001/")
        );
        assert_eq!(
            nas("Ugreen", vec![80, 9443]).as_deref(),
            Some("https://192.168.1.14:9443/")
        );
        // Its admin port closed, the first web UI as for anything else.
        assert_eq!(
            nas("Synology", vec![22, 80]).as_deref(),
            Some("http://192.168.1.14/")
        );
        assert_eq!(
            nas("Apple", vec![80, 5001]).as_deref(),
            Some("http://192.168.1.14/")
        );
        assert_eq!(nas("Synology", vec![22, 445]), None);
    }

    #[test]
    fn merges_ports_and_bonjour() {
        let mut nas = Device::new(Ipv4Addr::new(192, 168, 1, 14));
        nas.open_ports = vec![22, 80, 8080, 32400];
        let mut m = MdnsInfo::default();
        m.ports.insert("http".into(), 5000); // a web UI on a port we don't probe
        m.ports.insert("ssh".into(), 22); // the same service twice
        m.ports.insert("webdav".into(), 8080); // better than "HTTP alt"
        m.ports.insert("https".into(), 32400); // but not better than "Plex"
        m.ports.insert("airplay".into(), 7000); // not a server
        nas.mdns = Some(m);
        let mut phone = Device::new(Ipv4Addr::new(192, 168, 1, 2));
        phone.open_ports = vec![62078];
        let mut me = Device::new(Ipv4Addr::new(192, 168, 1, 3));
        me.open_ports = vec![22];
        me.this_device = true;

        let devices = [phone, me, nas];
        let rows: Vec<_> = list(&devices)
            .iter()
            .map(|s| (s.address(), s.device, s.name))
            .collect();
        assert_eq!(
            rows,
            [
                ("192.168.1.14:22".into(), 2, Some("SSH")),
                ("192.168.1.14:80".into(), 2, Some("HTTP")),
                ("192.168.1.14:5000".into(), 2, Some("HTTP")),
                ("192.168.1.14:8080".into(), 2, Some("WebDAV")),
                ("192.168.1.14:32400".into(), 2, Some("Plex")),
            ]
        );
    }
}
