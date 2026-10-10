//! The services view: every server running on the network, one row per
//! address and port, from open ports and from what devices advertise over
//! Bonjour (which finds web UIs on ports we never probe).

use crate::Device;
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// Open ports that are how a device talks to its owner's phone, not servers.
const DEVICE_PROTOCOLS: &[u16] = &[7000, 8008, 62078];

/// Open ports that mean too many things to list unless a device's maker
/// says what they are (see `ADMIN_PORTS`): 5000 is also a Mac's AirPlay
/// receiver and many routers' UPnP, and 9999 a Kasa plug's own protocol.
const AMBIGUOUS: &[u16] = &[5000, 9999];

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

/// Every service on `devices`, sorted by address and then port.
pub fn list(devices: &[Device]) -> Vec<Service> {
    let mut found: BTreeMap<(Ipv4Addr, u16), (usize, Option<&'static str>)> = BTreeMap::new();
    for (i, d) in devices.iter().enumerate() {
        let admin = admin(d).map_or(&[][..], |a| a.ports);
        for &port in d
            .open_ports
            .iter()
            .filter(|p| !DEVICE_PROTOCOLS.contains(p))
        {
            let name = match admin.iter().find(|(p, _)| *p == port) {
                Some(&(_, name)) => Some(name),
                None if AMBIGUOUS.contains(&port) => continue,
                None => port_name(port),
            };
            found.insert((d.ip, port), (i, name));
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
/// Each is known by its maker's name, or the name its NAS come with, for
/// when the MAC vendor's hidden and UPnP is off.
const ADMIN_PORTS: &[Admin] = &[
    // 80 and 443 are Web Station's, which until it's set up only says so.
    Admin {
        names: &["synology", "diskstation"],
        ports: &[(5001, "HTTPS"), (5000, "HTTP")],
        last: &[80, 443],
    },
    Admin {
        names: &["ugreen", "ugnas"],
        ports: &[(9443, "HTTPS"), (9999, "HTTP")],
        last: &[],
    },
    Admin {
        names: &["qnap"],
        ports: &[(443, "HTTPS"), (8080, "HTTP")],
        last: &[],
    },
];

struct Admin {
    names: &'static [&'static str],
    /// Each port, and what it serves.
    ports: &'static [(u16, &'static str)],
    /// Web ports to open only when nothing else will.
    last: &'static [u16],
}

/// `d`'s maker's entry in `ADMIN_PORTS`, if it has one.
fn admin(d: &Device) -> Option<&'static Admin> {
    let ssdp = d.ssdp.iter().flat_map(|s| [&s.manufacturer, &s.model_name]);
    let mdns = d.mdns.iter().map(|m| &m.hostname);
    let maker = [d.vendor.map(String::from), d.model.clone(), d.name.clone()]
        .into_iter()
        .chain(ssdp.cloned())
        .chain(mdns.cloned())
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    ADMIN_PORTS
        .iter()
        .find(|a| a.names.iter().any(|n| maker.contains(n)))
}

/// The web page to open for `devices[device]`: its maker's admin page if
/// it's one of `ADMIN_PORTS`' and it's open, or else its first web UI by
/// port, leaving the ones its maker's are known to waste until last.
pub fn device_url(services: &[Service], devices: &[Device], device: usize) -> Option<String> {
    let theirs: Vec<&Service> = services.iter().filter(|s| s.device == device).collect();
    let Some(admin) = admin(&devices[device]) else {
        return theirs.iter().find_map(|s| s.url());
    };
    let page = admin
        .ports
        .iter()
        .find_map(|&(port, _)| theirs.iter().find(|s| s.port == port)?.url());
    let (last, rest): (Vec<&Service>, Vec<&Service>) =
        theirs.iter().partition(|s| admin.last.contains(&s.port));
    page.or_else(|| rest.iter().chain(&last).find_map(|s| s.url()))
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
        // Its admin port closed, the first web UI, and Web Station's last.
        assert_eq!(
            nas("Synology", vec![22, 80, 443]).as_deref(),
            Some("http://192.168.1.14/")
        );
        assert_eq!(
            nas("Synology", vec![80, 443, 32400]).as_deref(),
            Some("http://192.168.1.14:32400/web")
        );
        assert_eq!(
            nas("Ugreen", vec![22, 80]).as_deref(),
            Some("http://192.168.1.14/")
        );
        assert_eq!(
            nas("Apple", vec![80, 5001]).as_deref(),
            Some("http://192.168.1.14/")
        );
        assert_eq!(nas("Synology", vec![22, 445]), None);
        // Their HTTP pages, on ports that mean other things elsewhere.
        assert_eq!(
            nas("Synology", vec![80, 5000]).as_deref(),
            Some("http://192.168.1.14:5000/")
        );
        assert_eq!(
            nas("Ugreen", vec![9999]).as_deref(),
            Some("http://192.168.1.14:9999/")
        );
        // Without a vendor, by the name it came with.
        let mut ugnas = Device::new(Ipv4Addr::new(192, 168, 1, 16));
        ugnas.name = Some("UGNAS".into());
        ugnas.open_ports = vec![80, 8123, 9443, 9999];
        let devices = vec![ugnas];
        assert_eq!(
            device_url(&list(&devices), &devices, 0).as_deref(),
            Some("https://192.168.1.16:9443/")
        );
    }

    #[test]
    fn ambiguous_ports_are_listed_only_for_their_nas() {
        let mut mac = Device::new(Ipv4Addr::new(192, 168, 1, 20));
        mac.vendor = Some("Apple");
        mac.open_ports = vec![5000, 7000];
        let mut plug = Device::new(Ipv4Addr::new(192, 168, 1, 21));
        plug.vendor = Some("TP-Link");
        plug.open_ports = vec![9999];
        let mut nas = Device::new(Ipv4Addr::new(192, 168, 1, 22));
        nas.vendor = Some("Synology");
        nas.open_ports = vec![5000];
        let listed: Vec<(u16, Option<&str>)> = list(&[mac, plug, nas])
            .iter()
            .map(|s| (s.port, s.name))
            .collect();
        assert_eq!(listed, [(5000, Some("HTTP"))]);
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
        // This machine's are servers like any other's.
        let mut me = Device::new(Ipv4Addr::new(192, 168, 1, 3));
        me.open_ports = vec![22, 7000];
        me.this_device = true;

        let devices = [phone, me, nas];
        let rows: Vec<_> = list(&devices)
            .iter()
            .map(|s| (s.address(), s.device, s.name))
            .collect();
        assert_eq!(
            rows,
            [
                ("192.168.1.3:22".into(), 1, Some("SSH")),
                ("192.168.1.14:22".into(), 2, Some("SSH")),
                ("192.168.1.14:80".into(), 2, Some("HTTP")),
                ("192.168.1.14:5000".into(), 2, Some("HTTP")),
                ("192.168.1.14:8080".into(), 2, Some("WebDAV")),
                ("192.168.1.14:32400".into(), 2, Some("Plex")),
            ]
        );
    }
}
