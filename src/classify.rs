//! Turn the evidence gathered about a device into a name, type and model.
//!
//! Sources are consulted from most to least specific: model identifiers a
//! device announces about itself (Bonjour TXT records, UPnP descriptions)
//! beat naming conventions, which beat open ports and MAC vendors.

use crate::Device;
use crate::services::port_name;

pub fn classify(d: &mut Device) {
    (d.name, d.name_from) = name_and_source(d).unzip();
    let ((kind, model), why) = match identify_why(d) {
        Some(((k, m), why)) => ((Some(k.to_string()), m), Some(why)),
        None if d.gateway => (
            (Some("Router".into()), None),
            Some("it's the default gateway".into()),
        ),
        None => ((None, None), None),
    };
    d.kind = kind;
    d.model = model;
    d.type_from = why;
}

type Id = (&'static str, Option<String>);

/// An identification, and the evidence that decided it, for people to read.
type Why = (Id, String);

#[cfg(test)]
fn identify(d: &Device) -> Option<Id> {
    identify_why(d).map(|(id, _)| id)
}

fn identify_why(d: &Device) -> Option<Why> {
    from_mdns(d)
        .or_else(|| from_kasa(d))
        .or_else(|| from_ssdp(d))
        .or_else(|| from_names(d))
        .or_else(|| from_http(d))
        .or_else(|| from_services(d))
        .or_else(|| from_ports(d))
        .or_else(|| from_brand_names(d))
        .or_else(|| from_vendor(d))
        .or_else(|| from_generic_ports(d))
}

fn from_mdns(d: &Device) -> Option<Why> {
    let m = d.mdns.as_ref()?;
    let txt = |svc: &str, key: &str| m.txt.get(svc).and_then(|t| t.get(key)).map(String::as_str);
    let said = |svc: &str, key: &str, value: &str| format!("Bonjour {svc} {key} = {value}");

    // Apple devices announce their model identifier in several places.
    let apple_id = [
        ("airplay", "model"),
        ("raop", "am"),
        ("companion-link", "rpmd"),
        ("device-info", "model"),
    ]
    .into_iter()
    .find_map(|(svc, key)| Some((svc, key, txt(svc, key)?)))
    .filter(|(_, _, id)| is_apple_id(id));
    if let Some((svc, key, id)) = apple_id {
        return Some((apple_model(id), said(svc, key, id)));
    }

    if let Some(md) = txt("googlecast", "md") {
        let lower = md.to_ascii_lowercase();
        let kind = if ["mini", "home", "speaker", "audio"]
            .iter()
            .any(|k| lower.contains(k))
        {
            "Speaker"
        } else if lower.contains("hub") {
            "Smart display"
        } else {
            "TV / streamer"
        };
        return Some(((kind, Some(md.to_string())), said("googlecast", "md", md)));
    }

    let printing = ["ipp", "ipps", "printer", "pdl-datastream"];
    if let Some(svc) = printing.iter().find(|s| m.services.contains_key(**s)) {
        let model = printing.iter().find_map(|s| txt(s, "ty")).map(String::from);
        return Some((("Printer", model), format!("advertises {svc} over Bonjour")));
    }

    if let Some(ci) = txt("hap", "ci").and_then(|c| c.parse().ok()) {
        let model = txt("hap", "md").map(|md| {
            let instance = &m.services["hap"];
            match brand(instance) {
                Some(b) if !md.to_ascii_lowercase().contains(&b.to_ascii_lowercase()) => {
                    format!("{b} {md}")
                }
                _ => md.to_string(),
            }
        });
        return Some((
            (homekit_category(ci), model),
            format!("HomeKit category, {}", said("hap", "ci", &ci.to_string())),
        ));
    }

    if let Some(mn) = txt("glinet", "mn") {
        let model = format!("GL.iNet {}", mn.to_ascii_uppercase());
        let kind = if mn.starts_with("rm") {
            "KVM"
        } else {
            "Router"
        };
        return Some(((kind, Some(model)), said("glinet", "mn", mn)));
    }

    None
}

fn from_kasa(d: &Device) -> Option<Why> {
    let k = d.kasa.as_ref()?;
    let device_type = k.device_type.as_deref().unwrap_or("").to_ascii_lowercase();
    let description = k.description.as_deref().unwrap_or("").to_ascii_lowercase();
    let kind = if device_type.contains("bulb") || description.contains("bulb") {
        "Smart light"
    } else if description.contains("switch") || description.contains("dimmer") {
        "Light switch"
    } else {
        "Smart plug"
    };
    // "HS105(US)" → "HS105".
    let model = k.model.as_deref().map(|m| {
        let m =
            kasa_model(m).unwrap_or_else(|| m.split('(').next().unwrap_or(m).trim().to_string());
        format!("TP-Link Kasa {m}")
    });
    let why = match &k.model {
        Some(m) => format!("Kasa reports model {m}"),
        None => "answers TP-Link Kasa's protocol".into(),
    };
    Some(((kind, model), why))
}

fn from_ssdp(d: &Device) -> Option<Why> {
    let s = d.ssdp.as_ref()?;
    let device_type = s.device_type.as_deref().unwrap_or("").to_ascii_lowercase();
    let maker = s.manufacturer.as_deref().unwrap_or("");
    let model = s.model_name.as_deref().map(|m| {
        if maker.is_empty()
            || m.to_ascii_lowercase()
                .starts_with(&maker.to_ascii_lowercase())
        {
            m.to_string()
        } else {
            format!("{maker} {m}")
        }
    });
    let lower_maker = maker.to_ascii_lowercase();
    let kind = if device_type.contains("internetgatewaydevice") || device_type.contains("wfadevice")
    {
        "Router"
    } else if ["synology", "qnap", "asustor", "ugreen", "terramaster"]
        .iter()
        .any(|m| lower_maker.contains(m))
    {
        "NAS"
    } else if lower_maker.contains("sonos") {
        "Speaker"
    } else if device_type.contains("mediarenderer") {
        "TV / streamer"
    } else if device_type.contains("mediaserver") {
        "Media server"
    } else if lower_maker.contains("philips") || lower_maker.contains("signify") {
        "Smart home hub"
    } else if model.is_some() {
        "UPnP device"
    } else {
        return None;
    };
    // urn:schemas-upnp-org:device:MediaRenderer:1 → MediaRenderer
    let short_type = s
        .device_type
        .as_deref()
        .map(|t| t.rsplit(':').nth(1).unwrap_or(t));
    let why = match (short_type, maker) {
        (Some(t), "") => format!("UPnP {t}"),
        (Some(t), m) => format!("UPnP {t} by {m}"),
        (None, "") => format!("UPnP model {}", model.as_deref().unwrap_or("")),
        (None, m) => format!("UPnP device by {m}"),
    };
    Some(((kind, model), why))
}

/// Every name a device goes by, lowercased.
fn all_names(d: &Device) -> Vec<String> {
    let mut names: Vec<String> = [
        d.hostname.as_deref(),
        d.mdns.as_ref().and_then(|m| m.hostname.as_deref()),
        d.netbios.as_ref().map(|n| n.name.as_str()),
        d.name.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(str::to_ascii_lowercase)
    .collect();
    names.dedup();
    names
}

/// Naming conventions: many devices ship with a hostname that says what they are.
fn from_names(d: &Device) -> Option<Why> {
    all_names(d)
        .into_iter()
        .find_map(|n| Some((named(&n)?, format!("its name \"{n}\""))))
}

fn named(n: &str) -> Option<Id> {
    let first = n.split(['.', ' ']).next().unwrap_or(n);
    if let Some(id) = xiaomi(first) {
        return Some(id);
    }
    // TP-Link Kasa plugs and bulbs name themselves after their model number.
    if let Some(model) = kasa_model(first) {
        let kind = if model.starts_with("KL") || model.starts_with("LB") {
            "Smart light"
        } else {
            "Smart plug"
        };
        return Some((kind, Some(format!("TP-Link Kasa {model}"))));
    }
    let has = |needle: &str| n.contains(needle);
    if n.starts_with("amazonaqm") {
        Some((
            "Air monitor",
            Some("Amazon Smart Air Quality Monitor".into()),
        ))
    } else if has("bitaxe") {
        Some(("Bitcoin miner", Some("Bitaxe".into())))
    } else if has("nerdqaxe") {
        Some(("Bitcoin miner", Some("NerdQAxe".into())))
    } else if has("nerdminer") || has("antminer") || has("avalon") {
        Some(("Bitcoin miner", None))
    } else if has("umbrel") {
        Some(("Home server", Some("Umbrel".into())))
    } else if has("awair") {
        Some((
            "Air monitor",
            Some(
                if has("elem") {
                    "Awair Element"
                } else {
                    "Awair"
                }
                .into(),
            ),
        ))
    } else if has("switchbot") {
        Some((
            "Smart home hub",
            Some(
                if has("hub-2") {
                    "SwitchBot Hub 2"
                } else {
                    "SwitchBot"
                }
                .into(),
            ),
        ))
    } else if has("blink") {
        Some((
            "Camera",
            Some(if has("mini") { "Blink Mini" } else { "Blink" }.into()),
        ))
    } else if has("wyze") {
        Some(("Camera", Some("Wyze".into())))
    } else if has("ring-") || n.starts_with("ring") {
        Some(("Doorbell / camera", Some("Ring".into())))
    } else if has("shelly") {
        Some(("Smart relay", Some("Shelly".into())))
    } else if has("tasmota") || has("esphome") || n.starts_with("esp-") || n.starts_with("esp32") {
        Some(("IoT device", None))
    } else if has("homeassistant") || has("home-assistant") {
        Some(("Home automation", Some("Home Assistant".into())))
    } else if has("raspberrypi") {
        Some(("Computer", Some("Raspberry Pi".into())))
    } else if has("iphone") {
        Some(("Phone", Some("iPhone".into())))
    } else if has("ipad") {
        Some(("Tablet", Some("iPad".into())))
    } else if has("macbook") || has("imac") || has("mac-mini") || has("macmini") {
        Some(("Computer", Some("Mac".into())))
    } else if n.starts_with("desktop-") || n.starts_with("laptop-") {
        Some(("Computer", Some("Windows PC".into())))
    } else if has("android") || has("galaxy") || has("pixel") {
        Some(("Phone", None))
    } else if has("roku") {
        Some(("TV / streamer", Some("Roku".into())))
    } else if has("firetv") || has("fire-tv") {
        Some(("TV / streamer", Some("Fire TV".into())))
    } else if has("echo") {
        Some(("Speaker", Some("Amazon Echo".into())))
    } else if has("sonos") {
        Some(("Speaker", Some("Sonos".into())))
    } else if has("xbox") {
        Some(("Game console", Some("Xbox".into())))
    } else if has("playstation") || n.starts_with("ps4") || n.starts_with("ps5") {
        Some(("Game console", Some("PlayStation".into())))
    } else if has("nintendo") {
        Some(("Game console", Some("Nintendo".into())))
    } else if has("diskstation") || has("synology") || has("nas") {
        Some(("NAS", None))
    } else if has("kvm") {
        Some(("KVM", None))
    } else if has("printer") || n.starts_with("brw") || n.starts_with("epson") {
        Some(("Printer", None))
    } else {
        None
    }
}

/// Brand-only naming conventions, consulted after services and ports so that
/// anything more specific (an Echo advertising Spotify is a speaker) wins.
fn from_brand_names(d: &Device) -> Option<Why> {
    let n = all_names(d)
        .into_iter()
        .find(|n| n.starts_with("amazon-"))?;
    Some((
        ("Amazon device", Some("Amazon".into())),
        format!("its name \"{n}\""),
    ))
}

/// Xiaomi's Mi Home ecosystem names devices `<brand>-<category>-<model>_miio<id>`
/// (or `_mibt<id>`), e.g. `zhimi-fan-za5_mibta3f0` or `roborock-vacuum-s5_miio12345`.
fn xiaomi(name: &str) -> Option<Id> {
    let (model, suffix) = name.rsplit_once('_')?;
    if !(suffix.starts_with("miio") || suffix.starts_with("mibt")) {
        return None;
    }
    let mut parts = model.splitn(3, '-');
    let (brand, category, variant) = (parts.next()?, parts.next()?, parts.next()?);
    let kind = match category {
        "fan" => "Fan",
        "airpurifier" | "airfresh" => "Air purifier",
        "humidifier" | "derh" => "Climate control",
        "heater" | "aircondition" | "acpartner" => "Climate control",
        "airmonitor" | "airp" => "Air monitor",
        "light" | "lamp" | "ceiling" | "bslamp" | "bulb" | "strip" => "Smart light",
        "plug" | "switch" | "powerstrip" | "outlet" => "Smart plug",
        "vacuum" | "mop" => "Robot vacuum",
        "gateway" | "hub" => "Smart home hub",
        "camera" | "cateye" => "Camera",
        "lock" => "Lock",
        "sensor" | "weather" => "Sensor",
        "curtain" => "Blinds",
        "kettle" | "cooker" | "oven" | "fridge" | "washer" => "Appliance",
        "speaker" | "wifispeaker" => "Speaker",
        _ => "Smart home",
    };
    let maker = match brand {
        "zhimi" => "Smartmi",
        "yeelink" => "Yeelight",
        "roborock" | "rockrobo" => "Roborock",
        "lumi" => "Aqara",
        "dreame" => "Dreame",
        "viomi" => "Viomi",
        "deerma" => "Deerma",
        "philips" => "Philips",
        _ => "Xiaomi",
    };
    // The miio model identifier, as the Mi Home app and integrations know it.
    Some((kind, Some(format!("{maker} {brand}.{category}.{variant}"))))
}

fn from_http(d: &Device) -> Option<Why> {
    let h = d.http.as_ref()?;
    let server = h.server.as_deref().unwrap_or("").to_ascii_lowercase();
    if server.starts_with("ship") {
        return Some((
            ("Smart plug", Some("TP-Link Kasa".into())),
            format!("web server \"{}\"", h.server.as_deref().unwrap_or("")),
        ));
    }
    let title = h.title.as_deref().unwrap_or("").to_ascii_lowercase();
    let has = |needle: &str| title.contains(needle);
    let id: Id = if has("axeos") {
        ("Bitcoin miner", Some("Bitaxe".into()))
    } else if has("nerd") && has("dashboard") {
        ("Bitcoin miner", Some("NerdQAxe".into()))
    } else if has("umbrel") {
        ("Home server", Some("Umbrel".into()))
    } else if has("synology") || has("diskstation") {
        ("NAS", Some("Synology".into()))
    } else if has("home assistant") {
        ("Home automation", Some("Home Assistant".into()))
    } else if has("pi-hole") {
        ("DNS server", Some("Pi-hole".into()))
    } else if has("unifi") {
        ("Network gear", Some("UniFi".into()))
    } else {
        return None;
    };
    Some((
        id,
        format!("web page title \"{}\"", h.title.as_deref().unwrap_or("")),
    ))
}

/// Bonjour services only one kind of device or app advertises, most
/// specific first.
const SERVICE_RULES: &[(&str, &str, Option<&str>)] = &[
    ("plexmediasvr", "Media server", Some("Plex")),
    ("mediaremotetv", "TV / streamer", Some("Apple TV")),
    ("viziocast", "TV / streamer", Some("Vizio")),
    ("nanoleafapi", "Smart light", Some("Nanoleaf")),
    ("elg", "Smart light", Some("Elgato")),
    ("scanner", "Printer", None),
    ("miio", "Smart home", Some("Xiaomi")),
    ("adisk", "NAS", None),
    ("nut", "NAS", None),
    ("home-assistant", "Home automation", Some("Home Assistant")),
    ("spotify-connect", "Speaker", None),
    ("sonos", "Speaker", None),
    ("raop", "Speaker", None),
    ("smb", "Server", None),
    ("afpovertcp", "Server", None),
    ("androidtvremote2", "TV / streamer", None),
    ("amzn-wplay", "TV / streamer", None),
    ("nvstream", "TV / streamer", None),
    ("matter", "Smart home", None),
    ("matterc", "Smart home", None),
    ("hap", "Smart home", None),
    ("hue", "Smart home", None),
    ("esphomelib", "Smart home", None),
    ("workstation", "Computer", None),
    ("ssh", "Computer", None),
    ("sftp-ssh", "Computer", None),
    ("daap", "Computer", None),
];

/// Every Dante service type: `_netaudio-arc` (routing), `_netaudio-cmc`
/// (control, on every device), and `_dante-safe` and `_dante-upgr` while a
/// device is in safe mode or being upgraded.
fn is_dante(service: &str) -> bool {
    service.starts_with("netaudio-") || service.starts_with("dante-")
}

fn from_services(d: &Device) -> Option<Why> {
    let m = d.mdns.as_ref()?;
    let advertises = |svc: &str| format!("advertises {svc} over Bonjour");
    // Audio and video over IP. Below anything more specific: a Mac running
    // Dante Virtual Soundcard, or a PC sending NDI from OBS, is still a computer.
    if let Some(svc) = m.services.keys().find(|s| is_dante(s)) {
        return Some((("Audio device", Some("Dante".into())), advertises(svc)));
    }
    if m.services.contains_key("ndi") {
        return Some((("Video device", Some("NDI".into())), advertises("ndi")));
    }
    SERVICE_RULES
        .iter()
        .find(|(svc, _, _)| m.services.contains_key(*svc))
        .map(|&(svc, kind, model)| ((kind, model.map(String::from)), advertises(svc)))
}

/// "port 8006 open (Proxmox)"
fn port_open(p: u16) -> String {
    match port_name(p) {
        Some(name) => format!("port {p} open ({name})"),
        None => format!("port {p} open"),
    }
}

/// Ports only one kind of device or app listens on, most specific first.
const PORT_RULES: &[(u16, &str, Option<&str>)] = &[
    (9100, "Printer", None),
    (8008, "TV / streamer", Some("Chromecast")),
    (7000, "AirPlay device", None),
    // Homelab apps that each claim a port of their own.
    (8006, "Server", Some("Proxmox VE")),
    (8123, "Home automation", Some("Home Assistant")),
    (32400, "Media server", Some("Plex")),
    (8096, "Media server", Some("Jellyfin / Emby")),
    // Samba doesn't listen on the RPC endpoint mapper; Windows always does.
    (135, "Computer", Some("Windows PC")),
];

fn from_ports(d: &Device) -> Option<Why> {
    let has = |p: u16| d.open_ports.contains(&p);
    if has(62078) {
        // 62078 is Apple's lockdown/sync port; AirPlay alongside it means an Apple TV or HomePod.
        return Some(if has(7000) {
            (
                ("Apple device", Some("Apple TV / HomePod".into())),
                "ports 62078 (iOS sync) and 7000 (AirPlay) open".into(),
            )
        } else {
            (
                ("Phone / tablet", Some("iPhone / iPad".into())),
                port_open(62078),
            )
        });
    }
    PORT_RULES
        .iter()
        .find(|(p, _, _)| has(*p))
        .map(|&(p, kind, model)| ((kind, model.map(String::from)), port_open(p)))
}

/// SSH and SMB run on everything from laptops to switches and NASes, so they
/// are the weakest hint of all: consulted only after the MAC vendor, and
/// labeled for what's known rather than guessing a kind of device.
fn from_generic_ports(d: &Device) -> Option<Why> {
    let has = |p: u16| d.open_ports.contains(&p);
    let found = |p: u16, kind: &'static str| Some(((kind, None), port_open(p)));
    // Databases, message brokers and mail: something is running as a server.
    if let Some(p) = [
        1433, 1521, 1883, 3306, 5432, 5672, 6379, 27017, 25, 110, 143, 993, 995,
    ]
    .into_iter()
    .find(|&p| has(p))
    {
        return found(p, "Server");
    }
    if has(445) {
        return found(445, "Computer / NAS");
    }
    if has(3389) {
        return found(3389, "Computer");
    }
    // Routers answer DNS too, but they're labeled as the gateway.
    if has(53) && !d.gateway {
        return found(53, "DNS server");
    }
    if has(22) {
        return found(22, "SSH device");
    }
    None
}

fn from_vendor(d: &Device) -> Option<Why> {
    // Phones, tablets and laptops use per-network random MACs and rarely
    // listen on any ports. VMs and containers also use random-looking MACs,
    // but usually run services, so only guess when nothing is listening.
    if d.vendor.is_none()
        && d.randomized_mac
        && d.open_ports.is_empty()
        && !d.gateway
        && !d.this_device
    {
        return Some((
            ("Phone / laptop", None),
            "private MAC, no open ports".into(),
        ));
    }
    let v = d.vendor?;
    let why = format!("MAC vendor {v}");
    let lower = v.to_ascii_lowercase();
    // Audinate makes only Dante modules, so its MACs are Dante interfaces.
    if lower.contains("audinate") {
        return Some((("Audio device", Some("Dante".into())), why));
    }
    let kind = match () {
        _ if lower.contains("raspberry") => "Computer",
        _ if lower.contains("espressif") || lower.contains("tuya") => "IoT device",
        _ if lower.contains("chamberlain") => "Garage door",
        // TP-Link makes routers too, but those listen on ports. Silent ones
        // are smart plugs and switches with newer firmware.
        // Kasa plugs answer on their own port, 9999, and nothing else.
        _ if lower.contains("tp-link") && d.open_ports.iter().all(|&p| p == 9999) => "Smart plug",
        _ if lower.contains("sonos") => "Speaker",
        _ if lower.contains("roku") => "TV / streamer",
        _ if lower.contains("nintendo") || lower.contains("sony interactive") => "Game console",
        _ if lower.contains("synology") || lower.contains("qnap") => "NAS",
        _ if lower.contains("ubiquiti") || lower.contains("netgear") || lower.contains("eero") => {
            "Network gear"
        }
        _ if lower.contains("ecobee") || lower.contains("nest") => "Thermostat",
        _ if lower.contains("signify") || lower.contains("philips lighting") => "Smart home hub",
        _ if ["brother", "canon", "seiko epson"]
            .iter()
            .any(|b| lower.contains(b)) =>
        {
            "Printer"
        }
        _ if lower.contains("ring") => "Doorbell / camera",
        _ if lower.contains("apple") => "Apple device",
        _ if lower.contains("amazon") => "Amazon device",
        _ if lower.contains("google") => "Google device",
        _ => return None,
    };
    Some(((kind, Some(v.to_string())), why))
}

/// The friendliest name the device gives itself, and where it came from.
///
/// Names people set themselves (AirPlay, HomeKit, Cast, Fire TV, Dante) come
/// first. Next is the device's primary `.local` name, kept whole so it can be
/// pasted into a browser or ssh, which beats generic service labels like Home
/// Assistant's "Home" or a file share's name. A Windows or Samba computer
/// name comes after UPnP's. Router DNS names are shortened to the host.
fn name_and_source(d: &Device) -> Option<(String, String)> {
    let m = d.mdns.as_ref();
    let service = |services: &[&str]| -> Option<(String, String)> {
        let m = m?;
        services
            .iter()
            .filter_map(|s| Some((*s, m.services.get(*s)?)))
            // RAOP instances are "<MAC>@<name>".
            .map(|(s, n)| {
                let name = n.rsplit_once('@').map_or(n.as_str(), |(_, name)| name);
                (name.to_string(), service_label(s))
            })
            .find(|(n, _)| !is_junk_name(n))
    };
    fn from(source: &'static str) -> impl Fn(String) -> (String, String) {
        move |name| (name, source.to_string())
    }
    let txt = |svc: &str, key: &str| m.and_then(|m| m.txt.get(svc)?.get(key).cloned());
    let dns = d.hostname.as_ref().map(|h| {
        if h.ends_with(".local") {
            h.clone()
        } else {
            h.split('.').next().unwrap_or(h).to_string()
        }
    });
    [
        // Cast and Fire TV keep the name their owner gave them in TXT records.
        txt("googlecast", "fn").map(from("Google Cast")),
        d.kasa
            .as_ref()
            .and_then(|k| k.alias.clone())
            .map(from("Kasa app")),
        txt("amzn-wplay", "n").map(from("Fire TV")),
        service(&[
            "device-info",
            "airplay",
            "companion-link",
            "raop",
            "hap",
            "netaudio-arc",
            "netaudio-cmc",
        ]),
        m.and_then(|m| m.hostname.clone())
            .filter(|h| h.ends_with(".local"))
            .map(from(".local name")),
        service(&["smb", "home-assistant", "ipp", "printer"]),
        d.ssdp
            .as_ref()
            .and_then(|s| s.friendly_name.clone())
            .map(from("UPnP")),
        d.netbios
            .as_ref()
            .map(|n| n.name.clone())
            .map(from("NetBIOS")),
        m.and_then(|m| m.hostname.clone()).map(from("mDNS")),
        dns.map(from("reverse DNS")),
    ]
    .into_iter()
    .flatten()
    .find(|(n, _)| !is_junk_name(n))
}

#[cfg(test)]
fn name(d: &Device) -> Option<String> {
    name_and_source(d).map(|(n, _)| n)
}

/// What to call a Bonjour service as the source of a name.
fn service_label(service: &str) -> String {
    match service {
        "airplay" | "raop" => "AirPlay".into(),
        "hap" => "HomeKit".into(),
        s if is_dante(s) => "Dante".into(),
        s => format!("Bonjour {s}"),
    }
}

/// Machine-generated names that tell a person nothing.
fn is_junk_name(n: &str) -> bool {
    let n = n.trim();
    let n = n.strip_suffix(".local").unwrap_or(n);
    let hex = |s: &str| s.len() >= 8 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    n.is_empty()
        || hex(n)
        // Brother printers default to "BRW" + MAC address.
        || n.len() == 15 && n.to_ascii_lowercase().starts_with("brw") && hex(&n[3..])
        || ["localhost", "none", "wlan0", "eth0", "espressif", "unknown"].contains(&n.to_ascii_lowercase().as_str())
}

fn kasa_model(s: &str) -> Option<String> {
    let s = s.to_ascii_uppercase();
    let prefix = ["KP", "HS", "EP", "KL", "LB", "KS"]
        .into_iter()
        .find(|p| s.starts_with(p))?;
    let digits: String = s[prefix.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    (2..=3)
        .contains(&digits.len())
        .then(|| format!("{prefix}{digits}"))
}

fn brand(instance: &str) -> Option<&'static str> {
    let lower = instance.to_ascii_lowercase();
    [
        ("tplink", "TP-Link"),
        ("tp-link", "TP-Link"),
        ("meross", "Meross"),
        ("eve ", "Eve"),
        ("ecobee", "ecobee"),
        ("aqara", "Aqara"),
        ("nanoleaf", "Nanoleaf"),
        ("lifx", "LIFX"),
        ("wemo", "Wemo"),
        ("hue", "Philips Hue"),
        ("vocolinc", "VOCOlinc"),
    ]
    .into_iter()
    .find(|(k, _)| lower.starts_with(k))
    .map(|(_, b)| b)
}

fn homekit_category(ci: u32) -> &'static str {
    match ci {
        2 => "Smart home hub",
        3 => "Fan",
        4 => "Garage door",
        5 => "Smart light",
        6 => "Lock",
        7 => "Smart plug",
        8 => "Switch",
        9 => "Thermostat",
        10 => "Sensor",
        11 => "Security system",
        14 => "Blinds",
        17 => "Camera",
        18 => "Doorbell / camera",
        19 => "Air purifier",
        20..=23 => "Climate control",
        28 => "Sprinkler",
        31 | 35 | 36 => "TV / streamer",
        33 => "Router",
        34 => "Speaker",
        _ => "Smart home",
    }
}

fn is_apple_id(id: &str) -> bool {
    [
        "iPhone",
        "iPad",
        "iPod",
        "AppleTV",
        "AudioAccessory",
        "Mac",
        "iMac",
        "Watch",
    ]
    .iter()
    .any(|p| {
        id.starts_with(p)
            && id[p.len()..].starts_with(|c: char| {
                c.is_ascii_digit() || c == 'B' || c == 'P' || c == 'm' || c == 'A'
            })
    })
}

/// Apple hardware identifier → (type, marketing name).
fn apple_model(id: &str) -> Id {
    let named = |kind, name: &str| (kind, Some(name.to_string()));
    let exact = match id {
        "AppleTV5,3" => Some(named("TV / streamer", "Apple TV HD")),
        "AppleTV6,2" => Some(named("TV / streamer", "Apple TV 4K")),
        "AppleTV11,1" => Some(named("TV / streamer", "Apple TV 4K (2nd gen)")),
        "AppleTV14,1" => Some(named("TV / streamer", "Apple TV 4K (3rd gen)")),
        "AudioAccessory1,1" | "AudioAccessory1,2" => Some(named("Speaker", "HomePod")),
        "AudioAccessory5,1" => Some(named("Speaker", "HomePod mini")),
        "AudioAccessory6,1" => Some(named("Speaker", "HomePod (2nd gen)")),
        "Mac13,1" | "Mac13,2" => Some(named("Computer", "Mac Studio (M1)")),
        "Mac14,3" => Some(named("Computer", "Mac mini (M2)")),
        "Mac14,12" => Some(named("Computer", "Mac mini (M2 Pro)")),
        "Mac14,13" | "Mac14,14" => Some(named("Computer", "Mac Studio (M2)")),
        "Mac14,2" | "Mac14,15" => Some(named("Computer", "MacBook Air (M2)")),
        "Mac14,5" | "Mac14,6" | "Mac14,7" | "Mac14,9" | "Mac14,10" => {
            Some(named("Computer", "MacBook Pro (M2)"))
        }
        "Mac14,8" => Some(named("Computer", "Mac Pro (M2)")),
        "Mac15,3" | "Mac15,6" | "Mac15,7" | "Mac15,8" | "Mac15,9" | "Mac15,10" | "Mac15,11" => {
            Some(named("Computer", "MacBook Pro (M3)"))
        }
        "Mac15,4" | "Mac15,5" => Some(named("Computer", "iMac (M3)")),
        "Mac15,12" | "Mac15,13" => Some(named("Computer", "MacBook Air (M3)")),
        "Mac15,14" => Some(named("Computer", "Mac Studio (M3 Ultra)")),
        "Mac16,1" | "Mac16,5" | "Mac16,6" | "Mac16,7" | "Mac16,8" => {
            Some(named("Computer", "MacBook Pro (M4)"))
        }
        "Mac16,2" | "Mac16,3" => Some(named("Computer", "iMac (M4)")),
        "Mac16,9" => Some(named("Computer", "Mac Studio (M4 Max)")),
        "Mac16,10" => Some(named("Computer", "Mac mini (M4)")),
        "Mac16,11" => Some(named("Computer", "Mac mini (M4 Pro)")),
        "Mac16,12" | "Mac16,13" => Some(named("Computer", "MacBook Air (M4)")),
        _ => None,
    };
    if let Some(id) = exact {
        return id;
    }
    let families: &[(&str, &str, &str)] = &[
        ("AppleTV", "TV / streamer", "Apple TV"),
        ("AudioAccessory", "Speaker", "HomePod"),
        ("iPhone", "Phone", "iPhone"),
        ("iPad", "Tablet", "iPad"),
        ("iPod", "Media player", "iPod"),
        ("Watch", "Watch", "Apple Watch"),
        ("MacBookPro", "Computer", "MacBook Pro"),
        ("MacBookAir", "Computer", "MacBook Air"),
        ("MacBook", "Computer", "MacBook"),
        ("Macmini", "Computer", "Mac mini"),
        ("MacPro", "Computer", "Mac Pro"),
        ("iMac", "Computer", "iMac"),
        ("Mac", "Computer", "Mac"),
    ];
    families
        .iter()
        .find(|(prefix, _, _)| id.starts_with(prefix))
        .map(|(_, kind, name)| named(kind, name))
        .unwrap_or(("Apple device", None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_models() {
        assert_eq!(
            apple_model("AppleTV14,1").1.as_deref(),
            Some("Apple TV 4K (3rd gen)")
        );
        assert_eq!(apple_model("AudioAccessory5,1").0, "Speaker");
        assert_eq!(apple_model("iPhone15,2").1.as_deref(), Some("iPhone"));
        assert_eq!(apple_model("Mac99,1").1.as_deref(), Some("Mac"));
        assert!(is_apple_id("MacBookPro18,3"));
        assert!(!is_apple_id("Xserve"));
        assert!(!is_apple_id("MacSamba"));
        assert!(!is_apple_id("J305AP"));
    }

    #[test]
    fn kasa() {
        assert_eq!(kasa_model("kp115").as_deref(), Some("KP115"));
        assert_eq!(kasa_model("ep25-2").as_deref(), Some("EP25"));
        assert_eq!(kasa_model("kl420").as_deref(), Some("KL420"));
        assert_eq!(kasa_model("hsbc"), None);
        assert_eq!(kasa_model("epson"), None);
    }

    #[test]
    fn kasa_sysinfo() {
        let mut d = device(&[], Some("TP-Link"));
        d.kasa = serde_json::from_str(
            r#"{"alias":"Living Room Lamp","model":"HS105(US)",
                "dev_name":"Smart Wi-Fi Plug Mini","type":"IOT.SMARTPLUGSWITCH"}"#,
        )
        .ok();
        assert_eq!(
            identify(&d),
            Some(("Smart plug", Some("TP-Link Kasa HS105".into())))
        );
        assert_eq!(name(&d).as_deref(), Some("Living Room Lamp"));
    }

    #[test]
    fn silent_vendors() {
        let id = |ports: &[u16], vendor| identify(&device(ports, Some(vendor))).map(|id| id.0);
        assert_eq!(
            id(&[80], "The Chamberlain Group, Inc."),
            Some("Garage door")
        );
        assert_eq!(id(&[], "TP-Link"), Some("Smart plug"));
        assert_ne!(id(&[80, 443], "TP-Link"), Some("Smart plug"));
    }

    fn device(ports: &[u16], vendor: Option<&'static str>) -> Device {
        let mut d = Device::new(std::net::Ipv4Addr::new(192, 168, 1, 2));
        d.open_ports = ports.to_vec();
        d.vendor = vendor;
        d
    }

    #[test]
    fn vendor_beats_generic_ports() {
        // A Ubiquiti switch with SSH open is network gear, not a computer.
        assert_eq!(
            identify(&device(&[22], Some("Ubiquiti"))).map(|id| id.0),
            Some("Network gear")
        );
        assert_eq!(
            identify(&device(&[22], None)).map(|id| id.0),
            Some("SSH device")
        );
        // Specific ports still beat the vendor: an Apple MAC with only the sync port is a phone.
        assert_eq!(
            identify(&device(&[62078], Some("Apple"))).map(|id| id.0),
            Some("Phone / tablet")
        );
    }

    #[test]
    fn homelab_ports() {
        let id = |ports: &[u16]| identify(&device(ports, None));
        assert_eq!(id(&[22, 8006]), Some(("Server", Some("Proxmox VE".into()))));
        assert_eq!(
            id(&[8123]),
            Some(("Home automation", Some("Home Assistant".into())))
        );
        assert_eq!(
            id(&[22, 32400]),
            Some(("Media server", Some("Plex".into())))
        );
        assert_eq!(
            id(&[135, 445, 3389]),
            Some(("Computer", Some("Windows PC".into())))
        );
        // A database makes a box a server, even one sharing files over SMB.
        assert_eq!(id(&[22, 445, 5432]).map(|id| id.0), Some("Server"));
        assert_eq!(id(&[53]).map(|id| id.0), Some("DNS server"));
        let mut router = device(&[53, 80], None);
        router.gateway = true;
        assert_eq!(identify(&router), None);
    }

    #[test]
    fn single_purpose_services() {
        let id = |services: &[&str]| {
            let mut d = device(&[], None);
            let mut m = crate::mdns::MdnsInfo::default();
            for s in services {
                m.services.insert(s.to_string(), "x".into());
            }
            d.mdns = Some(m);
            identify(&d)
        };
        // A NAS running Plex is reached as a media server.
        assert_eq!(
            id(&["adisk", "plexmediasvr"]),
            Some(("Media server", Some("Plex".into())))
        );
        assert_eq!(
            id(&["mediaremotetv"]),
            Some(("TV / streamer", Some("Apple TV".into())))
        );
        assert_eq!(id(&["nanoleafapi"]).map(|i| i.0), Some("Smart light"));
        assert_eq!(id(&["elg"]).and_then(|i| i.1).as_deref(), Some("Elgato"));
        assert_eq!(id(&["scanner"]), Some(("Printer", None)));
        assert_eq!(id(&["miio"]), Some(("Smart home", Some("Xiaomi".into()))));
        assert_eq!(id(&["matterc"]), Some(("Smart home", None)));
        assert_eq!(id(&["daap"]), Some(("Computer", None)));
    }

    #[test]
    fn says_why() {
        let why = |d: &Device| identify_why(d).map(|(_, why)| why);
        assert_eq!(
            why(&device(&[22, 8006], None)).as_deref(),
            Some("port 8006 open (Proxmox)")
        );
        assert_eq!(
            why(&device(&[22], Some("Ubiquiti"))).as_deref(),
            Some("MAC vendor Ubiquiti")
        );
        assert_eq!(
            why(&device(&[62078, 7000], None)).as_deref(),
            Some("ports 62078 (iOS sync) and 7000 (AirPlay) open")
        );
        let mut router = device(&[53, 80], None);
        router.gateway = true;
        classify(&mut router);
        assert_eq!(router.kind.as_deref(), Some("Router"));
        assert_eq!(
            router.type_from.as_deref(),
            Some("it's the default gateway")
        );
    }

    #[test]
    fn dante_and_ndi() {
        let id = |services: &[&str], vendor| {
            let mut d = device(&[], vendor);
            let mut m = crate::mdns::MdnsInfo::default();
            for s in services {
                m.services.insert(s.to_string(), "Stagebox-FOH".into());
            }
            d.mdns = Some(m);
            d
        };
        let dante = id(&["netaudio-cmc"], None);
        assert_eq!(
            identify_why(&dante),
            Some((
                ("Audio device", Some("Dante".into())),
                "advertises netaudio-cmc over Bonjour".into()
            ))
        );
        assert_eq!(
            name_and_source(&dante),
            Some(("Stagebox-FOH".into(), "Dante".into()))
        );
        // In safe mode, a Dante device still is one.
        assert_eq!(
            identify(&id(&["dante-safe"], None)).map(|i| i.0),
            Some("Audio device")
        );
        assert_eq!(
            identify(&id(&[], Some("Audinate Pty L"))),
            Some(("Audio device", Some("Dante".into())))
        );
        assert_eq!(
            identify(&id(&["ndi"], None)),
            Some(("Video device", Some("NDI".into())))
        );
    }

    #[test]
    fn netbios_names() {
        let mut d = device(&[445], None);
        d.netbios = Some(crate::netbios::NetbiosInfo {
            name: "DESKTOP-4F2K9QX".into(),
            mac: None,
        });
        d.hostname = Some("192-168-1-2.lan".into());
        assert_eq!(
            name_and_source(&d),
            Some(("DESKTOP-4F2K9QX".into(), "NetBIOS".into()))
        );
        assert_eq!(identify(&d), Some(("Computer", Some("Windows PC".into()))));
        // UPnP's friendly name comes first; NetBIOS beats the mDNS host.
        d.ssdp = Some(crate::ssdp::SsdpInfo {
            friendly_name: Some("NorthWoodsNAS (DS916+)".into()),
            ..Default::default()
        });
        assert_eq!(name(&d).as_deref(), Some("NorthWoodsNAS (DS916+)"));
        d.ssdp = None;
        d.mdns = Some(crate::mdns::MdnsInfo {
            hostname: Some("e6b1c9d2.lan".into()),
            ..Default::default()
        });
        assert_eq!(name(&d).as_deref(), Some("DESKTOP-4F2K9QX"));
    }

    #[test]
    fn fire_tv_names() {
        let mut d = device(&[], None);
        let mut m = crate::mdns::MdnsInfo::default();
        m.services
            .insert("amzn-wplay".into(), "amzn.dmgr:6F22".into());
        m.txt
            .entry("amzn-wplay".into())
            .or_default()
            .insert("n".into(), "Bedroom Fire TV".into());
        d.mdns = Some(m);
        assert_eq!(name(&d).as_deref(), Some("Bedroom Fire TV"));
    }

    #[test]
    fn xiaomi_names() {
        assert_eq!(
            xiaomi("zhimi-fan-za5_mibta3f0"),
            Some(("Fan", Some("Smartmi zhimi.fan.za5".into())))
        );
        assert_eq!(
            xiaomi("roborock-vacuum-s5_miio12345678"),
            Some(("Robot vacuum", Some("Roborock roborock.vacuum.s5".into())))
        );
        assert_eq!(
            xiaomi("yeelink-light-color1_miio1"),
            Some(("Smart light", Some("Yeelight yeelink.light.color1".into())))
        );
        assert_eq!(xiaomi("zhimi-fan-za5"), None);
        assert_eq!(xiaomi("my_laptop"), None);
    }

    #[test]
    fn junk_names() {
        assert!(is_junk_name("36814e2569ca121f"));
        assert!(is_junk_name("brwc0b5d7e7747d"));
        assert!(is_junk_name("36814e2569ca121f.local"));
        assert!(!is_junk_name("bitaxe01.local"));
        assert!(is_junk_name("wlan0"));
        assert!(!is_junk_name("bedroom"));
        assert!(!is_junk_name("ep25"));
    }
}
