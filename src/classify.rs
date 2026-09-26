//! Turn the evidence gathered about a device into a name, type and model.
//!
//! Sources are consulted from most to least specific: model identifiers a
//! device announces about itself (Bonjour TXT records, UPnP descriptions)
//! beat naming conventions, which beat open ports and MAC vendors.

use crate::Device;

pub fn classify(d: &mut Device) {
    d.name = name(d);
    let (kind, model) = identify(d)
        .map(|(k, m)| (Some(k.to_string()), m))
        .unwrap_or((None, None));
    d.kind = kind.or_else(|| d.gateway.then(|| "Router".to_string()));
    d.model = model;
}

type Id = (&'static str, Option<String>);

fn identify(d: &Device) -> Option<Id> {
    from_mdns(d)
        .or_else(|| from_ssdp(d))
        .or_else(|| from_names(d))
        .or_else(|| from_http(d))
        .or_else(|| from_services(d))
        .or_else(|| from_ports(d))
        .or_else(|| from_brand_names(d))
        .or_else(|| from_vendor(d))
        .or_else(|| from_generic_ports(d))
}

fn from_mdns(d: &Device) -> Option<Id> {
    let m = d.mdns.as_ref()?;
    let txt = |svc: &str, key: &str| m.txt.get(svc).and_then(|t| t.get(key)).map(String::as_str);

    // Apple devices announce their model identifier in several places.
    let apple_id = txt("airplay", "model")
        .or_else(|| txt("raop", "am"))
        .or_else(|| txt("companion-link", "rpmd"))
        .or_else(|| txt("device-info", "model"))
        .filter(|id| is_apple_id(id));
    if let Some(id) = apple_id {
        return Some(apple_model(id));
    }

    if let Some(md) = txt("googlecast", "md") {
        let lower = md.to_ascii_lowercase();
        let kind = if ["mini", "home", "speaker", "audio"].iter().any(|k| lower.contains(k)) {
            "Speaker"
        } else if lower.contains("hub") {
            "Smart display"
        } else {
            "TV / streamer"
        };
        return Some((kind, Some(md.to_string())));
    }

    if ["ipp", "ipps", "printer", "pdl-datastream"].iter().any(|s| m.services.contains_key(*s)) {
        let model = ["ipp", "ipps", "printer", "pdl-datastream"]
            .iter()
            .find_map(|s| txt(s, "ty"))
            .map(String::from);
        return Some(("Printer", model));
    }

    if let Some(ci) = txt("hap", "ci").and_then(|c| c.parse().ok()) {
        let model = txt("hap", "md").map(|md| {
            let instance = &m.services["hap"];
            match brand(instance) {
                Some(b) if !md.to_ascii_lowercase().contains(&b.to_ascii_lowercase()) => format!("{b} {md}"),
                _ => md.to_string(),
            }
        });
        return Some((homekit_category(ci), model));
    }

    if let Some(mn) = txt("glinet", "mn") {
        let model = format!("GL.iNet {}", mn.to_ascii_uppercase());
        let kind = if mn.starts_with("rm") { "KVM" } else { "Router" };
        return Some((kind, Some(model)));
    }

    None
}

fn from_ssdp(d: &Device) -> Option<Id> {
    let s = d.ssdp.as_ref()?;
    let device_type = s.device_type.as_deref().unwrap_or("").to_ascii_lowercase();
    let maker = s.manufacturer.as_deref().unwrap_or("");
    let model = s.model_name.as_deref().map(|m| {
        if maker.is_empty() || m.to_ascii_lowercase().starts_with(&maker.to_ascii_lowercase()) {
            m.to_string()
        } else {
            format!("{maker} {m}")
        }
    });
    let lower_maker = maker.to_ascii_lowercase();
    let kind = if device_type.contains("internetgatewaydevice") || device_type.contains("wfadevice") {
        "Router"
    } else if ["synology", "qnap", "asustor", "ugreen", "terramaster"].iter().any(|m| lower_maker.contains(m)) {
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
    Some((kind, model))
}

/// Every name a device goes by, lowercased.
fn all_names(d: &Device) -> Vec<String> {
    let mut names: Vec<String> = [
        d.hostname.as_deref(),
        d.mdns.as_ref().and_then(|m| m.hostname.as_deref()),
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
fn from_names(d: &Device) -> Option<Id> {
    for n in &all_names(d) {
        let first = n.split(['.', ' ']).next().unwrap_or(n);
        if let Some(id) = xiaomi(first) {
            return Some(id);
        }
        // TP-Link Kasa plugs and bulbs name themselves after their model number.
        if let Some(model) = kasa_model(first) {
            let kind = if model.starts_with("KL") || model.starts_with("LB") { "Smart light" } else { "Smart plug" };
            return Some((kind, Some(format!("TP-Link Kasa {model}"))));
        }
        let has = |needle: &str| n.contains(needle);
        let id: Option<Id> = if n.starts_with("amazonaqm") {
            Some(("Air monitor", Some("Amazon Smart Air Quality Monitor".into())))
        } else if has("bitaxe") {
            Some(("Bitcoin miner", Some("Bitaxe".into())))
        } else if has("nerdqaxe") {
            Some(("Bitcoin miner", Some("NerdQAxe".into())))
        } else if has("nerdminer") || has("antminer") || has("avalon") {
            Some(("Bitcoin miner", None))
        } else if has("umbrel") {
            Some(("Home server", Some("Umbrel".into())))
        } else if has("awair") {
            Some(("Air monitor", Some(if has("elem") { "Awair Element" } else { "Awair" }.into())))
        } else if has("switchbot") {
            Some(("Smart home hub", Some(if has("hub-2") { "SwitchBot Hub 2" } else { "SwitchBot" }.into())))
        } else if has("blink") {
            Some(("Camera", Some(if has("mini") { "Blink Mini" } else { "Blink" }.into())))
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
        };
        if id.is_some() {
            return id;
        }
    }
    None
}

/// Brand-only naming conventions, consulted after services and ports so that
/// anything more specific (an Echo advertising Spotify is a speaker) wins.
fn from_brand_names(d: &Device) -> Option<Id> {
    let names = all_names(d);
    if names.iter().any(|n| n.starts_with("amazon-")) {
        return Some(("Amazon device", Some("Amazon".into())));
    }
    None
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

fn from_http(d: &Device) -> Option<Id> {
    let h = d.http.as_ref()?;
    let server = h.server.as_deref().unwrap_or("").to_ascii_lowercase();
    let title = h.title.as_deref().unwrap_or("").to_ascii_lowercase();
    if server.starts_with("ship") {
        return Some(("Smart plug", Some("TP-Link Kasa".into())));
    }
    if title.contains("axeos") {
        return Some(("Bitcoin miner", Some("Bitaxe".into())));
    }
    if title.contains("nerd") && title.contains("dashboard") {
        return Some(("Bitcoin miner", Some("NerdQAxe".into())));
    }
    if title.contains("umbrel") {
        return Some(("Home server", Some("Umbrel".into())));
    }
    if title.contains("synology") || title.contains("diskstation") {
        return Some(("NAS", Some("Synology".into())));
    }
    if title.contains("home assistant") {
        return Some(("Home automation", Some("Home Assistant".into())));
    }
    if title.contains("pi-hole") {
        return Some(("DNS server", Some("Pi-hole".into())));
    }
    if title.contains("unifi") {
        return Some(("Network gear", Some("UniFi".into())));
    }
    None
}

fn from_services(d: &Device) -> Option<Id> {
    let m = d.mdns.as_ref()?;
    let has = |s: &str| m.services.contains_key(s);
    if has("adisk") || has("nut") {
        return Some(("NAS", None));
    }
    if has("home-assistant") {
        return Some(("Home automation", Some("Home Assistant".into())));
    }
    if has("spotify-connect") || has("sonos") || has("raop") {
        return Some(("Speaker", None));
    }
    if has("smb") || has("afpovertcp") {
        return Some(("Server", None));
    }
    if has("androidtvremote2") || has("amzn-wplay") || has("nvstream") {
        return Some(("TV / streamer", None));
    }
    if has("matter") || has("hap") || has("hue") || has("esphomelib") {
        return Some(("Smart home", None));
    }
    if has("workstation") || has("ssh") || has("sftp-ssh") {
        return Some(("Computer", None));
    }
    None
}

fn from_ports(d: &Device) -> Option<Id> {
    let has = |p: u16| d.open_ports.contains(&p);
    if has(62078) {
        // 62078 is Apple's lockdown/sync port; AirPlay alongside it means an Apple TV or HomePod.
        return Some(if has(7000) {
            ("Apple device", Some("Apple TV / HomePod".into()))
        } else {
            ("Phone / tablet", Some("iPhone / iPad".into()))
        });
    }
    if has(9100) {
        return Some(("Printer", None));
    }
    if has(8008) {
        return Some(("TV / streamer", Some("Chromecast".into())));
    }
    if has(7000) {
        return Some(("AirPlay device", None));
    }
    // Homelab apps that each claim a port of their own.
    if has(8006) {
        return Some(("Server", Some("Proxmox VE".into())));
    }
    if has(8123) {
        return Some(("Home automation", Some("Home Assistant".into())));
    }
    if has(32400) {
        return Some(("Media server", Some("Plex".into())));
    }
    if has(8096) {
        return Some(("Media server", Some("Jellyfin / Emby".into())));
    }
    // Samba doesn't listen on the RPC endpoint mapper; Windows always does.
    if has(135) {
        return Some(("Computer", Some("Windows PC".into())));
    }
    None
}

/// SSH and SMB run on everything from laptops to switches and NASes, so they
/// are the weakest hint of all: consulted only after the MAC vendor, and
/// labeled for what's known rather than guessing a kind of device.
fn from_generic_ports(d: &Device) -> Option<Id> {
    let has = |p: u16| d.open_ports.contains(&p);
    // Databases, message brokers and mail: something is running as a server.
    if [1433, 1521, 1883, 3306, 5432, 5672, 6379, 27017, 25, 110, 143, 993, 995].into_iter().any(has) {
        return Some(("Server", None));
    }
    if has(445) {
        return Some(("Computer / NAS", None));
    }
    if has(3389) {
        return Some(("Computer", None));
    }
    // Routers answer DNS too, but they're labeled as the gateway.
    if has(53) && !d.gateway {
        return Some(("DNS server", None));
    }
    if has(22) {
        return Some(("SSH device", None));
    }
    None
}

fn from_vendor(d: &Device) -> Option<Id> {
    // Phones, tablets and laptops use per-network random MACs and rarely
    // listen on any ports. VMs and containers also use random-looking MACs,
    // but usually run services, so only guess when nothing is listening.
    if d.vendor.is_none() && d.randomized_mac && d.open_ports.is_empty() && !d.gateway && !d.this_device {
        return Some(("Phone / laptop", None));
    }
    let v = d.vendor?;
    let lower = v.to_ascii_lowercase();
    let kind = match () {
        _ if lower.contains("raspberry") => "Computer",
        _ if lower.contains("espressif") || lower.contains("tuya") => "IoT device",
        _ if lower.contains("sonos") => "Speaker",
        _ if lower.contains("roku") => "TV / streamer",
        _ if lower.contains("nintendo") || lower.contains("sony interactive") => "Game console",
        _ if lower.contains("synology") || lower.contains("qnap") => "NAS",
        _ if lower.contains("ubiquiti") || lower.contains("netgear") || lower.contains("eero") => "Network gear",
        _ if lower.contains("ecobee") || lower.contains("nest") => "Thermostat",
        _ if lower.contains("signify") || lower.contains("philips lighting") => "Smart home hub",
        _ if ["brother", "canon", "seiko epson"].iter().any(|b| lower.contains(b)) => "Printer",
        _ if lower.contains("ring") => "Doorbell / camera",
        _ if lower.contains("apple") => "Apple device",
        _ if lower.contains("amazon") => "Amazon device",
        _ if lower.contains("google") => "Google device",
        _ => return None,
    };
    Some((kind, Some(v.to_string())))
}

/// The friendliest name the device gives itself.
///
/// Names people set themselves (AirPlay, HomeKit, Cast) come first. Next is
/// the device's primary `.local` name, kept whole so it can be pasted into a
/// browser or ssh, which beats generic service labels like Home Assistant's
/// "Home" or a file share's name. Router DNS names are shortened to the host.
fn name(d: &Device) -> Option<String> {
    let m = d.mdns.as_ref();
    let service = |services: &[&str]| -> Option<String> {
        let m = m?;
        services
            .iter()
            .filter_map(|s| m.services.get(*s))
            // RAOP instances are "<MAC>@<name>".
            .map(|n| n.rsplit_once('@').map_or(n.as_str(), |(_, name)| name).to_string())
            .find(|n| !is_junk_name(n))
    };
    let local = m.and_then(|m| m.hostname.clone()).filter(|h| h.ends_with(".local") && !is_junk_name(h));
    let cast = m.and_then(|m| m.txt.get("googlecast")?.get("fn").cloned());
    let personal = cast.or_else(|| service(&["device-info", "airplay", "companion-link", "raop", "hap"]));
    let dns = d.hostname.as_ref().map(|h| {
        if h.ends_with(".local") { h.clone() } else { h.split('.').next().unwrap_or(h).to_string() }
    });
    [
        personal,
        local,
        service(&["smb", "home-assistant", "ipp", "printer"]),
        d.ssdp.as_ref().and_then(|s| s.friendly_name.clone()),
        m.and_then(|m| m.hostname.clone()),
        dns,
    ]
    .into_iter()
    .flatten()
    .find(|n| !is_junk_name(n))
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
    let prefix = ["KP", "HS", "EP", "KL", "LB", "KS"].into_iter().find(|p| s.starts_with(p))?;
    let digits: String = s[prefix.len()..].chars().take_while(char::is_ascii_digit).collect();
    (2..=3).contains(&digits.len()).then(|| format!("{prefix}{digits}"))
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
    ["iPhone", "iPad", "iPod", "AppleTV", "AudioAccessory", "Mac", "iMac", "Watch"]
        .iter()
        .any(|p| id.starts_with(p) && id[p.len()..].starts_with(|c: char| c.is_ascii_digit() || c == 'B' || c == 'P' || c == 'm' || c == 'A'))
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
        "Mac14,5" | "Mac14,6" | "Mac14,7" | "Mac14,9" | "Mac14,10" => Some(named("Computer", "MacBook Pro (M2)")),
        "Mac14,8" => Some(named("Computer", "Mac Pro (M2)")),
        "Mac15,3" | "Mac15,6" | "Mac15,7" | "Mac15,8" | "Mac15,9" | "Mac15,10" | "Mac15,11" => {
            Some(named("Computer", "MacBook Pro (M3)"))
        }
        "Mac15,4" | "Mac15,5" => Some(named("Computer", "iMac (M3)")),
        "Mac15,12" | "Mac15,13" => Some(named("Computer", "MacBook Air (M3)")),
        "Mac15,14" => Some(named("Computer", "Mac Studio (M3 Ultra)")),
        "Mac16,1" | "Mac16,5" | "Mac16,6" | "Mac16,7" | "Mac16,8" => Some(named("Computer", "MacBook Pro (M4)")),
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
        assert_eq!(apple_model("AppleTV14,1").1.as_deref(), Some("Apple TV 4K (3rd gen)"));
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

    fn device(ports: &[u16], vendor: Option<&'static str>) -> Device {
        let mut d = Device::new(std::net::Ipv4Addr::new(192, 168, 1, 2));
        d.open_ports = ports.to_vec();
        d.vendor = vendor;
        d
    }

    #[test]
    fn vendor_beats_generic_ports() {
        // A Ubiquiti switch with SSH open is network gear, not a computer.
        assert_eq!(identify(&device(&[22], Some("Ubiquiti"))).map(|id| id.0), Some("Network gear"));
        assert_eq!(identify(&device(&[22], None)).map(|id| id.0), Some("SSH device"));
        // Specific ports still beat the vendor: an Apple MAC with only the sync port is a phone.
        assert_eq!(identify(&device(&[62078], Some("Apple"))).map(|id| id.0), Some("Phone / tablet"));
    }

    #[test]
    fn homelab_ports() {
        let id = |ports: &[u16]| identify(&device(ports, None));
        assert_eq!(id(&[22, 8006]), Some(("Server", Some("Proxmox VE".into()))));
        assert_eq!(id(&[8123]), Some(("Home automation", Some("Home Assistant".into()))));
        assert_eq!(id(&[22, 32400]), Some(("Media server", Some("Plex".into()))));
        assert_eq!(id(&[135, 445, 3389]), Some(("Computer", Some("Windows PC".into()))));
        // A database makes a box a server, even one sharing files over SMB.
        assert_eq!(id(&[22, 445, 5432]).map(|id| id.0), Some("Server"));
        assert_eq!(id(&[53]).map(|id| id.0), Some("DNS server"));
        let mut router = device(&[53, 80], None);
        router.gateway = true;
        assert_eq!(identify(&router), None);
    }

    #[test]
    fn xiaomi_names() {
        assert_eq!(xiaomi("zhimi-fan-za5_mibta3f0"), Some(("Fan", Some("Smartmi zhimi.fan.za5".into()))));
        assert_eq!(
            xiaomi("roborock-vacuum-s5_miio12345678"),
            Some(("Robot vacuum", Some("Roborock roborock.vacuum.s5".into())))
        );
        assert_eq!(xiaomi("yeelink-light-color1_miio1"), Some(("Smart light", Some("Yeelight yeelink.light.color1".into()))));
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
