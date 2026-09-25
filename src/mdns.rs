//! Bonjour / mDNS discovery.
//!
//! We ask for a list of well-known service types plus the DNS-SD "list every
//! service type" meta-query, with the unicast-response bit set so replies
//! come straight back to our ephemeral port (no fighting mDNSResponder for
//! port 5353). Any types we learn about get queried in a second round.
//! Records are resolved instance → SRV target → A record, so answers from a
//! Bonjour sleep proxy on behalf of a sleeping Mac are credited correctly.
//!
//! We also ask every address for its own name with a reverse lookup
//! (`20.1.168.192.in-addr.arpa`). That finds a device's primary `.local`
//! name even when it never advertises it: Home Assistant, for one, announces
//! its service under a random hex host but answers to `homeassistant.local`.

use serde::Serialize;
use simple_dns::rdata::RData;
use simple_dns::{CLASS, Name, Packet, QCLASS, Question, TYPE};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};

const MDNS: (Ipv4Addr, u16) = (Ipv4Addr::new(224, 0, 0, 251), 5353);
const META: &str = "_services._dns-sd._udp.local";

const SERVICE_TYPES: &[&str] = &[
    "_device-info._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_companion-link._tcp.local",
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
    "_sonos._tcp.local",
    "_hap._tcp.local",
    "_matter._tcp.local",
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_printer._tcp.local",
    "_pdl-datastream._tcp.local",
    "_uscan._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_http._tcp.local",
    "_workstation._tcp.local",
    "_amzn-wplay._tcp.local",
    "_androidtvremote2._tcp.local",
    "_hue._tcp.local",
    "_esphomelib._tcp.local",
    "_home-assistant._tcp.local",
    "_meshcop._udp.local",
    "_airport._tcp.local",
    "_sleep-proxy._udp.local",
    "_rdlink._tcp.local",
    "_nvstream._tcp.local",
    "_umbrel._tcp.local",
];

/// TXT keys that carry model or identity information; everything else is noise.
const TXT_KEYS: &[&str] = &[
    "model", "am", "md", "fn", "ty", "product", "ci", "rpmd", "manufacturer", "usb_mfg",
    "usb_mdl", "mn", "vn", "osxvers",
];

#[derive(Default, Clone, Serialize)]
pub struct MdnsInfo {
    /// The device's primary host name, e.g. `living-room.local`.
    pub hostname: Option<String>,
    /// Service type (e.g. "airplay") → instance name (e.g. "Living Room").
    pub services: BTreeMap<String, String>,
    /// Service type → interesting TXT key/values.
    pub txt: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Default)]
struct Records {
    /// instance (lowercased) → (display name, packet source)
    instances: HashMap<String, (String, Ipv4Addr)>,
    srv: HashMap<String, String>,
    txt: HashMap<String, BTreeMap<String, String>>,
    a: HashMap<String, Ipv4Addr>,
    types: HashSet<String>,
    /// Answers to reverse lookups: address → the name the device calls itself.
    reverse: HashMap<Ipv4Addr, String>,
}

pub async fn discover(
    local_ip: Ipv4Addr,
    targets: &[Ipv4Addr],
    wait: Duration,
) -> HashMap<Ipv4Addr, MdnsInfo> {
    let Ok(sock) = UdpSocket::bind((local_ip, 0)).await else {
        return HashMap::new();
    };
    let deadline = Instant::now() + wait;
    let resend_at = Instant::now() + wait / 3;

    // Only the owner of an address answers its reverse lookup, so asking about
    // every address up front costs a few packets and no extra time.
    let initial: Vec<String> = std::iter::once(META)
        .chain(SERVICE_TYPES.iter().copied())
        .map(String::from)
        .chain(targets.iter().map(|ip| reverse_name(*ip)))
        .collect();
    let mut asked: HashSet<String> = initial.iter().cloned().collect();
    send_queries(&sock, &initial).await;

    let mut rec = Records::default();
    let mut resent = false;
    let mut buf = vec![0u8; 9000];
    loop {
        let until = if resent { deadline } else { resend_at };
        match timeout_at(until, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, std::net::SocketAddr::V4(src)))) => {
                if let Ok(packet) = Packet::parse(&buf[..n]) {
                    absorb(&mut rec, &packet, *src.ip());
                }
            }
            Ok(_) => {}
            Err(_) if !resent => {
                // Second round: repeat for sleepy responders, plus newly learned types.
                resent = true;
                let mut round: Vec<String> = initial.clone();
                for t in &rec.types {
                    if asked.insert(t.clone()) {
                        round.push(t.clone());
                    }
                }
                send_queries(&sock, &round).await;
            }
            Err(_) => break,
        }
    }
    resolve(rec)
}

async fn send_queries(sock: &UdpSocket, types: &[String]) {
    // A few questions per packet keeps us well under typical MTUs.
    for chunk in types.chunks(8) {
        let mut packet = Packet::new_query(0);
        for t in chunk {
            packet.questions.push(Question::new(
                Name::new_unchecked(t),
                TYPE::PTR.into(),
                QCLASS::CLASS(CLASS::IN),
                true,
            ));
        }
        if let Ok(bytes) = packet.build_bytes_vec() {
            let _ = sock.send_to(&bytes, MDNS).await;
        }
    }
}

fn absorb(rec: &mut Records, packet: &Packet, src: Ipv4Addr) {
    let records = packet.answers.iter().chain(&packet.additional_records);
    for r in records {
        let owner = r.name.to_string();
        let key = owner.to_ascii_lowercase();
        match &r.rdata {
            RData::PTR(ptr) => {
                let target = ptr.0.to_string();
                if let Some(ip) = parse_reverse(&key) {
                    rec.reverse.insert(ip, target.to_ascii_lowercase());
                } else if key == META {
                    rec.types.insert(target.to_ascii_lowercase());
                } else {
                    let tkey = target.to_ascii_lowercase();
                    rec.instances.entry(tkey).or_insert((target, src));
                }
            }
            RData::SRV(srv) => {
                rec.instances.entry(key.clone()).or_insert((owner, src));
                rec.srv.insert(key, srv.target.to_string().to_ascii_lowercase());
            }
            RData::TXT(txt) => {
                let kv: BTreeMap<String, String> = txt
                    .attributes()
                    .into_iter()
                    .filter_map(|(k, v)| {
                        let k = k.to_ascii_lowercase();
                        let v = v?.trim().to_string();
                        (TXT_KEYS.contains(&k.as_str()) && !v.is_empty()).then_some((k, v))
                    })
                    .collect();
                if !kv.is_empty() {
                    rec.instances.entry(key.clone()).or_insert((owner, src));
                    rec.txt.entry(key).or_default().extend(kv);
                }
            }
            RData::A(a) => {
                rec.a.insert(key, Ipv4Addr::from(a.address));
            }
            _ => {}
        }
    }
}

/// 192.168.1.20 → `20.1.168.192.in-addr.arpa`
fn reverse_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

fn parse_reverse(name: &str) -> Option<Ipv4Addr> {
    let octets: Vec<u8> = name
        .strip_suffix(".in-addr.arpa")?
        .split('.')
        .map(|o| o.parse().ok())
        .collect::<Option<_>>()?;
    let [d, c, b, a] = octets[..] else { return None };
    Some(Ipv4Addr::new(a, b, c, d))
}

/// `Living Room._airplay._tcp.local` → ("Living Room", "airplay")
fn split_instance(name: &str) -> Option<(String, String)> {
    let parsed = Name::new_unchecked(name);
    let labels = parsed.get_labels();
    if labels.len() < 3 {
        return None;
    }
    let service = labels[labels.len() - 3].to_string();
    let service = service.strip_prefix('_')?.to_ascii_lowercase();
    let instance = labels[..labels.len() - 3]
        .iter()
        .map(|l| l.to_string())
        .collect::<Vec<_>>()
        .join(".");
    Some((instance, service))
}

fn resolve(rec: Records) -> HashMap<Ipv4Addr, MdnsInfo> {
    let mut out: HashMap<Ipv4Addr, MdnsInfo> = HashMap::new();
    for (key, (display, src)) in &rec.instances {
        let Some((instance, service)) = split_instance(display) else { continue };
        let host = rec.srv.get(key);
        let ip = host.and_then(|h| rec.a.get(h)).copied().unwrap_or(*src);
        let info = out.entry(ip).or_default();
        if let Some(h) = host {
            info.hostname.get_or_insert_with(|| h.clone());
        }
        info.services.insert(service.clone(), instance);
        if let Some(kv) = rec.txt.get(key) {
            info.txt.entry(service).or_default().extend(kv.clone());
        }
    }
    // Hosts that only answered with an address record still count.
    for (host, ip) in &rec.a {
        let info = out.entry(*ip).or_default();
        info.hostname.get_or_insert_with(|| host.clone());
    }
    // The name a device gives for its own address is its primary one, and
    // beats whatever host its services happen to be registered under.
    for (ip, name) in rec.reverse {
        out.entry(ip).or_default().hostname = Some(name);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_names_round_trip() {
        let ip = Ipv4Addr::new(192, 168, 1, 20);
        assert_eq!(reverse_name(ip), "20.1.168.192.in-addr.arpa");
        assert_eq!(parse_reverse(&reverse_name(ip)), Some(ip));
        assert_eq!(parse_reverse("_airplay._tcp.local"), None);
        assert_eq!(parse_reverse("1.2.3.in-addr.arpa"), None);
    }

    #[test]
    fn splits_instances() {
        assert_eq!(
            split_instance("Living Room._airplay._tcp.local"),
            Some(("Living Room".into(), "airplay".into()))
        );
        assert_eq!(split_instance("_tcp.local"), None);
    }
}
