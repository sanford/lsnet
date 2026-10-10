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

use serde::{Deserialize, Serialize};
use simple_dns::rdata::RData;
use simple_dns::{CLASS, Name, Packet, QCLASS, Question, TYPE};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
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
    "_mediaremotetv._tcp.local",
    "_viziocast._tcp.local",
    "_nanoleafapi._tcp.local",
    "_miio._udp.local",
    "_daap._tcp.local",
    "_plexmediasvr._tcp.local",
    "_touch-able._tcp.local",
    "_scanner._tcp.local",
    "_matterc._udp.local",
    "_elg._tcp.local",
    // Dante and NDI, asked for by name since not every embedded responder
    // answers the meta-query. Every Dante device runs _netaudio-cmc;
    // _netaudio-arc only where routing is on.
    "_netaudio-arc._udp.local",
    "_netaudio-cmc._udp.local",
    "_ndi._tcp.local",
];

/// TXT keys that carry model or identity information; everything else is noise.
const TXT_KEYS: &[&str] = &[
    "model",
    "am",
    "md",
    "fn",
    "ty",
    "product",
    "ci",
    "rpmd",
    "manufacturer",
    "usb_mfg",
    "usb_mdl",
    "mn",
    "vn",
    "osxvers",
    // Fire TV's owner-given name, on _amzn-wplay.
    "n",
];

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MdnsInfo {
    /// The device's primary host name, e.g. `living-room.local`.
    pub hostname: Option<String>,
    /// Service type (e.g. "airplay") → instance name (e.g. "Living Room").
    pub services: BTreeMap<String, String>,
    /// Service type → interesting TXT key/values.
    pub txt: BTreeMap<String, BTreeMap<String, String>>,
    /// Service type → the port it's offered on.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub ports: BTreeMap<String, u16>,
    /// A MAC address one of its service names gave away (see `instance_mac`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// The link-local IPv6 addresses its host name comes with.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ipv6: Vec<Ipv6Addr>,
    /// Whether a reply came from this address itself, which shows the device
    /// is on this network segment and using it. Other addresses are only
    /// what someone said: a device listing all of its addresses, a Bonjour
    /// Sleep Proxy answering for a sleeping Mac, or Dante publishing where
    /// its multicast audio comes from.
    #[serde(skip)]
    pub heard_from: bool,
}

#[derive(Clone, Default)]
struct Records {
    /// instance (lowercased) → (display name, packet source)
    instances: HashMap<String, (String, Ipv4Addr)>,
    /// instance → (target host, port)
    srv: HashMap<String, (String, u16)>,
    txt: HashMap<String, BTreeMap<String, String>>,
    /// host → its addresses, in the order announced. Multi-homed devices
    /// (a Dante interface's secondary port, say) list more than one.
    a: HashMap<String, Vec<Ipv4Addr>>,
    /// host → its link-local IPv6 addresses.
    aaaa: HashMap<String, Vec<Ipv6Addr>>,
    types: HashSet<String>,
    /// Every address a reply came from.
    senders: HashSet<Ipv4Addr>,
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
    rec.senders.insert(src);
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
                rec.srv
                    .insert(key, (srv.target.to_string().to_ascii_lowercase(), srv.port));
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
                let addrs = rec.a.entry(key).or_default();
                let ip = Ipv4Addr::from(a.address);
                if !addrs.contains(&ip) {
                    addrs.push(ip);
                }
            }
            RData::AAAA(aaaa) => {
                let ip = Ipv6Addr::from(aaaa.address);
                let addrs = rec.aaaa.entry(key).or_default();
                // The others are for the internet, not this network.
                if ip.segments()[0] & 0xffc0 == 0xfe80 && !addrs.contains(&ip) {
                    addrs.push(ip);
                }
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
    let [d, c, b, a] = octets[..] else {
        return None;
    };
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

/// The MAC address some services put in their instance names, which is the
/// only way to learn it without ARP: AirPlay audio (`raop`) names instances
/// `A1B2C3D4E5F6@Living Room`, and Linux workstations `host [aa:bb:cc:dd:ee:ff]`.
/// Returns the instance name to keep (without a workstation's suffix) and the MAC.
fn instance_mac(service: &str, instance: &str) -> (String, Option<String>) {
    let hex_pairs = |hex: &str| -> Option<String> {
        let bytes: Vec<u8> = (0..6)
            .map(|i| u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok())
            .collect::<Option<_>>()?;
        bytes.iter().any(|&b| b != 0).then(|| {
            bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        })
    };
    match service {
        "raop" => {
            let mac = instance
                .split_once('@')
                .filter(|(hex, _)| hex.len() == 12 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                .and_then(|(hex, _)| hex_pairs(hex));
            (instance.to_string(), mac)
        }
        "workstation" => {
            let parsed = instance
                .strip_suffix(']')
                .and_then(|rest| rest.rsplit_once(" ["))
                .and_then(|(name, mac)| {
                    let parts: Vec<&str> = mac.split(':').collect();
                    let ok = parts.len() == 6
                        && parts
                            .iter()
                            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()));
                    ok.then(|| (name.trim_end(), parts.concat()))
                });
            match parsed {
                Some((name, hex)) => (name.to_string(), hex_pairs(&hex)),
                None => (instance.to_string(), None),
            }
        }
        _ => (instance.to_string(), None),
    }
}

/// What's been overheard on port 5353, accumulated: announcements, and
/// answers to other machines' questions.
#[derive(Default)]
pub struct Overheard {
    rec: Records,
}

impl Overheard {
    pub fn absorb(&mut self, packet: &[u8], src: Ipv4Addr) {
        if let Ok(packet) = Packet::parse(packet) {
            absorb(&mut self.rec, &packet, src);
        }
    }

    /// Everything heard so far, per device, as `discover` would report it.
    pub fn resolve(&self) -> HashMap<Ipv4Addr, MdnsInfo> {
        resolve(self.rec.clone())
    }
}

/// Listen on the mDNS port alongside the system's own responder (Bonjour,
/// Avahi), passing each packet and its sender to `heard` until it returns
/// false or `stop` is set. False if the port can't be shared.
pub fn listen(
    local_ip: Ipv4Addr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mut heard: impl FnMut(Ipv4Addr, &[u8]) -> bool + Send + 'static,
) -> bool {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::sync::atomic::Ordering;
    let open = || -> std::io::Result<std::net::UdpSocket> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        // Both, so the system's responder keeps working and so do we.
        sock.set_reuse_address(true)?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
        sock.bind(&std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS.1).into())?;
        sock.join_multicast_v4(&MDNS.0, &local_ip)?;
        sock.set_read_timeout(Some(std::time::Duration::from_millis(250)))?;
        Ok(sock.into())
    };
    let Ok(sock) = open() else {
        return false;
    };
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 9000];
        while !stop.load(Ordering::Relaxed) {
            let Ok((n, std::net::SocketAddr::V4(src))) = sock.recv_from(&mut buf) else {
                continue;
            };
            if !heard(*src.ip(), &buf[..n]) {
                break;
            }
        }
    });
    true
}

fn resolve(rec: Records) -> HashMap<Ipv4Addr, MdnsInfo> {
    let mut out: HashMap<Ipv4Addr, MdnsInfo> = HashMap::new();
    for (key, (display, src)) in &rec.instances {
        let Some((instance, service)) = split_instance(display) else {
            continue;
        };
        let (instance, mac) = instance_mac(&service, &instance);
        let srv = rec.srv.get(key);
        // Every address of the host offering it: a machine on Wi-Fi and
        // Ethernet at once is the same device at both. Addresses off this
        // network count only if a reply came from them (see `heard_from`).
        let addrs = srv
            .and_then(|(h, _)| rec.a.get(h))
            .cloned()
            .unwrap_or_else(|| vec![*src]);
        for ip in addrs {
            let info = out.entry(ip).or_default();
            if info.mac.is_none() {
                info.mac = mac.clone();
            }
            if let Some((h, port)) = srv {
                info.hostname.get_or_insert_with(|| h.clone());
                info.ports.insert(service.clone(), *port);
            }
            info.services.insert(service.clone(), instance.clone());
            if let Some(kv) = rec.txt.get(key) {
                info.txt
                    .entry(service.clone())
                    .or_default()
                    .extend(kv.clone());
            }
        }
    }
    // Hosts that only answered with an address record still count.
    for (host, addrs) in &rec.a {
        let info = out.entry(pick(addrs, &rec.senders)).or_default();
        info.hostname.get_or_insert_with(|| host.clone());
    }
    // The name a device gives for its own address is its primary one, and
    // beats whatever host its services happen to be registered under.
    for (ip, name) in rec.reverse {
        out.entry(ip).or_default().hostname = Some(name);
    }
    for (host, addrs) in &rec.aaaa {
        for ip in rec.a.get(host).into_iter().flatten() {
            if let Some(info) = out.get_mut(ip) {
                info.ipv6 = addrs.clone();
            }
        }
    }
    for (ip, info) in &mut out {
        info.heard_from = rec.senders.contains(ip);
    }
    out
}

/// Which of the addresses a name has to credit with it: one a reply came
/// from, else the first announced.
fn pick(addrs: &[Ipv4Addr], senders: &HashSet<Ipv4Addr>) -> Ipv4Addr {
    addrs
        .iter()
        .copied()
        .find(|a| senders.contains(a))
        .unwrap_or(addrs[0])
}

/// Add what `more` says to `info`. Returns whether anything was new.
pub fn merge(info: &mut Option<MdnsInfo>, more: MdnsInfo) -> bool {
    let Some(info) = info else {
        *info = Some(more);
        return true;
    };
    let before = (
        info.services.len(),
        info.txt.values().map(BTreeMap::len).sum::<usize>(),
        info.ports.len(),
        info.hostname.is_some(),
        info.mac.is_some(),
        info.ipv6.len(),
    );
    for (svc, instance) in more.services {
        info.services.entry(svc).or_insert(instance);
    }
    for (svc, kv) in more.txt {
        let txt = info.txt.entry(svc).or_default();
        for (k, v) in kv {
            txt.entry(k).or_insert(v);
        }
    }
    for (svc, port) in more.ports {
        info.ports.entry(svc).or_insert(port);
    }
    if info.hostname.is_none() {
        info.hostname = more.hostname;
    }
    if info.mac.is_none() {
        info.mac = more.mac;
    }
    for ip in more.ipv6 {
        if !info.ipv6.contains(&ip) {
            info.ipv6.push(ip);
        }
    }
    info.heard_from |= more.heard_from;
    let after = (
        info.services.len(),
        info.txt.values().map(BTreeMap::len).sum::<usize>(),
        info.ports.len(),
        info.hostname.is_some(),
        info.mac.is_some(),
        info.ipv6.len(),
    );
    before != after
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
    fn macs_from_instance_names() {
        assert_eq!(
            instance_mac("raop", "6C4A85D1E0F2@Living Room"),
            (
                "6C4A85D1E0F2@Living Room".into(),
                Some("6c:4a:85:d1:e0:f2".into())
            )
        );
        assert_eq!(
            instance_mac("workstation", "nas [00:11:32:66:D8:71]"),
            ("nas".into(), Some("00:11:32:66:d8:71".into()))
        );
        // All zeros, the wrong shape, or the wrong service: no MAC.
        assert_eq!(instance_mac("raop", "000000000000@Speaker").1, None);
        assert_eq!(instance_mac("raop", "6C4A85D1E0@Speaker").1, None);
        assert_eq!(instance_mac("raop", "Kitchen").1, None);
        assert_eq!(
            instance_mac("workstation", "pi [not a mac]"),
            ("pi [not a mac]".into(), None)
        );
        assert_eq!(instance_mac("airplay", "6C4A85D1E0F2@Living Room").1, None);
    }

    use simple_dns::rdata::{A, PTR, SRV, TXT};
    use simple_dns::{Label, ResourceRecord};

    const SPROXY: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);

    fn rr<'a>(name: Name<'a>, rdata: RData<'a>) -> ResourceRecord<'a> {
        ResourceRecord::new(name, CLASS::IN, 120, rdata)
    }

    fn a(host: &str, ip: Ipv4Addr) -> ResourceRecord<'_> {
        rr(
            Name::new_unchecked(host),
            RData::A(A { address: ip.into() }),
        )
    }

    /// Parse `records` as one reply from `src`, the way `discover` does.
    fn heard(src: Ipv4Addr, records: Vec<ResourceRecord>) -> HashMap<Ipv4Addr, MdnsInfo> {
        let mut packet = Packet::new_reply(0);
        packet.answers = records;
        let bytes = packet.build_bytes_vec().unwrap();
        let mut rec = Records::default();
        absorb(&mut rec, &Packet::parse(&bytes).unwrap(), src);
        resolve(rec)
    }

    #[test]
    fn credits_the_srv_target_not_the_sender() {
        // A Bonjour Sleep Proxy (an Apple TV) answering for a sleeping Mac.
        let mac = Ipv4Addr::new(192, 168, 1, 42);
        let instance = "Studio._airplay._tcp.local";
        let out = heard(
            SPROXY,
            vec![
                rr(
                    Name::new_unchecked("_airplay._tcp.local"),
                    RData::PTR(PTR(Name::new_unchecked(instance))),
                ),
                rr(
                    Name::new_unchecked(instance),
                    RData::SRV(SRV {
                        priority: 0,
                        weight: 0,
                        port: 7000,
                        target: Name::new_unchecked("Studio-Mac.local"),
                    }),
                ),
                a("Studio-Mac.local", mac),
            ],
        );
        assert!(!out.contains_key(&SPROXY));
        let info = &out[&mac];
        assert_eq!(info.services["airplay"], "Studio");
        assert_eq!(info.ports["airplay"], 7000);
        assert_eq!(info.hostname.as_deref(), Some("studio-mac.local"));
    }

    #[test]
    fn credits_every_address_of_a_multi_homed_device() {
        // A Dante device with its secondary port on a link-local address.
        let dante = Ipv4Addr::new(192, 168, 1, 77);
        let instance = "Stagebox._netaudio-arc._udp.local";
        let out = heard(
            dante,
            vec![
                rr(
                    Name::new_unchecked(instance),
                    RData::SRV(SRV {
                        priority: 0,
                        weight: 0,
                        port: 4440,
                        target: Name::new_unchecked("Stagebox.local"),
                    }),
                ),
                a("Stagebox.local", Ipv4Addr::new(169, 254, 9, 9)),
                a("Stagebox.local", dante),
            ],
        );
        assert_eq!(out[&dante].services["netaudio-arc"], "Stagebox");
        assert!(out[&dante].heard_from);
        // Its other address has the same services, but no reply came from
        // it, so it's not taken as a device on this segment.
        let secondary = &out[&Ipv4Addr::new(169, 254, 9, 9)];
        assert_eq!(secondary.services["netaudio-arc"], "Stagebox");
        assert!(!secondary.heard_from);
    }

    #[test]
    fn only_the_sender_was_heard_from() {
        // Dante names a record after each multicast flow, whose address is
        // the transmitter, on another network.
        let dante = Ipv4Addr::new(192, 168, 1, 77);
        let transmitter = Ipv4Addr::new(10, 0, 0, 12);
        let out = heard(dante, vec![a("10.0.255.239.in-addr.local", transmitter)]);
        assert!(!out[&transmitter].heard_from);
    }

    #[test]
    fn falls_back_to_the_sender_without_an_address() {
        let out = heard(
            SPROXY,
            vec![rr(
                Name::new_unchecked("_hap._tcp.local"),
                RData::PTR(PTR(Name::new_unchecked("Plug._hap._tcp.local"))),
            )],
        );
        assert_eq!(out[&SPROXY].services["hap"], "Plug");
    }

    #[test]
    fn a_reverse_answer_names_the_device() {
        let ha = Ipv4Addr::new(192, 168, 1, 130);
        let instance = "Home._home-assistant._tcp.local";
        let out = heard(
            ha,
            vec![
                rr(
                    Name::new_unchecked(instance),
                    RData::SRV(SRV {
                        priority: 0,
                        weight: 0,
                        port: 8123,
                        target: Name::new_unchecked("36814e2569ca121f.local"),
                    }),
                ),
                a("36814e2569ca121f.local", ha),
                rr(
                    Name::new_unchecked("130.1.168.192.in-addr.arpa"),
                    RData::PTR(PTR(Name::new_unchecked("homeassistant.local"))),
                ),
            ],
        );
        assert_eq!(out[&ha].hostname.as_deref(), Some("homeassistant.local"));
    }

    #[test]
    fn keeps_only_identifying_txt_keys() {
        let tv = Ipv4Addr::new(192, 168, 1, 52);
        let instance = "Living Room._airplay._tcp.local";
        let txt = TXT::new()
            .with_string("model=AppleTV14,1")
            .unwrap()
            .with_string("features=0x4A7FDFD5,0xBC157FDE")
            .unwrap()
            .with_string("fn=")
            .unwrap();
        let out = heard(tv, vec![rr(Name::new_unchecked(instance), RData::TXT(txt))]);
        let txt = &out[&tv].txt["airplay"];
        assert_eq!(txt.len(), 1);
        assert_eq!(txt["model"], "AppleTV14,1");
    }

    #[test]
    fn instance_names_may_contain_dots() {
        // NDI names sources after the machine, which on a Mac ends ".LOCAL".
        let src = Ipv4Addr::new(192, 168, 1, 31);
        let instance = Name::new_with_labels(&[
            Label::new_unchecked("STAGE-MBP.LOCAL (Scan Converter)".as_bytes()),
            Label::new_unchecked("_ndi".as_bytes()),
            Label::new_unchecked("_tcp".as_bytes()),
            Label::new_unchecked("local".as_bytes()),
        ]);
        let out = heard(
            src,
            vec![rr(
                Name::new_unchecked("_ndi._tcp.local"),
                RData::PTR(PTR(instance)),
            )],
        );
        assert_eq!(
            out[&src].services["ndi"],
            "STAGE-MBP.LOCAL (Scan Converter)"
        );
    }

    #[test]
    fn merges_only_what_is_new() {
        let mut info = None;
        let mut first = MdnsInfo::default();
        first
            .services
            .insert("airplay".into(), "Living Room".into());
        assert!(merge(&mut info, first.clone()));
        assert!(!merge(&mut info, first));
        let mut more = MdnsInfo::default();
        more.services.insert("airplay".into(), "Renamed".into());
        more.services
            .insert("raop".into(), "AABBCCDDEEFF@Living Room".into());
        assert!(merge(&mut info, more));
        let info = info.unwrap();
        // What was heard first stays.
        assert_eq!(info.services["airplay"], "Living Room");
        assert_eq!(info.services.len(), 2);
    }

    #[test]
    fn overheard_packets_accumulate() {
        let tv = Ipv4Addr::new(192, 168, 1, 52);
        let instance = "Living Room._airplay._tcp.local";
        let mut packet = Packet::new_reply(0);
        packet.answers = vec![rr(
            Name::new_unchecked("_airplay._tcp.local"),
            RData::PTR(PTR(Name::new_unchecked(instance))),
        )];
        let mut heard = Overheard::default();
        heard.absorb(&packet.build_bytes_vec().unwrap(), tv);
        heard.absorb(b"not a DNS packet", tv);
        let out = heard.resolve();
        assert_eq!(out[&tv].services["airplay"], "Living Room");
        assert!(out[&tv].heard_from);
    }

    /// Shares port 5353 with the system's responder and hears multicast on
    /// it. Needs a network interface with multicast, so it's run by hand:
    /// `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn listens_alongside_the_system_responder() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        let local = local_ip();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(listen(local, stop.clone(), move |src, packet| {
            tx.send((src, packet.to_vec())).is_ok()
        }));
        let mut packet = Packet::new_reply(0);
        packet.answers = vec![rr(
            Name::new_unchecked("_lsnet-test._tcp.local"),
            RData::PTR(PTR(Name::new_unchecked("probe._lsnet-test._tcp.local"))),
        )];
        let bytes = packet.build_bytes_vec().unwrap();
        let sock = std::net::UdpSocket::bind((local, 0)).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let heard = loop {
            sock.send_to(&bytes, MDNS).unwrap();
            if let Ok((src, got)) = rx.recv_timeout(std::time::Duration::from_millis(200))
                && got == bytes
            {
                break Some(src);
            }
            if std::time::Instant::now() > deadline {
                break None;
            }
        };
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(heard, Some(local));
    }

    /// The address this machine reaches the internet from.
    fn local_ip() -> Ipv4Addr {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.connect("1.1.1.1:53").unwrap();
        match sock.local_addr().unwrap().ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => panic!("no IPv4 address"),
        }
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
