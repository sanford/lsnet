//! Scanning in the background for the browser, so it can show results as
//! they arrive, then listening for devices the scan missed: ones that were
//! asleep, or that only speak now and then.
//!
//! After the scan, nothing is sent except follow-up questions to devices
//! heard for the first time, the same ones the scan asks (ports, web page,
//! NetBIOS, UPnP, Kasa, reverse DNS).

use crate::history::{self, History};
use crate::scan::{self, Context, Progress, Tracker};
use crate::{Args, Device, Scan, arp, demo, mdns};
use pnet_base::MacAddr;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

/// What the background scan has to say.
pub enum Update {
    /// What it's doing: "waiting for ports 43%", "listening for more
    /// devices", or empty when it's done.
    Status(String),
    /// The results so far, replacing any before.
    Scan(Scan),
    /// The scan couldn't run at all.
    Failed(String),
}

/// A background scan's updates. Dropping it stops the scan's listening.
pub struct Feed {
    pub updates: Receiver<Update>,
    stop: Arc<AtomicBool>,
}

impl Drop for Feed {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// What history says about the network, for marking each scan's results.
pub struct Memory {
    /// None with `--no-history`.
    pub history: Option<History>,
    /// The time to compare with: now, except for the demo's fixed one.
    pub now: Option<u64>,
    /// Something to tell the user about the history file.
    pub warning: Option<String>,
}

impl Memory {
    /// Where devices were last seen, for second chances.
    fn recheck(&self) -> Vec<Ipv4Addr> {
        self.history
            .as_ref()
            .map(History::addresses)
            .unwrap_or_default()
    }

    /// Mark what changed since the last scan of the network.
    pub fn mark(&self, scan: &mut Scan) {
        if let Some(w) = &self.warning
            && !scan.notes.contains(w)
        {
            scan.notes.push(w.clone());
        }
        let (Some(history), Some(id)) = (&self.history, scan.network.clone()) else {
            return;
        };
        let now = self.now.unwrap_or_else(history::now);
        scan.clock = now;
        scan.changes = history.annotate(&mut scan.devices, &id, now, scan.arp_ran);
    }
}

/// Scan once, reporting what it's waiting for to `status`.
pub fn once(
    args: &Args,
    memory: &Memory,
    status: &(dyn Fn(String) + Sync),
) -> Result<Scan, String> {
    let mut scan = if args.demo {
        demo::scan()
    } else {
        let report = |p| {
            if let Progress::Status(s) = p {
                status(s);
            }
        };
        scan::run(args, &report, &memory.recheck())?.0
    };
    memory.mark(&mut scan);
    Ok(scan)
}

/// Scan in the background, then, with `listen`, keep listening.
pub fn start(args: Arc<Args>, memory: Arc<Memory>, listen: bool) -> Feed {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let feed = Feed {
        updates: rx,
        stop: stop.clone(),
    };
    thread::spawn(move || produce(&args, &memory, listen, &tx, &stop));
    feed
}

fn produce(
    args: &Args,
    memory: &Memory,
    listen: bool,
    tx: &Sender<Update>,
    stop: &Arc<AtomicBool>,
) {
    if args.demo {
        let mut scan = demo::scan();
        memory.mark(&mut scan);
        let _ = tx.send(Update::Scan(scan));
        let _ = tx.send(Update::Status(String::new()));
        return;
    }
    let report = |p| {
        let _ = tx.send(match p {
            Progress::Status(s) => Update::Status(s),
            Progress::Partial(mut scan) => {
                memory.mark(&mut scan);
                Update::Scan(scan)
            }
        });
    };
    match scan::run(args, &report, &memory.recheck()) {
        Err(e) => {
            let _ = tx.send(Update::Failed(e));
        }
        Ok((mut scan, ctx)) => {
            memory.mark(&mut scan);
            if tx.send(Update::Scan(scan.clone())).is_ok() && listen {
                keep_listening(scan, ctx, memory, tx, stop);
            }
        }
    }
}

enum Heard {
    Arp(Ipv4Addr, MacAddr),
    Mdns(Ipv4Addr, Vec<u8>),
}

/// Listen to ARP (with raw access) and mDNS until stopped, adding what's
/// heard to the results and sending them again each time they change.
fn keep_listening(
    scan: Scan,
    mut ctx: Context,
    memory: &Memory,
    tx: &Sender<Update>,
    stop: &Arc<AtomicBool>,
) {
    let (heard_tx, heard) = mpsc::channel();
    let arp_tx = heard_tx.clone();
    let arp = arp::listen(&ctx.ifc, stop.clone(), move |ip, mac| {
        arp_tx.send(Heard::Arp(ip, mac)).is_ok()
    });
    let mdns = mdns::listen(ctx.ifc.ip, stop.clone(), move |src, packet| {
        heard_tx.send(Heard::Mdns(src, packet.to_vec())).is_ok()
    });
    if !arp && !mdns {
        let _ = tx.send(Update::Status(String::new()));
        return;
    }
    if tx
        .send(Update::Status("listening for more devices".into()))
        .is_err()
    {
        return;
    }
    let mut hosts: BTreeMap<Ipv4Addr, Device> = scan
        .devices
        .into_iter()
        .filter(|d| !d.missing())
        .map(|d| (d.ip, d))
        .collect();
    let mut overheard = mdns::Overheard::default();
    let mut names = HashMap::new();
    let ignore = |_| {};
    let quiet = Tracker::new(&ignore);
    while !stop.load(Ordering::Relaxed) {
        let first = match heard.recv_timeout(Duration::from_millis(500)) {
            Ok(h) => h,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        // Whatever else arrives in the next moment comes along with it.
        let mut batch = vec![first];
        let until = Instant::now() + Duration::from_millis(300);
        while let Ok(h) = heard.recv_timeout(until.saturating_duration_since(Instant::now())) {
            batch.push(h);
        }
        let (new, changed) = absorb(&mut ctx, &mut hosts, &mut overheard, batch);
        if !changed {
            continue;
        }
        let mut found: Vec<Device> = new.iter().filter_map(|ip| hosts.remove(ip)).collect();
        for d in &mut found {
            d.gateway = Some(d.ip) == ctx.ifc.gateway;
            d.this_device = ctx.ifc.own_ips.contains(&d.ip);
            d.heard_later = true;
        }
        let look_up = !ctx.no_dns;
        scan::follow_up(
            &ctx,
            &mut found,
            &HashSet::new(),
            &mut names,
            look_up,
            &quiet,
        );
        hosts.extend(found.into_iter().map(|d| (d.ip, d)));
        for d in hosts.values_mut() {
            crate::finish(d);
        }
        let mut scan = ctx.snapshot(hosts.values().cloned().collect());
        memory.mark(&mut scan);
        if tx.send(Update::Scan(scan)).is_err() {
            return;
        }
    }
}

/// Add what was heard to `hosts`. Returns the addresses of devices heard
/// for the first time, and whether anything changed.
fn absorb(
    ctx: &mut Context,
    hosts: &mut BTreeMap<Ipv4Addr, Device>,
    overheard: &mut mdns::Overheard,
    batch: Vec<Heard>,
) -> (Vec<Ipv4Addr>, bool) {
    let before: HashSet<Ipv4Addr> = hosts.keys().copied().collect();
    let (mut arp_news, mut mdns_news, mut changed) = (false, false, false);
    for h in batch {
        match h {
            Heard::Arp(ip, mac) => {
                let macs = ctx.heard.entry(ip).or_default();
                if !macs.contains(&mac) {
                    macs.push(mac);
                    arp_news = true;
                }
            }
            Heard::Mdns(src, packet) => {
                overheard.absorb(&packet, src);
                mdns_news = true;
            }
        }
    }
    if arp_news {
        let ifc = &ctx.ifc;
        let sorted = arp::sort_out(ctx.heard.clone(), ifc.net, ifc.link, ifc.ip, ifc.mac);
        for (ip, mac) in sorted.found {
            let d = scan::host(hosts, ip);
            if d.mac.is_none() {
                d.mac = Some(mac.to_string());
            }
        }
        scan::add_address_findings(hosts, sorted.conflicts, &sorted.strays, Vec::new());
        changed = true;
    }
    if mdns_news {
        let mut strays = Vec::new();
        for (ip, info) in overheard.resolve() {
            if ctx.on_lan(ip) {
                match hosts.get_mut(&ip) {
                    Some(d) => changed |= mdns::merge(&mut d.mdns, info),
                    // Only a device speaking for itself is news: not a
                    // sleep proxy, say, answering for a Mac.
                    None if info.heard_from => {
                        scan::host(hosts, ip).mdns = Some(info);
                    }
                    None => {}
                }
            } else if ctx.link_local_stray(ip, &info) && !hosts.contains_key(&ip) {
                strays.push((ip, info));
            }
        }
        if !strays.is_empty() {
            scan::add_address_findings(hosts, HashMap::new(), &[], strays);
        }
    }
    let new: Vec<Ipv4Addr> = hosts
        .keys()
        .filter(|ip| !before.contains(ip))
        .copied()
        .collect();
    changed |= !new.is_empty();
    (new, changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iface::Iface;
    use crate::platform::Adapter;
    use simple_dns::rdata::{A, PTR, RData};
    use simple_dns::{CLASS, Name, Packet, ResourceRecord};

    const OWN_MAC: MacAddr = MacAddr(0xf0, 0x18, 0x98, 0xa1, 0xb2, 0xc3);

    fn context() -> Context {
        Context {
            ifc: Iface {
                iface: Adapter {
                    name: "en0".into(),
                    index: 0,
                    mac: Some(OWN_MAC),
                    ips: Vec::new(),
                    up: true,
                    loopback: false,
                    physical: true,
                    gateway: None,
                },
                ip: "192.168.1.196".parse().unwrap(),
                mac: Some(OWN_MAC),
                net: "192.168.1.0/24".parse().unwrap(),
                narrowed_from: None,
                link: "192.168.1.0/24".parse().unwrap(),
                gateway: Some("192.168.1.1".parse().unwrap()),
                own_ips: vec!["192.168.1.196".parse().unwrap()],
            },
            rt: tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
            wait: Duration::ZERO,
            grace: Duration::ZERO,
            no_dns: true,
            user_net: false,
            heard: arp::Heard::new(),
            arp_ran: true,
            took: Duration::ZERO,
            caveats: Vec::new(),
        }
    }

    /// The scan found the gateway and nothing else.
    fn scanned() -> BTreeMap<Ipv4Addr, Device> {
        let mut gateway = Device::new("192.168.1.1".parse().unwrap());
        gateway.mac = Some("00:09:5b:7a:10:01".into());
        BTreeMap::from([(gateway.ip, gateway)])
    }

    /// An announcement: `host` is at `addr`, offering AirPlay as `name`.
    fn announcement(name: &str, host: &str, addr: Ipv4Addr) -> Vec<u8> {
        let instance = format!("{name}._airplay._tcp.local");
        let mut packet = Packet::new_reply(0);
        packet.answers = vec![
            ResourceRecord::new(
                Name::new_unchecked("_airplay._tcp.local"),
                CLASS::IN,
                120,
                RData::PTR(PTR(Name::new_unchecked(&instance))),
            ),
            ResourceRecord::new(
                Name::new_unchecked(host),
                CLASS::IN,
                120,
                RData::A(A {
                    address: addr.into(),
                }),
            ),
        ];
        packet.build_bytes_vec().unwrap()
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn a_device_announcing_itself_is_new() {
        let (mut ctx, mut hosts) = (context(), scanned());
        let packet = announcement("Kitchen", "Kitchen.local", ip("192.168.1.60"));
        let heard = vec![Heard::Mdns(ip("192.168.1.60"), packet)];
        let (new, changed) = absorb(&mut ctx, &mut hosts, &mut Default::default(), heard);
        assert_eq!(new, [ip("192.168.1.60")]);
        assert!(changed);
        let mdns = hosts[&ip("192.168.1.60")].mdns.as_ref().unwrap();
        assert_eq!(mdns.services["airplay"], "Kitchen");
    }

    #[test]
    fn a_device_spoken_for_is_not() {
        // A sleep proxy (the gateway, here) announcing for a sleeping Mac.
        let (mut ctx, mut hosts) = (context(), scanned());
        let packet = announcement("Studio", "Studio.local", ip("192.168.1.42"));
        let heard = vec![Heard::Mdns(ip("192.168.1.1"), packet)];
        let (new, _) = absorb(&mut ctx, &mut hosts, &mut Default::default(), heard);
        assert!(new.is_empty());
        assert!(!hosts.contains_key(&ip("192.168.1.42")));
    }

    #[test]
    fn arp_finds_new_devices_conflicts_and_strays() {
        let (mut ctx, mut hosts) = (context(), scanned());
        let mut overheard = Default::default();
        let mac = |last| MacAddr(0x24, 0x0a, 0xc4, 0, 0, last);
        let heard = vec![
            Heard::Arp(ip("192.168.1.230"), mac(1)),
            Heard::Arp(ip("169.254.37.12"), mac(2)),
        ];
        let (mut new, _) = absorb(&mut ctx, &mut hosts, &mut overheard, heard);
        new.sort();
        assert_eq!(new, [ip("169.254.37.12"), ip("192.168.1.230")]);
        assert_eq!(hosts[&ip("169.254.37.12")].flags, [arp::Flag::LinkLocal]);

        // A second device answering for .230: a conflict, not a new device.
        let heard = vec![Heard::Arp(ip("192.168.1.230"), mac(3))];
        let (new, changed) = absorb(&mut ctx, &mut hosts, &mut overheard, heard);
        assert!(new.is_empty() && changed);
        let d = &hosts[&ip("192.168.1.230")];
        assert_eq!(d.flags, [arp::Flag::AddressConflict]);
        assert_eq!(d.other_macs, ["24:0a:c4:00:00:03"]);

        // Heard again: nothing new.
        let heard = vec![Heard::Arp(ip("192.168.1.230"), mac(3))];
        let (new, changed) = absorb(&mut ctx, &mut hosts, &mut overheard, heard);
        assert!(new.is_empty() && !changed);
        assert_eq!(hosts[&ip("192.168.1.230")].flags.len(), 1);
    }

    #[test]
    fn a_self_assigned_device_announcing_itself_is_a_stray() {
        let (mut ctx, mut hosts) = (context(), scanned());
        let cam = ip("169.254.37.12");
        let packet = announcement("PTZ-CAM-1", "PTZ-CAM-1.local", cam);
        let heard = vec![Heard::Mdns(cam, packet)];
        let (new, _) = absorb(&mut ctx, &mut hosts, &mut Default::default(), heard);
        assert_eq!(new, [cam]);
        assert_eq!(hosts[&cam].flags, [arp::Flag::LinkLocal]);
    }
}
