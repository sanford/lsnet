//! One pass over the network: every discovery method at once (phase 1),
//! then follow-up questions for the devices found (phase 2).
//!
//! Progress is reported as it happens, both which probes are still running
//! and, after phase 1, a first look at the devices, so the browser can show
//! results before the scan is done.

use crate::arp;
use crate::history::NetworkId;
use crate::iface::{self, Iface};
use crate::mdns::{self, MdnsInfo};
use crate::{Args, Device, Scan, finish, http, kasa, netbios, ping, probe, ssdp};
use pnet_base::MacAddr;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::task::JoinSet;

/// Up to this many addresses (a /22), every one gets a reverse DNS and mDNS
/// lookup up front, before we know which are in use.
pub const ALL_AT_ONCE: usize = 1024;

/// What a scan reports while it runs.
pub enum Progress {
    /// What it's waiting for, e.g. "waiting for ports 43%, reverse DNS".
    /// Empty when it isn't waiting for anything.
    Status(String),
    /// The devices found so far, before follow-ups.
    Partial(Scan),
}

pub type Report<'a> = &'a (dyn Fn(Progress) + Sync);

/// What a finished scan leaves behind for asking more questions later:
/// the browser's listener follows up on devices heard after the scan.
pub struct Context {
    pub ifc: Iface,
    pub rt: Runtime,
    pub wait: Duration,
    pub grace: Duration,
    pub no_dns: bool,
    /// Whether the user named the network with `--net`.
    pub user_net: bool,
    /// Every ARP sender heard so far, from the sweep and then the listener.
    pub heard: arp::Heard,
    /// Whether the ARP sweep ran, so devices that answer nothing else could
    /// be found.
    pub arp_ran: bool,
    /// How long the scan took.
    pub took: Duration,
    /// Caveats about the scan that aren't about any one device.
    pub caveats: Vec<String>,
}

impl Context {
    /// Whether `ip` belongs in the results: the scanned network, and this
    /// machine's other addresses (it may be on Wi-Fi and Ethernet at once)
    /// unless the user named the network to scan.
    pub fn on_lan(&self, ip: Ipv4Addr) -> bool {
        self.ifc.net.contains(ip) || (!self.user_net && self.ifc.own_ips.contains(&ip))
    }

    /// A device replying from a self-assigned address is on this segment
    /// but not this network. Only link-local ones: a reply from any other
    /// foreign address may have come in on another interface (a VM's
    /// bridge, say).
    pub fn link_local_stray(&self, ip: Ipv4Addr, info: &MdnsInfo) -> bool {
        info.heard_from
            && ip.is_link_local()
            && !self.ifc.link.contains(ip)
            && !self.ifc.own_ips.contains(&ip)
    }

    /// The scan's results as of now.
    pub fn snapshot(&self, devices: Vec<Device>) -> Scan {
        let summary = format!(
            "{} devices on {} ({}) in {:.1}s",
            devices.len(),
            self.ifc.net,
            self.ifc.iface.name,
            self.took.as_secs_f64()
        );
        let notes = flag_notes(&devices, self.ifc.link);
        // Only the network this machine is on, scanned whole, is remembered:
        // anything less would make everything else look missing.
        let network = (!self.user_net && self.ifc.on_link())
            .then(|| NetworkId::new(self.ifc.net.to_string(), self.ifc.gateway, &devices));
        Scan {
            devices,
            summary,
            notes,
            caveats: self.caveats.clone(),
            changes: None,
            network,
            arp_ran: self.arp_ran,
            clock: crate::history::now(),
        }
    }
}

/// Which probes are still running, reported each time one finishes.
pub struct Tracker<'a> {
    report: Report<'a>,
    pending: Mutex<Vec<&'static str>>,
    /// Liveness checks done, of `checks`, for the port probe's percentage.
    checked: AtomicUsize,
    checks: AtomicUsize,
}

impl<'a> Tracker<'a> {
    pub fn new(report: Report<'a>) -> Self {
        Tracker {
            report,
            pending: Mutex::new(Vec::new()),
            checked: AtomicUsize::new(0),
            checks: AtomicUsize::new(0),
        }
    }

    fn waiting(&self, probes: &[&'static str]) {
        *self.pending.lock().unwrap() = probes.to_vec();
        self.publish();
    }

    fn done(&self, probe: &'static str) {
        self.pending.lock().unwrap().retain(|p| *p != probe);
        self.publish();
    }

    fn publish(&self) {
        let pending = self.pending.lock().unwrap().clone();
        let names: Vec<String> = pending
            .iter()
            .map(|&p| {
                let (done, of) = (
                    self.checked.load(Ordering::Relaxed),
                    self.checks.load(Ordering::Relaxed),
                );
                if p == "ports" && of > 0 && done < of {
                    format!("ports {}%", done * 100 / of)
                } else {
                    p.to_string()
                }
            })
            .collect();
        let status = if names.is_empty() {
            String::new()
        } else {
            format!("waiting for {}", names.join(", "))
        };
        (self.report)(Progress::Status(status));
    }
}

/// Await `work`, then mark `probe` done.
async fn finished<T>(
    tracker: &Tracker<'_>,
    probe: &'static str,
    work: impl Future<Output = T>,
) -> T {
    let out = work.await;
    tracker.done(probe);
    out
}

/// Run `work`, then mark `probe` done.
fn tracked<T>(tracker: &Tracker, probe: &'static str, work: impl FnOnce() -> T) -> T {
    let out = work();
    tracker.done(probe);
    out
}

/// Scan the network `args` describe. Devices last seen at the addresses in
/// `recheck` that don't answer get a second chance.
pub fn run(args: &Args, report: Report, recheck: &[Ipv4Addr]) -> Result<(Scan, Context), String> {
    let start = Instant::now();
    let tracker = Tracker::new(report);
    let ifc = iface::detect(args.interface.as_deref(), args.net)?;
    let targets = ifc.targets();
    // ARP and mDNS reverse lookups only reach this machine's own link.
    let link_targets: Vec<Ipv4Addr> = targets
        .iter()
        .copied()
        .filter(|ip| ifc.link.contains(*ip))
        .collect();
    // `--also`: other networks' addresses to ask for on this segment, where
    // a device left on one of them can still be heard.
    if cfg!(windows) && !args.also.is_empty() {
        return Err("--also isn't available on Windows, which only sends ARP for addresses on its own network".into());
    }
    let mut caveats = Vec::new();
    let mut arp_targets = link_targets.clone();
    for &range in &args.also {
        let before = arp_targets.len();
        arp_targets.extend(also_targets(range, ifc.link));
        if arp_targets.len() == before {
            caveats.push(format!(
                "--also {range} is part of this network ({}) already; --net {range} scans it",
                ifc.link
            ));
        }
    }
    let small = targets.len() <= ALL_AT_ONCE;
    let wait = Duration::from_millis(args.timeout);
    // Extra time for follow-up requests (UPnP descriptions, web banners).
    let grace = Duration::from_millis(800);

    probe::raise_fd_limit();
    let rt = Runtime::new().map_err(|e| format!("can't start runtime: {e}"))?;

    // On a large network, sweep ARP first when we can, so the port probe
    // and ping only need the hosts that answered. Probing every address
    // makes the kernel look each one up, and past about 1,000 Linux's ARP
    // table overflows and hosts go missing. It's much faster, too.
    let early_arp = (!small && !link_targets.is_empty()).then(|| {
        tracker.waiting(&["ARP"]);
        arp::sweep(&ifc, &arp_targets, wait)
    });
    let probe_targets: Vec<Ipv4Addr> = match &early_arp {
        Some(Ok(heard)) => targets
            .iter()
            .copied()
            .filter(|ip| !ifc.link.contains(*ip) || heard.contains_key(ip))
            .collect(),
        _ => targets.clone(),
    };
    tracker
        .checks
        .store(probe::liveness_checks(&probe_targets), Ordering::Relaxed);

    // Phase 1: every discovery method at once. The ARP sweep is blocking, so
    // it gets its own thread while the async probes share the runtime.
    let look_up_now = !args.no_dns && small;
    let mut phase_one = vec!["ARP", "ping", "ports", "Bonjour", "UPnP", "Kasa"];
    if look_up_now {
        phase_one.push("reverse DNS");
    }
    tracker.waiting(&phase_one);
    let phase_one_done = AtomicBool::new(false);
    let (arp_result, pinged, mut names, (open_ports, mdns, ssdp, kasa)) = thread::scope(|s| {
        let arp = s.spawn(|| {
            tracked(&tracker, "ARP", || {
                early_arp.unwrap_or_else(|| arp::sweep(&ifc, &arp_targets, wait))
            })
        });
        let pinged = s.spawn(|| tracked(&tracker, "ping", || ping::sweep(&probe_targets, wait)));
        // Reverse DNS is slow per lookup but cheap in parallel, so start it for
        // every address now instead of waiting to learn which ones are alive.
        let names = s.spawn(|| {
            if !look_up_now {
                return HashMap::new();
            }
            let mut ips = targets.clone();
            ips.push(ifc.ip);
            tracked(&tracker, "reverse DNS", || hostnames(ips, wait + grace))
        });
        // On a big network the port probe takes a while: show how far it is.
        if !small {
            s.spawn(|| {
                while !phase_one_done.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(250));
                    tracker.publish();
                }
            });
        }
        let reverse = if small { &link_targets[..] } else { &[] };
        let rest = rt.block_on(async {
            tokio::join!(
                finished(
                    &tracker,
                    "ports",
                    probe::scan(&probe_targets, wait, &tracker.checked)
                ),
                finished(&tracker, "Bonjour", mdns::discover(ifc.ip, reverse, wait)),
                finished(
                    &tracker,
                    "UPnP",
                    ssdp::discover(ifc.ip, ifc.net, &ifc.own_ips, wait, grace)
                ),
                finished(&tracker, "Kasa", kasa::discover(ifc.ip, ifc.net, wait)),
            )
        });
        let out = (
            arp.join().expect("arp thread"),
            pinged.join().expect("ping thread"),
            names.join().expect("dns thread"),
            rest,
        );
        phase_one_done.store(true, Ordering::Relaxed);
        out
    });
    let (heard, privileged) = match arp_result {
        Ok(heard) => (heard, true),
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::PermissionDenied | ErrorKind::Unsupported
            ) =>
        {
            (arp::Heard::new(), false)
        }
        Err(e) => return Err(format!("ARP sweep on {} failed: {e}", ifc.iface.name)),
    };
    // Rather that than quietly scanning less than was asked for.
    if !privileged && !args.also.is_empty() {
        return Err(
            "--also asks for addresses over ARP, which lsnet can't send without raw access: run with sudo".into(),
        );
    }
    let mut ctx = Context {
        arp_ran: privileged,
        rt,
        wait,
        grace,
        no_dns: args.no_dns,
        user_net: args.net.is_some(),
        heard,
        took: Duration::ZERO,
        caveats: Vec::new(),
        ifc,
    };
    let arp::Sorted {
        found: mut arp_found,
        conflicts,
        strays,
    } = arp::sort_out(
        ctx.heard.clone(),
        ctx.ifc.net,
        ctx.ifc.link,
        ctx.ifc.ip,
        ctx.ifc.mac,
    );
    // The kernel's cache fills in hosts the sweep missed (asleep through
    // both rounds) or couldn't send at all: the probes above made the kernel
    // resolve every address that answered them, and any that ignored them
    // but talked to us lately.
    for (ip, mac) in arp::read_cache(&ctx.ifc) {
        arp_found.entry(ip).or_insert(mac);
    }

    let mut hosts: BTreeMap<Ipv4Addr, Device> = BTreeMap::new();
    let ifc = &ctx.ifc;
    if ifc.net.contains(ifc.ip) {
        host(&mut hosts, ifc.ip).mac = ifc.mac.map(|m| m.to_string());
    }
    for (ip, mac) in arp_found {
        host(&mut hosts, ip).mac = Some(mac.to_string());
    }
    for &ip in &pinged {
        host(&mut hosts, ip);
    }
    // Hosts the TCP probe didn't reach get their ports checked in phase 2.
    let port_scanned: HashSet<Ipv4Addr> = open_ports.keys().copied().collect();
    for (ip, ports) in open_ports {
        host(&mut hosts, ip).open_ports = ports;
    }
    let mut mdns_strays = Vec::new();
    for (ip, info) in mdns {
        if ctx.on_lan(ip) {
            host(&mut hosts, ip).mdns = Some(info);
        } else if ctx.link_local_stray(ip, &info) {
            mdns_strays.push((ip, info));
        }
    }
    for (ip, info) in ssdp.into_iter().filter(|(ip, _)| ctx.on_lan(*ip)) {
        host(&mut hosts, ip).ssdp = Some(info);
    }
    for (ip, info) in kasa.into_iter().filter(|(ip, _)| ctx.on_lan(*ip)) {
        host(&mut hosts, ip).kasa = Some(info);
    }
    add_address_findings(&mut hosts, conflicts, &strays, mdns_strays);

    let mut devices: Vec<Device> = hosts.into_values().collect();
    for d in &mut devices {
        d.gateway = Some(d.ip) == ctx.ifc.gateway;
        d.this_device = ctx.ifc.own_ips.contains(&d.ip);
    }
    // Whether ARP (or the OS's cache) gave us MACs, before NetBIOS and
    // Bonjour names fill in some of the rest.
    let have_macs = devices.iter().any(|d| d.mac.is_some() && !d.this_device);

    // A first look, while phase 2 asks its questions.
    ctx.took = start.elapsed();
    let mut first_look = devices.clone();
    for d in &mut first_look {
        d.hostname = names.get(&d.ip).cloned();
        finish(d);
    }
    report(Progress::Partial(ctx.snapshot(first_look)));

    // Phase 2. Too many addresses to look them all up in advance, so look
    // up just the devices found. Alongside, addresses where devices were
    // seen before, and that didn't answer, get a second chance.
    let found: HashSet<Ipv4Addr> = devices.iter().map(|d| d.ip).collect();
    let targets: HashSet<Ipv4Addr> = targets.into_iter().collect();
    let dozing: Vec<Ipv4Addr> = recheck
        .iter()
        .copied()
        .filter(|ip| targets.contains(ip) && !found.contains(ip))
        .collect();
    let woke = thread::scope(|s| {
        let woke = s.spawn(|| second_chance(&ctx, &dozing));
        follow_up(
            &ctx,
            &mut devices,
            &port_scanned,
            &mut names,
            !args.no_dns && !small,
            &tracker,
        );
        woke.join().expect("second chance thread")
    });
    devices.extend(woke);
    devices.sort_by_key(|d| d.ip);

    let ifc = &ctx.ifc;
    if let Some(full) = ifc.narrowed_from {
        caveats.push(if full.prefix() >= iface::MAX_NET_PREFIX {
            format!("{full} is large; scanned only the local /24 (--net {full} scans all of it)")
        } else {
            format!("{full} is large; scanned only the local /24 (--net scans up to a /16 of it)")
        });
    }
    if cfg!(target_os = "linux") && !privileged && link_targets.len() > ALL_AT_ONCE {
        caveats.push(
            "without root, Linux tracks only about 1,000 addresses at once, so devices may be missing; run with sudo to see them all".into(),
        );
    }
    if !ifc.on_link() {
        caveats.push(format!(
            "{} isn't on {}'s network ({}), so devices were found by their open ports alone, without names from mDNS or UPnP",
            ifc.net, ifc.iface.name, ifc.link
        ));
    }
    // Where the OS shares its ARP cache (Linux), unprivileged scans already
    // see MACs and quiet devices, so the tip only matters when it doesn't.
    if !privileged && !have_macs && ifc.on_link() {
        caveats.push("tip: run with sudo to see MAC addresses and vendors, and find devices that ignore pings".into());
    }
    ctx.caveats = caveats;
    ctx.took = start.elapsed();
    report(Progress::Status(String::new()));
    Ok((ctx.snapshot(devices), ctx))
}

/// Phase 2, for `devices`: ports for hosts found some way other than the
/// port probe (`port_scanned`), then web banners for everything serving
/// HTTP. Alongside, every device is asked for its NetBIOS name, and those
/// that stayed quiet to the UPnP and Kasa broadcasts are asked directly,
/// and each is pinged, to time it. With `look_up`, their names are looked
/// up too. Then each is finished.
/// Strays are outside this network, so nothing here routes to them.
pub fn follow_up(
    ctx: &Context,
    devices: &mut [Device],
    port_scanned: &HashSet<Ipv4Addr>,
    names: &mut HashMap<Ipv4Addr, String>,
    look_up: bool,
    tracker: &Tracker,
) {
    let (ifc, grace) = (&ctx.ifc, ctx.grace);
    let asked: Vec<(Ipv4Addr, bool)> = devices
        .iter()
        .filter(|d| !d.this_device && !d.stray())
        .filter_map(|d| {
            let needs_ports = !port_scanned.contains(&d.ip);
            (needs_ports || d.open_ports.contains(&80)).then_some((d.ip, needs_ports))
        })
        .collect();
    let others = |missing: fn(&Device) -> bool| -> Vec<Ipv4Addr> {
        devices
            .iter()
            .filter(|d| !d.this_device && !d.stray() && missing(d))
            .map(|d| d.ip)
            .collect()
    };
    let netbios_targets = others(|_| true);
    let ssdp_targets = others(|d| d.ssdp.is_none());
    let kasa_targets = others(|d| d.kasa.is_none());
    let late: Vec<Ipv4Addr> = if look_up {
        devices
            .iter()
            .filter(|d| !d.stray())
            .map(|d| d.ip)
            .collect()
    } else {
        Vec::new()
    };
    let mut phase_two = vec!["ports", "web pages", "NetBIOS", "UPnP", "Kasa", "ping"];
    if look_up {
        phase_two.push("reverse DNS");
    }
    tracker.checks.store(0, Ordering::Relaxed);
    tracker.waiting(&phase_two);
    let wait = ctx.wait;
    let (followed, netbios, late_ssdp, late_kasa, late_names, pings) = thread::scope(|s| {
        let late_names = s.spawn(|| tracked(tracker, "reverse DNS", || hostnames(late, wait)));
        let pings = s.spawn(|| tracked(tracker, "ping", || ping::times(&netbios_targets, grace)));
        let (followed, netbios, ssdp, kasa) = ctx.rt.block_on(async {
            let followed = async {
                let mut set = JoinSet::new();
                for (ip, needs_ports) in asked {
                    set.spawn(async move {
                        let (ports, web_wait) = if needs_ports {
                            (
                                Some(probe::all_ports(ip, probe::AWAKE_WAIT).await),
                                grace - probe::AWAKE_WAIT,
                            )
                        } else {
                            (None, grace)
                        };
                        let web = ports.as_ref().is_none_or(|p| p.contains(&80));
                        let banner = if web {
                            http::banner(ip, 80, web_wait).await
                        } else {
                            None
                        };
                        (ip, ports, banner)
                    });
                }
                let mut out = HashMap::new();
                while let Some(joined) = set.join_next().await {
                    if let Ok((ip, ports, banner)) = joined {
                        out.insert(ip, (ports, banner));
                    }
                }
                tracker.done("ports");
                tracker.done("web pages");
                out
            };
            tokio::join!(
                followed,
                finished(
                    tracker,
                    "NetBIOS",
                    netbios::query(ifc.ip, &netbios_targets, grace)
                ),
                finished(
                    tracker,
                    "UPnP",
                    ssdp::query(ifc.ip, ifc.net, &ifc.own_ips, &ssdp_targets, grace)
                ),
                finished(
                    tracker,
                    "Kasa",
                    kasa::query(ifc.ip, ifc.net, &kasa_targets, grace)
                ),
            )
        });
        let late_names = late_names.join().expect("dns thread");
        let pings = pings.join().expect("ping thread");
        (followed, netbios, ssdp, kasa, late_names, pings)
    });
    names.extend(late_names);
    for d in devices {
        if let Some((ports, banner)) = followed.get(&d.ip) {
            if let Some(p) = ports {
                d.open_ports = p.clone();
            }
            d.http = banner.clone();
        }
        if d.ssdp.is_none() {
            d.ssdp = late_ssdp.get(&d.ip).cloned();
        }
        if d.kasa.is_none() {
            d.kasa = late_kasa.get(&d.ip).cloned();
        }
        if let Some(n) = netbios.get(&d.ip) {
            d.netbios = Some(n.clone());
        }
        // Without ARP, Windows and Samba hosts report their MAC over
        // NetBIOS, and some Bonjour names carry one.
        if d.mac.is_none() {
            d.mac = d
                .netbios
                .as_ref()
                .and_then(|n| n.mac.clone())
                .or_else(|| d.mdns.as_ref().and_then(|m| m.mac.clone()));
        }
        if let Some(name) = names.get(&d.ip) {
            d.hostname = Some(name.clone());
        }
        if let Some(took) = pings.get(&d.ip) {
            // To a hundredth of a millisecond: finer is noise.
            d.ping_ms = Some((took.as_secs_f64() * 100_000.0).round() / 100.0);
        }
        finish(d);
    }
}

/// Ask `ips` again: a ping, the liveness ports and a Kasa query, which
/// between them wake most Wi-Fi devices that dozed through the sweep (as
/// NetWho, lsnet's iOS sibling, found). Returns the devices that answered,
/// known by address and ports alone; history fills in what they are.
fn second_chance(ctx: &Context, ips: &[Ipv4Addr]) -> Vec<Device> {
    if ips.is_empty() {
        return Vec::new();
    }
    let (ifc, grace) = (&ctx.ifc, ctx.grace);
    let checked = AtomicUsize::new(0);
    let (pinged, (open, kasa)) = thread::scope(|s| {
        let pinged = s.spawn(|| ping::sweep(ips, grace));
        let rest = ctx.rt.block_on(async {
            tokio::join!(
                probe::scan(ips, grace, &checked),
                kasa::query(ifc.ip, ifc.net, ips, grace),
            )
        });
        (pinged.join().expect("ping thread"), rest)
    });
    let mut woke = BTreeMap::new();
    for ip in pinged {
        host(&mut woke, ip);
    }
    for (ip, ports) in open {
        host(&mut woke, ip).open_ports = ports;
    }
    for (ip, info) in kasa {
        host(&mut woke, ip).kasa = Some(info);
    }
    let mut woke: Vec<Device> = woke.into_values().collect();
    for d in &mut woke {
        d.gateway = Some(d.ip) == ifc.gateway;
        d.this_device = ifc.own_ips.contains(&d.ip);
        finish(d);
    }
    woke
}

/// Reverse lookups (which on macOS also ask mDNS for `.local` names), in
/// parallel, giving up on stragglers at the deadline.
pub fn hostnames(ips: Vec<Ipv4Addr>, deadline: Duration) -> HashMap<Ipv4Addr, String> {
    let (tx, rx) = mpsc::channel();
    let n = ips.len();
    for ip in ips {
        let tx = tx.clone();
        thread::spawn(move || {
            let name = dns_lookup::lookup_addr(&IpAddr::V4(ip))
                .ok()
                .filter(|n| n.parse::<IpAddr>().is_err())
                .map(|n| n.trim_end_matches('.').to_string());
            let _ = tx.send((ip, name));
        });
    }
    let end = Instant::now() + deadline;
    let mut out = HashMap::new();
    for _ in 0..n {
        match rx.recv_timeout(end.saturating_duration_since(Instant::now())) {
            Ok((ip, Some(name))) => {
                out.insert(ip, name);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    out
}

/// The addresses `--also range` adds to the ARP sweep: its hosts, but for
/// any on `link`, this interface's own network, which `--net` scans.
fn also_targets(range: ipnetwork::Ipv4Network, link: ipnetwork::Ipv4Network) -> Vec<Ipv4Addr> {
    let ends = range.prefix() < 31;
    range
        .iter()
        .filter(|&a| !(ends && (a == range.network() || a == range.broadcast())))
        .filter(|&a| !link.contains(a))
        .collect()
}

pub fn host(hosts: &mut BTreeMap<Ipv4Addr, Device>, ip: Ipv4Addr) -> &mut Device {
    hosts.entry(ip).or_insert_with(|| Device::new(ip))
}

/// Mark address conflicts, and place devices heard using addresses outside
/// this network: ARP `strays`, and Bonjour replies from self-assigned
/// addresses. A stray address whose MAC belongs to a device already found is
/// that device's second address; anything else is a device of its own.
/// Safe to call again with what's been heard since.
pub fn add_address_findings(
    hosts: &mut BTreeMap<Ipv4Addr, Device>,
    conflicts: HashMap<Ipv4Addr, Vec<MacAddr>>,
    strays: &[(Ipv4Addr, MacAddr)],
    mdns_strays: Vec<(Ipv4Addr, MdnsInfo)>,
) {
    fn flag(d: &mut Device, flag: arp::Flag) {
        if !d.flags.contains(&flag) {
            d.flags.push(flag);
        }
    }
    fn also_uses(d: &mut Device, ip: Ipv4Addr) {
        if !d.other_ips.contains(&ip) {
            d.other_ips.push(ip);
        }
    }
    for (ip, macs) in conflicts {
        let d = host(hosts, ip);
        flag(d, arp::Flag::AddressConflict);
        d.other_macs = macs.iter().skip(1).map(MacAddr::to_string).collect();
    }
    let known: HashMap<String, Ipv4Addr> = hosts
        .values()
        .filter(|d| !d.stray())
        .filter_map(|d| Some((d.mac.clone()?, d.ip)))
        .collect();
    for (mac, ips) in arp::strays_by_mac(strays) {
        let mac = mac.to_string();
        if let Some(ip) = known.get(&mac) {
            let d = host(hosts, *ip);
            for stray in ips {
                also_uses(d, stray);
            }
            continue;
        }
        let d = host(hosts, ips[0]);
        d.mac = Some(mac);
        flag(d, arp::stray_flag(ips[0]));
        for &stray in &ips[1..] {
            also_uses(d, stray);
        }
    }
    for (ip, info) in mdns_strays {
        // Already known, from ARP, as another device's second address.
        if hosts.values().any(|d| d.other_ips.contains(&ip)) {
            continue;
        }
        let other_ip_of = info.mac.as_ref().and_then(|m| known.get(m));
        if let Some(&known_ip) = other_ip_of.filter(|_| !hosts.contains_key(&ip)) {
            also_uses(host(hosts, known_ip), ip);
            continue;
        }
        let d = host(hosts, ip);
        flag(d, arp::Flag::LinkLocal);
        d.mdns = Some(info);
    }
}

/// One line per flagged device, for under the results.
pub fn flag_notes(devices: &[Device], link: ipnetwork::Ipv4Network) -> Vec<String> {
    let mut notes = Vec::new();
    for d in devices.iter().filter(|d| !d.missing()) {
        // "169.254.37.12 (PTZ-CAM-1.local)", or its MAC without a name.
        let who = match d.name.as_deref().or(d.mac.as_deref()) {
            Some(n) => format!("{} ({n})", d.ip),
            None => d.ip.to_string(),
        };
        for flag in &d.flags {
            notes.push(match flag {
                arp::Flag::LinkLocal => {
                    format!("{who} gave itself an address: it got no answer from DHCP")
                }
                arp::Flag::OffSubnet => format!(
                    "{who} is outside {link}: probably a static address from another network"
                ),
                arp::Flag::AddressConflict => {
                    let macs: Vec<&str> = d
                        .mac
                        .as_deref()
                        .into_iter()
                        .chain(d.other_macs.iter().map(String::as_str))
                        .collect();
                    format!(
                        "{} is claimed by {} devices ({}): an address conflict",
                        d.ip,
                        macs.len(),
                        macs.join(", ")
                    )
                }
            });
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    /// A network with one device, 192.168.1.77, whose MAC is known.
    fn one_device() -> BTreeMap<Ipv4Addr, Device> {
        let mut d = Device::new(ip("192.168.1.77"));
        d.mac = Some("00:1d:c1:0a:4f:20".into());
        BTreeMap::from([(d.ip, d)])
    }

    fn bonjour(heard_from: bool, mac: Option<&str>) -> MdnsInfo {
        MdnsInfo {
            hostname: Some("PTZ-CAM-1.local".into()),
            mac: mac.map(String::from),
            heard_from,
            ..Default::default()
        }
    }

    #[test]
    fn also_asks_only_for_addresses_off_this_network() {
        let link = "192.168.1.0/24".parse().unwrap();
        let hosts = also_targets("192.168.0.0/24".parse().unwrap(), link);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], ip("192.168.0.1"));
        // One address, and a range that takes in this network.
        assert_eq!(
            also_targets("10.0.0.10/32".parse().unwrap(), link),
            [ip("10.0.0.10")]
        );
        let wide = also_targets("192.168.0.0/23".parse().unwrap(), link);
        assert_eq!(wide.len(), 255);
        assert!(!wide.contains(&ip("192.168.1.20")));
        assert!(also_targets("192.168.1.128/25".parse().unwrap(), link).is_empty());
    }

    #[test]
    fn strays_become_devices_or_second_addresses() {
        let mut hosts = one_device();
        let strays = [
            // The known device's secondary port...
            (ip("169.254.9.9"), mac("00:1d:c1:0a:4f:20")),
            // ...and a box from another site.
            (ip("10.1.1.20"), mac("00:1d:c1:12:34:56")),
        ];
        add_address_findings(&mut hosts, HashMap::new(), &strays, Vec::new());
        assert_eq!(hosts[&ip("192.168.1.77")].other_ips, [ip("169.254.9.9")]);
        let stray = &hosts[&ip("10.1.1.20")];
        assert_eq!(stray.flags, [arp::Flag::OffSubnet]);
        assert_eq!(stray.mac.as_deref(), Some("00:1d:c1:12:34:56"));
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn bonjour_from_a_self_assigned_address_is_a_device() {
        let mut hosts = one_device();
        let found = vec![(ip("169.254.37.12"), bonjour(true, None))];
        add_address_findings(&mut hosts, HashMap::new(), &[], found);
        let cam = &hosts[&ip("169.254.37.12")];
        assert_eq!(cam.flags, [arp::Flag::LinkLocal]);
        assert!(cam.mdns.is_some());

        // Heard over ARP as well: one device, flagged once.
        let mut hosts = one_device();
        let strays = [(ip("169.254.37.12"), mac("00:01:4a:5e:21:9c"))];
        let found = vec![(ip("169.254.37.12"), bonjour(true, None))];
        add_address_findings(&mut hosts, HashMap::new(), &strays, found);
        let cam = &hosts[&ip("169.254.37.12")];
        assert_eq!(cam.flags, [arp::Flag::LinkLocal]);
        assert_eq!(cam.mac.as_deref(), Some("00:01:4a:5e:21:9c"));
        assert!(cam.mdns.is_some());

        // A known device's MAC in its service names: its second address.
        let mut hosts = one_device();
        let found = vec![(ip("169.254.9.9"), bonjour(true, Some("00:1d:c1:0a:4f:20")))];
        add_address_findings(&mut hosts, HashMap::new(), &[], found);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[&ip("192.168.1.77")].other_ips, [ip("169.254.9.9")]);
    }

    #[test]
    fn conflicts_list_the_other_macs() {
        let mut hosts = one_device();
        let conflicts = HashMap::from([(
            ip("192.168.1.77"),
            vec![mac("00:1d:c1:0a:4f:20"), mac("24:0a:c4:88:31:5b")],
        )]);
        add_address_findings(&mut hosts, conflicts, &[], Vec::new());
        let d = &hosts[&ip("192.168.1.77")];
        assert_eq!(d.flags, [arp::Flag::AddressConflict]);
        assert_eq!(d.other_macs, ["24:0a:c4:88:31:5b"]);
    }
}
