mod arp;
mod classify;
mod http;
mod iface;
mod mdns;
mod oui;
mod ping;
mod platform;
mod probe;
mod services;
mod ssdp;
mod tui;

use clap::Parser;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table, presets};
use mdns::MdnsInfo;
use owo_colors::{OwoColorize, Stream::Stderr};
use pnet_base::MacAddr;
use serde::Serialize;
use ssdp::SsdpInfo;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{ErrorKind, IsTerminal};
use std::net::{IpAddr, Ipv4Addr};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

/// See what's on your local network.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Network interface to scan (default: the one your internet traffic uses)
    #[arg(short, long, short_alias = 'I')]
    interface: Option<String>,

    /// Print a table instead of opening the device browser (the default
    /// when output isn't a terminal)
    #[arg(short, long)]
    list: bool,

    /// Print results as JSON
    #[arg(long)]
    json: bool,

    /// List the services running on the network (web UIs, SSH, databases,
    /// media servers) instead of devices
    #[arg(short, long)]
    services: bool,

    /// Show hostnames, open ports and advertised services
    #[arg(short, long)]
    verbose: bool,

    /// How long to wait for devices to answer, in milliseconds
    #[arg(short, long, default_value_t = 1200)]
    timeout: u64,

    /// Skip hostname lookups
    #[arg(long)]
    no_dns: bool,
}

#[derive(Serialize)]
pub struct Device {
    ip: Ipv4Addr,
    name: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    model: Option<String>,
    vendor: Option<&'static str>,
    mac: Option<String>,
    randomized_mac: bool,
    hostname: Option<String>,
    open_ports: Vec<u16>,
    gateway: bool,
    this_device: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mdns: Option<MdnsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssdp: Option<SsdpInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http: Option<http::Banner>,
}

impl Device {
    fn new(ip: Ipv4Addr) -> Self {
        Device {
            ip,
            name: None,
            kind: None,
            model: None,
            vendor: None,
            mac: None,
            randomized_mac: false,
            hostname: None,
            open_ports: Vec::new(),
            gateway: false,
            this_device: false,
            mdns: None,
            ssdp: None,
            http: None,
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!(
                "{} {e}",
                "error:".if_supports_color(Stderr, |t| t.red().bold().to_string())
            );
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    // Browse in a terminal; print for pipes, files and anything asking for text.
    // Windows terminals don't set TERM, so there only TERM=dumb says no.
    let interactive = !(args.list || args.json || args.verbose)
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::env::var("TERM").map_or(cfg!(windows), |t| t != "dumb");
    // After browsing, the table is still printed so the results stay in the scrollback.
    let (scan, show_services) = if interactive {
        tui::run(|| scan(args), args.services)?
    } else if std::io::stderr().is_terminal() {
        let dim = |s: String| {
            s.if_supports_color(Stderr, |t| t.dimmed().to_string())
                .to_string()
        };
        let result = animate(
            || scan(args),
            |ping| eprint!("\r{}", dim(format!("{ping}  Scanning the network…"))),
        );
        eprint!("\r\x1b[2K");
        (result?, args.services)
    } else {
        (scan(args)?, args.services)
    };
    let json = if !args.json {
        None
    } else if show_services {
        let rows: Vec<_> = services::list(&scan.devices)
            .iter()
            .map(|s| services::Json::new(s, &scan.devices))
            .collect();
        Some(serde_json::to_string_pretty(&rows))
    } else {
        Some(serde_json::to_string_pretty(&scan.devices))
    };
    if let Some(json) = json {
        println!("{}", json.unwrap());
        return Ok(());
    }

    if show_services {
        print_services(&scan.devices);
    } else {
        print_table(&scan.devices, args.verbose);
    }
    let dim = |s: &str| {
        s.if_supports_color(Stderr, |t| t.dimmed().to_string())
            .to_string()
    };
    eprintln!("\n{}", dim(&scan.summary));
    for note in &scan.notes {
        eprintln!("{}", dim(note));
    }
    Ok(())
}

/// A sonar ping: ripples leave the dot and fade out.
const PING: &[&str] = &[
    "●      ",
    "● )    ",
    "● ) )  ",
    "● ) ) )",
    "●   ) )",
    "●     )",
    "●      ",
];

/// Run `work` on another thread, calling `frame` with each frame of the
/// ping animation until it's done.
fn animate<T: Send>(work: impl FnOnce() -> T + Send, mut frame: impl FnMut(&str)) -> T {
    let (tx, rx) = mpsc::channel();
    thread::scope(|s| {
        s.spawn(move || tx.send(work()));
        for ping in PING.iter().cycle() {
            frame(ping);
            if let Ok(done) = rx.recv_timeout(Duration::from_millis(120)) {
                return done;
            }
        }
        unreachable!("the animation cycles forever")
    })
}

/// The results of one pass over the network.
pub struct Scan {
    devices: Vec<Device>,
    /// e.g. "27 devices on 192.168.1.0/24 (en0) in 2.1s"
    summary: String,
    /// Caveats about what the scan couldn't see.
    notes: Vec<String>,
}

fn scan(args: &Args) -> Result<Scan, String> {
    let start = Instant::now();
    let ifc = iface::detect(args.interface.as_deref())?;
    let targets = ifc.targets();
    let wait = Duration::from_millis(args.timeout);
    // Extra time for follow-up requests (UPnP descriptions, web banners).
    let grace = Duration::from_millis(800);

    probe::raise_fd_limit();
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("can't start runtime: {e}"))?;

    // Phase 1: every discovery method at once. The ARP sweep is blocking, so
    // it gets its own thread while the async probes share the runtime.
    let (arp_result, pinged, names, (open_ports, mdns, ssdp)) = thread::scope(|s| {
        let arp = s.spawn(|| arp::sweep(&ifc, &targets, wait));
        let pinged = s.spawn(|| ping::sweep(&targets, wait));
        // Reverse DNS is slow per lookup but cheap in parallel, so start it for
        // every address now instead of waiting to learn which ones are alive.
        let names = s.spawn(|| {
            if args.no_dns {
                return HashMap::new();
            }
            let mut ips = targets.clone();
            ips.push(ifc.ip);
            hostnames(ips, wait + grace)
        });
        let rest = rt.block_on(async {
            tokio::join!(
                probe::scan(&targets, wait),
                mdns::discover(ifc.ip, &targets, wait),
                ssdp::discover(ifc.ip, ifc.net, wait, grace),
            )
        });
        (
            arp.join().expect("arp thread"),
            pinged.join().expect("ping thread"),
            names.join().expect("dns thread"),
            rest,
        )
    });
    let (arp_found, privileged) = match arp_result {
        Ok(found) => (found, true),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => (arp::read_cache(&ifc), false),
        Err(e) => return Err(format!("ARP sweep on {} failed: {e}", ifc.iface.name)),
    };

    let mut hosts: BTreeMap<Ipv4Addr, Device> = BTreeMap::new();
    let on_lan = |ip: &Ipv4Addr| ifc.net.contains(*ip) || ifc.own_ips.contains(ip);
    fn host(hosts: &mut BTreeMap<Ipv4Addr, Device>, ip: Ipv4Addr) -> &mut Device {
        hosts.entry(ip).or_insert_with(|| Device::new(ip))
    }
    host(&mut hosts, ifc.ip).mac = ifc.mac.map(|m| m.to_string());
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
    for (ip, info) in mdns.into_iter().filter(|(ip, _)| on_lan(ip)) {
        host(&mut hosts, ip).mdns = Some(info);
    }
    for (ip, info) in ssdp.into_iter().filter(|(ip, _)| on_lan(ip)) {
        host(&mut hosts, ip).ssdp = Some(info);
    }

    let mut devices: Vec<Device> = hosts.into_values().collect();
    for d in &mut devices {
        let mac: Option<MacAddr> = d.mac.as_deref().and_then(|m| m.parse().ok());
        d.vendor = mac.and_then(oui::vendor);
        d.randomized_mac = mac.is_some_and(oui::is_randomized);
        d.gateway = Some(d.ip) == ifc.gateway;
        d.this_device = ifc.own_ips.contains(&d.ip);
    }

    // Phase 2: ports for hosts found only some other way, then web banners
    // for everything serving HTTP.
    let follow_up: Vec<(Ipv4Addr, bool)> = devices
        .iter()
        .filter(|d| !d.this_device)
        .filter_map(|d| {
            let needs_ports = !port_scanned.contains(&d.ip);
            (needs_ports || d.open_ports.contains(&80)).then_some((d.ip, needs_ports))
        })
        .collect();
    let followed = rt.block_on(async {
        let mut set = JoinSet::new();
        for (ip, needs_ports) in follow_up {
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
        out
    });
    for d in &mut devices {
        if let Some((ports, banner)) = followed.get(&d.ip) {
            if let Some(p) = ports {
                d.open_ports = p.clone();
            }
            d.http = banner.clone();
        }
        d.hostname = names.get(&d.ip).cloned();
        classify::classify(d);
    }

    let summary = format!(
        "{} devices on {} ({}) in {:.1}s",
        devices.len(),
        ifc.net,
        ifc.iface.name,
        start.elapsed().as_secs_f64()
    );
    let mut notes = Vec::new();
    if let Some(full) = ifc.narrowed_from {
        notes.push(format!("{full} is large; scanned only the local /24"));
    }
    // Where the OS shares its ARP cache (Linux), unprivileged scans already
    // see MACs and quiet devices, so the tip only matters when it doesn't.
    let have_macs = devices.iter().any(|d| d.mac.is_some() && !d.this_device);
    if !privileged && !have_macs {
        notes.push("tip: run with sudo to see MAC addresses and vendors, and find devices that ignore pings".into());
    }
    Ok(Scan {
        devices,
        summary,
        notes,
    })
}

/// Reverse lookups (which on macOS also ask mDNS for `.local` names), in
/// parallel, giving up on stragglers at the deadline.
fn hostnames(ips: Vec<Ipv4Addr>, deadline: Duration) -> HashMap<Ipv4Addr, String> {
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

/// Infrastructure services that say nothing about what a device is.
const NOISY_SERVICES: &[&str] = &[
    "sleep-proxy",
    "trel",
    "srpl-tls",
    "meshcop",
    "ieee1588",
    "nrd",
    "infra-analytics",
    "dnssd-server",
    "device-info",
    "companion-link",
];

/// One table cell before rendering. Empty cells are drawn as a dimmed row
/// of periods spanning the column, a leader line that carries the eye from
/// the IP across to the data on the right.
struct Field {
    text: Option<String>,
    color: Option<Color>,
    bold: bool,
}

impl Field {
    fn new(text: Option<&str>) -> Self {
        let text = text.map(printable).filter(|t| !t.is_empty());
        Field {
            text,
            color: None,
            bold: false,
        }
    }

    fn fg(mut self, color: Color) -> Self {
        self.color = Some(color);
        self
    }

    fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    fn width(&self) -> usize {
        self.text.as_deref().map_or(0, |t| t.chars().count())
    }

    fn render(self, column_width: usize) -> Cell {
        match self.text {
            Some(t) => {
                let mut cell = Cell::new(t);
                if let Some(c) = self.color {
                    cell = cell.fg(c);
                }
                if self.bold {
                    cell = cell.add_attribute(Attribute::Bold);
                }
                cell
            }
            None => Cell::new(".".repeat(column_width)).fg(Color::DarkGrey),
        }
    }
}

fn print_table(devices: &[Device], verbose: bool) {
    // Without raw access there are no MACs at all; don't waste two columns on blanks.
    let show_mac = devices.iter().any(|d| d.mac.is_some() && !d.this_device);

    // With vendors known, unnamed devices show their vendor in the NAME column.
    let name_header = if show_mac { "NAME/VENDOR" } else { "NAME" };
    let mut header = vec!["IP", name_header, "TYPE", "MODEL"];
    if show_mac {
        header.extend(["VENDOR", "MAC"]);
    }
    if verbose {
        header.extend(["HOSTNAME", "PORTS", "SERVICES"]);
    }

    print_fields(
        &header,
        devices.iter().map(|d| row(d, show_mac, verbose)).collect(),
    );
}

fn print_services(devices: &[Device]) {
    let rows = services::list(devices)
        .iter()
        .map(|s| {
            let d = &devices[s.device];
            let host = match (&d.name, &d.hostname, d.vendor) {
                (Some(n), _, _) => Field::new(Some(n)).bold(),
                (None, Some(h), _) => Field::new(Some(h)),
                (None, None, v) => Field::new(v),
            };
            vec![
                Field::new(Some(&s.address())).fg(Color::Green),
                Field::new(s.name),
                host,
            ]
        })
        .collect();
    print_fields(&["ADDRESS", "SERVICE", "HOST"], rows);
}

fn print_fields(header: &[&str], rows: Vec<Vec<Field>>) {
    let widths: Vec<usize> = (0..header.len())
        .map(|i| {
            rows.iter()
                .map(|r| r[i].width())
                .chain([header[i].len()])
                .max()
                .unwrap_or(0)
        })
        .collect();

    let mut table = Table::new();
    table
        .load_style(presets::NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(
            header
                .iter()
                .map(|h| Cell::new(h).add_attribute(Attribute::Bold)),
        );
    for r in rows {
        table.add_row(r.into_iter().zip(&widths).map(|(f, &w)| f.render(w)));
    }
    println!("{table}");
}

/// `s` with terminal control characters removed. Names and models come from
/// the network, and an ESC or BEL in one could otherwise drive the terminal
/// (set the title, write the clipboard, hide rows). Bidi overrides go too, so a
/// name can't visually reorder the rest of its row.
fn printable(s: &str) -> String {
    s.chars()
        .filter(|&c| {
            !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

/// The TYPE column, marking this machine and the gateway.
fn kind_label(d: &Device) -> Option<String> {
    match (d.kind.as_deref(), d.this_device, d.gateway) {
        (k, true, _) => Some(format!("{} (this device)", k.unwrap_or("Computer"))),
        (Some("Router") | None, _, true) => Some("Router (gateway)".into()),
        (Some(k), _, true) => Some(format!("{k} (gateway)")),
        (k, _, _) => k.map(String::from),
    }
}

fn row(d: &Device, show_mac: bool, verbose: bool) -> Vec<Field> {
    let kind = Field::new(kind_label(d).as_deref());
    let kind = match (d.this_device, d.gateway) {
        (true, _) => kind.fg(Color::Cyan),
        (_, true) => kind.fg(Color::Yellow),
        _ => kind,
    };
    let mut row = vec![
        Field::new(Some(&d.ip.to_string())).fg(Color::Green),
        // Real names are bold; a backfilled vendor isn't, so the two stay distinguishable.
        match (d.name.as_deref(), d.vendor) {
            (Some(n), _) => Field::new(Some(n)).bold(),
            (None, Some(v)) if show_mac => Field::new(Some(v)),
            (None, _) => Field::new(None),
        },
        kind,
        Field::new(d.model.as_deref()),
    ];
    if show_mac {
        row.push(match (d.vendor, d.randomized_mac) {
            (Some(v), _) => Field::new(Some(v)),
            (None, true) => Field::new(Some("(private MAC)")).fg(Color::DarkGrey),
            (None, false) => Field::new(None),
        });
        row.push(Field::new(d.mac.as_deref()).fg(Color::DarkGrey));
    }
    if verbose {
        let ports = d
            .open_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let services = d
            .mdns
            .as_ref()
            .map(|m| {
                m.services
                    .keys()
                    .filter(|s| !NOISY_SERVICES.contains(&s.as_str()))
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        row.push(Field::new(d.hostname.as_deref()));
        row.push(Field::new(Some(&ports)).fg(Color::DarkGrey));
        row.push(Field::new(Some(&services)).fg(Color::DarkGrey));
    }
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(name: Option<&str>, vendor: Option<&'static str>) -> Device {
        let mut d = Device::new(Ipv4Addr::new(192, 168, 1, 50));
        d.name = name.map(String::from);
        d.vendor = vendor;
        d.mac = vendor.map(|_| "b8:27:eb:01:02:03".into());
        d
    }

    #[test]
    fn strips_terminal_controls() {
        assert_eq!(
            printable("TV\x1b]52;c;aGk=\x07\u{9b}2J\u{202e}"),
            "TV]52;c;aGk=2J"
        );
        assert_eq!(printable("Living Room"), "Living Room");
        assert_eq!(Field::new(Some("\x1b\x07")).text, None);
    }

    #[test]
    fn vendor_backfills_missing_name() {
        let r = row(&device(None, Some("Raspberry Pi")), true, false);
        assert_eq!(r[1].text.as_deref(), Some("Raspberry Pi"));
        assert!(!r[1].bold);

        let r = row(
            &device(Some("octopi.local"), Some("Raspberry Pi")),
            true,
            false,
        );
        assert_eq!(r[1].text.as_deref(), Some("octopi.local"));
        assert!(r[1].bold);
    }

    #[test]
    fn no_backfill_without_mac_columns() {
        let r = row(&device(None, Some("Raspberry Pi")), false, false);
        assert_eq!(r[1].text, None);
    }
}
