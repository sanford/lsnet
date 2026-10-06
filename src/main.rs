mod arp;
mod classify;
mod demo;
mod history;
mod http;
mod iface;
mod kasa;
mod live;
mod mdns;
mod netbios;
mod oui;
mod ping;
mod platform;
mod probe;
#[cfg(test)]
mod readme;
mod scan;
mod services;
mod ssdp;
mod tui;

use clap::Parser;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table, presets};
use kasa::KasaInfo;
use mdns::MdnsInfo;
use netbios::NetbiosInfo;
use owo_colors::{OwoColorize, Stream::Stderr};
use pnet_base::MacAddr;
use serde::{Deserialize, Serialize};
use ssdp::SsdpInfo;
use std::io::{IsTerminal, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

/// See what's on your local network.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Network interface to scan (default: the one your internet traffic uses)
    #[arg(short, long, short_alias = 'I')]
    interface: Option<String>,

    /// Network to scan, in CIDR form (default: the interface's own, or the
    /// /24 around this machine if that's larger than a /22). At most a /16
    #[arg(short, long, value_name = "CIDR", value_parser = iface::parse_net)]
    net: Option<ipnetwork::Ipv4Network>,

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

    /// Show a made-up network instead of scanning (no packets are sent)
    #[arg(long, conflicts_with_all = ["interface", "net", "timeout", "no_dns"])]
    demo: bool,

    /// Don't compare with earlier scans of this network, or remember this one
    #[arg(long)]
    no_history: bool,

    /// Show what lsnet remembers about the networks it has scanned, and
    /// delete it
    #[arg(long, exclusive = true)]
    forget: bool,
}

/// Everything known about one address. `--json` prints it, and reading that
/// back (the demo, the fixture tests) recomputes every derived field from
/// the evidence rather than trusting it: see `finish`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    ip: Ipv4Addr,
    #[serde(skip_deserializing)]
    name: Option<String>,
    /// Where the name came from, e.g. "AirPlay" or "reverse DNS".
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    name_from: Option<String>,
    #[serde(rename = "type", skip_deserializing)]
    kind: Option<String>,
    #[serde(skip_deserializing)]
    model: Option<String>,
    /// The evidence that decided the type, e.g. "port 8006 open (Proxmox)".
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    type_from: Option<String>,
    #[serde(skip_deserializing)]
    vendor: Option<&'static str>,
    mac: Option<String>,
    #[serde(skip_deserializing)]
    randomized_mac: bool,
    hostname: Option<String>,
    #[serde(default)]
    open_ports: Vec<u16>,
    #[serde(default)]
    gateway: bool,
    #[serde(default)]
    this_device: bool,
    /// What's wrong with its address, if anything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    flags: Vec<arp::Flag>,
    /// For an address conflict, the other MACs that answered for its address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    other_macs: Vec<String>,
    /// Addresses outside this network that it also uses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    other_ips: Vec<Ipv4Addr>,
    /// When this network's history first saw it, in Unix seconds.
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    first_seen: Option<u64>,
    /// When it was last seen, for a device that didn't answer this time.
    #[serde(skip)]
    last_seen: Option<u64>,
    /// How it differs from the last scan of this network.
    #[serde(skip_deserializing, skip_serializing_if = "Vec::is_empty")]
    changes: Vec<history::Change>,
    /// Heard from after the scan, while the browser was listening.
    #[serde(skip)]
    heard_later: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mdns: Option<MdnsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssdp: Option<SsdpInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kasa: Option<KasaInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    netbios: Option<NetbiosInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http: Option<http::Banner>,
}

impl Device {
    fn new(ip: Ipv4Addr) -> Self {
        Device {
            ip,
            name: None,
            name_from: None,
            kind: None,
            model: None,
            type_from: None,
            vendor: None,
            mac: None,
            randomized_mac: false,
            hostname: None,
            open_ports: Vec::new(),
            gateway: false,
            this_device: false,
            flags: Vec::new(),
            other_macs: Vec::new(),
            other_ips: Vec::new(),
            first_seen: None,
            last_seen: None,
            changes: Vec::new(),
            heard_later: false,
            mdns: None,
            ssdp: None,
            kasa: None,
            netbios: None,
            http: None,
        }
    }

    /// Here last time, but not this time: a row from history, not the scan.
    fn missing(&self) -> bool {
        self.changes.contains(&history::Change::Missing)
    }

    /// Whether its address is outside this network, so it can't be probed.
    fn stray(&self) -> bool {
        self.flags
            .iter()
            .any(|f| matches!(f, arp::Flag::LinkLocal | arp::Flag::OffSubnet))
    }
}

/// The last step for every device, scanned or read back from JSON: what its
/// MAC says, then what it is.
fn finish(d: &mut Device) {
    let mac: Option<MacAddr> = d.mac.as_deref().and_then(|m| m.parse().ok());
    d.vendor = mac.and_then(oui::vendor);
    d.randomized_mac = mac.is_some_and(oui::is_randomized);
    classify::classify(d);
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
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

fn run(args: Args) -> Result<(), String> {
    if args.forget {
        return forget();
    }
    // Browse in a terminal; print for pipes, files and anything asking for text.
    // Windows terminals don't set TERM, so there only TERM=dumb says no.
    let interactive = !(args.list || args.json || args.verbose)
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::env::var("TERM").map_or(cfg!(windows), |t| t != "dumb");
    let store = (!args.demo && !args.no_history)
        .then(history::path)
        .flatten();
    let memory = Arc::new(memory(&args, store.as_deref()));
    let args = Arc::new(args);
    // After browsing, the table is still printed so the results stay in the scrollback.
    let (scan, show_services) = if interactive {
        tui::run(
            || live::start(args.clone(), memory.clone(), true),
            args.services,
        )?
    } else if std::io::stderr().is_terminal() {
        let dim = |s: String| {
            s.if_supports_color(Stderr, |t| t.dimmed().to_string())
                .to_string()
        };
        let status = Mutex::new(String::new());
        let result = animate(
            || live::once(&args, &memory, &|s| *status.lock().unwrap() = s),
            |ping| {
                let status = status.lock().unwrap();
                let status = if status.is_empty() {
                    String::new()
                } else {
                    format!(" {status}")
                };
                eprint!(
                    "\r\x1b[2K{}",
                    dim(format!("{ping}  Scanning the network…{status}"))
                )
            },
        );
        eprint!("\r\x1b[2K");
        (result?, args.services)
    } else {
        (live::once(&args, &memory, &|_| {})?, args.services)
    };
    if let Some(path) = &store {
        remember(path, &scan);
    }

    let present: Vec<Device> = scan.present().cloned().collect();
    let json = if !args.json {
        None
    } else if show_services {
        let rows: Vec<_> = services::list(&present)
            .iter()
            .map(|s| services::Json::new(s, &present))
            .collect();
        Some(serde_json::to_string_pretty(&rows))
    } else {
        Some(serde_json::to_string_pretty(&present))
    };
    if let Some(json) = json {
        println!("{}", json.unwrap());
        return Ok(());
    }

    if show_services {
        println!("{}", services_table(&present, Style::Terminal));
    } else {
        println!("{}", device_table(&present, args.verbose, Style::Terminal));
    }
    let dim = |s: &str| {
        s.if_supports_color(Stderr, |t| t.dimmed().to_string())
            .to_string()
    };
    eprintln!();
    for line in footer(&scan) {
        eprintln!("{}", dim(&line));
    }
    Ok(())
}

/// What's printed under a table: the summary, what changed since last
/// time, caveats, and the devices that didn't answer this time.
fn footer(scan: &Scan) -> Vec<String> {
    let mut lines = vec![scan.summary.clone()];
    lines.extend(scan.changes.clone());
    lines.extend(scan.notes.iter().cloned());
    for d in scan.devices.iter().filter(|d| d.missing()) {
        let who = match &d.name {
            Some(name) => format!("{name} ({})", d.ip),
            None => d.ip.to_string(),
        };
        let when = d.last_seen.map_or(String::new(), |t| {
            format!(", last seen {}", history::ago(scan.clock, t))
        });
        lines.push(format!("missing: {who} didn't answer this time{when}"));
    }
    lines
}

/// The history to compare scans with.
fn memory(args: &Args, store: Option<&Path>) -> live::Memory {
    if args.demo {
        return demo::memory();
    }
    match store {
        Some(path) => {
            let loaded = history::load(path);
            live::Memory {
                history: Some(loaded.history),
                now: None,
                warning: loaded.warning,
            }
        }
        None => live::Memory {
            history: None,
            now: None,
            warning: None,
        },
    }
}

/// Add this scan to the history at `path`, if it's of a network to remember.
fn remember(path: &Path, scan: &Scan) {
    let Some(id) = &scan.network else {
        return;
    };
    // Read it again, so a scan that finished meanwhile isn't lost.
    let loaded = history::load(path);
    if !loaded.writable {
        return;
    }
    let mut history = loaded.history;
    history.record(&scan.devices, id, history::now());
    if let Err(e) = history::save(path, &history) {
        eprintln!("lsnet: couldn't save history to {}: {e}", path.display());
    }
}

/// `--forget`: say what's remembered, and delete it if the user agrees.
fn forget() -> Result<(), String> {
    let path = history::path().ok_or("can't tell where history would be kept")?;
    if !path.exists() {
        println!("Nothing to forget: {} doesn't exist.", path.display());
        return Ok(());
    }
    let loaded = history::load(&path);
    println!("{} remembers:", path.display());
    for line in loaded.history.describe() {
        println!("  {line}");
    }
    if !std::io::stdin().is_terminal() {
        return Err("run --forget in a terminal, to confirm".into());
    }
    print!("Forget all of it? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        std::fs::remove_file(&path).map_err(|e| format!("can't delete {}: {e}", path.display()))?;
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir(dir); // only if it's empty
        }
        println!("Forgotten.");
    } else {
        println!("Kept.");
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
#[derive(Clone)]
pub struct Scan {
    /// Sorted by address, then any devices that were here last time but
    /// didn't answer (see `Device::missing`).
    devices: Vec<Device>,
    /// e.g. "27 devices on 192.168.1.0/24 (en0) in 2.1s"
    summary: String,
    /// Caveats about what the scan couldn't see, and devices whose address
    /// is wrong.
    notes: Vec<String>,
    /// What changed since the last scan of this network, from its history.
    changes: Option<String>,
    /// Which network this was, when it's one to remember.
    network: Option<history::NetworkId>,
    /// Whether ARP ran, so devices that answer nothing else could be found.
    arp_ran: bool,
    /// The time "2 hours ago" is counted from, in Unix seconds: when history
    /// marked it (the demo's is fixed).
    clock: u64,
}

impl Scan {
    fn empty() -> Scan {
        Scan {
            devices: Vec::new(),
            summary: String::new(),
            notes: Vec::new(),
            changes: None,
            network: None,
            arp_ran: false,
            clock: 0,
        }
    }

    /// The devices that answered, without the ones history says are missing.
    fn present(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter().filter(|d| !d.missing())
    }
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
    /// Whether an empty cell gets the dotted leader.
    leader: bool,
}

impl Field {
    fn new(text: Option<&str>) -> Self {
        let text = text.map(printable).filter(|t| !t.is_empty());
        Field {
            text,
            color: None,
            bold: false,
            leader: true,
        }
    }

    /// Empty is blank: for a last column, where a leader leads nowhere.
    fn without_leader(mut self) -> Self {
        self.leader = false;
        self
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
            None if self.leader => Cell::new(".".repeat(column_width)).fg(Color::DarkGrey),
            None => Cell::new(""),
        }
    }
}

/// Whether a table may use the terminal's colors and width.
#[derive(Clone, Copy)]
enum Style {
    /// Colored and fitted to the terminal, when there is one.
    Terminal,
    /// Plain text at full width, as the README shows it.
    #[cfg(test)]
    Plain,
}

fn device_table(devices: &[Device], verbose: bool, style: Style) -> String {
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
    // What changed since the last scan, when anything did.
    let show_changes = devices.iter().any(|d| !d.changes.is_empty());
    if show_changes {
        header.push("CHANGE");
    }

    fields_table(
        &header,
        devices
            .iter()
            .map(|d| {
                let mut row = row(d, show_mac, verbose);
                if show_changes {
                    let change = Field::new(change_words(d).as_deref()).fg(Color::Yellow);
                    row.push(change.without_leader());
                }
                row
            })
            .collect(),
        style,
    )
}

/// "new", "moved from 192.168.1.61", "renamed from dns".
fn change_words(d: &Device) -> Option<String> {
    let words: Vec<String> = d
        .changes
        .iter()
        .map(|c| match c {
            history::Change::New => "new".into(),
            history::Change::Moved { from } => format!("moved from {from}"),
            history::Change::Renamed { from } => format!("renamed from {from}"),
            history::Change::Missing => "missing".into(),
        })
        .collect();
    (!words.is_empty()).then(|| words.join(", "))
}

fn services_table(devices: &[Device], style: Style) -> String {
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
    fields_table(&["ADDRESS", "SERVICE", "HOST"], rows, style)
}

fn fields_table(header: &[&str], rows: Vec<Vec<Field>>, style: Style) -> String {
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
    match style {
        Style::Terminal => {}
        #[cfg(test)]
        Style::Plain => {
            table.force_no_tty();
        }
    }
    table.to_string()
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

/// The most serious thing wrong with a device's address, if anything.
fn ip_alarm(d: &Device) -> Option<arp::Flag> {
    if d.flags.contains(&arp::Flag::AddressConflict) {
        Some(arp::Flag::AddressConflict)
    } else {
        d.flags.first().copied()
    }
}

/// Green, unless something is wrong with the address: red for a conflict,
/// yellow for an address from somewhere else.
fn ip_color(d: &Device) -> Color {
    match ip_alarm(d) {
        Some(arp::Flag::AddressConflict) => Color::Red,
        Some(_) => Color::Yellow,
        None => Color::Green,
    }
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
        Field::new(Some(&d.ip.to_string())).fg(ip_color(d)),
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
