mod arp;
mod classify;
mod http;
mod iface;
mod mdns;
mod oui;
mod platform;
mod probe;
mod ssdp;

use clap::Parser;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table, presets};
use mdns::MdnsInfo;
use owo_colors::{OwoColorize, Stream::Stderr};
use pnet::util::MacAddr;
use serde::Serialize;
use ssdp::SsdpInfo;
use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
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
    #[arg(short, long)]
    interface: Option<String>,

    /// Print results as JSON
    #[arg(long)]
    json: bool,

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
            eprintln!("{} {e}", "error:".if_supports_color(Stderr, |t| t.red().bold().to_string()));
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
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
    let (arp_result, names, (open_ports, mdns, ssdp)) = thread::scope(|s| {
        let arp = s.spawn(|| arp::sweep(&ifc, &targets, wait));
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
                mdns::discover(ifc.ip, wait),
                ssdp::discover(ifc.ip, ifc.net, wait, grace),
            )
        });
        (arp.join().expect("arp thread"), names.join().expect("dns thread"), rest)
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

    // Phase 2: web banners, now that we know which hosts serve HTTP.
    let web: Vec<Ipv4Addr> = devices
        .iter()
        .filter(|d| d.open_ports.contains(&80) && !d.this_device)
        .map(|d| d.ip)
        .collect();
    let banners = rt.block_on(async {
        let mut set = JoinSet::new();
        for ip in web {
            set.spawn(async move { (ip, http::banner(ip, 80, grace).await) });
        }
        let mut out = HashMap::new();
        while let Some(joined) = set.join_next().await {
            if let Ok((ip, Some(b))) = joined {
                out.insert(ip, b);
            }
        }
        out
    });
    for d in &mut devices {
        d.hostname = names.get(&d.ip).cloned();
        d.http = banners.get(&d.ip).cloned();
        classify::classify(d);
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&devices).unwrap());
        return Ok(());
    }

    print_table(&devices, args.verbose);
    let dim = |s: String| s.if_supports_color(Stderr, |t| t.dimmed().to_string()).to_string();
    eprintln!(
        "\n{}",
        dim(format!(
            "{} devices on {} ({}) in {:.1}s",
            devices.len(),
            ifc.net,
            ifc.iface.name,
            start.elapsed().as_secs_f64()
        ))
    );
    if let Some(full) = ifc.narrowed_from {
        eprintln!("{}", dim(format!("{full} is large; scanned only the local /24")));
    }
    // Where the OS shares its ARP cache (Linux), unprivileged scans already
    // see MACs and quiet devices, so the tip only matters when it doesn't.
    let have_macs = devices.iter().any(|d| d.mac.is_some() && !d.this_device);
    if !privileged && !have_macs {
        eprintln!(
            "{}",
            dim("tip: run with sudo to see MAC addresses and vendors, and find devices with no open ports".into())
        );
    }
    Ok(())
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
    "sleep-proxy", "trel", "srpl-tls", "meshcop", "ieee1588", "nrd", "infra-analytics",
    "dnssd-server", "device-info", "companion-link",
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
        let text = text.filter(|t| !t.is_empty()).map(String::from);
        Field { text, color: None, bold: false }
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

    let rows: Vec<Vec<Field>> = devices.iter().map(|d| row(d, show_mac, verbose)).collect();
    let widths: Vec<usize> = (0..header.len())
        .map(|i| rows.iter().map(|r| r[i].width()).chain([header[i].len()]).max().unwrap_or(0))
        .collect();

    let mut table = Table::new();
    table
        .load_style(presets::NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(header.into_iter().map(|h| Cell::new(h).add_attribute(Attribute::Bold)));
    for r in rows {
        table.add_row(r.into_iter().zip(&widths).map(|(f, &w)| f.render(w)));
    }
    println!("{table}");
}

fn row(d: &Device, show_mac: bool, verbose: bool) -> Vec<Field> {
    let kind = match (d.kind.as_deref(), d.this_device, d.gateway) {
        (k, true, _) => Field::new(Some(&format!("{} (this device)", k.unwrap_or("Computer")))).fg(Color::Cyan),
        (Some("Router") | None, _, true) => Field::new(Some("Router (gateway)")).fg(Color::Yellow),
        (Some(k), _, true) => Field::new(Some(&format!("{k} (gateway)"))).fg(Color::Yellow),
        (Some(k), _, _) => Field::new(Some(k)),
        (None, _, _) => Field::new(None),
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
        let ports = d.open_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
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
    fn vendor_backfills_missing_name() {
        let r = row(&device(None, Some("Raspberry Pi")), true, false);
        assert_eq!(r[1].text.as_deref(), Some("Raspberry Pi"));
        assert!(!r[1].bold);

        let r = row(&device(Some("octopi.local"), Some("Raspberry Pi")), true, false);
        assert_eq!(r[1].text.as_deref(), Some("octopi.local"));
        assert!(r[1].bold);
    }

    #[test]
    fn no_backfill_without_mac_columns() {
        let r = row(&device(None, Some("Raspberry Pi")), false, false);
        assert_eq!(r[1].text, None);
    }
}
