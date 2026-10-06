//! Remembering each network between runs, to say what changed since last
//! time: new devices, ones that moved to another address or were renamed,
//! and ones that didn't answer.
//!
//! One JSON file per user (see `path`), readable by them alone:
//!
//! ```json
//! {
//!   "version": 1,
//!   "networks": [
//!     {
//!       "subnet": "192.168.1.0/24",
//!       "gateway_ip": "192.168.1.1",
//!       "router": {
//!         "udn": "uuid:4d696e69-444c-164e-9d41-001ec92f0001",
//!         "mac": "00:09:5b:7a:10:01"
//!       },
//!       "first_seen": 1759700000,
//!       "last_seen": 1759786400,
//!       "scans": 12,
//!       "devices": [
//!         {
//!           "ip": "192.168.1.52",
//!           "mac": "f0:18:98:3c:62:8d",
//!           "local": "Living-Room.local",
//!           "name": "Living Room",
//!           "name_from": "AirPlay",
//!           "type": "TV / streamer",
//!           "model": "Apple TV 4K (3rd gen)",
//!           "first_seen": 1759700000,
//!           "last_seen": 1759786400
//!         }
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! Times are Unix seconds. Nothing else is kept: no open ports, Bonjour
//! records or anything `--json` has beyond this.
//!
//! Telling networks apart is the hard part, since most home routers hand
//! out the same addresses (192.168.1.0/24, router at .1). As in NetWho,
//! lsnet's iOS sibling, a network is recognized, most reliable first, by:
//!
//! 1. its router: its permanent UPnP identifier (UDN), its MAC, or its
//!    `.local` name, whichever this scan and earlier ones learned. The UDN
//!    needs no root, so even macOS without `sudo` tells networks apart;
//! 2. failing that, its subnet and router address, and its devices: two
//!    homes share almost no devices known by a MAC or a `.local` name.
//!
//! A device is recognized by its MAC, then its `.local` name, then its
//! address, unless something says it's another device: a different
//! manufacturer-assigned MAC, or a different `.local` name.

use crate::{Device, oui};
use pnet_base::MacAddr;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The file format this version writes. A file from a newer lsnet is read
/// as far as it can be, and never overwritten.
pub const VERSION: u32 = 1;

/// Devices not seen for this long are forgotten, and networks not scanned
/// for this long, so the cafés and hotels of past trips don't pile up.
const KEEP_FOR: u64 = 365 * DAY;
const DAY: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct History {
    pub version: u32,
    #[serde(default)]
    pub networks: Vec<Network>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Network {
    pub subnet: String,
    #[serde(default)]
    pub gateway_ip: Option<Ipv4Addr>,
    /// What identifies the router, by kind: "udn", "mac", "host".
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub router: BTreeMap<String, String>,
    pub first_seen: u64,
    /// When it was last scanned. Devices seen then were "here last time".
    pub last_seen: u64,
    #[serde(default)]
    pub scans: u32,
    #[serde(default)]
    pub devices: Vec<Remembered>,
}

/// A device as it was last seen.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Remembered {
    pub ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// The `.local` name it answers to over Bonjour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_from: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    /// Found only by ARP: no open ports, no announcements. Without ARP (no
    /// root), such a device can't be found at all, so its absence means
    /// nothing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub quiet: bool,
}

/// What a scan says about which network it was.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetworkId {
    pub subnet: String,
    pub gateway_ip: Option<Ipv4Addr>,
    /// What identifies the router, by kind; see `Network::router`.
    pub router: BTreeMap<String, String>,
}

impl NetworkId {
    /// The network `devices` are on: `subnet`, and what the router (the
    /// gateway among them) says about itself.
    pub fn new(subnet: String, gateway_ip: Option<Ipv4Addr>, devices: &[Device]) -> NetworkId {
        let mut router = BTreeMap::new();
        if let Some(gw) = devices.iter().find(|d| d.gateway) {
            if let Some(udn) = gw.ssdp.as_ref().and_then(|s| s.udn.as_ref()) {
                router.insert("udn".into(), udn.to_ascii_lowercase());
            }
            if let Some(mac) = gw.mac.as_ref().filter(|_| !gw.randomized_mac) {
                router.insert("mac".into(), mac.clone());
            }
            if let Some(host) = local_name(gw) {
                router.insert("host".into(), host);
            }
        }
        NetworkId {
            subnet,
            gateway_ip,
            router,
        }
    }
}

/// How a device differs from last time.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "change", rename_all = "kebab-case")]
pub enum Change {
    /// Not seen on this network before.
    New,
    /// The same device at another address.
    Moved { from: Ipv4Addr },
    /// The same source names it differently.
    Renamed { from: String },
    /// Here last time, not this time. Only in the browser.
    Missing,
}

impl History {
    /// The remembered network the scan of `id` that found `devices` was on.
    fn find(&self, id: &NetworkId, devices: &[Device]) -> Option<usize> {
        let disagrees = |n: &Network| {
            id.router
                .iter()
                .any(|(kind, value)| n.router.get(kind).is_some_and(|v| v != value))
        };
        let latest = |a: &usize, b: &usize| {
            self.networks[*a]
                .last_seen
                .cmp(&self.networks[*b].last_seen)
        };
        // 1. The router, wherever it is: a network can change its subnet.
        let by_router = (0..self.networks.len())
            .filter(|&i| {
                let n = &self.networks[i];
                id.router
                    .iter()
                    .any(|(kind, value)| n.router.get(kind) == Some(value))
                    && !disagrees(n)
            })
            .max_by(latest);
        if by_router.is_some() {
            return by_router;
        }
        // 2. The same subnet and router address, nothing about the router
        // saying otherwise, and the devices. Each known by the same MAC or
        // `.local` name counts for a network; each address now answering as
        // a different device counts against it. A network is ruled out only
        // when those outnumber the matches (an address can be handed out
        // again), so a scan that learned no names rules nothing out.
        (0..self.networks.len())
            .filter(|&i| {
                let n = &self.networks[i];
                n.subnet == id.subnet && n.gateway_ip == id.gateway_ip && !disagrees(n)
            })
            .map(|i| {
                let known = &self.networks[i].devices;
                let mut score = 0i32;
                for d in devices.iter().filter(|d| !d.missing()) {
                    if known.iter().any(|r| same_identity(r, d)) {
                        score += 1;
                    } else if known.iter().any(|r| r.ip == d.ip && !r.could_be(d)) {
                        score -= 1;
                    }
                }
                (i, score)
            })
            .filter(|&(_, score)| score >= 0)
            .max_by(|a, b| a.1.cmp(&b.1).then(latest(&a.0, &b.0)))
            .map(|(i, _)| i)
    }

    /// Mark what changed since the last scan of this network: each device's
    /// `changes` and `first_seen`, plus a row for each device that was here
    /// last time and didn't answer. A device that answered but said nothing
    /// about itself gets its name and type from memory. Returns a line for
    /// under the results. Safe to call again on the same devices.
    ///
    /// `arp_ran` says whether this scan could find devices that only answer
    /// ARP; without it, their absence says nothing.
    pub fn annotate(
        &self,
        devices: &mut Vec<Device>,
        id: &NetworkId,
        now: u64,
        arp_ran: bool,
    ) -> Option<String> {
        devices.retain(|d| !d.missing());
        for d in devices.iter_mut() {
            d.changes.clear();
            d.first_seen = None;
            d.last_seen = None;
            if d.name_from.as_deref() == Some(REMEMBERED) {
                (d.name, d.name_from) = (None, None);
            }
            if d.type_from.as_deref() == Some(REMEMBERED) {
                (d.kind, d.model, d.type_from) = (None, None, None);
            }
        }
        let Some(net) = self.find(id, devices).map(|i| &self.networks[i]) else {
            return Some(
                "first scan of this network: next time, lsnet will point out what changed".into(),
            );
        };
        let mut used = vec![false; net.devices.len()];
        for d in devices.iter_mut() {
            let Some(i) = find_device(&net.devices, d, &used) else {
                d.changes.push(Change::New);
                d.first_seen = Some(now);
                continue;
            };
            used[i] = true;
            let was = &net.devices[i];
            d.first_seen = Some(was.first_seen);
            if was.ip != d.ip {
                d.changes.push(Change::Moved { from: was.ip });
            }
            if let (Some(before), Some(after)) = (&was.name, &d.name)
                && before != after
                && was.name_from == d.name_from
            {
                d.changes.push(Change::Renamed {
                    from: before.clone(),
                });
            }
            // A device that woke for a second chance, or whose announcements
            // went unheard, is still what it was.
            if d.name.is_none() && was.name.is_some() {
                (d.name, d.name_from) = (was.name.clone(), Some(REMEMBERED.into()));
            }
            if d.kind.is_none() && was.kind.is_some() {
                (d.kind, d.model) = (was.kind.clone(), was.model.clone());
                d.type_from = Some(REMEMBERED.into());
            }
        }
        let missing: Vec<Device> = net
            .devices
            .iter()
            .zip(&used)
            .filter(|(was, used)| {
                !**used && was.last_seen >= net.last_seen && (arp_ran || !was.quiet)
            })
            .map(|(was, _)| was.to_device())
            .collect();
        devices.extend(missing);

        let count =
            |f: fn(&Change) -> bool| devices.iter().filter(|d| d.changes.iter().any(f)).count();
        let counts = [
            (count(|c| *c == Change::New), "new"),
            (count(|c| matches!(c, Change::Moved { .. })), "moved"),
            (count(|c| matches!(c, Change::Renamed { .. })), "renamed"),
            (count(|c| *c == Change::Missing), "missing"),
        ];
        let parts: Vec<String> = counts
            .iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, what)| format!("{n} {what}"))
            .collect();
        let when = ago(now, net.last_seen);
        Some(if parts.is_empty() {
            format!("nothing changed since the last scan, {when}")
        } else {
            format!("since the last scan, {when}: {}", parts.join(", "))
        })
    }

    /// Remember this scan of the network `id`.
    pub fn record(&mut self, devices: &[Device], id: &NetworkId, now: u64) {
        self.version = VERSION;
        let i = match self.find(id, devices) {
            Some(i) => i,
            None => {
                self.networks.push(Network {
                    subnet: id.subnet.clone(),
                    gateway_ip: id.gateway_ip,
                    router: BTreeMap::new(),
                    first_seen: now,
                    last_seen: now,
                    scans: 0,
                    devices: Vec::new(),
                });
                self.networks.len() - 1
            }
        };
        let net = &mut self.networks[i];
        net.subnet = id.subnet.clone();
        net.gateway_ip = id.gateway_ip.or(net.gateway_ip);
        net.router.extend(id.router.clone());
        net.last_seen = now;
        net.scans += 1;
        let mut used = vec![false; net.devices.len()];
        for d in devices.iter().filter(|d| !d.missing()) {
            // What memory filled in isn't news to remember.
            let name = (d.name_from.as_deref() != Some(REMEMBERED)).then_some(d);
            let kind = (d.type_from.as_deref() != Some(REMEMBERED)).then_some(d);
            match find_device(&net.devices, d, &used) {
                Some(i) => {
                    used[i] = true;
                    let was = &mut net.devices[i];
                    was.ip = d.ip;
                    was.mac = d.mac.clone().or(was.mac.take());
                    was.local = local_name(d).or(was.local.take());
                    if let Some(d) = name.filter(|d| d.name.is_some()) {
                        (was.name, was.name_from) = (d.name.clone(), d.name_from.clone());
                    }
                    if let Some(d) = kind.filter(|d| d.kind.is_some()) {
                        (was.kind, was.model) = (d.kind.clone(), d.model.clone());
                    }
                    was.last_seen = now;
                    was.quiet = quiet(d);
                }
                None => {
                    net.devices.push(Remembered {
                        ip: d.ip,
                        mac: d.mac.clone(),
                        local: local_name(d),
                        name: name.and_then(|d| d.name.clone()),
                        name_from: name.and_then(|d| d.name_from.clone()),
                        kind: kind.and_then(|d| d.kind.clone()),
                        model: kind.and_then(|d| d.model.clone()),
                        first_seen: now,
                        last_seen: now,
                        quiet: quiet(d),
                    });
                    used.push(true);
                }
            }
        }
        net.devices
            .retain(|d| now.saturating_sub(d.last_seen) < KEEP_FOR);
        net.devices.sort_by_key(|d| d.ip);
        self.networks
            .retain(|n| now.saturating_sub(n.last_seen) < KEEP_FOR);
    }

    /// Every address a device was last seen at, on any network: worth a
    /// second chance before a device there is called missing.
    pub fn addresses(&self) -> Vec<Ipv4Addr> {
        let mut out: Vec<Ipv4Addr> = self
            .networks
            .iter()
            .flat_map(|n| n.devices.iter().filter(|d| d.last_seen >= n.last_seen))
            .map(|d| d.ip)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// One line per network, for `--forget`.
    pub fn describe(&self) -> Vec<String> {
        self.networks
            .iter()
            .map(|n| {
                let gateway = match (&n.gateway_ip, n.router.get("mac")) {
                    (Some(ip), Some(mac)) => format!(", gateway {ip} ({mac})"),
                    (Some(ip), None) => format!(", gateway {ip}"),
                    _ => String::new(),
                };
                format!(
                    "{}{gateway}: {} devices, {} scans, last on {}",
                    n.subnet,
                    n.devices.len(),
                    n.scans,
                    date(n.last_seen)
                )
            })
            .collect()
    }
}

/// Where a name or type came from when memory supplied it.
const REMEMBERED: &str = "remembered from an earlier scan";

impl Remembered {
    /// A row for a device that didn't answer this time.
    fn to_device(&self) -> Device {
        let mut d = Device::new(self.ip);
        d.mac = self.mac.clone();
        let mac = d.mac.as_deref().and_then(|m| m.parse().ok());
        d.vendor = mac.and_then(oui::vendor);
        d.randomized_mac = mac.is_some_and(oui::is_randomized);
        d.name = self.name.clone();
        d.name_from = self.name_from.clone();
        d.kind = self.kind.clone();
        d.model = self.model.clone();
        d.first_seen = Some(self.first_seen);
        d.last_seen = Some(self.last_seen);
        d.changes = vec![Change::Missing];
        d
    }

    /// Nothing about `d` says it's a different device: no other
    /// manufacturer-assigned MAC (private ones change), no other `.local` name.
    fn could_be(&self, d: &Device) -> bool {
        let fixed = |mac: &str| mac.parse::<MacAddr>().is_ok_and(|m| !oui::is_randomized(m));
        let other_mac = match (&self.mac, &d.mac) {
            (Some(a), Some(b)) => a != b && fixed(a) && fixed(b),
            _ => false,
        };
        let other_name = match (&self.local, local_name(d)) {
            (Some(a), Some(b)) => !a.eq_ignore_ascii_case(&b),
            _ => false,
        };
        !other_mac && !other_name
    }
}

/// The `.local` name a device answers to over Bonjour.
fn local_name(d: &Device) -> Option<String> {
    [
        d.mdns.as_ref().and_then(|m| m.hostname.as_ref()),
        d.hostname.as_ref(),
    ]
    .into_iter()
    .flatten()
    .find(|h| h.to_ascii_lowercase().ends_with(".local"))
    .cloned()
}

/// Whether `r` is `d` by something that names a device rather than an
/// address: its MAC or its `.local` name.
fn same_identity(r: &Remembered, d: &Device) -> bool {
    let mac = d.mac.is_some() && r.mac == d.mac;
    let local = match (&r.local, local_name(d)) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(&b),
        _ => false,
    };
    (mac || local) && r.could_be(d)
}

/// Which remembered device `d` is: one with its MAC or `.local` name, or
/// else the one last at its address, unless something says it's another
/// device. Each remembered device stands for one device at most.
fn find_device(known: &[Remembered], d: &Device, used: &[bool]) -> Option<usize> {
    let free = |i: &usize| !used.get(*i).copied().unwrap_or(false);
    if let Some(i) = (0..known.len())
        .filter(free)
        .find(|&i| same_identity(&known[i], d))
    {
        return Some(i);
    }
    (0..known.len())
        .filter(free)
        .filter(|&i| known[i].ip == d.ip && known[i].could_be(d))
        .max_by_key(|&i| known[i].last_seen)
}

/// Found by ARP alone: nothing that finds devices without root (open
/// ports, Bonjour, UPnP, Kasa) found it. What follow-up questions learn
/// (a NetBIOS name, a web page) doesn't count: they're only asked of devices
/// already found, so a firewalled PC that ARP found and NetBIOS named can't
/// be found without ARP.
fn quiet(d: &Device) -> bool {
    d.open_ports.is_empty() && d.mdns.is_none() && d.ssdp.is_none() && d.kasa.is_none()
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// "2 hours ago", or a date for anything over a week.
pub fn ago(now: u64, then: u64) -> String {
    let secs = now.saturating_sub(then);
    let plural = |n: u64, unit: &str| {
        if n == 1 {
            format!("1 {unit} ago")
        } else {
            format!("{n} {unit}s ago")
        }
    };
    match secs {
        0..60 => "just now".into(),
        60..3600 => plural(secs / 60, "minute"),
        3600..DAY => plural(secs / 3600, "hour"),
        _ if secs < 7 * DAY => plural(secs / DAY, "day"),
        _ => format!("on {}", date(then)),
    }
}

/// "6 Oct 2026", in UTC.
pub fn date(secs: u64) -> String {
    // Howard Hinnant's days-to-civil algorithm.
    let z = (secs / DAY) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!("{day} {} {year}", MONTHS[(month - 1) as usize])
}

/// Where the history lives: `LSNET_HISTORY` if set, else the per-user data
/// directory. Under `sudo`, the invoking user's, not root's.
pub fn path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("LSNET_HISTORY") {
        return Some(PathBuf::from(p));
    }
    let dir = if cfg!(windows) {
        PathBuf::from(std::env::var_os("LOCALAPPDATA")?)
    } else if cfg!(target_os = "macos") {
        home()?.join("Library/Application Support")
    } else {
        match std::env::var_os("XDG_DATA_HOME").filter(|_| !sudo()) {
            Some(d) if !d.is_empty() => PathBuf::from(d),
            _ => home()?.join(".local/share"),
        }
    };
    Some(dir.join("lsnet").join("history.json"))
}

/// Whether we're root by way of `sudo`, with a user to write files for.
fn sudo() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 && std::env::var_os("SUDO_UID").is_some() }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn home() -> Option<PathBuf> {
    #[cfg(unix)]
    if sudo()
        && let Some(user) = std::env::var_os("SUDO_USER")
    {
        use std::ffi::{CStr, CString};
        use std::os::unix::ffi::OsStrExt;
        let name = CString::new(user.as_bytes()).ok()?;
        // SAFETY: getpwnam returns null or a pointer to a static record,
        // which we copy out of before anything else can call it.
        let dir = unsafe {
            let pw = libc::getpwnam(name.as_ptr());
            if pw.is_null() || (*pw).pw_dir.is_null() {
                return None;
            }
            CStr::from_ptr((*pw).pw_dir).to_owned()
        };
        return Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.as_bytes())));
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// The history at `path`, and whether it may be written back.
pub struct Loaded {
    pub history: History,
    pub writable: bool,
    /// Something to tell the user, such as a damaged file set aside.
    pub warning: Option<String>,
}

pub fn load(path: &Path) -> Loaded {
    let fresh = |warning| Loaded {
        history: History {
            version: VERSION,
            networks: Vec::new(),
        },
        writable: true,
        warning,
    };
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return fresh(None),
        Err(e) => {
            return Loaded {
                writable: false,
                ..fresh(Some(format!("can't read {}: {e}", path.display())))
            };
        }
    };
    match serde_json::from_str::<History>(&text) {
        Ok(h) if h.version > VERSION => Loaded {
            history: h,
            writable: false,
            warning: Some(format!(
                "{} was written by a newer lsnet, so this one won't change it",
                path.display()
            )),
        },
        Ok(h) => Loaded {
            history: h,
            writable: true,
            warning: None,
        },
        Err(e) => {
            // Keep it for whoever wants to look, and start again.
            let aside = path.with_extension(format!("json.damaged-{}", now()));
            let moved = fs::rename(path, &aside).is_ok();
            fresh(Some(if moved {
                format!(
                    "{} was damaged ({e}); moved it to {} and started a new one",
                    path.display(),
                    aside.display()
                )
            } else {
                format!("{} is damaged ({e})", path.display())
            }))
        }
    }
}

/// Write `history` to `path` all at once: to a temporary file beside it,
/// then renamed over it, so a crash or a second lsnet can't leave half a
/// file. Readable by the user only.
pub fn save(path: &Path, history: &History) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("no directory"))?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)?;
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let result = (|| {
        let mut file = options.open(&tmp)?;
        let json = serde_json::to_string_pretty(history).map_err(io::Error::other)?;
        file.write_all(json.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        give_to_user(dir);
        give_to_user(&tmp);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Under `sudo`, hand what we wrote to the user who ran it, so their next
/// run without `sudo` can update it.
fn give_to_user(_path: &Path) {
    #[cfg(unix)]
    if sudo() {
        let id = |var| std::env::var(var).ok()?.parse::<u32>().ok();
        if let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) {
            let _ = std::os::unix::fs::chown(_path, Some(uid), Some(gid));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3600;
    const THEN: u64 = 1_790_000_000;
    const NOW: u64 = THEN + 2 * HOUR;

    fn id() -> NetworkId {
        router(&[("mac", "00:09:5b:7a:10:01")])
    }

    /// A network on 192.168.1.0/24 whose router says `ids` about itself.
    fn router(ids: &[(&str, &str)]) -> NetworkId {
        NetworkId {
            subnet: "192.168.1.0/24".into(),
            gateway_ip: Some("192.168.1.1".parse().unwrap()),
            router: ids
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// A device known only by its `.local` name, as on macOS without root.
    fn local(ip: u8, host: &str) -> Device {
        let mut d = device(ip, None, None);
        d.mdns = Some(crate::mdns::MdnsInfo {
            hostname: Some(host.into()),
            ..Default::default()
        });
        d
    }

    fn device(ip: u8, mac: Option<&str>, name: Option<&str>) -> Device {
        let mut d = Device::new(Ipv4Addr::new(192, 168, 1, ip));
        d.mac = mac.map(String::from);
        d.name = name.map(String::from);
        d.name_from = name.map(|_| "AirPlay".to_string());
        d.open_ports = vec![80];
        d
    }

    /// History after one scan of `devices` at THEN.
    fn after(devices: &[Device]) -> History {
        let mut h = History::default();
        h.record(devices, &id(), THEN);
        h
    }

    fn changes(devices: &[Device], ip: u8) -> Vec<Change> {
        let ip = Ipv4Addr::new(192, 168, 1, ip);
        devices.iter().find(|d| d.ip == ip).unwrap().changes.clone()
    }

    #[test]
    fn the_first_scan_marks_nothing() {
        let mut now = vec![device(2, Some("02:00:00:00:00:02"), None)];
        let note = History::default().annotate(&mut now, &id(), NOW, true);
        assert!(now[0].changes.is_empty());
        assert!(note.unwrap().starts_with("first scan"));
    }

    #[test]
    fn new_moved_renamed_and_missing() {
        let h = after(&[
            device(60, Some("6c:4a:85:0b:77:21"), Some("Kitchen")),
            device(52, Some("f0:18:98:3c:62:8d"), Some("Living Room")),
            device(95, Some("0c:95:05:11:22:33"), Some("Garage")),
        ]);
        let mut now = vec![
            device(61, Some("6c:4a:85:0b:77:21"), Some("Kitchen")),
            device(52, Some("f0:18:98:3c:62:8d"), Some("Lounge")),
            device(90, Some("fc:65:de:2b:80:17"), None),
        ];
        let note = h.annotate(&mut now, &id(), NOW, true).unwrap();
        assert_eq!(
            changes(&now, 61),
            [Change::Moved {
                from: Ipv4Addr::new(192, 168, 1, 60)
            }]
        );
        assert_eq!(
            changes(&now, 52),
            [Change::Renamed {
                from: "Living Room".into()
            }]
        );
        assert_eq!(changes(&now, 90), [Change::New]);
        assert_eq!(changes(&now, 95), [Change::Missing]);
        let garage = now.iter().find(|d| d.missing()).unwrap();
        assert_eq!(garage.name.as_deref(), Some("Garage"));
        assert_eq!(garage.vendor, Some("The Chamberlain"));
        assert_eq!(
            note,
            "since the last scan, 2 hours ago: 1 new, 1 moved, 1 renamed, 1 missing"
        );
        assert_eq!(now[0].first_seen, Some(THEN));
        assert_eq!(now[2].first_seen, Some(NOW));

        // Again: the same marks, and the missing row only once.
        h.annotate(&mut now, &id(), NOW, true);
        assert_eq!(now.iter().filter(|d| d.missing()).count(), 1);
        assert_eq!(changes(&now, 90), [Change::New]);
    }

    #[test]
    fn names_from_different_sources_are_not_renames() {
        let h = after(&[device(14, Some("00:11:32:66:d8:71"), Some("OFFICE-NAS"))]);
        let mut d = device(14, Some("00:11:32:66:d8:71"), Some("office-nas.local"));
        d.name_from = Some(".local name".into());
        let mut now = vec![d];
        h.annotate(&mut now, &id(), NOW, true);
        assert!(now[0].changes.is_empty());
    }

    #[test]
    fn without_macs_devices_are_known_by_address() {
        let h = after(&[device(14, Some("00:11:32:66:d8:71"), None)]);
        let mut now = vec![device(14, None, None)];
        h.annotate(&mut now, &id(), NOW, true);
        assert!(now[0].changes.is_empty());
        // A different MAC at the same address is a different device...
        let mut now = vec![device(14, Some("00:11:32:00:00:99"), None)];
        h.annotate(&mut now, &id(), NOW, true);
        assert_eq!(changes(&now, 14), [Change::New]);
        // ...unless it's a private one, which phones change now and then.
        let h = after(&[device(112, Some("3a:91:5c:e2:07:1b"), None)]);
        let mut now = vec![device(112, Some("3a:91:5c:00:00:01"), None)];
        h.annotate(&mut now, &id(), NOW, true);
        assert!(now[0].changes.is_empty());
    }

    #[test]
    fn local_names_follow_devices_without_macs() {
        let h = after(&[local(60, "Kitchen.local"), local(130, "octopi.local")]);
        let mut now = vec![local(61, "kitchen.local"), local(130, "pihole.local")];
        h.annotate(&mut now, &router(&[]), NOW, true);
        assert_eq!(
            changes(&now, 61),
            [Change::Moved {
                from: Ipv4Addr::new(192, 168, 1, 60)
            }]
        );
        // Another name at the same address is another device.
        assert_eq!(changes(&now, 130), [Change::New]);
    }

    #[test]
    fn memory_fills_in_a_device_that_says_nothing() {
        let mut was = device(201, None, Some("Kitchen"));
        was.kind = Some("Speaker".into());
        let h = after(&[was]);
        // It woke for a second chance: an address and nothing else.
        let mut now = vec![device(201, None, None)];
        h.annotate(&mut now, &id(), NOW, true);
        assert_eq!(now[0].name.as_deref(), Some("Kitchen"));
        assert_eq!(now[0].kind.as_deref(), Some("Speaker"));
        assert_eq!(now[0].type_from.as_deref(), Some(REMEMBERED));
        assert!(now[0].changes.is_empty());
        // Marking again starts from what the scan said, not what memory did.
        h.annotate(&mut now, &id(), NOW, true);
        assert_eq!(now[0].name_from.as_deref(), Some(REMEMBERED));
        // And memory doesn't remember its own guesses as news.
        let mut h = h;
        h.record(&now, &id(), NOW);
        assert_eq!(
            h.networks[0].devices[0].name_from.as_deref(),
            Some("AirPlay")
        );
    }

    #[test]
    fn remembers_where_to_look_again() {
        let mut h = after(&[device(2, None, None), device(3, None, None)]);
        h.record(&[device(2, None, None)], &id(), NOW);
        // .3 wasn't seen last time, so it's no longer worth a second chance.
        assert_eq!(h.addresses(), [Ipv4Addr::new(192, 168, 1, 2)]);
    }

    #[test]
    fn quiet_devices_are_not_missing_without_arp() {
        let mut silent = device(203, Some("3c:6a:9d:12:ab:7f"), None);
        silent.open_ports.clear();
        let h = after(&[silent]);
        let mut now = Vec::new();
        h.annotate(&mut now, &id(), NOW, false);
        assert!(now.is_empty());
        h.annotate(&mut now, &id(), NOW, true);
        assert_eq!(now.len(), 1);
    }

    #[test]
    fn what_follow_ups_learn_does_not_make_a_device_findable() {
        // A firewalled PC: found by ARP, then named over NetBIOS.
        let mut pc = device(224, Some("00:02:b3:4d:6e:01"), None);
        pc.open_ports.clear();
        pc.netbios = Some(crate::netbios::NetbiosInfo {
            name: "ZILLI-9800X3D".into(),
            mac: None,
        });
        let h = after(&[pc]);
        assert!(h.networks[0].devices[0].quiet);
        let mut now = Vec::new();
        h.annotate(&mut now, &id(), NOW, false);
        assert!(now.is_empty(), "not missing when scanned without root");
    }

    #[test]
    fn only_devices_from_the_last_scan_go_missing() {
        let mut h = after(&[
            device(2, Some("02:00:00:00:00:02"), None),
            device(3, Some("02:00:00:00:00:03"), None),
        ]);
        // Scanned again without .3; a scan later still, it's not "missing" again.
        h.record(&[device(2, Some("02:00:00:00:00:02"), None)], &id(), NOW);
        let mut now = vec![device(2, Some("02:00:00:00:00:02"), None)];
        h.annotate(&mut now, &id(), NOW + HOUR, true);
        assert!(!now.iter().any(Device::missing));
        assert_eq!(h.networks[0].devices.len(), 2);
        assert_eq!(h.networks[0].scans, 2);
    }

    #[test]
    fn networks_are_told_apart_by_their_router() {
        let h = after(&[device(2, Some("00:11:32:00:00:02"), None)]);
        let mut now = vec![device(2, Some("00:11:32:00:00:02"), None)];
        let elsewhere = router(&[("mac", "00:09:5b:aa:aa:aa")]);
        let note = h.annotate(&mut now, &elsewhere, NOW, true).unwrap();
        assert!(note.starts_with("first scan"));
        // Without the router's MAC (no root on macOS), the devices decide.
        h.annotate(&mut now, &router(&[]), NOW, true);
        assert!(now[0].changes.is_empty());
    }

    #[test]
    fn a_routers_upnp_identity_needs_no_root() {
        let mut h = History::default();
        let home = router(&[("udn", "uuid:home")]);
        h.record(&[device(2, None, None)], &home, THEN);
        let mut now = vec![device(2, None, None)];
        let note = h
            .annotate(&mut now, &router(&[("udn", "uuid:cafe")]), NOW, true)
            .unwrap();
        assert!(note.starts_with("first scan"));
        // The same router, renumbered.
        let moved = NetworkId {
            subnet: "10.0.0.0/24".into(),
            ..home.clone()
        };
        let note = h.annotate(&mut now, &moved, NOW, true).unwrap();
        assert!(!note.starts_with("first scan"));
        // What's learned about a router adds up.
        h.record(
            &now,
            &router(&[("udn", "uuid:home"), ("mac", "00:09:5b:7a:10:01")]),
            NOW,
        );
        assert_eq!(h.networks.len(), 1);
        assert_eq!(h.networks[0].router.len(), 2);
    }

    #[test]
    fn houses_with_the_same_addresses_stay_apart() {
        // Nothing known about either router: only the devices tell.
        let h = after(&[
            local(20, "homeassistant.local"),
            local(52, "Living-Room.local"),
        ]);
        let mut next_door = vec![local(20, "printer.local"), local(52, "Lounge.local")];
        let note = h.annotate(&mut next_door, &router(&[]), NOW, true).unwrap();
        assert!(note.starts_with("first scan"));
        // Home again, with one device renamed: still home.
        let mut home = vec![local(20, "homeassistant.local"), local(52, "Lounge.local")];
        let note = h.annotate(&mut home, &router(&[]), NOW, true).unwrap();
        assert!(!note.starts_with("first scan"));
    }

    #[test]
    fn forgets_devices_after_a_year() {
        let mut h = after(&[device(2, Some("02:00:00:00:00:02"), None)]);
        h.record(&[], &id(), THEN + KEEP_FOR);
        assert!(h.networks[0].devices.is_empty());
    }

    #[test]
    fn dates_and_ages() {
        assert_eq!(date(0), "1 Jan 1970");
        assert_eq!(date(1_791_244_800), "6 Oct 2026");
        assert_eq!(date(951_782_400), "29 Feb 2000");
        assert_eq!(ago(NOW, NOW - 30), "just now");
        assert_eq!(ago(NOW, NOW - 60), "1 minute ago");
        assert_eq!(ago(NOW, NOW - 2 * HOUR), "2 hours ago");
        assert_eq!(ago(NOW, NOW - 3 * DAY), "3 days ago");
        assert_eq!(
            ago(1_791_244_800 + 30 * DAY, 1_791_244_800),
            "on 6 Oct 2026"
        );
    }

    #[test]
    fn saves_atomically_and_privately() {
        let dir = std::env::temp_dir().join(format!("lsnet-history-{}", std::process::id()));
        let path = dir.join("sub").join("history.json");
        let h = after(&[device(2, Some("02:00:00:00:00:02"), Some("Kitchen"))]);
        save(&path, &h).unwrap();
        let loaded = load(&path);
        assert_eq!(loaded.history, h);
        assert!(loaded.writable && loaded.warning.is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let leftovers = fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(leftovers, 1, "no temporary files left behind");

        // A damaged file is set aside, not lost or overwritten.
        fs::write(&path, "{ not json").unwrap();
        let loaded = load(&path);
        assert!(loaded.history.networks.is_empty() && loaded.writable);
        assert!(loaded.warning.unwrap().contains("damaged"));
        assert!(!path.exists());

        // A newer lsnet's file is read but never written.
        fs::write(&path, r#"{"version": 99, "networks": []}"#).unwrap();
        assert!(!load(&path).writable);
        fs::remove_dir_all(&dir).unwrap();
    }
}
