//! `--demo`: a made-up network, so lsnet can be tried, developed and
//! documented without one. No packets are sent.
//!
//! The network is `lsnet --json` output, read back like any other and run
//! through the same last step as a real scan (`finish`), so everything after
//! the scan is the real program. Only the evidence counts: names, types,
//! models and vendors in the file are recomputed. The fixture tests below
//! check that they come out as recorded.
//!
//! It has a history too, in the same format as a real one: the network as
//! it was two hours before the demo's clock, so the browser has new, moved,
//! renamed and missing devices to show. Nothing is ever written to it.

use crate::history::{History, NetworkId};
use crate::live::Memory;
use crate::scan::flag_notes;
use crate::{Device, Scan, finish};

const NETWORK: &str = include_str!("../data/demo.json");
const HISTORY: &str = include_str!("../data/demo-history.json");

/// The demo's clock: 6 Oct 2026, 10:00 UTC.
pub const NOW: u64 = 1_791_280_800;

pub fn scan() -> Scan {
    let mut devices = read(NETWORK).expect("data/demo.json is valid");
    for d in &mut devices {
        finish(d);
    }
    let link: ipnetwork::Ipv4Network = "192.168.1.0/24".parse().expect("valid network");
    let gateway = "192.168.1.1".parse().expect("valid address");
    let network = NetworkId::new(link.to_string(), Some(gateway), &devices);
    Scan {
        summary: format!("{} devices on {link} (demo)", devices.len()),
        notes: flag_notes(&devices, link),
        caveats: Vec::new(),
        devices,
        changes: None,
        network: Some(network),
        arp_ran: true,
        clock: NOW,
    }
}

/// The demo network's history, on the demo's clock.
pub fn memory() -> Memory {
    let history: History = serde_json::from_str(HISTORY).expect("data/demo-history.json is valid");
    Memory {
        history: Some(history),
        now: Some(NOW),
        warning: None,
    }
}

fn read(json: &str) -> serde_json::Result<Vec<Device>> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::Path;

    /// What `finish` works out; everything else in the file is evidence.
    const DERIVED: &[&str] = &[
        "name",
        "name_from",
        "type",
        "model",
        "type_from",
        "vendor",
        "randomized_mac",
    ];

    /// Every device in a `--json` file, recomputed from its evidence, must
    /// come out as recorded: the same name, type, model and vendor, for the
    /// same reasons. A field left out counts as recorded empty. Returns a
    /// line per difference.
    fn check(label: &str, json: &str) -> Vec<String> {
        let recorded: Vec<Value> = serde_json::from_str(json).expect(label);
        let mut devices = read(json).expect(label);
        let mut problems = Vec::new();
        for (d, want) in devices.iter_mut().zip(&recorded) {
            finish(d);
            let got = serde_json::to_value(&*d).unwrap();
            for k in DERIVED {
                let empty = |v: Option<&Value>| match v {
                    None | Some(Value::Null) | Some(Value::Bool(false)) => Value::Null,
                    Some(v) => v.clone(),
                };
                let (g, w) = (empty(got.get(k)), empty(want.get(k)));
                if g != w {
                    problems.push(format!("{label} {}: {k} is {g} but {w} was recorded", d.ip));
                }
            }
        }
        problems
    }

    #[test]
    fn demo_network_comes_out_as_recorded() {
        let problems = check("data/demo.json", NETWORK);
        assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
    }

    /// Devices from real networks, as `lsnet --json` printed them (with
    /// anything private changed), and corrected where lsnet got them wrong.
    #[test]
    fn fixtures_come_out_as_recorded() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let mut problems = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("tests/fixtures") {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "json") {
                let json = std::fs::read_to_string(&path).unwrap();
                let name = path.file_name().unwrap().to_string_lossy();
                problems.extend(check(&name, &json));
            }
        }
        assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
    }

    #[test]
    fn demo_scan_notes_every_flag() {
        let scan = scan();
        assert_eq!(scan.notes.len(), 3);
        assert!(scan.summary.ends_with("(demo)"));
    }

    #[test]
    fn demo_history_shows_every_kind_of_change() {
        let mut scan = scan();
        memory().mark(&mut scan);
        assert_eq!(
            scan.changes.as_deref(),
            Some("since the last scan, 2 hours ago: 2 new, 1 moved, 1 renamed, 1 missing")
        );
        let missing: Vec<_> = scan.devices.iter().filter(|d| d.missing()).collect();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].name.as_deref(), Some("myq-garage"));
    }
}
