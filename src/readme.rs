//! The README's example screens and tables are the demo network (`--demo`),
//! rendered by the real code, so they can't drift from what lsnet prints.
//!
//! `cargo test readme` fails when they differ, and
//! `LSNET_UPDATE_README=1 cargo test readme` rewrites them.

use crate::{Device, Scan, Style, demo, device_table, footer, services_table, tui};
use std::net::Ipv4Addr;
use std::path::Path;

/// The demo network, summarised as if it had been scanned, and compared
/// with its history.
fn scanned() -> Scan {
    let mut scan = demo::scan();
    scan.summary = scan.summary.replace("(demo)", "(en0) in 2.0s");
    demo::memory().mark(&mut scan);
    scan
}

/// What follows a table: the summary and notes lsnet prints to stderr.
fn below(scan: &Scan) -> String {
    let mut out = String::from("\n");
    for line in footer(scan) {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// The devices a table shows: the ones that answered.
fn present(scan: &Scan) -> Vec<Device> {
    scan.present().cloned().collect()
}

/// A table as the README shows it: plain, without trailing spaces.
fn plain(table: String) -> String {
    table
        .lines()
        .map(|l| l.trim_end().to_string() + "\n")
        .collect()
}

/// The browser, tall enough for every row of the list.
fn browser(show_services: bool, ip: &str, port: Option<u16>) -> String {
    let scan = scanned();
    let rows = if show_services {
        crate::services::list(&scan.devices).len()
    } else {
        scan.devices.len()
    };
    // Summary and notes, the list's borders and header, then the footer.
    let height = 1 + scan.changes.iter().count() + scan.notes.len() + 3 + rows + 1;
    let ip: Ipv4Addr = ip.parse().unwrap();
    tui::screen(scan, show_services, (ip, port), 124, height as u16)
}

/// Each example: the command line that starts its block, and what follows.
fn examples() -> Vec<(&'static str, String)> {
    let scan = scanned();
    let devices = present(&scan);
    let some: Vec<_> = present(&scan)
        .into_iter()
        .filter(|d| {
            [
                "192.168.1.52",
                "192.168.1.112",
                "192.168.1.130",
                "192.168.1.230",
            ]
            .contains(&d.ip.to_string().as_str())
        })
        .collect();
    vec![
        ("$ lsnet", browser(false, "192.168.1.52", None)),
        ("$ lsnet -s", browser(true, "192.168.1.14", Some(32400))),
        (
            "$ lsnet -l",
            plain(device_table(&devices, false, Style::Plain)) + &below(&scan),
        ),
        (
            "$ lsnet -s -l",
            plain(services_table(&devices, Style::Plain)) + &below(&scan),
        ),
        (
            "$ sudo lsnet -l",
            plain(device_table(&some, false, Style::Plain)),
        ),
    ]
}

/// The body of the code block in `readme` that starts with `command`.
fn block(readme: &str, command: &str) -> Option<std::ops::Range<usize>> {
    let opening = format!("```\n{command}\n");
    let start = readme.find(&opening)? + opening.len();
    let end = start + readme[start..].find("```\n")?;
    Some(start..end)
}

#[test]
fn readme_shows_the_demo_network() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let mut readme = std::fs::read_to_string(&path).unwrap();
    let update = std::env::var_os("LSNET_UPDATE_README").is_some();
    let mut stale = Vec::new();
    for (command, want) in examples() {
        let range = block(&readme, command)
            .unwrap_or_else(|| panic!("README.md has no example starting `{command}`"));
        if readme[range.clone()] != want {
            stale.push(command);
            readme.replace_range(range, &want);
        }
    }
    if update {
        std::fs::write(&path, readme).unwrap();
    } else {
        assert!(
            stale.is_empty(),
            "README.md's examples for {stale:?} don't match the demo network; \
             LSNET_UPDATE_README=1 cargo test readme rewrites them"
        );
    }
}
