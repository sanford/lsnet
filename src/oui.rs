//! MAC address → manufacturer, from the embedded IEEE registry via
//! Wireshark's `manuf` database (GPL-2.0-or-later; regenerate with
//! `scripts/update-oui.py`).

use pnet_base::MacAddr;
use std::collections::HashMap;
use std::sync::OnceLock;

static DB: &str = include_str!("../data/oui.tsv");

fn table() -> &'static HashMap<&'static str, &'static str> {
    static TABLE: OnceLock<HashMap<&str, &str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        DB.lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once('\t'))
            .collect()
    })
}

/// Phones and laptops use a random "locally administered" MAC per network for privacy.
pub fn is_randomized(mac: MacAddr) -> bool {
    mac.0 & 0x02 != 0
}

pub fn vendor(mac: MacAddr) -> Option<&'static str> {
    let hex = format!(
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
    );
    // Most specific assignment first: 36-bit, 28-bit, then 24-bit.
    [9, 7, 6]
        .iter()
        .find_map(|&n| table().get(&hex[..n]).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_vendors() {
        assert_eq!(
            vendor(MacAddr::new(0xf0, 0x18, 0x98, 1, 2, 3)),
            Some("Apple")
        );
        assert_eq!(
            vendor(MacAddr::new(0xb8, 0x27, 0xeb, 1, 2, 3)),
            Some("Raspberry Pi")
        );
    }

    #[test]
    fn detects_randomized() {
        assert!(is_randomized(MacAddr::new(0x3a, 0, 0, 0, 0, 0)));
        assert!(!is_randomized(MacAddr::new(0xf0, 0x18, 0x98, 0, 0, 0)));
    }
}
