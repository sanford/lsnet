//! OS-specific lookups: the default gateway and the kernel's ARP cache.
//!
//! Linux exposes both under /proc. macOS (and the BSDs) only offer them
//! through `netstat` and `arp`. The parsers take plain text so every
//! platform's can be tested anywhere.

use pnet::util::MacAddr;
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
pub fn default_gateway(iface: &str) -> Option<Ipv4Addr> {
    parse_proc_route(&std::fs::read_to_string("/proc/net/route").ok()?, iface)
}

#[cfg(target_os = "linux")]
pub fn arp_cache(iface: &str) -> Vec<(Ipv4Addr, MacAddr)> {
    std::fs::read_to_string("/proc/net/arp")
        .map(|text| parse_proc_arp(&text, iface))
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
pub fn default_gateway(iface: &str) -> Option<Ipv4Addr> {
    parse_netstat(&run("netstat", &["-rn", "-f", "inet"])?, iface)
}

#[cfg(not(target_os = "linux"))]
pub fn arp_cache(iface: &str) -> Vec<(Ipv4Addr, MacAddr)> {
    run("arp", &["-an"]).map(|text| parse_arp_an(&text, iface)).unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `/proc/net/route`: addresses are little-endian hex; the default route has
/// destination 0. With several, the lowest metric wins, as in the kernel.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_proc_route(text: &str, iface: &str) -> Option<Ipv4Addr> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 7 || f[0] != iface || f[1] != "00000000" {
                return None;
            }
            let gw = u32::from_str_radix(f[2], 16).ok()?;
            let metric: u32 = f[6].parse().ok()?;
            (gw != 0).then(|| (metric, Ipv4Addr::from(gw.to_le_bytes())))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, gw)| gw)
}

/// `/proc/net/arp`: `IP  HW-type  Flags  HW-address  Mask  Device`.
/// Flags 0x0 marks an incomplete entry (the address didn't answer).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_proc_arp(text: &str, iface: &str) -> Vec<(Ipv4Addr, MacAddr)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 || f[5] != iface || f[2] == "0x0" {
                return None;
            }
            let mac = parse_mac(f[3])?;
            (mac != MacAddr::zero()).then_some((f[0].parse().ok()?, mac))
        })
        .collect()
}

/// `netstat -rn -f inet`: `default  192.168.1.1  UGScg  en0`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub fn parse_netstat(text: &str, iface: &str) -> Option<Ipv4Addr> {
    text.lines()
        .filter(|l| l.starts_with("default"))
        .find(|l| l.split_whitespace().any(|w| w == iface))
        .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
}

/// `arp -an`: `? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub fn parse_arp_an(text: &str, iface: &str) -> Vec<(Ipv4Addr, MacAddr)> {
    text.lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let ip: Ipv4Addr = words.get(1)?.trim_matches(|c| c == '(' || c == ')').parse().ok()?;
            let mac = parse_mac(words.get(3)?)?;
            let on_iface = words.windows(2).any(|w| w[0] == "on" && w[1] == iface);
            on_iface.then_some((ip, mac))
        })
        .collect()
}

/// macOS drops leading zeros (`a4:2b:0:1:2:3`), so parse each octet individually.
fn parse_mac(s: &str) -> Option<MacAddr> {
    let o: Vec<u8> = s
        .split(':')
        .map(|p| u8::from_str_radix(p, 16))
        .collect::<Result<_, _>>()
        .ok()?;
    (o.len() == 6).then(|| MacAddr::new(o[0], o[1], o[2], o[3], o[4], o[5]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_ROUTE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    #[test]
    fn proc_route() {
        assert_eq!(parse_proc_route(PROC_ROUTE, "wlan0"), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(parse_proc_route(PROC_ROUTE, "eth0"), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(parse_proc_route(PROC_ROUTE, "docker0"), None);
    }

    #[test]
    fn proc_arp() {
        let text = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         1c:d6:be:3c:62:8d     *        wlan0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0
10.0.0.5         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
";
        assert_eq!(
            parse_proc_arp(text, "wlan0"),
            vec![(Ipv4Addr::new(192, 168, 1, 1), MacAddr::new(0x1c, 0xd6, 0xbe, 0x3c, 0x62, 0x8d))]
        );
    }

    #[test]
    fn netstat() {
        let text = "Destination  Gateway  Flags  Netif Expire\n\
                    default      192.168.1.1  UGScg  en0\n\
                    default      10.0.0.1     UGScIg en1\n";
        assert_eq!(parse_netstat(text, "en1"), Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn arp_an() {
        let text = "? (192.168.1.1) at a4:2b:0:1:2:ff on en0 ifscope [ethernet]\n\
                    ? (192.168.1.3) at (incomplete) on en0 ifscope [ethernet]\n\
                    ? (192.168.1.8) at c0:b5:d7:e7:74:7d on en1 ifscope [ethernet]\n";
        assert_eq!(
            parse_arp_an(text, "en0"),
            vec![(Ipv4Addr::new(192, 168, 1, 1), MacAddr::new(0xa4, 0x2b, 0, 1, 2, 0xff))]
        );
    }
}
