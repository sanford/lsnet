//! Host discovery over ARP.
//!
//! With raw-socket access (root; CAP_NET_RAW on Linux; BPF access on macOS) we broadcast ARP requests
//! ourselves and listen for replies: fast, finds devices that ignore every
//! port, and gives us MAC addresses. Either way we also read the kernel's
//! ARP cache, which is all we have without it. Windows sends ARP requests
//! for anyone who asks, so there the sweep never needs privileges.

use crate::iface::Iface;
use crate::platform;
use ipnetwork::Ipv4Network;
use pnet_base::MacAddr;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

pub type Found = HashMap<Ipv4Addr, MacAddr>;

/// Every address a sweep heard ARP from, with the MACs that claimed it in the
/// order they were heard, inside the scanned network or not.
pub type Heard = HashMap<Ipv4Addr, Vec<MacAddr>>;

/// Something wrong with a device's address, as its ARP traffic shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Flag {
    /// Self-assigned (169.254.0.0/16): it asked for DHCP and got no answer.
    LinkLocal,
    /// Outside this interface's network, usually a static address from elsewhere.
    OffSubnet,
    /// More than one device answered for the address.
    AddressConflict,
}

/// A sweep's ARP traffic, sorted into what it means.
#[derive(Debug, Default, PartialEq)]
pub struct Sorted {
    /// Addresses in the scanned network, with the first MAC heard for each.
    pub found: Found,
    /// Addresses in the scanned network that more than one MAC answered for,
    /// every MAC in the order heard (this machine's own first, when it's ours).
    pub conflicts: HashMap<Ipv4Addr, Vec<MacAddr>>,
    /// Addresses outside the interface's own network, with each MAC using them.
    pub strays: Vec<(Ipv4Addr, MacAddr)>,
}

/// Sort what a sweep heard into devices on the scanned network `net`,
/// address conflicts, and strays: devices using an address outside `link`,
/// the interface's own network, so nothing here can route to them. Addresses
/// in `link` but outside `net` (scanning half a /24 with `--net`) are simply
/// out of scope.
pub fn sort_out(
    heard: Heard,
    net: Ipv4Network,
    link: Ipv4Network,
    own_ip: Ipv4Addr,
    own_mac: Option<MacAddr>,
) -> Sorted {
    let mut out = Sorted::default();
    for (ip, mut macs) in heard {
        let mut seen = Vec::new();
        macs.retain(|m| {
            let first = !seen.contains(m);
            seen.push(*m);
            first
        });
        if macs.is_empty()
            || ip.is_unspecified()
            || ip.is_broadcast()
            || ip.is_multicast()
            || ip == link.broadcast()
        {
            continue;
        }
        if !link.contains(ip) {
            out.strays.extend(macs.into_iter().map(|m| (ip, m)));
        } else if net.contains(ip) {
            if ip == own_ip {
                // Our own frames are never recorded, so anything here is
                // another device claiming this machine's address.
                out.conflicts
                    .insert(ip, own_mac.into_iter().chain(macs).collect());
            } else {
                out.found.insert(ip, macs[0]);
                if macs.len() > 1 {
                    out.conflicts.insert(ip, macs);
                }
            }
        }
    }
    // ARP flux: Linux answers for all of a machine's addresses on all its
    // interfaces, so a machine on Wi-Fi and Ethernet at once answers for both
    // addresses with both MACs. Two addresses claimed by the same MACs are one
    // machine, not a conflict.
    let mut by_macs: HashMap<Vec<MacAddr>, usize> = HashMap::new();
    for macs in out.conflicts.values() {
        let mut key = macs.clone();
        key.sort();
        *by_macs.entry(key).or_default() += 1;
    }
    out.conflicts.retain(|_, macs| {
        let mut key = macs.clone();
        key.sort();
        by_macs[&key] < 2
    });
    out.strays.sort();
    out
}

/// Strays grouped by MAC, since one device may use several stray addresses.
pub fn strays_by_mac(strays: &[(Ipv4Addr, MacAddr)]) -> BTreeMap<MacAddr, Vec<Ipv4Addr>> {
    let mut out: BTreeMap<MacAddr, Vec<Ipv4Addr>> = BTreeMap::new();
    for &(ip, mac) in strays {
        out.entry(mac).or_default().push(ip);
    }
    out
}

/// The flag for an address outside the interface's network.
pub fn stray_flag(ip: Ipv4Addr) -> Flag {
    if ip.is_link_local() {
        Flag::LinkLocal
    } else {
        Flag::OffSubnet
    }
}

/// Active ARP sweep. Fails with PermissionDenied when we can't open BPF.
/// Records every sender heard, wherever its address is; see `sort_out`.
/// Targets may be on other networks (`--also`); see `asking_as`.
#[cfg(unix)]
pub fn sweep(ifc: &Iface, targets: &[Ipv4Addr], wait: Duration) -> io::Result<Heard> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    // Replies go to the source MAC we put in the frame, so we must know our real one.
    let Some(own_mac) = ifc.mac else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "own MAC address is hidden",
        ));
    };
    let (mut tx, mut rx) = open(ifc)?;

    let found = Arc::new(Mutex::new(Heard::new()));
    let stop = Arc::new(AtomicBool::new(false));
    {
        let (found, stop) = (found.clone(), stop.clone());
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let Ok(frame) = rx.next() else { continue };
                // Any ARP traffic (replies, and other hosts' requests) proves
                // the sender is alive. Our own frames come back to us too.
                if let Some((ip, mac)) = sender(frame).filter(|(_, mac)| *mac != own_mac) {
                    let mut found = found.lock().unwrap();
                    let macs = found.entry(ip).or_default();
                    if !macs.contains(&mac) {
                        macs.push(mac);
                    }
                }
            }
        });
    }

    // Two rounds: Wi-Fi clients in power-save often miss the first request.
    for round in 0..2 {
        let pending: Vec<_> = {
            let f = found.lock().unwrap();
            targets
                .iter()
                .filter(|ip| !f.contains_key(ip))
                .copied()
                .collect()
        };
        for (i, &target) in pending.iter().enumerate() {
            let frame = arp_request(own_mac, asking_as(ifc, target), target);
            if let Some(Err(e)) = tx.send_to(&frame, None)
                && round == 0
                && i == 0
            {
                return Err(e);
            }
            if i % 64 == 63 {
                thread::sleep(Duration::from_millis(2)); // don't overrun the send buffer
            }
        }
        thread::sleep(wait / 2);
    }
    stop.store(true, Ordering::Relaxed);

    let found = found.lock().unwrap().clone();
    Ok(found)
}

/// The address an ARP request for `target` says is asking. For an address
/// on another network (`--also`) that's none at all, an RFC 5227 probe:
/// whoever holds it must still answer, and nobody there ends up with this
/// machine's address, from a network they don't know, in their ARP cache.
#[cfg(unix)]
fn asking_as(ifc: &Iface, target: Ipv4Addr) -> Ipv4Addr {
    if ifc.link.contains(target) {
        ifc.ip
    } else {
        Ipv4Addr::UNSPECIFIED
    }
}

/// Keep listening for ARP after the sweep: devices announcing themselves,
/// asking for their gateway, or answering someone else. Passes each sender
/// (but not this machine) to `heard` until it returns false or `stop` is
/// set. False without raw access.
#[cfg(unix)]
pub fn listen(
    ifc: &Iface,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mut heard: impl FnMut(Ipv4Addr, MacAddr) -> bool + Send + 'static,
) -> bool {
    use std::sync::atomic::Ordering;
    let Some(own_mac) = ifc.mac else {
        return false;
    };
    let Ok((_tx, mut rx)) = open(ifc) else {
        return false;
    };
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let Ok(frame) = rx.next() else { continue };
            if let Some((ip, mac)) = sender(frame).filter(|(_, mac)| *mac != own_mac)
                && !heard(ip, mac)
            {
                break;
            }
        }
    });
    true
}

/// Windows has no raw packet access without Npcap, so there's no listening.
#[cfg(windows)]
pub fn listen(
    _ifc: &Iface,
    _stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    _heard: impl FnMut(Ipv4Addr, MacAddr) -> bool + Send + 'static,
) -> bool {
    false
}

/// The sender of an ARP frame, if it has an address.
#[cfg(unix)]
fn sender(frame: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    use pnet_packet::Packet;
    use pnet_packet::arp::ArpPacket;
    use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    let ip = arp.get_sender_proto_addr();
    (!ip.is_unspecified()).then(|| (ip, arp.get_sender_hw_addr()))
}

#[cfg(unix)]
type Channel = (
    Box<dyn pnet_datalink::DataLinkSender>,
    Box<dyn pnet_datalink::DataLinkReceiver>,
);

/// A raw channel on the interface. Fails with PermissionDenied without access.
#[cfg(unix)]
fn open(ifc: &Iface) -> io::Result<Channel> {
    use pnet_datalink::Config;
    let iface = pnet_datalink::interfaces()
        .into_iter()
        .find(|i| i.name == ifc.iface.name)
        .ok_or_else(|| io::Error::other(format!("{} disappeared", ifc.iface.name)))?;
    // pnet's default 4 KB capture buffer holds about 50 frames. We see our
    // own broadcasts as well as every other frame on the link, so on a busy
    // network a sweep of a /22 overflows it and replies are dropped. 256 KB
    // is within macOS's BPF limit (512 KB).
    let cfg = Config {
        read_timeout: Some(Duration::from_millis(50)),
        read_buffer_size: 256 * 1024,
        ..Default::default()
    };
    // pnet walks /dev/bpf0..N and reports whatever the last failure was
    // (usually ENOENT), so any open failure here means "no raw access".
    let channel = pnet_datalink::channel(&iface, cfg)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
    match channel {
        pnet_datalink::Channel::Ethernet(tx, rx) => Ok((tx, rx)),
        _ => Err(io::Error::other("unsupported datalink channel")),
    }
}

/// Active ARP sweep through `SendARP`, which needs no privileges. Each
/// request blocks until the address answers or Windows gives up, which takes
/// seconds for an empty address, so every address gets its own thread and
/// we stop listening at the deadline. That's too many threads past a /22, so
/// larger sweeps fail with Unsupported and fall back to the ARP cache.
#[cfg(windows)]
pub fn sweep(ifc: &Iface, targets: &[Ipv4Addr], wait: Duration) -> io::Result<Heard> {
    use std::sync::mpsc;
    use std::time::Instant;

    if targets.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "too many addresses for SendARP",
        ));
    }

    let deadline = Instant::now() + wait;
    let (tx, rx) = mpsc::channel();
    for &ip in targets {
        let (tx, source) = (tx.clone(), ifc.ip);
        thread::spawn(move || {
            if let Some(mac) = platform::send_arp(ip, source) {
                let _ = tx.send((ip, mac));
            }
        });
    }
    drop(tx);
    let mut found = Heard::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let Ok((ip, mac)) = rx.recv_timeout(left) else {
            break;
        };
        found.insert(ip, vec![mac]);
    }
    Ok(found)
}

#[cfg(unix)]
fn arp_request(src_mac: MacAddr, src_ip: Ipv4Addr, target: Ipv4Addr) -> [u8; 42] {
    use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
    use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};

    let mut buf = [0u8; 42];
    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    let mut arp = MutableArpPacket::new(&mut buf[14..]).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(src_mac);
    arp.set_sender_proto_addr(src_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target);
    buf
}

/// Whatever the kernel's ARP cache knows about this network. Linux shares
/// it freely; recent macOS returns nothing to a binary that isn't signed
/// with a Developer ID, even through `arp`.
pub fn read_cache(ifc: &Iface) -> Found {
    platform::arp_cache(&ifc.iface)
        .into_iter()
        .filter(|(ip, mac)| {
            ifc.net.contains(*ip)
                && *ip != ifc.ip
                && *ip != ifc.net.broadcast()
                && *mac != MacAddr::broadcast()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(last: u8) -> MacAddr {
        MacAddr(0x02, 0, 0, 0, 0, last)
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn sort(heard: &[(&str, &[u8])], net: &str) -> Sorted {
        let heard = heard
            .iter()
            .map(|(a, macs)| (ip(a), macs.iter().map(|&m| mac(m)).collect()))
            .collect();
        sort_out(
            heard,
            net.parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
            ip("192.168.1.196"),
            Some(mac(0xee)),
        )
    }

    #[test]
    fn strays_are_outside_the_link() {
        let s = sort(
            &[
                ("192.168.1.20", &[1]),
                ("169.254.37.12", &[2]),
                ("10.1.1.20", &[3]),
            ],
            "192.168.1.0/24",
        );
        assert_eq!(s.found, Found::from([(ip("192.168.1.20"), mac(1))]));
        assert_eq!(
            s.strays,
            [(ip("10.1.1.20"), mac(3)), (ip("169.254.37.12"), mac(2))]
        );
        assert_eq!(stray_flag(ip("169.254.37.12")), Flag::LinkLocal);
        assert_eq!(stray_flag(ip("10.1.1.20")), Flag::OffSubnet);
        assert!(s.conflicts.is_empty());
    }

    #[test]
    fn the_rest_of_the_link_is_out_of_scope_not_stray() {
        // Scanning the upper half of the /24: the lower half is neither found nor flagged.
        let s = sort(
            &[("192.168.1.20", &[1]), ("192.168.1.200", &[2])],
            "192.168.1.128/25",
        );
        assert_eq!(s.found, Found::from([(ip("192.168.1.200"), mac(2))]));
        assert!(s.strays.is_empty());
    }

    #[test]
    fn a_link_local_network_has_no_link_local_strays() {
        let heard = Heard::from([(ip("169.254.9.9"), vec![mac(1)])]);
        let link: Ipv4Network = "169.254.0.0/16".parse().unwrap();
        let s = sort_out(heard, link, link, ip("169.254.1.1"), None);
        assert_eq!(s.found.len(), 1);
        assert!(s.strays.is_empty());
    }

    #[test]
    fn two_macs_for_one_address_conflict() {
        let s = sort(&[("192.168.1.230", &[1, 2, 1])], "192.168.1.0/24");
        assert_eq!(s.found[&ip("192.168.1.230")], mac(1));
        assert_eq!(s.conflicts[&ip("192.168.1.230")], [mac(1), mac(2)]);
    }

    #[test]
    fn someone_else_on_our_address_conflicts_with_us() {
        let s = sort(&[("192.168.1.196", &[7])], "192.168.1.0/24");
        assert!(s.found.is_empty());
        assert_eq!(s.conflicts[&ip("192.168.1.196")], [mac(0xee), mac(7)]);
    }

    #[test]
    fn arp_flux_is_one_machine_not_a_conflict() {
        let s = sort(
            &[("192.168.1.10", &[1, 2]), ("192.168.1.11", &[2, 1])],
            "192.168.1.0/24",
        );
        assert!(s.conflicts.is_empty());
        assert_eq!(s.found.len(), 2);
    }

    #[test]
    fn ignores_probes_and_broadcasts() {
        let s = sort(
            &[
                ("0.0.0.0", &[1]),
                ("192.168.1.255", &[2]),
                ("224.0.0.1", &[3]),
            ],
            "192.168.1.0/24",
        );
        assert_eq!(s, Sorted::default());
    }
}
