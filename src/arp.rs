//! Host discovery over ARP.
//!
//! With raw-socket access (root, or BPF permissions) we broadcast ARP requests
//! ourselves and listen for replies: fast, finds devices that ignore every
//! port, and gives us MAC addresses. Without it we can only read the
//! kernel's ARP cache.

use crate::iface::Iface;
use pnet::datalink::{self, Channel, Config};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub type Found = HashMap<Ipv4Addr, MacAddr>;

/// Active ARP sweep. Fails with PermissionDenied when we can't open BPF.
pub fn sweep(ifc: &Iface, targets: &[Ipv4Addr], wait: Duration) -> io::Result<Found> {
    // Replies go to the source MAC we put in the frame, so we must know our real one.
    let Some(own_mac) = ifc.mac else {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "own MAC address is hidden"));
    };
    let cfg = Config {
        read_timeout: Some(Duration::from_millis(50)),
        ..Default::default()
    };
    // pnet walks /dev/bpf0..N and reports whatever the last failure was
    // (usually ENOENT), so any open failure here means "no raw access".
    let channel = datalink::channel(&ifc.iface, cfg)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
    let (mut tx, mut rx) = match channel {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(io::Error::other("unsupported datalink channel")),
    };

    let found = Arc::new(Mutex::new(Found::new()));
    let stop = Arc::new(AtomicBool::new(false));
    {
        let (found, stop, net) = (found.clone(), stop.clone(), ifc.net);
        let own_ip = ifc.ip;
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let Ok(frame) = rx.next() else { continue };
                let Some(eth) = EthernetPacket::new(frame) else { continue };
                if eth.get_ethertype() != EtherTypes::Arp {
                    continue;
                }
                let Some(arp) = ArpPacket::new(eth.payload()) else { continue };
                // Any ARP traffic (replies, and other hosts' requests) proves the sender is alive.
                let ip = arp.get_sender_proto_addr();
                if net.contains(ip) && ip != own_ip && !ip.is_unspecified() {
                    found.lock().unwrap().insert(ip, arp.get_sender_hw_addr());
                }
            }
        });
    }

    // Two rounds: Wi-Fi clients in power-save often miss the first request.
    for round in 0..2 {
        let pending: Vec<_> = {
            let f = found.lock().unwrap();
            targets.iter().filter(|ip| !f.contains_key(ip)).copied().collect()
        };
        for (i, &target) in pending.iter().enumerate() {
            let frame = arp_request(own_mac, ifc.ip, target);
            if let Some(Err(e)) = tx.send_to(&frame, None)
                && round == 0 && i == 0 {
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

fn arp_request(src_mac: MacAddr, src_ip: Ipv4Addr, target: Ipv4Addr) -> [u8; 42] {
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

/// Whatever the kernel's ARP cache knows, from `arp -an`, e.g.
/// `? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]`.
/// Recent macOS returns nothing here unless the binary is Apple-signed.
pub fn read_cache(ifc: &Iface) -> Found {
    let Ok(out) = Command::new("arp").arg("-an").output() else {
        return Found::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let ip: Ipv4Addr = words.get(1)?.trim_matches(|c| c == '(' || c == ')').parse().ok()?;
            let mac = parse_mac(words.get(3)?)?;
            let on_iface = words.windows(2).any(|w| w[0] == "on" && w[1] == ifc.iface.name);
            (on_iface && ifc.net.contains(ip) && ip != ifc.ip && ip != ifc.net.broadcast())
                .then_some((ip, mac))
        })
        .filter(|(_, mac)| *mac != MacAddr::broadcast())
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

    #[test]
    fn parses_short_macs() {
        assert_eq!(parse_mac("a4:2b:0:1:2:ff"), Some(MacAddr::new(0xa4, 0x2b, 0, 1, 2, 0xff)));
        assert_eq!(parse_mac("(incomplete)"), None);
    }
}
