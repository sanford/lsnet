//! NetBIOS node status. Windows PCs, Samba servers and many NASes answer a
//! unicast query on UDP 137 with their computer name and, in the same reply,
//! their MAC address, which is often the only way to get one without ARP
//! (unprivileged on macOS, say).

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};

const PORT: u16 = 137;

#[derive(Clone, Serialize)]
pub struct NetbiosInfo {
    /// The computer name, e.g. "DESKTOP-4F2K9QX" or "NORTHWOODSNAS".
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

/// Ask each of `targets` for its name table, collecting answers for `wait`.
pub async fn query(
    local_ip: Ipv4Addr,
    targets: &[Ipv4Addr],
    wait: Duration,
) -> HashMap<Ipv4Addr, NetbiosInfo> {
    let mut found = HashMap::new();
    if targets.is_empty() {
        return found;
    }
    let Ok(sock) = UdpSocket::bind((local_ip, 0)).await else {
        return found;
    };
    let deadline = Instant::now() + wait;
    let request = node_status_request(0x4c53);
    for &ip in targets {
        let _ = sock.send_to(&request, (ip, PORT)).await;
    }
    let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut buf = vec![0u8; 1500];
    while let Ok(Ok((n, SocketAddr::V4(src)))) =
        timeout_at(deadline, sock.recv_from(&mut buf)).await
    {
        if wanted.contains(src.ip())
            && let Some(info) = parse_reply(&buf[..n])
        {
            found.insert(*src.ip(), info);
        }
    }
    found
}

/// A node status request (NBSTAT) for the wildcard name "*".
fn node_status_request(id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(50);
    pkt.extend_from_slice(&id.to_be_bytes());
    // Flags 0 (a query), one question, no other records.
    pkt.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    // The name, first-level encoded: 16 bytes ("*" then NULs), each split
    // into two nibbles written as 'A' + nibble.
    pkt.push(32);
    let mut name = [0u8; 16];
    name[0] = b'*';
    for b in name {
        pkt.push(b'A' + (b >> 4));
        pkt.push(b'A' + (b & 0x0f));
    }
    pkt.push(0);
    pkt.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // NBSTAT, IN
    pkt
}

/// The computer name (the first unique name with the 0x00 "workstation"
/// suffix) and the MAC address that follows the name table.
fn parse_reply(pkt: &[u8]) -> Option<NetbiosInfo> {
    // Must be a response with one answer.
    if pkt.get(2)? & 0x80 == 0 || u16::from_be_bytes([*pkt.get(6)?, *pkt.get(7)?]) == 0 {
        return None;
    }
    // Skip the echoed name: labels ending in 0, or a compression pointer.
    let mut at = 12;
    loop {
        let len = *pkt.get(at)?;
        if len == 0 {
            at += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            at += 2;
            break;
        }
        at += 1 + usize::from(len);
    }
    // Type, class, TTL and data length, then the name count.
    at += 10;
    let count = usize::from(*pkt.get(at)?);
    at += 1;
    let mut name = None;
    for _ in 0..count {
        let entry = pkt.get(at..at + 18)?;
        at += 18;
        let (suffix, group) = (entry[15], entry[16] & 0x80 != 0);
        if name.is_none() && suffix == 0x00 && !group {
            let text = String::from_utf8_lossy(&entry[..15]);
            let text = text.trim_matches(|c: char| c == ' ' || c == '\0');
            if !text.is_empty() {
                name = Some(text.to_string());
            }
        }
    }
    let mac = pkt
        .get(at..at + 6)
        .filter(|m| m.iter().any(|&b| b != 0))
        .map(|m| {
            m.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        });
    Some(NetbiosInfo { name: name?, mac })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_wildcard_query() {
        let pkt = node_status_request(0x1234);
        assert_eq!(pkt.len(), 50);
        assert_eq!(&pkt[..2], &[0x12, 0x34]);
        // '*' is 0x2A: 'A' + 2, 'A' + 10. Each NUL is "AA".
        assert_eq!(&pkt[12..15], b"\x20CK");
        assert!(pkt[15..45].iter().all(|&b| b == b'A'));
        assert_eq!(&pkt[45..], &[0, 0x00, 0x21, 0x00, 0x01]);
    }

    /// A reply naming `entries`, then `mac`.
    fn reply(entries: &[(&str, u8, bool)], mac: [u8; 6]) -> Vec<u8> {
        let mut pkt = vec![0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        pkt.extend(&node_status_request(0)[12..46]);
        pkt.extend([0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0]);
        let len = 1 + entries.len() * 18 + 46;
        pkt.extend((len as u16).to_be_bytes());
        pkt.push(entries.len() as u8);
        for (name, suffix, group) in entries {
            let mut padded = format!("{name:<15}").into_bytes();
            padded.truncate(15);
            pkt.extend(padded);
            pkt.push(*suffix);
            pkt.extend([if *group { 0x84 } else { 0x04 }, 0x00]);
        }
        pkt.extend(mac);
        pkt.extend([0u8; 40]);
        pkt
    }

    #[test]
    fn reads_the_name_and_mac() {
        let info = parse_reply(&reply(
            &[
                ("WORKGROUP", 0x00, true),
                ("DESKTOP-4F2K9QX", 0x20, false),
                ("DESKTOP-4F2K9QX", 0x00, false),
            ],
            [0x00, 0x11, 0x32, 0x66, 0xd8, 0x71],
        ))
        .unwrap();
        assert_eq!(info.name, "DESKTOP-4F2K9QX");
        assert_eq!(info.mac.as_deref(), Some("00:11:32:66:d8:71"));

        // Samba often reports no MAC.
        let samba = parse_reply(&reply(&[("PI", 0x00, false)], [0; 6])).unwrap();
        assert_eq!(samba.name, "PI");
        assert_eq!(samba.mac, None);
    }

    #[test]
    fn rejects_queries_and_truncated_replies() {
        assert!(parse_reply(&node_status_request(1)).is_none());
        let full = reply(&[("NAS", 0x00, false)], [1, 2, 3, 4, 5, 6]);
        assert!(parse_reply(&full[..60]).is_none());
        // Only group names: no computer name.
        assert!(parse_reply(&reply(&[("WORKGROUP", 0x00, true)], [1; 6])).is_none());
    }
}
