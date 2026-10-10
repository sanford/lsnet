//! SNMP's system group. Printers, managed switches, UPSes and many NASes
//! answer a query on UDP 161 with a line describing themselves, the name
//! their admin gave them and their maker's number, and printers with their
//! model as well.
//!
//! Asked as SNMPv1, which whatever speaks v2c answers too, with the
//! community "public": the read-only default nearly everywhere it's on.
//! Devices set up with another community, or SNMPv3 alone, stay silent.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};

const PORT: u16 = 161;
const COMMUNITY: &[u8] = b"public";

// Object identifiers, BER-encoded (1.3 packs into the first byte, 0x2b).
const SYS_DESCR: &[u8] = &[0x2b, 6, 1, 2, 1, 1, 1, 0];
const SYS_OBJECT_ID: &[u8] = &[0x2b, 6, 1, 2, 1, 1, 2, 0];
const SYS_NAME: &[u8] = &[0x2b, 6, 1, 2, 1, 1, 5, 0];
/// hrDeviceDescr.1: on a printer, the printer itself.
const HR_DEVICE_DESCR: &[u8] = &[0x2b, 6, 1, 2, 1, 25, 3, 2, 1, 3, 1];

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const NULL: u8 = 0x05;
const OBJECT_ID: u8 = 0x06;
const GET_REQUEST: u8 = 0xa0;
const GET_RESPONSE: u8 = 0xa2;

#[derive(Clone, Default, PartialEq, Debug, Serialize, Deserialize)]
pub struct SnmpInfo {
    /// sysName: the name its admin gave it, or the one it came with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// sysDescr, e.g. "Canon MF740C Series /P" or "RouterOS RB4011iGS+".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// sysObjectID, e.g. "1.3.6.1.4.1.2435.2.3.9.1": the number after
    /// 1.3.6.1.4.1 is its maker's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    /// hrDeviceDescr.1, e.g. "Brother HL-L2350DW series".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
}

impl SnmpInfo {
    /// Who made it, going by the enterprise number in its object ID.
    pub fn maker(&self) -> Option<&'static str> {
        let number = self
            .object_id
            .as_deref()?
            .strip_prefix("1.3.6.1.4.1.")?
            .split('.')
            .next()?
            .parse()
            .ok()?;
        enterprise(number)
    }
}

/// IANA's private enterprise numbers, for the makers of things that answer
/// SNMP on a small network. Not net-snmp's (8072) or Microsoft's (311):
/// those name the agent, and say nothing of the device.
fn enterprise(number: u32) -> Option<&'static str> {
    Some(match number {
        9 => "Cisco",
        11 => "HP",
        171 => "D-Link",
        236 => "Samsung",
        253 => "Xerox",
        318 => "APC",
        367 => "Ricoh",
        534 => "Eaton",
        641 => "Lexmark",
        674 => "Dell",
        1248 => "Epson",
        1347 => "Kyocera",
        1602 => "Canon",
        2385 => "Sharp",
        2435 => "Brother",
        2636 => "Juniper",
        3808 => "CyberPower",
        4526 => "Netgear",
        6574 => "Synology",
        11863 => "TP-Link",
        12356 => "Fortinet",
        14823 => "Aruba",
        14988 => "MikroTik",
        18334 => "Konica Minolta",
        24681 => "QNAP",
        25506 => "HPE",
        30065 => "Arista",
        41112 => "Ubiquiti",
        _ => return None,
    })
}

/// Ask each of `targets` about itself, collecting answers for `wait`.
pub async fn query(
    local_ip: Ipv4Addr,
    targets: &[Ipv4Addr],
    wait: Duration,
) -> HashMap<Ipv4Addr, SnmpInfo> {
    let mut found: HashMap<Ipv4Addr, SnmpInfo> = HashMap::new();
    if targets.is_empty() {
        return found;
    }
    let Ok(sock) = UdpSocket::bind((local_ip, 0)).await else {
        return found;
    };
    let deadline = Instant::now() + wait;
    // SNMPv1 refuses a whole request over one object it doesn't have, so
    // what only printers have is asked for on its own.
    let system = get_request(1, &[SYS_DESCR, SYS_OBJECT_ID, SYS_NAME]);
    let device = get_request(2, &[HR_DEVICE_DESCR]);
    for &ip in targets {
        let _ = sock.send_to(&system, (ip, PORT)).await;
        let _ = sock.send_to(&device, (ip, PORT)).await;
    }
    let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut buf = vec![0u8; 1500];
    while let Ok(Ok((n, SocketAddr::V4(src)))) =
        timeout_at(deadline, sock.recv_from(&mut buf)).await
    {
        if wanted.contains(src.ip()) {
            parse_reply(&buf[..n], found.entry(*src.ip()).or_default());
        }
    }
    found.retain(|_, info| *info != SnmpInfo::default());
    found
}

/// A value with its tag and length. Everything we send is shorter than the
/// 128 bytes a one-byte length can say.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, value.len() as u8];
    out.extend_from_slice(value);
    out
}

/// An SNMPv1 GetRequest for `oids`.
fn get_request(id: u8, oids: &[&[u8]]) -> Vec<u8> {
    let bindings: Vec<u8> = oids
        .iter()
        .flat_map(|oid| tlv(SEQUENCE, &[tlv(OBJECT_ID, oid), tlv(NULL, &[])].concat()))
        .collect();
    let pdu = [
        tlv(INTEGER, &[id]),
        tlv(INTEGER, &[0]), // error status
        tlv(INTEGER, &[0]), // error index
        tlv(SEQUENCE, &bindings),
    ]
    .concat();
    let message = [
        tlv(INTEGER, &[0]), // version 1
        tlv(OCTET_STRING, COMMUNITY),
        tlv(GET_REQUEST, &pdu),
    ]
    .concat();
    tlv(SEQUENCE, &message)
}

/// The next value in `data`: its tag, its contents and what follows it.
fn read(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        // The long form: how many bytes of length (never more than two in
        // a UDP packet), then the length.
        let n = usize::from(first & 0x7f);
        let len = rest.get(..n.min(4))?.iter();
        let len = len.fold(0usize, |len, &b| len << 8 | usize::from(b));
        (len, rest.get(n..)?)
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// The contents of the next value in `data`, if it has this `tag`.
fn expect(data: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (found, value, rest) = read(data)?;
    (found == tag).then_some((value, rest))
}

/// Add what a GetResponse says to `info`. One that reports an error, or
/// isn't a response at all, adds nothing.
fn parse_reply(pkt: &[u8], info: &mut SnmpInfo) -> Option<()> {
    let (message, _) = expect(pkt, SEQUENCE)?;
    let (_version, rest) = expect(message, INTEGER)?;
    let (_community, rest) = expect(rest, OCTET_STRING)?;
    let (pdu, _) = expect(rest, GET_RESPONSE)?;
    let (_id, rest) = expect(pdu, INTEGER)?;
    let (status, rest) = expect(rest, INTEGER)?;
    if status.iter().any(|&b| b != 0) {
        return None;
    }
    let (_index, rest) = expect(rest, INTEGER)?;
    let (mut bindings, _) = expect(rest, SEQUENCE)?;
    while let Some((binding, rest)) = expect(bindings, SEQUENCE) {
        bindings = rest;
        let (oid, value) = expect(binding, OBJECT_ID)?;
        let (tag, value, _) = read(value)?;
        let slot = match (oid, tag) {
            (SYS_DESCR, OCTET_STRING) => &mut info.description,
            (SYS_NAME, OCTET_STRING) => &mut info.name,
            (HR_DEVICE_DESCR, OCTET_STRING) => &mut info.device,
            (SYS_OBJECT_ID, OBJECT_ID) => {
                info.object_id = dotted(value);
                continue;
            }
            _ => continue,
        };
        *slot = text(value);
    }
    Some(())
}

/// A description as one line: Cisco's runs to several.
fn text(value: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(value);
    let line = text
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!line.is_empty()).then_some(line)
}

/// An object identifier as people write it: "1.3.6.1.4.1.2435.2.3.9.1".
fn dotted(oid: &[u8]) -> Option<String> {
    let (&first, rest) = oid.split_first()?;
    let mut parts = vec![u32::from(first / 40), u32::from(first % 40)];
    let mut part = 0u32;
    for &b in rest {
        part = part.checked_shl(7)? | u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            parts.push(part);
            part = 0;
        }
    }
    let parts: Vec<String> = parts.iter().map(u32::to_string).collect();
    Some(parts.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GetResponse binding each of `values` (a tag and its contents).
    fn reply(status: u8, values: &[(&[u8], u8, &[u8])]) -> Vec<u8> {
        // Long-form lengths throughout, as real agents send for long values.
        fn long(tag: u8, value: &[u8]) -> Vec<u8> {
            let len = value.len() as u16;
            let mut out = vec![tag, 0x82, (len >> 8) as u8, len as u8];
            out.extend_from_slice(value);
            out
        }
        let bindings: Vec<u8> = values
            .iter()
            .flat_map(|(oid, tag, value)| {
                long(SEQUENCE, &[tlv(OBJECT_ID, oid), long(*tag, value)].concat())
            })
            .collect();
        let pdu = [
            tlv(INTEGER, &[1]),
            tlv(INTEGER, &[status]),
            tlv(INTEGER, &[0]),
            long(SEQUENCE, &bindings),
        ]
        .concat();
        let message = [
            tlv(INTEGER, &[0]),
            tlv(OCTET_STRING, COMMUNITY),
            long(GET_RESPONSE, &pdu),
        ]
        .concat();
        long(SEQUENCE, &message)
    }

    #[test]
    fn asks_for_the_system_group() {
        let pkt = get_request(1, &[SYS_DESCR]);
        assert_eq!(
            pkt,
            [
                0x30, 0x26, // message
                0x02, 0x01, 0x00, // version 1
                0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', //
                0xa0, 0x19, // GetRequest
                0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, // id, no error
                0x30, 0x0e, 0x30, 0x0c, // bindings, the binding
                0x06, 0x08, 0x2b, 6, 1, 2, 1, 1, 1, 0, // sysDescr.0
                0x05, 0x00, // null
            ]
        );
        // Three objects still fit a one-byte length.
        assert!(get_request(1, &[SYS_DESCR, SYS_OBJECT_ID, SYS_NAME]).len() < 128);
    }

    #[test]
    fn reads_what_a_printer_says() {
        let mut info = SnmpInfo::default();
        let brother: &[u8] = &[0x2b, 6, 1, 4, 1, 0x93, 0x03, 2, 3, 9, 1];
        let system = reply(
            0,
            &[
                (
                    SYS_DESCR,
                    OCTET_STRING,
                    b"Brother NC-8900w, Firmware Ver.1.20\r\n (17.11.21)",
                ),
                (SYS_OBJECT_ID, OBJECT_ID, brother),
                (SYS_NAME, OCTET_STRING, b"BRW001BA9D2E1F0"),
            ],
        );
        assert!(parse_reply(&system, &mut info).is_some());
        let device = reply(
            0,
            &[(HR_DEVICE_DESCR, OCTET_STRING, b"Brother HL-L2350DW series")],
        );
        assert!(parse_reply(&device, &mut info).is_some());
        assert_eq!(
            info.description.as_deref(),
            Some("Brother NC-8900w, Firmware Ver.1.20 (17.11.21)")
        );
        assert_eq!(info.object_id.as_deref(), Some("1.3.6.1.4.1.2435.2.3.9.1"));
        assert_eq!(info.maker(), Some("Brother"));
        assert_eq!(info.name.as_deref(), Some("BRW001BA9D2E1F0"));
        assert_eq!(info.device.as_deref(), Some("Brother HL-L2350DW series"));
    }

    #[test]
    fn errors_and_other_packets_add_nothing() {
        let mut info = SnmpInfo::default();
        // noSuchName: it has no such device.
        let refused = reply(2, &[(HR_DEVICE_DESCR, NULL, b"")]);
        assert!(parse_reply(&refused, &mut info).is_none());
        // Our own request, a reply cut short, and noise.
        assert!(parse_reply(&get_request(1, &[SYS_DESCR]), &mut info).is_none());
        let full = reply(0, &[(SYS_NAME, OCTET_STRING, b"switch")]);
        assert!(parse_reply(&full[..full.len() - 3], &mut info).is_none());
        assert!(parse_reply(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff], &mut info).is_none());
        assert!(parse_reply(b"", &mut info).is_none());
        // An empty name is no name.
        let blank = reply(0, &[(SYS_NAME, OCTET_STRING, b" ")]);
        assert!(parse_reply(&blank, &mut info).is_some());
        assert_eq!(info, SnmpInfo::default());
    }

    #[test]
    fn makers_go_by_enterprise_number() {
        let by = |id: &str| {
            let info = SnmpInfo {
                object_id: Some(id.into()),
                ..Default::default()
            };
            info.maker()
        };
        assert_eq!(by("1.3.6.1.4.1.14988.1"), Some("MikroTik"));
        assert_eq!(by("1.3.6.1.4.1.318.1.3.27"), Some("APC"));
        // net-snmp on Linux: the agent, not the device.
        assert_eq!(by("1.3.6.1.4.1.8072.3.2.10"), None);
        assert_eq!(by("1.3.6.1.2.1.1"), None);
    }
}
