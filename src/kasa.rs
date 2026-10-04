//! TP-Link Kasa discovery. Kasa plugs, switches and bulbs answer a broadcast
//! on UDP 9999 with their system info, including the name their owner gave
//! them in the app. The protocol "encrypts" JSON with a rolling XOR.
//!
//! Newer firmware (and Tapo devices) only speak an authenticated protocol,
//! so they stay silent here.

use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};

const PORT: u16 = 9999;
const QUERY: &str = r#"{"system":{"get_sysinfo":{}}}"#;

#[derive(Clone, Serialize, Deserialize)]
pub struct KasaInfo {
    /// The name set in the Kasa app, e.g. "Living Room Lamp".
    pub alias: Option<String>,
    /// e.g. "HS105(US)".
    pub model: Option<String>,
    /// e.g. "Smart Wi-Fi Plug Mini".
    #[serde(alias = "dev_name")]
    pub description: Option<String>,
    /// e.g. "IOT.SMARTPLUGSWITCH" or "IOT.SMARTBULB". Plugs call it
    /// `type` and bulbs `mic_type`; some firmware sends both.
    #[serde(rename = "type")]
    pub device_type: Option<String>,
    #[serde(skip_serializing)]
    mic_type: Option<String>,
}

/// Broadcast the query, again a third of the way in for devices that missed
/// it, and collect answers for `wait`.
pub async fn discover(
    local_ip: Ipv4Addr,
    net: Ipv4Network,
    wait: Duration,
) -> HashMap<Ipv4Addr, KasaInfo> {
    let mut found = HashMap::new();
    let Ok(sock) = UdpSocket::bind((local_ip, 0)).await else {
        return found;
    };
    if sock.set_broadcast(true).is_err() {
        return found;
    }
    let query = xor_encrypt(QUERY.as_bytes());
    let send = || async {
        let _ = sock.send_to(&query, (net.broadcast(), PORT)).await;
    };
    send().await;

    let deadline = Instant::now() + wait;
    let resend_at = Instant::now() + wait / 3;
    let mut resent = false;
    let mut buf = vec![0u8; 4096];
    loop {
        let until = if resent { deadline } else { resend_at };
        match timeout_at(until, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, SocketAddr::V4(src)))) if net.contains(*src.ip()) => {
                if let Some(info) = parse(&xor_decrypt(&buf[..n])) {
                    found.insert(*src.ip(), info);
                }
            }
            Ok(_) => {}
            Err(_) if !resent => {
                resent = true;
                send().await;
            }
            Err(_) => break,
        }
    }
    found
}

fn parse(json: &[u8]) -> Option<KasaInfo> {
    #[derive(Deserialize)]
    struct Reply {
        system: System,
    }
    #[derive(Deserialize)]
    struct System {
        get_sysinfo: KasaInfo,
    }
    let mut info = serde_json::from_slice::<Reply>(json)
        .ok()?
        .system
        .get_sysinfo;
    info.device_type = info.device_type.or(info.mic_type.take());
    Some(info)
}

/// Each byte is XORed with the previous ciphertext byte, starting from 171.
fn xor_encrypt(plain: &[u8]) -> Vec<u8> {
    let mut key = 171u8;
    plain
        .iter()
        .map(|&b| {
            key ^= b;
            key
        })
        .collect()
}

fn xor_decrypt(cipher: &[u8]) -> Vec<u8> {
    let mut key = 171u8;
    cipher
        .iter()
        .map(|&b| {
            let plain = key ^ b;
            key = b;
            plain
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        assert_eq!(
            xor_decrypt(&xor_encrypt(QUERY.as_bytes())),
            QUERY.as_bytes()
        );
        // The first byte of every query is '{' ^ 171.
        assert_eq!(xor_encrypt(b"{")[0], 0xd0);
    }

    #[test]
    fn sysinfo() {
        let reply = br#"{"system":{"get_sysinfo":{"sw_ver":"1.0.6","model":"HS105(US)",
            "dev_name":"Smart Wi-Fi Plug Mini","alias":"Living Room Lamp",
            "mic_type":"IOT.SMARTPLUGSWITCH","relay_state":1}}}"#;
        let info = parse(reply).unwrap();
        assert_eq!(info.alias.as_deref(), Some("Living Room Lamp"));
        assert_eq!(info.model.as_deref(), Some("HS105(US)"));
        assert_eq!(info.description.as_deref(), Some("Smart Wi-Fi Plug Mini"));
        assert_eq!(info.device_type.as_deref(), Some("IOT.SMARTPLUGSWITCH"));
        assert!(parse(b"{}").is_none());
    }
}
