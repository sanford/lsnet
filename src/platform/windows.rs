//! Windows, through the IP Helper API. Everything here works without
//! administrator rights, and none of it needs Npcap.

use super::Adapter;
use ipnetwork::Ipv4Network;
use pnet_base::MacAddr;
use std::net::Ipv4Addr;
use std::os::windows::io::AsRawSocket;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, GlobalFree, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetIfEntry2, GetIpNetTable2, IF_TYPE_SOFTWARE_LOOPBACK,
    IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2, MIB_IPNET_TABLE2, SendARP,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, NlnsIncomplete, SIO_TCP_INITIAL_RTO, SOCKADDR, SOCKADDR_IN, SOCKET, TCP_INITIAL_RTO_PARAMETERS,
    WSAIoctl,
};
use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

pub fn adapters() -> Vec<Adapter> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // The list's size isn't known up front: ask, and grow the buffer if told to.
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64>; // u64 for the structs' alignment
    loop {
        buf = vec![0; (size as usize).div_ceil(8)];
        let ret = unsafe {
            GetAdaptersAddresses(u32::from(AF_INET), flags, ptr::null(), buf.as_mut_ptr().cast(), &mut size)
        };
        match ret {
            NO_ERROR => break,
            ERROR_BUFFER_OVERFLOW => continue,
            _ => return Vec::new(),
        }
    }

    let mut out = Vec::new();
    let mut next = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while let Some(a) = unsafe { next.as_ref() } {
        next = a.Next;
        let index = unsafe { a.Anonymous1.Anonymous.IfIndex };
        let mut ips = Vec::new();
        let mut addr = a.FirstUnicastAddress;
        while let Some(u) = unsafe { addr.as_ref() } {
            if let Some(ip) = unsafe { ipv4(u.Address.lpSockaddr) }
                && let Ok(net) = Ipv4Network::new(ip, u.OnLinkPrefixLength)
            {
                ips.push(net);
            }
            addr = u.Next;
        }
        let gateway = unsafe { a.FirstGatewayAddress.as_ref() }.and_then(|g| unsafe { ipv4(g.Address.lpSockaddr) });
        let m = &a.PhysicalAddress;
        out.push(Adapter {
            name: unsafe { wide_str(a.FriendlyName) },
            index,
            mac: (a.PhysicalAddressLength == 6).then(|| MacAddr::new(m[0], m[1], m[2], m[3], m[4], m[5])),
            ips,
            up: a.OperStatus == IfOperStatusUp,
            loopback: a.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
            physical: is_hardware(index),
            gateway,
        });
    }
    out
}

/// Hyper-V and WSL switches look like Ethernet adapters; only the interface
/// row says whether there's hardware behind one.
fn is_hardware(index: u32) -> bool {
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = index;
    unsafe { GetIfEntry2(&mut row) == NO_ERROR && row.InterfaceAndOperStatusFlags._bitfield & 1 != 0 }
}

pub fn default_gateway(adapter: &Adapter) -> Option<Ipv4Addr> {
    adapter.gateway
}

/// The neighbor table, minus entries that never got an answer.
pub fn arp_cache(adapter: &Adapter) -> Vec<(Ipv4Addr, MacAddr)> {
    let mut table: *mut MIB_IPNET_TABLE2 = ptr::null_mut();
    if unsafe { GetIpNetTable2(AF_INET, &mut table) } != NO_ERROR {
        return Vec::new();
    }
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let found = rows
        .iter()
        .filter(|r| r.InterfaceIndex == adapter.index && r.State > NlnsIncomplete && r.PhysicalAddressLength == 6)
        .map(|r| {
            let ip = Ipv4Addr::from(unsafe { r.Address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes());
            let m = &r.PhysicalAddress;
            (ip, MacAddr::new(m[0], m[1], m[2], m[3], m[4], m[5]))
        })
        .filter(|(_, mac)| *mac != MacAddr::zero())
        .collect();
    unsafe { FreeMibTable(table.cast()) };
    found
}

/// Ask `target` for its MAC address with a real ARP request, sent from the
/// adapter that owns `source`. Blocks until it answers or Windows gives up
/// (a few seconds).
pub fn send_arp(target: Ipv4Addr, source: Ipv4Addr) -> Option<MacAddr> {
    let mut mac = [0u8; 8];
    let mut len = mac.len() as u32;
    let ret = unsafe {
        SendARP(
            u32::from_ne_bytes(target.octets()),
            u32::from_ne_bytes(source.octets()),
            mac.as_mut_ptr().cast(),
            &mut len,
        )
    };
    (ret == NO_ERROR && len == 6).then(|| MacAddr::new(mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]))
}

/// Windows answers a refused connection (RST) by trying again, so a closed
/// port takes about two seconds to fail instead of a round trip. Without SYN
/// retransmissions it fails at once, as on other systems.
pub fn fail_fast_on_refusal(sock: &impl AsRawSocket) {
    let params = TCP_INITIAL_RTO_PARAMETERS {
        Rtt: 0, // the default
        MaxSynRetransmissions: TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS,
    };
    let mut returned = 0u32;
    unsafe {
        WSAIoctl(
            sock.as_raw_socket() as SOCKET,
            SIO_TCP_INITIAL_RTO,
            (&raw const params).cast(),
            size_of::<TCP_INITIAL_RTO_PARAMETERS>() as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
            None,
        );
    }
}

/// `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS` is `(UCHAR)-2` in the SDK;
/// windows-sys widens it to a u16.
const TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS: u8 = 0xfe;

pub fn set_clipboard(text: &str) -> bool {
    let wide: Vec<u16> = text.encode_utf16().chain([0]).collect();
    unsafe {
        if OpenClipboard(ptr::null_mut()) == 0 {
            return false;
        }
        EmptyClipboard();
        let mem = GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2);
        let dst = if mem.is_null() { ptr::null_mut() } else { GlobalLock(mem).cast::<u16>() };
        let ok = !dst.is_null() && {
            ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
            GlobalUnlock(mem);
            // On success the clipboard owns the memory.
            !SetClipboardData(u32::from(CF_UNICODETEXT), mem).is_null()
        };
        if !ok && !mem.is_null() {
            GlobalFree(mem);
        }
        CloseClipboard();
        ok
    }
}

unsafe fn ipv4(sa: *const SOCKADDR) -> Option<Ipv4Addr> {
    let sa = unsafe { sa.as_ref() }?;
    if sa.sa_family != AF_INET {
        return None;
    }
    let sin = unsafe { &*(sa as *const SOCKADDR).cast::<SOCKADDR_IN>() };
    Some(Ipv4Addr::from(unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes()))
}

unsafe fn wide_str(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "replaces the clipboard's contents"]
    fn clipboard_takes_unicode() {
        assert!(set_clipboard("Sanford’s Mac mini · 192.168.1.179"));
    }
}
