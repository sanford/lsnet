# lsnet

**See what's on your local network.** `lsnet` finds every device on your LAN and tells you what each one is (an Apple TV, a printer, a smart plug, a NAS) in about two seconds, with no configuration and no flags to learn.

```
$ lsnet
 IP             NAME                 TYPE                    MODEL
 192.168.1.1    Home Router          Router (gateway)        Netgear RAX50
 192.168.1.8    Brother HL-L2350DW   Printer                 Brother HL-L2350DW series
 192.168.1.14   diskstation          NAS                     Synology DS920+
 192.168.1.52   Living Room          TV / streamer           Apple TV 4K (3rd gen)
 192.168.1.60   Kitchen              Speaker                 HomePod mini
 192.168.1.71   Office speaker       Speaker                 Google Nest Mini
 192.168.1.88   kp115                Smart plug              TP-Link Kasa KP115
 192.168.1.90   Hallway              Camera                  Blink Mini
 192.168.1.112  alex-phone           Phone / tablet          iPhone / iPad
 192.168.1.150  pihole               DNS server              Pi-hole
 192.168.1.196  Alex's MacBook Pro   Computer (this device)  MacBook Pro (M4)

11 devices on 192.168.1.0/24 (en0) in 2.0s
```

It's meant to answer the question "what is that?" faster and more simply than [nmap](https://nmap.org). It isn't a port scanner or a security tool.

## Features

- **Zero config.** It detects your interface, subnet and gateway on its own.
- **Fast.** Every discovery method runs concurrently, and a /24 takes about 2 seconds.
- **Identifies devices, not just addresses.** It combines what devices announce about themselves (Bonjour, UPnP), their naming conventions, web UI banners, open ports and MAC vendors into a type and a model.
- **Works without root.** On Linux you even get MAC addresses and vendors without it.
- **macOS and Linux.**
- **Scriptable.** `--json` outputs every piece of evidence behind each identification.

## Install

You'll need a [Rust toolchain](https://rustup.rs). lsnet runs on macOS and Linux (x86_64 and 64-bit ARM, including 64-bit Raspberry Pi OS).

```sh
cargo install --git https://github.com/sanford/lsnet
```

Or build from source:

```sh
git clone https://github.com/sanford/lsnet
cd lsnet
cargo build --release
./target/release/lsnet
```

While hacking on it, `./run.sh [ARGS]` builds, installs to `~/.local/bin`, and runs in one step.

## Usage

```
lsnet [OPTIONS]

  -i, --interface <NAME>  Network interface to scan (default: the one your internet traffic uses)
  -v, --verbose           Also show hostnames, open ports and advertised services
      --json              Print results as JSON
  -t, --timeout <MS>      How long to wait for devices to answer [default: 1200]
      --no-dns            Skip reverse DNS lookups
```

Some examples:

```sh
lsnet                  # scan the local network
sudo lsnet             # also show MAC addresses and vendors
lsnet -v               # show the evidence: hostnames, ports, services
lsnet -t 3000          # wait longer for sleepy Wi-Fi devices
lsnet --json | jq '.[] | select(.type == "Printer")'
```

### Device names

The NAME column shows the friendliest name a device gives itself, in this order:

1. The name set in its app or settings, from Bonjour or UPnP ("Living Room", "Office speaker")
2. Its `.local` hostname, kept whole ("octopi.local", "homeassistant.local")
3. The host part of its DNS name from your router ("fhrouter")

`.local` names are shown in full because you can use them directly, even when the device's IP address changes. Try `http://octopi.local` in a browser, or `ssh pi@octopi.local`. Machine-generated names like `36814e2569ca121f.local` are hidden. Run `lsnet --json` to see every name a device reported, including its `.local` hostname under `mdns.hostname`.

## How it works

`lsnet` runs these at the same time:

| Source | What it finds | Needs root |
|---|---|---|
| **ARP sweep** | Every device that has an IP address, including ones with no open ports, plus its MAC address | yes (or `CAP_NET_RAW` on Linux) |
| **ARP cache** | MAC addresses the kernel learned during the scan | no (Linux only) |
| **TCP probe** | Live hosts, since even a refused connection proves a device is there, and which common ports are open | no |
| **mDNS / Bonjour** | Friendly names ("Living Room") and model identifiers from TXT records (`AppleTV14,1`, Chromecast `md=`, printer `ty=`, HomeKit categories) | no |
| **SSDP / UPnP** | Manufacturer, model and name from each device's UPnP description, which is how routers, TVs and NASes usually identify themselves | no |
| **Reverse DNS** | Hostnames from your router's DHCP leases | no |
| **HTTP banner** | `Server` header and page `<title>` from web UIs | no |

Then it classifies each device using the most specific evidence available: what the device says about its own model, then naming conventions, then web banners, then advertised services, then open ports, then the MAC vendor. The vendor database comes from the IEEE registry and is built into the binary, so no network lookups are needed.

### Running without sudo

Without root, `lsnet` can't send its own ARP packets. It finds devices with the TCP probe and the discovery protocols instead, and how much else you get depends on the OS:

- **Linux:** almost nothing is lost. The TCP probe makes the kernel look up the MAC of every live address, and `lsnet` reads the results from `/proc/net/arp`. That gives MACs and vendors, and even finds devices with no open ports.
- **macOS:** recent versions don't let binaries that aren't Apple-signed read the ARP table or MAC addresses. Without `sudo`, the VENDOR and MAC columns are hidden, devices are identified from what they announce, and devices that are both silent and fully firewalled are missed.

On Linux, you can give the binary raw-socket access once instead of using `sudo` every time:

```sh
sudo setcap cap_net_raw+ep "$(which lsnet)"
```

### Firewalls

mDNS and SSDP replies come back to `lsnet` as unicast packets from each device. A host firewall that blocks unsolicited incoming UDP can silently drop them, for example `ufw` or `firewalld` with default settings on some Linux distributions. The scan still works, but names and models will be missing. If `lsnet -v` shows no SERVICES for devices you know advertise them, check the firewall.

## Output fields

In `--json`, each device includes:

| Field | Meaning |
|---|---|
| `ip`, `mac`, `vendor` | Address, hardware address, and manufacturer from the MAC prefix |
| `name` | The friendliest name the device gives itself |
| `type`, `model` | What `lsnet` thinks the device is |
| `hostname` | Reverse DNS name |
| `randomized_mac` | The device uses a private, per-network MAC (typical of phones and laptops) |
| `open_ports` | Which of the probed ports (22, 80, 443, 445, 7000, 8008, 9100, 62078) are open |
| `gateway`, `this_device` | Your router, and the machine running the scan |
| `mdns`, `ssdp`, `http` | The raw evidence: services, TXT records, UPnP description fields, web banner |

## Limitations

- **macOS and Linux only.** Windows isn't supported. The raw-packet library needs Npcap there.
- **IPv4 only.** Networks larger than /22 are narrowed to your local /24 to keep scans fast.
- **Identification is heuristic.** Devices that announce nothing and have no open ports show up as `?`. Running with `sudo` at least adds their vendor.
- **The Linux ARP cache can be stale.** Entries for devices that just left the network can linger for a few seconds after they disconnect.
- **Sleepy devices can be missed.** Phones and IoT devices in Wi-Fi power-save mode may not answer within the default window. Use `-t` to wait longer.

## Updating the vendor database

MAC vendor names come from Wireshark's copy of the IEEE OUI registry, cleaned up (for example "Apple, Inc." becomes "Apple") and stored in `data/oui.tsv`. To refresh it:

```sh
python3 scripts/update-oui.py
```

## Contributing

Better identification rules are the most useful contribution. If `lsnet` shows `?` or gets a device wrong, open an issue with the output of `lsnet --json` for that device, with anything private removed. The rules live in [`src/classify.rs`](src/classify.rs).

## License

Copyright (C) 2026 Sanford Lincoln

`lsnet` is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE).
