# lsnet

**See what's on your local network.** `lsnet` finds every device on your LAN and tells you what each one is (an Apple TV, a printer, a smart plug, a NAS) in about two seconds, with no configuration and no flags to learn.

```
$ lsnet
 lsnet  14 devices on 192.168.1.0/24 (en0) in 2.0s
┌ Devices (14) ─────────────────────────────────────────────┐┌ Living Room ──────────────────────────────────┐
│  IP              NAME               TYPE                  ││ TV / streamer · Apple TV 4K (3rd gen)         │
│  192.168.1.1     Home Router        Router (gateway)      ││                                               │
│  192.168.1.8     Brother HL-L2350DW Printer               ││ IP             192.168.1.52                   │
│  192.168.1.14    diskstation        NAS                   ││ Hostname       living-room                    │
│› 192.168.1.52    Living Room        TV / streamer         ││ Open ports     7000 AirPlay · 62078 iOS sync  │
│  192.168.1.60    Kitchen            Speaker               ││                                               │
│  192.168.1.71    Office speaker     Speaker               ││ Bonjour (mDNS)                                │
│  192.168.1.88    kp115              Smart plug            ││ Name           Living-Room.local              │
│  192.168.1.90    blink-mini         Camera                ││ airplay        Living Room                    │
│  192.168.1.112   alex-phone         Phone / tablet        ││                model = AppleTV14,1            │
│  192.168.1.130   raspberrypi.local  Computer              ││ raop           6C4A85D1E0F2@Living Room       │
│  192.168.1.150   pihole             DNS server            ││                am = AppleTV14,1               │
│  192.168.1.196   Alex's MacBook Pro Computer (this device)││ companion-link Living Room                    │
│  192.168.1.201   ·                  Computer              ││                rpmd = AppleTV14,1             │
│  192.168.1.203   ·                                        ││                                               │
│                                                           ││                                               │
└───────────────────────────────────────────────────────────┘└───────────────────────────────────────────────┘
 ↑↓ move  tab services  ⏎ copy IP  c copy details  / filter  r rescan  ? help  q quit
```

It's meant to answer the question "what is that?" faster and more simply than [nmap](https://nmap.org). It isn't a port scanner or a security tool.

## Features

- **Zero config.** It detects your interface, subnet and gateway on its own.
- **Fast.** Every discovery method runs concurrently, and a /24 takes about 2 seconds.
- **Identifies devices, not just addresses.** It combines what devices announce about themselves (Bonjour, UPnP), their naming conventions, web UI banners, open ports (including homelab staples like Proxmox, Plex and Home Assistant) and MAC vendors into a type and a model.
- **Works without root.** On Linux and Windows you even get MAC addresses and vendors without it.
- **macOS, Linux and Windows.**
- **Browse or print.** In a terminal, `lsnet` opens a browser with everything known about each device. When piped, or with `-l`, it prints a table.
- **Find your servers.** `Tab` in the browser, or `-s`, lists every service on the network (web UIs, SSH, file shares, databases, Plex, Proxmox, Home Assistant) with the address to reach it.
- **Scriptable.** `--json` outputs every piece of evidence behind each identification.

## Install

lsnet runs on macOS, Linux (x86_64 and 64-bit ARM, including 64-bit Raspberry Pi OS) and Windows 10 or later (x86_64).

With [Homebrew](https://brew.sh), on macOS and Linux:

```sh
brew install sanford/tap/lsnet
```

With Cargo, if you have a [Rust toolchain](https://rustup.rs) (on Windows, see [below](#installing-rust-on-windows)):

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

While hacking on it, `./run.sh [ARGS]` (or `.\run.ps1 [ARGS]` on Windows) builds, installs to `~/.local/bin`, and runs in one step.

### Installing Rust on Windows

Rust on Windows uses Microsoft's C++ linker, so it needs the Visual Studio Build Tools as well as Rust itself. Both install with `winget`, from PowerShell:

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install Rustlang.Rustup
```

The first command installs the "Desktop development with C++" workload, about 2 GB, and takes a while. If the Build Tools are already installed, it fails with "already installed", which is fine. Add the workload from the Visual Studio Installer instead if it's missing.

Then open a new terminal, so `cargo` is on your `PATH`, and check that it works:

```powershell
cargo --version
cargo install --git https://github.com/sanford/lsnet
lsnet
```

`lsnet` needs no administrator rights on Windows. If the scan finds devices but no names or models, check that Windows has the network set to Private rather than Public (see [Firewalls](#firewalls)).

## Usage

```
lsnet [OPTIONS]

  -i, --interface <NAME>  Network interface to scan (default: the one your internet traffic uses)
  -l, --list              Print a table instead of opening the device browser
  -v, --verbose           Print a table that also shows hostnames, open ports and advertised services
  -s, --services          List the services running on the network instead of devices
      --json              Print results as JSON
  -t, --timeout <MS>      How long to wait for devices to answer [default: 1200]
      --no-dns            Skip reverse DNS lookups
```

Some examples:

```sh
lsnet                  # browse the devices on your network
lsnet -l               # just print the list
sudo lsnet             # also show MAC addresses and vendors
lsnet -v               # show the evidence: hostnames, ports, services
lsnet -s -l            # print every service and its address
lsnet -t 3000          # wait longer for sleepy Wi-Fi devices
lsnet --json | jq '.[] | select(.type == "Printer")'
```

### The device browser

Run in a terminal, `lsnet` opens the browser shown at the top. Devices are listed on the left, and everything `lsnet` learned about the selected one is on the right: open ports, Bonjour services with their TXT records, UPnP details and the web page banner. Press `?` to see every key:

| Key | Action |
|---|---|
| `↑` `↓` or `j` `k` | Move through the list |
| `g` `G` or `Home` `End` | Jump to the first or last row |
| `Tab` | Switch between devices and services |
| `Enter` or `y` | Copy the selected IP address (or, for a service, its address and port) to the clipboard |
| `c` | Copy all the details to the clipboard as plain text |
| `PgUp` `PgDn` or `Ctrl-u` `Ctrl-d` | Scroll the details by half a page |
| `J` `K` | Scroll the details by one line |
| `/` | Filter by IP, name, type, model, vendor, MAC or hostname, and in the services view by port or service. `Enter` keeps the filter, `Esc` clears it |
| `r` | Scan again, keeping your place |
| `Esc` | Clear the filter, or quit if there isn't one |
| `h` or `?` | Show all the keys |
| `q` or `Ctrl-c` | Quit |

Selecting text with the mouse picks up both panes, so use `c` to copy the details instead. It copies every line, including any scrolled out of view, without wrapping. In narrow terminals the details appear below the list instead of beside it. Copying uses `pbcopy` on macOS, `wl-copy`, `xclip` or `xsel` on Linux, and the clipboard directly on Windows. Without any of those, `lsnet` asks the terminal to do the copy, which also works over SSH in most modern terminals.

### The services view

Press `Tab` in the browser, or start it with `lsnet -s`, to list services instead of devices: one row per server, sorted by address, with the device's details beside it as usual.

```
$ lsnet -s
 lsnet  14 devices on 192.168.1.0/24 (en0) in 2.0s
┌ Services (21) ───────────────────────────────────────┐┌ diskstation ────────────────────────────────────────┐
│  ADDRESS            SERVICE        HOST              ││ NAS · Synology DS920+                               │
│  192.168.1.1:53     DNS            Home Router       ││                                                     │
│  192.168.1.1:80     HTTP           Home Router       ││ IP            192.168.1.14                          │
│  192.168.1.1:443    HTTPS          Home Router       ││ Hostname      diskstation                           │
│  192.168.1.8:80     HTTP           Brother HL-L2350DW││ Open ports    22 SSH · 80 HTTP · 139 NetBIOS · 443  │
│  192.168.1.8:443    HTTPS          Brother HL-L2350DW││               HTTPS · 445 SMB · 5001 HTTPS · 32400  │
│  192.168.1.8:9100   printing       Brother HL-L2350DW││               Plex                                  │
│  192.168.1.14:22    SSH            diskstation       ││                                                     │
│  192.168.1.14:80    HTTP           diskstation       ││ Bonjour (mDNS)                                      │
│  192.168.1.14:139   NetBIOS        diskstation       ││ Name          diskstation.local                     │
│  192.168.1.14:443   HTTPS          diskstation       ││ smb           diskstation                           │
│  192.168.1.14:445   SMB            diskstation       ││                                                     │
│  192.168.1.14:5001  HTTPS          diskstation       ││ Web (port 80)                                       │
│› 192.168.1.14:32400 Plex           diskstation       ││ Title         diskstation - Synology DiskStation    │
│  192.168.1.88:80    HTTP           kp115             ││ Server        nginx                                 │
│  192.168.1.130:22   SSH            raspberrypi.local ││                                                     │
│  192.168.1.130:1883 MQTT           raspberrypi.local ││                                                     │
│  192.168.1.130:8123 Home Assistant raspberrypi.local ││                                                     │
│  192.168.1.150:22   SSH            pihole            ││                                                     │
│  192.168.1.150:53   DNS            pihole            ││                                                     │
│  192.168.1.150:80   HTTP           pihole            ││                                                     │
│  192.168.1.201:3389 RDP            ·                 ││                                                     │
└──────────────────────────────────────────────────────┘└─────────────────────────────────────────────────────┘
 ↑↓ move  tab devices  ⏎ copy address  c copy details  / filter  r rescan  ? help  q quit
```

It lists the open ports `lsnet` found (all but AirPlay, Cast and iPhone sync, which are how devices talk to phones rather than servers) plus the web, SSH, file-sharing, VNC and similar services devices advertise over Bonjour, on whatever port they use. This machine's own services aren't listed, since `lsnet` doesn't probe it. `lsnet -s -l` prints the same list as a table (see [Text output](#text-output)), and `lsnet -s --json` gives `ip`, `port`, `service` and `host` for each.

### Text output

When you quit the browser, `lsnet` prints the results as a table, so they stay in your terminal after it closes. To skip the browser and print the table straight away, use `-l`. `lsnet` also skips the browser when its output is piped or redirected, and with `-v` or `--json`.

```
$ lsnet -l
 IP             NAME                TYPE                    MODEL
 192.168.1.1    Home Router         Router (gateway)        Netgear RAX50
 192.168.1.8    Brother HL-L2350DW  Printer                 Brother HL-L2350DW series
 192.168.1.14   diskstation         NAS                     Synology DS920+
 192.168.1.52   Living Room         TV / streamer           Apple TV 4K (3rd gen)
 192.168.1.60   Kitchen             Speaker                 HomePod mini
 192.168.1.71   Office speaker      Speaker                 Google Nest Mini
 192.168.1.88   kp115               Smart plug              TP-Link Kasa KP115
 192.168.1.90   blink-mini          Camera                  Blink Mini
 192.168.1.112  alex-phone          Phone / tablet          iPhone / iPad
 192.168.1.130  raspberrypi.local   Computer                Raspberry Pi
 192.168.1.150  pihole              DNS server              Pi-hole
 192.168.1.196  Alex's MacBook Pro  Computer (this device)  MacBook Pro (M4)
 192.168.1.201  ..................  Computer                .........................
 192.168.1.203  ..................  ......................  .........................

14 devices on 192.168.1.0/24 (en0) in 2.0s
```

With `-s`, or after quitting the services view, the table lists services instead:

```
$ lsnet -s -l
 ADDRESS             SERVICE         HOST
 192.168.1.1:53      DNS             Home Router
 192.168.1.1:80      HTTP            Home Router
 192.168.1.1:443     HTTPS           Home Router
 192.168.1.8:80      HTTP            Brother HL-L2350DW
 192.168.1.8:443     HTTPS           Brother HL-L2350DW
 192.168.1.8:9100    printing        Brother HL-L2350DW
 192.168.1.14:22     SSH             diskstation
 192.168.1.14:80     HTTP            diskstation
 192.168.1.14:139    NetBIOS         diskstation
 192.168.1.14:443    HTTPS           diskstation
 192.168.1.14:445    SMB             diskstation
 192.168.1.14:5001   HTTPS           diskstation
 192.168.1.14:32400  Plex            diskstation
 192.168.1.88:80     HTTP            kp115
 192.168.1.130:22    SSH             raspberrypi.local
 192.168.1.130:1883  MQTT            raspberrypi.local
 192.168.1.130:8123  Home Assistant  raspberrypi.local
 192.168.1.150:22    SSH             pihole
 192.168.1.150:53    DNS             pihole
 192.168.1.150:80    HTTP            pihole
 192.168.1.201:3389  RDP             ..................

14 devices on 192.168.1.0/24 (en0) in 2.0s
```

### Device names

The NAME column shows the friendliest name a device gives itself, in this order:

1. A name someone set in its app or settings, from AirPlay, HomeKit or Cast ("Living Room", "Office speaker")
2. Its primary `.local` hostname, kept whole ("octopi.local", "homeassistant.local")
3. A generic service or UPnP name (a file share, a printer queue, "Home Router")
4. The host part of its DNS name from your router ("fhrouter")

When MAC vendors are known (always on Linux and Windows, and with `sudo` on macOS), the column becomes NAME/VENDOR. A device with none of the names above shows its manufacturer instead, in regular weight rather than bold, so you can tell it apart from a real name:

```
$ sudo lsnet
 IP             NAME/VENDOR        TYPE            MODEL                  VENDOR         MAC
 192.168.1.52   Living Room        TV / streamer   Apple TV 4K (3rd gen)  Apple          f0:18:98:3c:62:8d
 192.168.1.77   Espressif          IoT device      Espressif              Espressif      24:0a:c4:1d:9e:02
 192.168.1.130  raspberrypi.local  Computer        Raspberry Pi           Raspberry Pi   b8:27:eb:5a:11:c4
 192.168.1.144  .................  Phone / laptop  .....................  (private MAC)  3a:91:5c:e2:07:1b
```

Empty cells are filled with dimmed dots, so even a row with little information is easy to follow from its IP address across to the columns on the right.

`.local` names are shown in full because you can use them directly, even when the device's IP address changes. Try `http://octopi.local` in a browser, or `ssh pi@octopi.local`. Machine-generated names like `36814e2569ca121f.local` are hidden. Run `lsnet --json` to see every name a device reported, including its `.local` hostname under `mdns.hostname`.

## How it works

`lsnet` runs these at the same time:

| Source | What it finds | Needs root |
|---|---|---|
| **ARP sweep** | Every device that has an IP address, including ones with no open ports, plus its MAC address | yes (or `CAP_NET_RAW` on Linux); no on Windows |
| **ARP cache** | MAC addresses the kernel learned during the scan | no (Linux only) |
| **TCP probe** | Live hosts, since even a refused connection proves a device is there. Every host that answers is then checked for common server and homelab ports (databases, Proxmox, Home Assistant, Plex, Jellyfin, RDP) | no |
| **Ping** | Devices that ignore every TCP port but still answer ICMP echo (macOS; on Linux and Windows ARP already covers them) | no |
| **mDNS / Bonjour** | Friendly names ("Living Room") and model identifiers from TXT records (`AppleTV14,1`, Chromecast `md=`, printer `ty=`, HomeKit categories), plus each device's primary `.local` name from a reverse lookup of its address | no |
| **SSDP / UPnP** | Manufacturer, model and name from each device's UPnP description, which is how routers, TVs and NASes usually identify themselves | no |
| **Reverse DNS** | Hostnames from your router's DHCP leases | no |
| **HTTP banner** | `Server` header and page `<title>` from web UIs | no |

Then it classifies each device using the most specific evidence available: what the device says about its own model, then naming conventions, then web banners, then advertised services, then open ports, then the MAC vendor. The vendor database comes from the IEEE registry and is built into the binary, so no network lookups are needed.

### Running without sudo

Without root, `lsnet` can't send its own ARP packets on macOS or Linux. It finds devices with the TCP probe and the discovery protocols instead, and how much else you get depends on the OS:

- **Linux:** almost nothing is lost. The TCP probe makes the kernel look up the MAC of every live address, and `lsnet` reads the results from `/proc/net/arp`. That gives MACs and vendors, and even finds devices with no open ports.
- **macOS:** recent versions don't let binaries that aren't Apple-signed read the ARP table or MAC addresses. Without `sudo`, the VENDOR and MAC columns are hidden, devices are identified from what they announce, and devices that are silent, fully firewalled and ignore pings are missed.
- **Windows:** nothing is lost, and there's no need to run as administrator. Windows sends ARP requests on anyone's behalf, so the full ARP sweep always runs.

On Linux, you can give the binary raw-socket access once instead of using `sudo` every time:

```sh
sudo setcap cap_net_raw+ep "$(which lsnet)"
```

### Firewalls

mDNS and SSDP replies come back to `lsnet` as unicast packets from each device. A host firewall that blocks unsolicited incoming UDP can silently drop them, for example `ufw` or `firewalld` with default settings on some Linux distributions. The scan still works, but names and models will be missing. If `lsnet -v` shows no SERVICES for devices you know advertise them, check the firewall. On Windows, that means making sure the network is set to Private rather than Public.

## Output fields

In `--json`, each device includes:

| Field | Meaning |
|---|---|
| `ip`, `mac`, `vendor` | Address, hardware address, and manufacturer from the MAC prefix |
| `name` | The friendliest name the device gives itself |
| `type`, `model` | What `lsnet` thinks the device is |
| `hostname` | Reverse DNS name |
| `randomized_mac` | The device uses a private, per-network MAC (typical of phones and laptops) |
| `open_ports` | Which of the probed ports are open. Every address is checked for 22, 80, 443, 445, 7000, 8008, 9100 and 62078, and every live device also for 21, 25, 53, 110, 111, 135, 139, 143, 993, 995, 1433, 1521, 1883, 3306, 3389, 5001, 5060, 5432, 5672, 6379, 8000, 8001, 8006, 8080, 8081, 8096, 8123, 8443, 8888, 9090, 9091, 9443, 27017 and 32400 |
| `gateway`, `this_device` | Your router, and the machine running the scan |
| `mdns`, `ssdp`, `http` | The raw evidence: Bonjour services with their TXT records and ports, UPnP description fields, web banner |

## Limitations

- **IPv4 only.** Networks larger than /22 are narrowed to your local /24 to keep scans fast.
- **Identification is heuristic.** Devices that announce nothing and have no open ports show up with no type. Running with `sudo` at least adds their vendor, in the NAME/VENDOR column.
- **The Linux ARP cache can be stale.** Entries for devices that just left the network can linger for a few seconds after they disconnect.
- **Sleepy devices can be missed.** Phones and IoT devices in Wi-Fi power-save mode may not answer within the default window. Use `-t` to wait longer.

## Updating the vendor database

MAC vendor names come from Wireshark's copy of the IEEE OUI registry, cleaned up (for example "Apple, Inc." becomes "Apple") and stored in `data/oui.tsv` along with a license header (see [Third-party data](#third-party-data)). To refresh it:

```sh
python3 scripts/update-oui.py
```

Wireshark updates the database weekly and asks that it not be downloaded more often than that.

## Contributing

Better identification rules are the most useful contribution. If `lsnet` leaves a device's type blank or gets it wrong, open an issue with the output of `lsnet --json` for that device, with anything private removed. The rules live in [`src/classify.rs`](src/classify.rs).

## License

Copyright (C) 2026 Sanford Lincoln

`lsnet` is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE).

### Third-party data

`data/oui.tsv`, the MAC vendor database built into the binary, is derived from [Wireshark](https://www.wireshark.org)'s `manuf` database. Wireshark generates that database from the [IEEE OUI registries](https://standards-oui.ieee.org/). The file is Copyright 1998 Gerald Combs and contributors and is licensed under GPL-2.0-or-later, which allows it to be redistributed as part of `lsnet` under GPL-3.0-or-later.
