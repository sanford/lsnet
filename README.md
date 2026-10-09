# lsnet

**See what's on your local network.** `lsnet` finds every device on your LAN and tells you what each one is (an Apple TV, a printer, a smart plug, a NAS) in about two seconds, with no configuration and no flags to learn.

```
$ lsnet
 lsnet  1 Devices  2 Services
 19 devices on 192.168.1.0/24 (en0) in 2.0s · 1 address conflict · 1 self-assigned address · 1 off-subnet address
┌ Devices (19 · 1 missing) ──────────────────────────────────────────┐┌ Living Room ───────────────────────────────────────┐
│    IP              NAME                      TYPE                  ││ TV / streamer · Apple TV 4K (3rd gen)              │
│  + 169.254.37.12   PTZ-CAM-1.local           Video device          ││ Type from      Bonjour airplay model = AppleTV14,1 │
│    192.168.0.78    Audinate Pty L            Audio device          ││ Name from      AirPlay                             │
│    192.168.1.1     Home Router               Router (gateway)      ││                                                    │
│    192.168.1.8     Brother HL-L2350DW series Printer               ││ IP             192.168.1.52                        │
│    192.168.1.14    diskstation.local         NAS                   ││ MAC            f0:18:98:3c:62:8d                   │
│    192.168.1.40    ptz-cam-2.local           Video device          ││ Vendor         Apple                               │
│›   192.168.1.52    Living Room               TV / streamer         ││ Hostname       living-room.lan                     │
│  → 192.168.1.60    Kitchen                   Speaker               ││ First seen     1 Sep 2026                          │
│    192.168.1.71    Office speaker            Speaker               ││ Open ports     7000 AirPlay · 62078 iOS sync       │
│    192.168.1.77    Stagebox-FOH              Audio device          ││                                                    │
│    192.168.1.88    kp115                     Smart plug            ││ Bonjour (mDNS)                                     │
│  + 192.168.1.90    blink-mini                Camera                ││ Name           Living-Room.local                   │
│    192.168.1.112   alex-phone                Phone / tablet        ││ airplay        Living Room                         │
│    192.168.1.130   raspberrypi.local         Computer              ││                model = AppleTV14,1                 │
│  ~ 192.168.1.150   pihole                    DNS server            ││ raop           6C4A85D1E0F2@Living Room            │
│    192.168.1.196   Alex's MacBook Pro        Computer (this device)││                am = AppleTV14,1                    │
│    192.168.1.201   Intel                     Computer              ││ companion-link Living Room                         │
│    192.168.1.203   Dexatek                                         ││                rpmd = AppleTV14,1                  │
│    192.168.1.230   Espressif                 IoT device            ││                                                    │
│  - 192.168.1.95    myq-garage                Garage door           ││                                                    │
└────────────────────────────────────────────────────────────────────┘└────────────────────────────────────────────────────┘
 ↑↓ move  tab details  ⏎ copy IP  c copy all  / filter  r rescan  ? help  q quit
```

It's meant to answer the question "what is that?" faster and more simply than [nmap](https://nmap.org). It isn't a port scanner or a security tool.

## Features

- **Zero config.** It detects your interface, subnet and gateway on its own.
- **Fast.** Every discovery method runs concurrently, and a /24 takes about 2 seconds.
- **Identifies devices, not just addresses.** It combines what devices announce about themselves (Bonjour, UPnP, Windows and Samba NetBIOS names), their naming conventions, web UI banners, open ports (including homelab staples like Proxmox, Plex and Home Assistant) and MAC vendors into a type and a model.
- **Works without root.** On Linux and Windows you even get MAC addresses and vendors without it. On macOS, some come through anyway: Windows and Samba hosts report theirs over NetBIOS, and AirPlay speakers and Linux machines put theirs in their Bonjour names.
- **macOS, Linux and Windows.**
- **Browse or print.** In a terminal, `lsnet` opens a browser with everything known about each device, and any line of it copies with a keypress. When piped, or with `-l`, it prints a table.
- **Find your servers.** `2` in the browser, or `-s`, lists every service on the network (web UIs, SSH, file shares, databases, Plex, Proxmox, Home Assistant) with the address to reach it.
- **One key to its web page.** Press `w` on a router, a printer, a NAS or a Plex server and its web UI opens in your browser, at the right port and scheme: DSM on a Synology, not port 80. No more typing `https://192.168.1.14:5001` from memory. See [Opening web UIs](#opening-web-uis).
- **Says what changed.** It remembers each network, so the next scan points out new devices, ones that moved or were renamed, and ones that didn't answer.
- **Scriptable.** `--json` outputs every piece of evidence behind each identification.

## Install

lsnet runs on macOS, Linux (x86_64 and 64-bit ARM, including 64-bit Raspberry Pi OS) and Windows 10 or later (x86_64).

With [Homebrew](https://brew.sh), on macOS and Linux:

```sh
brew install sanford/tap/lsnet
```

On Windows, with [Scoop](https://scoop.sh):

```powershell
scoop bucket add sanford https://github.com/sanford/scoop-bucket
scoop install sanford/lsnet
```

Or download `lsnet-windows-x64.zip` from the [latest release](https://github.com/sanford/lsnet/releases/latest), unzip it, and put `lsnet.exe` in a folder on your `PATH`. It needs nothing else installed. Or, from PowerShell:

```powershell
$dir = "$env:LOCALAPPDATA\Programs\lsnet"
Invoke-WebRequest https://github.com/sanford/lsnet/releases/latest/download/lsnet-windows-x64.zip -OutFile "$env:TEMP\lsnet.zip"
Expand-Archive "$env:TEMP\lsnet.zip" $dir -Force
[Environment]::SetEnvironmentVariable('Path', "$([Environment]::GetEnvironmentVariable('Path', 'User'));$dir", 'User')
```

Then open a new terminal and run `lsnet`.

With Cargo, if you have a [Rust toolchain](https://rustup.rs), from [crates.io](https://crates.io/crates/lsnet) (on Windows, see [below](#installing-rust-on-windows)):

```sh
cargo install lsnet
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
cargo install lsnet
lsnet
```

`lsnet` needs no administrator rights on Windows. If the scan finds devices but no names or models, check that Windows has the network set to Private rather than Public (see [Firewalls](#firewalls)).

## Usage

```
lsnet [OPTIONS]

  -i, --interface <NAME>  Network interface to scan (default: the one your internet traffic uses)
  -n, --net <CIDR>        Network to scan, up to a /16 (default: see "Which network it scans")
  -l, --list              Print a table instead of opening the device browser
  -v, --verbose           Print a table that also shows hostnames, open ports and advertised services
  -s, --services          List the services running on the network instead of devices
      --json              Print results as JSON
  -t, --timeout <MS>      How long to wait for devices to answer [default: 1200]
      --no-dns            Skip reverse DNS lookups
      --demo              Show a made-up network instead of scanning (no packets are sent)
      --no-history        Don't compare with earlier scans of this network, or remember this one
      --no-mouse          Leave the mouse to the terminal, so its own text selection works
      --forget            Show what lsnet remembers about the networks it has scanned, and delete it
```

Some examples:

```sh
lsnet                  # browse the devices on your network
lsnet -l               # just print the list
sudo lsnet             # also show MAC addresses and vendors
lsnet -v               # show the evidence: hostnames, ports, services
lsnet -s -l            # print every service and its address
lsnet -t 3000          # wait longer for sleepy Wi-Fi devices
lsnet --net 10.0.0.0/16 # scan all of a large network, not just your /24
lsnet --json | jq '.[] | select(.type == "Printer")'
lsnet --demo           # try it without a network
```

### The device browser

Run in a terminal, `lsnet` opens the browser shown at the top. Devices are listed on the left, and everything `lsnet` learned about the selected one is on the right: open ports, Bonjour services with their TXT records, UPnP details and the web page banner.

The first line has the two tabs, **1 Devices** and **2 Services** (see [The services view](#the-services-view)): press `1` or `2` to switch. The second sums up the scan: what was scanned, what it's still waiting for, how many addresses are wrong (see [Address problems](#address-problems)) and anything it couldn't see, such as the tip to run with `sudo`. The footer shows the keys that fit, most useful first, and `w` only when there's a web page to open; `?` lists them all.

Devices appear as soon as they're found, and the details fill in as `lsnet` asks each one more questions. The header says what it's still waiting for, which on a large network includes how far the port probe has got. Once the scan is done, the browser keeps listening, to Bonjour announcements and (with `sudo`) ARP. A device heard then, such as a phone waking up, is added to the list and asked the same questions as the rest. Its details say it was heard after the scan. Nothing else is sent while it listens.

Press `?` to see every key:

| Key | Action |
|---|---|
| `↑` `↓` or `j` `k` | Move through the list, or through the details |
| `g` `G` or `Home` `End` | Jump to the first or last row |
| `1` `2` | Show devices or services |
| `Tab`, `→` or `l` | Go into the details, to copy any line of them |
| `Tab`, `←`, `h` or `Esc` | Back from the details to the list |
| `Enter` or `y` | Copy the selected IP address (or, for a service, its address and port) to the clipboard |
| `c` | Copy all the details to the clipboard as plain text |
| `w` | Open the device's or service's web UI in your browser (see [Opening web UIs](#opening-web-uis)) |
| `Enter` or `c` in the details | Copy the selected line's value: a MAC address, a hostname, a TXT record's value |
| `PgUp` `PgDn` or `Ctrl-u` `Ctrl-d` | Scroll the details by half a page |
| `J` `K` | Scroll the details by one line |
| `/` | Filter by IP, name, type, model, vendor, MAC or hostname, and in the services view by port or service. `Enter` keeps the filter, `Esc` clears it |
| `r` | Scan again, keeping your place |
| `Esc` | Clear the filter, or quit if there isn't one |
| `?` | Show all the keys |
| `q` or `Ctrl-c` | Quit |

Emacs keys work too: `Ctrl-n` `Ctrl-p` move down and up, `Ctrl-v` `Alt-v` scroll the details like `PgDn` `PgUp`, `Alt-<` `Alt->` jump to the first or last row, and `Ctrl-g` clears the filter (it never quits).

So does the mouse. Click a tab (`1 Devices`, `2 Services`) to switch to it, a row of the list to select it, or a line of the details to go into them with that line selected. Click what's already selected to copy it: a row's IP address (or a service's address and port), or a line's value. The wheel moves through the list, or scrolls the details, and every hint in the footer clicks as its key, so `w open` opens the web page. `--no-mouse` leaves the mouse to the terminal; most terminals still select text while you hold `Shift` (`Option` in iTerm2).

Under the type and model, the details say what decided them and where the name came from, for example `Type from  Bonjour airplay model = AppleTV14,1` and `Name from  AirPlay`. If `lsnet` gets a device wrong, that line points at the rule to fix.

To copy all the details, press `c`: it copies every line, including any scrolled out of view, without wrapping, which selecting them with the mouse can't. For just one value, click its line twice, or press `Tab` to go into the details, move to its line and press `Enter` or `c`. On a terminal narrower than 80 columns there's only room for the list, and `Tab` shows the details in its place. Copying uses `pbcopy` on macOS, `wl-copy`, `xclip` or `xsel` on Linux, and the clipboard directly on Windows. Without any of those, `lsnet` asks the terminal to do the copy, which also works over SSH in most modern terminals.

### The services view

Press `2` in the browser, or start it with `lsnet -s`, to list services instead of devices: one row per server, sorted by address, with the device's details beside it as usual. The port is in bold, since it's what tells one row from the next.

```
$ lsnet -s
 lsnet  1 Devices  2 Services
 19 devices on 192.168.1.0/24 (en0) in 2.0s · 1 address conflict · 1 self-assigned address · 1 off-subnet address
┌ Services (23) ──────────────────────────────────────────────┐┌ diskstation.local ────────────────────────────────────────┐
│  ADDRESS            SERVICE        HOST                     ││ NAS · Synology DS920+                                     │
│  192.168.1.1:53     DNS            Home Router              ││ Type from     UPnP Basic by Synology                      │
│  192.168.1.1:80     HTTP           Home Router              ││ Name from     .local name                                 │
│  192.168.1.1:443    HTTPS          Home Router              ││                                                           │
│  192.168.1.8:80     HTTP           Brother HL-L2350DW series││ IP            192.168.1.14                                │
│  192.168.1.8:443    HTTPS          Brother HL-L2350DW series││ MAC           00:11:32:66:d8:71                           │
│  192.168.1.8:9100   printing       Brother HL-L2350DW series││ Vendor        Synology                                    │
│  192.168.1.14:22    SSH            diskstation.local        ││ Hostname      diskstation.lan                             │
│  192.168.1.14:80    HTTP           diskstation.local        ││ First seen    1 Sep 2026                                  │
│  192.168.1.14:139   NetBIOS        diskstation.local        ││ Open ports    22 SSH · 80 HTTP · 139 NetBIOS · 443 HTTPS  │
│  192.168.1.14:443   HTTPS          diskstation.local        ││               · 445 SMB · 5001 HTTPS · 32400 Plex         │
│  192.168.1.14:445   SMB            diskstation.local        ││                                                           │
│  192.168.1.14:5001  HTTPS          diskstation.local        ││ Bonjour (mDNS)                                            │
│› 192.168.1.14:32400 Plex           diskstation.local        ││ Name          diskstation.local                           │
│  192.168.1.40:80    HTTP           ptz-cam-2.local          ││ adisk         diskstation                                 │
│  192.168.1.88:80    HTTP           kp115                    ││ smb           diskstation                                 │
│  192.168.1.130:22   SSH            raspberrypi.local        ││                                                           │
│  192.168.1.130:1883 MQTT           raspberrypi.local        ││ UPnP                                                      │
│  192.168.1.130:8123 Home Assistant raspberrypi.local        ││ Name          diskstation (DS920+)                        │
│  192.168.1.150:22   SSH            pihole                   ││ Manufacturer  Synology                                    │
│  192.168.1.150:53   DNS            pihole                   ││ Model         DS920+                                      │
│  192.168.1.150:80   HTTP           pihole                   ││ Device type   urn:schemas-upnp-org:device:Basic:1         │
│  192.168.1.201:3389 RDP            Intel                    ││                                                           │
│  192.168.1.230:80   HTTP           Espressif                ││ Web (port 80)                                             │
│                                                             ││ Title         diskstation - Synology DiskStation          │
│                                                             ││ Server        nginx                                       │
└─────────────────────────────────────────────────────────────┘└───────────────────────────────────────────────────────────┘
 ↑↓ move  tab details  ⏎ copy address  c copy all  w open  / filter  r rescan  ? help  q quit
```

It lists the open ports `lsnet` found (all but AirPlay, Cast and iPhone sync, which are how devices talk to phones rather than servers) plus the web, SSH, file-sharing, VNC and similar services devices advertise over Bonjour, on whatever port they use. This machine's own services aren't listed, since `lsnet` doesn't probe it. `lsnet -s -l` prints the same list as a table (see [Text output](#text-output)), and `lsnet -s --json` gives `ip`, `port`, `service` and `host` for each.

### Opening web UIs

Most things on a home network have a web page: the router, the printer, the NAS, Home Assistant, Plex, Proxmox, a Pi-hole. Press `w` in the browser and the selected one opens in your default browser. `w open` is in the footer whenever there's something to open.

- **In the services view,** `w` opens the service on the selected row: `https://` for HTTPS (ports 443, 5001, 8443, 9443), Proxmox and WebDAVS, and `http://` for HTTP, HTTP alt (8000, 8080 and the like), Home Assistant, Plex, Jellyfin, ESPHome, OctoPrint, Umbrel, Prometheus and WebDAV, on whatever port `lsnet` found it. Plex opens at `/web`, its web app.
- **In the devices view,** `w` opens the device's web UI: for a NAS from Synology, UGREEN or QNAP (known by its maker, or by the name it came with, like `DiskStation` or `UGNAS`), its maker's admin page (DSM on 5001 or 5000, UGOS on 9443 or 9999, QTS on 443 or 8080), and for anything else, its first web UI by port. On a Synology, ports 80 and 443 come last: they're Web Station's, which until it's set up only says so. Ports 5000 and 9999 are listed as services only on those NAS: elsewhere they're a Mac's AirPlay receiver, a router's UPnP or a Kasa plug.

SSH, file shares, VNC and the like have no `w`: only pages a browser can show are opened. Pages are opened with `open` on macOS, `xdg-open` on Linux, and the default browser on Windows.

### Text output

When you quit the browser, `lsnet` prints the results as a table, so they stay in your terminal after it closes. To skip the browser and print the table straight away, use `-l`. `lsnet` also skips the browser when its output is piped or redirected, and with `-v` or `--json`.

```
$ lsnet -l
 IP             NAME/VENDOR                TYPE                    MODEL                      VENDOR              MAC                CHANGE
 169.254.37.12  PTZ-CAM-1.local            Video device            NDI                        Sony                00:01:4a:5e:21:9c  new
 192.168.0.78   Audinate Pty L             Audio device            Dante                      Audinate Pty L      00:1d:c1:12:34:56
 192.168.1.1    Home Router                Router (gateway)        NETGEAR RAX50              Netgear             00:09:5b:7a:10:01
 192.168.1.8    Brother HL-L2350DW series  Printer                 Brother HL-L2350DW series  Brother industries  00:1b:a9:d2:e1:f0
 192.168.1.14   diskstation.local          NAS                     Synology DS920+            Synology            00:11:32:66:d8:71
 192.168.1.40   ptz-cam-2.local            Video device            NDI                        Amcrest             9c:8e:cd:31:07:aa
 192.168.1.52   Living Room                TV / streamer           Apple TV 4K (3rd gen)      Apple               f0:18:98:3c:62:8d
 192.168.1.60   Kitchen                    Speaker                 HomePod mini               Apple               6c:4a:85:0b:77:21  moved from 192.168.1.61
 192.168.1.71   Office speaker             Speaker                 Google Nest Mini           Google              f4:f5:d8:44:19:0e
 192.168.1.77   Stagebox-FOH               Audio device            Dante                      Audinate Pty L      00:1d:c1:0a:4f:20
 192.168.1.88   kp115                      Smart plug              TP-Link Kasa KP115         TP-Link             6c:5a:b0:9e:41:3d
 192.168.1.90   blink-mini                 Camera                  Blink Mini                 Amazon              fc:65:de:2b:80:17  new
 192.168.1.112  alex-phone                 Phone / tablet          iPhone / iPad              (private MAC)       3a:91:5c:e2:07:1b
 192.168.1.130  raspberrypi.local          Computer                Raspberry Pi               Raspberry Pi        b8:27:eb:5a:11:c4
 192.168.1.150  pihole                     DNS server              Pi-hole                    Raspberry Pi        b8:27:eb:c0:33:5e  renamed from dns
 192.168.1.196  Alex's MacBook Pro         Computer (this device)  MacBook Pro (M4)           Apple               f0:18:98:a1:b2:c3
 192.168.1.201  Intel                      Computer                .........................  Intel               00:02:b3:4d:6e:01
 192.168.1.203  Dexatek                    ......................  .........................  Dexatek             3c:6a:9d:12:ab:7f
 192.168.1.230  Espressif                  IoT device              Espressif                  Espressif           24:0a:c4:1d:9e:02

19 devices on 192.168.1.0/24 (en0) in 2.0s
since the last scan, 2 hours ago: 2 new, 1 moved, 1 renamed, 1 missing
169.254.37.12 (PTZ-CAM-1.local) gave itself an address: it got no answer from DHCP
192.168.0.78 (00:1d:c1:12:34:56) is outside 192.168.1.0/24: probably a static address from another network
192.168.1.230 is claimed by 2 devices (24:0a:c4:1d:9e:02, 24:0a:c4:88:31:5b): an address conflict
missing: myq-garage (192.168.1.95) didn't answer this time, last seen 2 hours ago
```

With `-s`, or after quitting the services view, the table lists services instead:

```
$ lsnet -s -l
 ADDRESS             SERVICE         HOST
 192.168.1.1:53      DNS             Home Router
 192.168.1.1:80      HTTP            Home Router
 192.168.1.1:443     HTTPS           Home Router
 192.168.1.8:80      HTTP            Brother HL-L2350DW series
 192.168.1.8:443     HTTPS           Brother HL-L2350DW series
 192.168.1.8:9100    printing        Brother HL-L2350DW series
 192.168.1.14:22     SSH             diskstation.local
 192.168.1.14:80     HTTP            diskstation.local
 192.168.1.14:139    NetBIOS         diskstation.local
 192.168.1.14:443    HTTPS           diskstation.local
 192.168.1.14:445    SMB             diskstation.local
 192.168.1.14:5001   HTTPS           diskstation.local
 192.168.1.14:32400  Plex            diskstation.local
 192.168.1.40:80     HTTP            ptz-cam-2.local
 192.168.1.88:80     HTTP            kp115
 192.168.1.130:22    SSH             raspberrypi.local
 192.168.1.130:1883  MQTT            raspberrypi.local
 192.168.1.130:8123  Home Assistant  raspberrypi.local
 192.168.1.150:22    SSH             pihole
 192.168.1.150:53    DNS             pihole
 192.168.1.150:80    HTTP            pihole
 192.168.1.201:3389  RDP             Intel
 192.168.1.230:80    HTTP            Espressif

19 devices on 192.168.1.0/24 (en0) in 2.0s
since the last scan, 2 hours ago: 2 new, 1 moved, 1 renamed, 1 missing
169.254.37.12 (PTZ-CAM-1.local) gave itself an address: it got no answer from DHCP
192.168.0.78 (00:1d:c1:12:34:56) is outside 192.168.1.0/24: probably a static address from another network
192.168.1.230 is claimed by 2 devices (24:0a:c4:1d:9e:02, 24:0a:c4:88:31:5b): an address conflict
missing: myq-garage (192.168.1.95) didn't answer this time, last seen 2 hours ago
```

### Device names

The NAME column shows the friendliest name a device gives itself, in this order:

1. A name someone set in its app or settings, from AirPlay, HomeKit or Cast ("Living Room", "Office speaker")
2. Its primary `.local` hostname, kept whole ("octopi.local", "homeassistant.local")
3. A generic service or UPnP name (a file share, a printer queue, "Home Router")
4. The host part of its DNS name from your router ("fhrouter")

When MAC vendors are known (always on Linux and Windows, and with `sudo` on macOS), the column becomes NAME/VENDOR. A device with none of the names above shows its manufacturer instead, in regular weight rather than bold, so you can tell it apart from a real name:

```
$ sudo lsnet -l
 IP             NAME/VENDOR        TYPE            MODEL                  VENDOR         MAC
 192.168.1.52   Living Room        TV / streamer   Apple TV 4K (3rd gen)  Apple          f0:18:98:3c:62:8d
 192.168.1.112  alex-phone         Phone / tablet  iPhone / iPad          (private MAC)  3a:91:5c:e2:07:1b
 192.168.1.130  raspberrypi.local  Computer        Raspberry Pi           Raspberry Pi   b8:27:eb:5a:11:c4
 192.168.1.230  Espressif          IoT device      Espressif              Espressif      24:0a:c4:1d:9e:02
```

Empty cells are filled with dimmed dots, so even a row with little information is easy to follow from its IP address across to the columns on the right.

`.local` names are shown in full because you can use them directly, even when the device's IP address changes. Try `http://octopi.local` in a browser, or `ssh pi@octopi.local`. Machine-generated names like `36814e2569ca121f.local` are hidden. Run `lsnet --json` to see every name a device reported, including its `.local` hostname under `mdns.hostname`.

### Which network it scans

By default, `lsnet` scans the network of the interface your internet traffic uses. It takes the size from the interface's subnet mask (the `/24` in `192.168.1.0/24`):

| Your network | What `lsnet` scans |
|---|---|
| `/22` or smaller (up to 1,022 addresses, including every home `/24`) | The whole network |
| Larger than `/22` (for example a `/16` on an office or campus network) | Only the `/24` around your own address, so the scan stays at about two seconds |

When it narrows a large network, `lsnet` says so under the results:

```
10.0.0.0/16 is large; scanned only the local /24 (--net 10.0.0.0/16 scans all of it)
```

To scan something else, give the network with `--net` (or `-n`) in CIDR form:

```sh
lsnet --net 10.0.0.0/16        # all of a large network (65,534 addresses)
lsnet --net 10.0.4.0/22        # just one part of it
lsnet --net 192.168.1.128/25   # the upper half of your /24
lsnet --net 192.168.20.0/24    # another subnet, such as a VLAN behind your router
```

- **Size.** The largest network `--net` takes is a `/16`. Host bits are ignored, so `192.168.1.7/24` means `192.168.1.0/24`. Up to a `/22` takes about two seconds.
- **Your own network, or part of it.** Everything works as usual: ARP, Bonjour, UPnP, names and MAC addresses.
- **Larger than a `/22`, on your own network.** Use `sudo` on macOS and Linux (or `setcap`, see [Running without sudo](#running-without-sudo)). `lsnet` then sweeps ARP first and probes only the devices that answer, so a `/16` takes about ten seconds. Without it, every address gets probed: a `/20` takes about five seconds and a `/16` about a minute and a half. On Linux, devices may also go missing, because the kernel tracks only about 1,000 addresses at once (`lsnet` says so under the results). Reverse DNS lookups wait until the devices are found, and Bonjour isn't asked about every address. On Windows, the ARP sweep is replaced by reading the ARP cache after the port probe.
- **Another network through a router.** Bonjour, UPnP and ARP don't cross routers, so `lsnet` finds devices only by their open ports, and shows no MAC addresses and fewer names. It says so under the results. Devices behind a firewall that drops these probes won't show up.
- **Which interface.** Without `-i`, `lsnet` uses the interface on the network you gave, if there is one, and otherwise the one your internet traffic uses.

### What changed since last time

`lsnet` remembers each network it scans, so the next scan can say what's different. The list marks each device that changed, and the details and the line under the results say how:

| Mark | Meaning |
|---|---|
| `+` | New: not seen on this network before |
| `→` | Moved: the same MAC at a different address |
| `~` | Renamed: the same device, named differently by the same source (a NetBIOS name and a Bonjour name for one device aren't a rename) |
| `-` | Missing: here last time, but didn't answer this time. These rows are dimmed, at the bottom of the browser, and listed under printed tables |

Printed tables get a CHANGE column, and `--json` gets `changes` and `first_seen`. The first scan of a network marks nothing, since everything would be new.

Most home networks use the same addresses (`192.168.1.0/24`, router at `.1`), so a network is recognized by its router: the permanent identifier it announces over UPnP, which needs no `sudo`, its MAC address, or its `.local` name. When the router says none of those, the devices decide: two homes share almost no devices known by a MAC or a `.local` name. A device is recognized by its MAC, then its `.local` name, then its address, unless something says it's another device, like a different `.local` name. Phones' private MACs can change, so a different one alone doesn't count.

Before calling a device missing, `lsnet` gives the address it was last seen at a second chance: another ping, port probe and Kasa query, alongside the scan's follow-up questions, which wake most Wi-Fi devices that dozed through the first round. A device that answers but says nothing about itself keeps the name and type it had, marked as remembered. Without `sudo`, devices that answer only ARP can't be found at all, so `lsnet` doesn't call them missing.

Only a scan of the network this machine is on is remembered. Scans with `--net` and `--demo` aren't.

#### History and privacy

The history is a JSON file, readable only by you:

| OS | Where |
|---|---|
| Linux | `~/.local/share/lsnet/history.json` (or under `$XDG_DATA_HOME`) |
| macOS | `~/Library/Application Support/lsnet/history.json` |
| Windows | `%LOCALAPPDATA%\lsnet\history.json` |

It holds, for each network, its subnet and its router's address, MAC, UPnP identifier and `.local` name, and for each device its address, MAC, `.local` name, name, type and model, and when it was first and last seen. Devices not seen for a year are dropped, and so are networks not scanned for a year. It doesn't hold open ports, Bonjour records or anything else from the scan, and nothing leaves your machine. Run with `sudo`, `lsnet` uses your history rather than root's, and leaves the file owned by you.

`--no-history` neither reads nor writes it. `lsnet --forget` lists what's in it and deletes it once you agree. Deleting the file by hand forgets everything too. Set `LSNET_HISTORY` to keep it somewhere else.

### Address problems

`lsnet` also points out devices whose address doesn't fit, since those are usually the hardest to find:

| Flag | What it means |
|---|---|
| `link-local` | The device has a `169.254.x.x` address it gave itself, because it asked for one over DHCP and got no answer |
| `off-subnet` | The device is on this network segment, but using an address from another network, usually a static one left over from somewhere else |
| `address-conflict` | More than one device answered for the same address |

Flagged devices have their IP shown in yellow (red for a conflict) and an explanation in the details. Printed tables end with a line for each saying what's wrong, and the browser's header counts them, like `1 address conflict`. `/conflict`, `/link-local` and `/off-subnet` filter for them. Devices on the wrong network can't be reached through this one, so `lsnet` lists them with what they said about themselves, but doesn't probe them.

Most of this comes from listening to ARP, which needs raw access (`sudo` on macOS and Linux, or `setcap`). Without it, `lsnet` still finds `link-local` devices that answer Bonjour, but not the other two flags. Windows reports only one MAC per address, so there only Bonjour's `link-local` devices are found. On Linux, strict reverse-path filtering (`rp_filter = 1`) drops Bonjour replies from self-assigned addresses before `lsnet` sees them; the default on most distributions (`2`) lets them through.

## How it works

`lsnet` runs these at the same time:

| Source | What it finds | Needs root |
|---|---|---|
| **ARP sweep** | Every device that has an IP address, including ones with no open ports, plus its MAC address | yes (or `CAP_NET_RAW` on Linux); no on Windows |
| **ARP cache** | MAC addresses the kernel learned during the scan, including devices the sweep missed | no on Linux and Windows; on macOS, root or a Developer ID–signed binary |
| **TCP probe** | Live hosts, since even a refused connection proves a device is there. Every host that answers is then checked for common server and homelab ports (databases, Proxmox, Home Assistant, Plex, Jellyfin, RDP) | no |
| **Ping** | Devices that ignore every TCP port but still answer ICMP echo (macOS; on Linux and Windows ARP already covers them) | no |
| **mDNS / Bonjour** | Friendly names ("Living Room") and model identifiers from TXT records (`AppleTV14,1`, Chromecast `md=`, printer `ty=`, HomeKit categories), plus each device's primary `.local` name from a reverse lookup of its address | no |
| **SSDP / UPnP** | Manufacturer, model and name from each device's UPnP description, which is how routers, TVs and NASes usually identify themselves | no |
| **Reverse DNS** | Hostnames from your router's DHCP leases | no |
| **HTTP banner** | `Server` header and page `<title>` from web UIs | no |
| **TP-Link Kasa** | The names plugs, switches and bulbs were given in the Kasa app, and their models, from a UDP broadcast | no |

Bonjour also finds Dante audio and NDI video devices, and the name a Dante device was given in Dante Controller.

Then it classifies each device using the most specific evidence available: what the device says about its own model, then naming conventions, then web banners, then advertised services, then open ports, then the MAC vendor. The vendor database comes from the IEEE registry and is built into the binary, so no network lookups are needed.

### Running without sudo

Without root, `lsnet` can't send its own ARP packets on macOS or Linux. It finds devices with the TCP probe and the discovery protocols instead, and how much else you get depends on the OS:

- **Linux:** almost nothing is lost. The TCP probe makes the kernel look up the MAC of every live address, and `lsnet` reads the results from `/proc/net/arp`. That gives MACs and vendors, and even finds devices with no open ports.
- **macOS:** recent versions don't let binaries that aren't signed with a Developer ID read the ARP table or MAC addresses, even through `arp`. Without `sudo`, the VENDOR and MAC columns are hidden, devices are identified from what they announce, and devices that are silent, fully firewalled and ignore pings are missed.
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
| `name`, `name_from` | The friendliest name the device gives itself, and where it came from |
| `type`, `model`, `type_from` | What `lsnet` thinks the device is, and the evidence that decided it |
| `hostname` | Reverse DNS name |
| `randomized_mac` | The device uses a private, per-network MAC (typical of phones and laptops) |
| `open_ports` | Which of the probed ports are open. Every address is checked for 22, 80, 443, 445, 7000, 8008, 9100 and 62078, and every live device also for 21, 25, 53, 110, 111, 135, 139, 143, 993, 995, 1433, 1521, 1883, 3306, 3389, 5000, 5001, 5060, 5432, 5672, 6379, 8000, 8001, 8006, 8080, 8081, 8096, 8123, 8443, 8888, 9090, 9091, 9443, 9999, 27017 and 32400 |
| `gateway`, `this_device` | Your router, and the machine running the scan |
| `flags`, `other_macs`, `other_ips` | Address problems (see [Address problems](#address-problems)), the other MACs in an address conflict, and any addresses from other networks the device also uses |
| `first_seen`, `changes` | When `lsnet` first saw the device on this network, in Unix seconds, and what changed since the last scan: `new`, `moved` (with `from`) or `renamed` (with `from`). See [What changed since last time](#what-changed-since-last-time) |
| `mdns`, `ssdp`, `http` | The raw evidence: Bonjour services with their TXT records and ports, UPnP description fields, web banner |

## Limitations

- **IPv4 only.** Networks larger than /22 are narrowed to your local /24 to keep scans fast, unless you ask for more with `--net` (see [Which network it scans](#which-network-it-scans)).
- **Identification is heuristic.** Devices that announce nothing and have no open ports show up with no type. Running with `sudo` at least adds their vendor, in the NAME/VENDOR column.
- **The Linux ARP cache can be stale.** Entries for devices that just left the network can linger for a few seconds after they disconnect.
- **Sleepy devices can be missed.** Phones and IoT devices in Wi-Fi power-save mode may not answer within the default window. The browser keeps listening and adds them when they speak up. For printed output, use `-t` to wait longer.

## Updating the vendor database

MAC vendor names come from Wireshark's copy of the IEEE OUI registry, cleaned up (for example "Apple, Inc." becomes "Apple") and stored in `data/oui.tsv` along with a license header (see [Third-party data](#third-party-data)). To refresh it:

```sh
python3 scripts/update-oui.py
```

Wireshark updates the database weekly and asks that it not be downloaded more often than that.

## Contributing

Better identification rules are the most useful contribution. If `lsnet` leaves a device's type blank or gets it wrong, open an issue with the output of `lsnet --json` for that device, with anything private removed. [`scripts/anonymize.py`](scripts/anonymize.py) does most of that: it changes IP addresses, the second half of each MAC, owners' names and your router's domain, consistently everywhere, then lists the names left so you can check them:

```sh
lsnet --json | python3 scripts/anonymize.py --only 192.168.1.52 > living-room.json
```

The rules live in [`src/classify.rs`](src/classify.rs).

That output is also a test. Saved in [`tests/fixtures/`](tests/fixtures/) with the `name`, `type` and `model` corrected, it's run on every `cargo test`: each device is classified again from its evidence and must come out as recorded. [`data/demo.json`](data/demo.json), the network `--demo` shows, is checked the same way.

## License

Copyright (C) 2026 Sanford Lincoln

`lsnet` is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE).

### Third-party data

`data/oui.tsv`, the MAC vendor database built into the binary, is derived from [Wireshark](https://www.wireshark.org)'s `manuf` database. Wireshark generates that database from the [IEEE OUI registries](https://standards-oui.ieee.org/). The file is Copyright 1998 Gerald Combs and contributors and is licensed under GPL-2.0-or-later, which allows it to be redistributed as part of `lsnet` under GPL-3.0-or-later.
