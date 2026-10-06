#!/usr/bin/env python3
"""Make `lsnet --json` output safe to share, as a bug report or a test fixture.

    lsnet --json | python3 scripts/anonymize.py > tests/fixtures/my-network.json
    lsnet --json | python3 scripts/anonymize.py --only 192.168.1.52 --replace Smith=Alex

What changes:

- IP addresses: each private /24 becomes 192.168.1.x, 192.168.2.x and so on,
  keeping the last number; public addresses become 203.0.113.x. Self-assigned
  169.254.x.x addresses stay, since they say nothing about where you are.
- MAC addresses keep their first half, which names the maker and is what
  lsnet identifies devices by, and get a made-up second half. That includes
  MACs inside names, like AirPlay's `6C4A85D1E0F2@Living Room`.
- "Sam's MacBook Pro" becomes "Alex's MacBook Pro", and "Sam" becomes "Alex"
  everywhere else too, so `Sams-MacBook-Pro.local` follows.
- Hostnames from your router lose their domain: `nas.example.com` becomes
  `nas.lan`.
- Anything else you name with --replace OLD=NEW, ignoring case.

Each change is made everywhere at once, so a device still comes out as the
same type, model and name: `cargo test` checks that for every file in
tests/fixtures/. Names people chose can still be private, so the names left
are listed at the end for you to check.
"""

import argparse
import hashlib
import ipaddress
import json
import re
import secrets
import sys

IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
MAC = re.compile(r"(?i)(?<![0-9a-f:])([0-9a-f]{2}(?::[0-9a-f]{2}){5})(?![0-9a-f:])")
# AirPlay names instances "<12 hex digits>@<name>".
RAOP_MAC = re.compile(r"(?i)^([0-9a-f]{12})@")
POSSESSIVE = re.compile(r"\b([A-Z][a-z]+)(['’])s\b")
STAND_IN = "Alex"


class Anonymizer:
    def __init__(self, replace):
        self.salt = secrets.token_bytes(16)
        self.nets = {}  # private /24 → stand-in /24
        self.public = {}  # public address → stand-in
        self.replace = dict(replace)

    def ip(self, match):
        text = match.group(0)
        try:
            addr = ipaddress.IPv4Address(text)
        except ValueError:
            return text
        if addr.is_link_local or addr.is_unspecified or addr.is_loopback:
            return text
        if addr.is_private:
            prefix = text.rsplit(".", 1)[0]
            if prefix not in self.nets:
                self.nets[prefix] = f"192.168.{len(self.nets) + 1}"
            return f"{self.nets[prefix]}.{text.rsplit('.', 1)[1]}"
        if text not in self.public:
            self.public[text] = f"203.0.113.{len(self.public) + 1}"
        return self.public[text]

    def mac_tail(self, hex12):
        """A made-up second half for a MAC, the same each time it's asked."""
        digest = hashlib.sha256(self.salt + hex12.lower().encode()).hexdigest()
        return hex12[:6] + digest[:6]

    def mac(self, match):
        text = match.group(1)
        new = self.mac_tail(text.replace(":", ""))
        new = ":".join(new[i : i + 2] for i in range(0, 12, 2))
        return new.upper() if text.isupper() else new

    def raop(self, match):
        text = match.group(1)
        new = self.mac_tail(text)
        return (new.upper() if text.isupper() else new) + "@"

    def learn_owners(self, value):
        """Owners named in possessives anywhere get replaced everywhere."""
        if isinstance(value, str):
            for name, _ in POSSESSIVE.findall(value):
                if name != STAND_IN:
                    self.replace.setdefault(name, STAND_IN)
        elif isinstance(value, list):
            for v in value:
                self.learn_owners(v)
        elif isinstance(value, dict):
            for v in value.values():
                self.learn_owners(v)

    def learn_domains(self, devices):
        """Router DNS names lose their domain."""
        for d in devices:
            host = d.get("hostname")
            if not host or host.endswith(".local") or "." not in host:
                continue
            first = host.split(".", 1)[0]
            self.replace.setdefault(host, f"{first}.lan")

    def text(self, s):
        for old, new in sorted(self.replace.items(), key=lambda kv: -len(kv[0])):
            s = replace_ignoring_case(s, old, new)
        s = RAOP_MAC.sub(self.raop, s)
        s = MAC.sub(self.mac, s)
        return IPV4.sub(self.ip, s)

    def walk(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.walk(v) for v in value]
        if isinstance(value, dict):
            return {k: self.walk(v) for k, v in value.items()}
        return value


def replace_ignoring_case(s, old, new):
    """Replace `old` in any case, matching the case of what was there."""

    def same_case(match):
        found = match.group(0)
        if found.islower():
            return new.lower()
        if found.isupper():
            return new.upper()
        return new

    return re.sub(re.escape(old), same_case, s, flags=re.IGNORECASE)


def names(devices):
    """Every name a person might have chosen, to check by eye."""
    out = set()
    for d in devices:
        for key in ("name", "hostname"):
            if d.get(key):
                out.add(d[key])
        mdns = d.get("mdns") or {}
        if mdns.get("hostname"):
            out.add(mdns["hostname"])
        out.update((mdns.get("services") or {}).values())
        for txt in (mdns.get("txt") or {}).values():
            out.update(v for k, v in txt.items() if k in ("fn", "n"))
        for source, key in (
            ("ssdp", "friendly_name"),
            ("netbios", "name"),
            ("kasa", "alias"),
            ("http", "title"),
        ):
            value = (d.get(source) or {}).get(key)
            if value:
                out.add(value)
    return sorted(out, key=str.lower)


def main():
    parser = argparse.ArgumentParser(
        description="Make lsnet --json output safe to share.",
        epilog="Reads stdin, or FILE, and writes to stdout.",
    )
    parser.add_argument("file", nargs="?", help="lsnet --json output (default: stdin)")
    parser.add_argument(
        "--only",
        metavar="IP",
        action="append",
        default=[],
        help="keep just this device (may be repeated)",
    )
    parser.add_argument(
        "--replace",
        metavar="OLD=NEW",
        action="append",
        default=[],
        help="replace OLD with NEW everywhere, ignoring case (may be repeated)",
    )
    args = parser.parse_args()

    replace = []
    for pair in args.replace:
        old, sep, new = pair.partition("=")
        if not sep or not old:
            parser.error(f"--replace takes OLD=NEW, not {pair!r}")
        replace.append((old, new))

    raw = open(args.file, encoding="utf-8").read() if args.file else sys.stdin.read()
    try:
        devices = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit(f"anonymize: not lsnet --json output: {e}")
    if not isinstance(devices, list) or not all(
        isinstance(d, dict) and "ip" in d for d in devices
    ):
        sys.exit("anonymize: expected lsnet --json output (a list of devices)")
    if args.only:
        devices = [d for d in devices if d["ip"] in args.only]
        missing = set(args.only) - {d["ip"] for d in devices}
        if missing:
            sys.exit(f"anonymize: no device at {', '.join(sorted(missing))}")

    anon = Anonymizer(replace)
    anon.learn_owners(devices)
    anon.learn_domains(devices)
    devices = anon.walk(devices)

    json.dump(devices, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    left = names(devices)
    if left:
        print(
            "Check these names for anything private, and rerun with "
            "--replace OLD=NEW for any that are:",
            file=sys.stderr,
        )
        for name in left:
            print(f"  {name}", file=sys.stderr)


if __name__ == "__main__":
    main()
