#!/usr/bin/env python3
"""Regenerate data/oui.tsv from Wireshark's manuf database.

Output lines are `HEXPREFIX<TAB>Vendor`, where HEXPREFIX is 6, 7 or 9 hex
digits (24, 28 or 36-bit assignments). Vendor names are trimmed of corporate
suffixes so they fit in a table column ("Apple, Inc." -> "Apple").
"""
import re
import sys
import urllib.request
from pathlib import Path

URL = "https://www.wireshark.org/download/automated/data/manuf"
OUT = Path(__file__).resolve().parent.parent / "data" / "oui.tsv"

SUFFIXES = {
    "inc", "incorporated", "corp", "corporation", "co", "company", "ltd",
    "limited", "llc", "gmbh", "ag", "sa", "s.a", "bv", "b.v", "srl", "spa",
    "plc", "pty", "kg", "oy", "ab", "as", "nv", "sas", "technologies",
    "technology", "tech", "electronics", "electronic", "international",
    "systems", "networks", "communications", "holdings", "group", "industrial",
    "trading", "foundation", "(china)", "america", "usa",
}
PREFIXES = ("shenzhen ", "guangdong ", "guangzhou ", "beijing ", "shanghai ",
            "hangzhou ", "zhejiang ", "xiamen ", "dongguan ", "suzhou ")
OVERRIDES = {
    "hon hai precision ind": "Foxconn",
    "hon hai precision": "Foxconn",
    "amazon": "Amazon",
    "google": "Google",
    "raspberry pi": "Raspberry Pi",
    "tp-link": "TP-Link",
    "murata manufacturing": "Murata",
    "intel": "Intel",
    "espressif": "Espressif",
}


def clean(name: str) -> str:
    name = re.sub(r"\s+", " ", name).strip()
    low = name.lower()
    for p in PREFIXES:
        if low.startswith(p) and len(name) > len(p) + 3:
            name = name[len(p):]
            break
    words = re.split(r"[ ,]+", name)
    while len(words) > 1 and words[-1].lower().rstrip(".") in SUFFIXES:
        words.pop()
    name = " ".join(words).strip(" ,.")
    key = name.lower()
    for k, v in OVERRIDES.items():
        if key == k or key.startswith(k + " "):
            return v
    return name[:24].rstrip()


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else None
    if src:
        text = Path(src).read_text(encoding="utf-8")
    else:
        with urllib.request.urlopen(URL) as r:
            text = r.read().decode("utf-8")

    rows = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        prefix = parts[0].strip()
        long_name = parts[2].strip() if len(parts) > 2 and parts[2].strip() else parts[1].strip()
        bits = 24
        if "/" in prefix:
            prefix, b = prefix.split("/")
            bits = int(b)
        if bits not in (24, 28, 36):
            continue
        hexpre = prefix.replace(":", "").replace("-", "").upper()[: bits // 4]
        rows.append(f"{hexpre}\t{clean(long_name)}")

    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("\n".join(sorted(rows)) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} entries to {OUT}")


if __name__ == "__main__":
    main()
