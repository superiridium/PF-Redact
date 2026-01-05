#!/usr/bin/env python3
"""
pfsense_redact.py — redact sensitive fields from a pfSense config backup (config.xml or config.xml.gz).

Defaults:
- Redacts common credential/secret fields based on XML tag/attribute name heuristics
- Redacts PEM blocks and long base64/hex-looking blobs

Optional:
- --redact-ips: redact IPv4/IPv6 addresses found in text nodes
- --redact-hostnames: redact hostnames/FQDNs found in text nodes
- --in-place: overwrite input file (a .bak copy is created)

Notes:
- pfSense configs are XML. If parsing fails (e.g., encrypted export or corrupted file),
  we fall back to conservative regex redaction.
"""

from __future__ import annotations

import argparse
import gzip
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from typing import Tuple


GZIP_MAGIC = b"\x1f\x8b"

# pfSense commonly uses these for user passwords/hash, GUI, services, tunnels, etc.
SENSITIVE_EXACT = {
    # Generic
    "password",
    "passwd",
    "pass",
    "secret",
    "sharedsecret",
    "shared-secret",
    "pre-shared-key",
    "psk",
    "token",
    "apikey",
    "api_key",
    "key",
    "privatekey",
    "private-key",
    "privkey",

    # pfSense specifics
    "passwordhash",     # webConfigurator/user hash
    "password-hash",
    "pwdhash",
    "md5-hash",
    "bcrypt-hash",

    # Services
    "community",        # SNMP community
    "snmp_community",
    "radius_secret",
    "radiussecret",
    "bindpw",
    "bind_password",
    "ldap_bindpw",
    "ddns_password",
    "dyndns_password",
    "pppoe_password",

    # VPN/tunnels
    "sharedkey",        # some IPsec/OpenVPN configs
    "psksecret",
    "wireguard_privatekey",
    "wireguard-privatekey",
    "openvpn_tlskey",
    "tlskey",
    "tls_key",
}

SENSITIVE_SUFFIXES = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "privatekey",
    "private-key",
    "privkey",
    "psk",
    "hash",          # catches passwordhash / md5-hash etc (still sensitive)
    "tlskey",
    "tls_key",
)

SENSITIVE_ATTRS = {
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "key",
    "privatekey",
    "hash",
}

# PEM blocks for keys/certs (often embedded)
PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----", re.DOTALL)

# Blob heuristics
BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")
HEXISH_RE = re.compile(r"^[0-9a-fA-F:\s]+$")

# Optional redaction patterns (applied to text nodes)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
HOST_RE = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b"
)


def read_input(path: str) -> Tuple[bytes, bool]:
    with open(path, "rb") as f:
        head = f.read(2)
        f.seek(0)
        data = f.read()
    if head == GZIP_MAGIC:
        return gzip.decompress(data), True
    return data, False


def write_output(path: str, data: bytes, gzip_out: bool) -> None:
    if gzip_out:
        out = gzip.compress(data)
        with open(path, "wb") as f:
            f.write(out)
    else:
        with open(path, "wb") as f:
            f.write(data)


def redact_text(label: str, original: str) -> str:
    # Leave a hint of original length without exposing content
    return f"[REDACTED:{label};len={len(original.strip())}]"


def should_redact_by_tag(tag: str) -> bool:
    t = tag.lower()
    if t in SENSITIVE_EXACT:
        return True
    return any(t.endswith(suf) for suf in SENSITIVE_SUFFIXES)


def looks_like_blob(s: str) -> bool:
    t = s.strip()
    if len(t) < 32:
        return False
    if "-----BEGIN " in t and "-----END " in t:
        return True
    # long base64-ish: often keys/tokens/cert material
    if len(t) >= 80 and BASE64ISH_RE.match(t):
        return True
    # long hex-ish: sometimes keys/hashes
    if len(t) >= 80 and HEXISH_RE.match(t.replace(":", "")):
        return True
    return False


def apply_optional_text_redactions(s: str, redact_ips: bool, redact_hostnames: bool) -> str:
    out = s
    if redact_ips:
        out = IPV4_RE.sub("[REDACTED:ipv4]", out)
        out = IPV6_RE.sub("[REDACTED:ipv6]", out)
    if redact_hostnames:
        out = HOST_RE.sub("[REDACTED:hostname]", out)
    return out


def fallback_regex_redact(text: str, redact_ips: bool, redact_hostnames: bool) -> str:
    # If XML parse fails (encrypted export or non-XML), do conservative redactions.
    out = PEM_RE.sub("[REDACTED:PEM]", text)
    # Replace very long base64-ish runs (common for embedded keys/certs)
    out = re.sub(r"([A-Za-z0-9+/=]{120,})", "[REDACTED:BLOB]", out)
    out = apply_optional_text_redactions(out, redact_ips, redact_hostnames)
    return out


def redact_xml(xml_bytes: bytes, redact_ips: bool, redact_hostnames: bool) -> bytes:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        # Possibly encrypted export or invalid XML.
        txt = xml_bytes.decode("utf-8", errors="replace")
        return fallback_regex_redact(txt, redact_ips, redact_hostnames).encode("utf-8")

    # Walk all nodes
    for elem in root.iter():
        # Handle namespaces
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        tag_l = tag.lower()

        # Redact sensitive attributes
        if elem.attrib:
            for k in list(elem.attrib.keys()):
                k_l = k.lower()
                if k_l in SENSITIVE_ATTRS or should_redact_by_tag(k_l):
                    elem.attrib[k] = redact_text(k_l, elem.attrib.get(k, ""))

        # Redact sensitive text content
        if elem.text and elem.text.strip():
            txt = elem.text

            if should_redact_by_tag(tag_l):
                elem.text = redact_text(tag_l, txt)
            elif PEM_RE.search(txt):
                elem.text = "[REDACTED:PEM]"
            elif looks_like_blob(txt):
                elem.text = redact_text("blob", txt)
            else:
                elem.text = apply_optional_text_redactions(txt, redact_ips, redact_hostnames)

        # Redact tail if needed (rarely contains meaningful text)
        if elem.tail and elem.tail.strip():
            elem.tail = apply_optional_text_redactions(elem.tail, redact_ips, redact_hostnames)

    xml_out = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return xml_out


def main() -> int:
    p = argparse.ArgumentParser(description="Redact sensitive information from a pfSense config backup.")
    p.add_argument("input", help="Input pfSense backup/config (.xml or .xml.gz)")
    p.add_argument("output", nargs="?", help="Output redacted file (default: input.redacted.xml[.gz])")
    p.add_argument("--redact-ips", action="store_true", help="Also redact IPv4/IPv6 addresses in text nodes")
    p.add_argument("--redact-hostnames", action="store_true", help="Also redact hostnames/FQDNs in text nodes")
    p.add_argument("--in-place", action="store_true", help="Overwrite input file (creates a .bak backup)")
    args = p.parse_args()

    in_path = args.input
    raw, was_gz = read_input(in_path)

    redacted = redact_xml(raw, redact_ips=args.redact_ips, redact_hostnames=args.redact_hostnames)

    # Output path decision
    if args.in_place:
        bak_path = in_path + ".bak"
        if not os.path.exists(bak_path):
            shutil.copy2(in_path, bak_path)
        out_path = in_path
        out_gz = was_gz
    else:
        if args.output:
            out_path = args.output
            out_gz = out_path.endswith(".gz") or was_gz
        else:
            base = in_path
            if base.endswith(".gz"):
                base = base[:-3]
            if base.lower().endswith(".xml"):
                base = base[:-4]
            out_path = base + ".redacted.xml" + (".gz" if was_gz else "")
            out_gz = was_gz

    write_output(out_path, redacted, gzip_out=out_gz)

    sys.stderr.write(f"Redacted file written to: {out_path}\n")
    if args.in_place:
        sys.stderr.write(f"Backup created at: {in_path}.bak\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
