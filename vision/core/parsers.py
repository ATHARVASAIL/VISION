"""Tool output parsers.

These were previously inline in the enrichment stages, which made them
untestable without spawning the real tool — so they were the least-verified
code in the project despite being the part most exposed to reality. Every
finding depends on one of these reading correctly.

Extracted here as pure functions: text in, structured data out. That means they
can be tested against realistic output from several tool versions, which is the
closest thing to a real target available without one.

Two principles throughout:

**Tolerate formatting drift.** These tools reformat between releases — column
widths change, colour codes appear, headers get reworded. Parsers match on
structure and keywords, never on exact spacing, because a parser that silently
returns nothing after a `apt upgrade` produces a clean report for a vulnerable
network.

**Prefer returning nothing over guessing.** A missed finding is a gap; an
invented one destroys the report's credibility. Where output is ambiguous these
return empty.
"""

from __future__ import annotations

import json
import re
from typing import Optional

# Tools increasingly emit colour even when piped.
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI.sub("", text or "")


# --------------------------------------------------------------------------
# smbmap — share enumeration
# --------------------------------------------------------------------------

_PERM = re.compile(r"\b(NO ACCESS|READ[ ,_]*WRITE|READ[ ,_]*ONLY|WRITE[ ,_]*ONLY)\b",
                   re.I)

HIDDEN_SHARES = {"IPC$"}


def parse_smbmap_shares(output: str) -> list[tuple[str, str]]:
    """Readable or writable shares as (name, permission).

    Excludes NO ACCESS entries and IPC$, which is present on every Windows host
    and is not itself a finding.
    """
    out: list[tuple[str, str]] = []
    for raw in strip_ansi(output).splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        perm_match = _PERM.search(line)
        if not perm_match:
            continue
        perm = re.sub(r"[ ,_]+", " ", perm_match.group(1).upper()).strip()
        if perm == "NO ACCESS":
            continue
        # The share name is whatever precedes the permission column.
        name = line[:perm_match.start()].strip().strip("|")
        # Drop any leading status marker such as "[+]" or a tree glyph.
        name = re.sub(r"^[\[\]\+\-\*\s>|]+", "", name).strip()
        if not name or name.upper() in HIDDEN_SHARES:
            continue
        if name.lower() in ("disk", "share", "----"):   # header rows
            continue
        out.append((name, perm))
    return out


def smbmap_has_write(shares: list[tuple[str, str]]) -> bool:
    return any("WRITE" in perm for _name, perm in shares)


# --------------------------------------------------------------------------
# rpcclient — user enumeration
# --------------------------------------------------------------------------

_RPC_USER = re.compile(r"user:\[([^\]]+)\]")


def parse_rpcclient_users(output: str) -> list[str]:
    seen, out = set(), []
    for name in _RPC_USER.findall(strip_ansi(output)):
        name = name.strip()
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


# --------------------------------------------------------------------------
# showmount — NFS exports
# --------------------------------------------------------------------------

def parse_showmount_exports(output: str) -> list[tuple[str, str]]:
    """Exports as (path, allowed clients)."""
    out = []
    for raw in strip_ansi(output).splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("export list"):
            continue
        if line.startswith("clnt_create") or "RPC:" in line:
            continue    # error text, not an export
        parts = line.split(None, 1)
        if not parts[0].startswith("/"):
            continue
        out.append((parts[0], parts[1].strip() if len(parts) > 1 else ""))
    return out


def export_is_world_readable(clients: str) -> bool:
    """`*` or an empty client list means anyone who can reach the port."""
    clients = (clients or "").strip()
    return clients in ("", "*") or bool(re.search(r"(^|[\s,])\*([\s,]|$)", clients))


# --------------------------------------------------------------------------
# sslscan — protocol support
# --------------------------------------------------------------------------

# Matched on structure rather than column width: previously this required
# exactly three spaces between the protocol and "enabled", so a version that
# padded differently silently reported a vulnerable host as clean.
_SSL_PROTO = re.compile(
    r"^\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3|TLSv1)\s+"
    r"(enabled|disabled)\b", re.I | re.M)

DEPRECATED_PROTOCOLS = {
    "SSLv2": "critical", "SSLv3": "high",
    "TLSv1.0": "medium", "TLSv1": "medium", "TLSv1.1": "medium",
}


def parse_sslscan_protocols(output: str) -> dict[str, bool]:
    """Protocol name -> enabled."""
    out: dict[str, bool] = {}
    for proto, state in _SSL_PROTO.findall(strip_ansi(output)):
        out[proto] = state.lower() == "enabled"
    return out


def deprecated_enabled(protocols: dict[str, bool]) -> list[tuple[str, str]]:
    return [(p, DEPRECATED_PROTOCOLS[p])
            for p, enabled in protocols.items()
            if enabled and p in DEPRECATED_PROTOCOLS]


# --------------------------------------------------------------------------
# netexec / crackmapexec — SMB host details
# --------------------------------------------------------------------------

_NXC_FIELD = re.compile(r"\(([a-zA-Z0-9_]+):([^)]*)\)")


def parse_netexec_smb(output: str) -> dict[str, str]:
    """Fields from a netexec SMB banner line: signing, SMBv1, domain, name."""
    fields: dict[str, str] = {}
    for key, value in _NXC_FIELD.findall(strip_ansi(output)):
        fields[key.lower()] = value.strip()
    return fields


def signing_disabled(fields: dict[str, str]) -> Optional[bool]:
    """True when signing is off, False when on, None when not reported.

    None matters: absent output is not evidence of a secure configuration, and
    reporting it as such would be a false negative in the client's favour.
    """
    value = fields.get("signing")
    if value is None:
        return None
    return value.strip().lower() in ("false", "0", "no")


# --------------------------------------------------------------------------
# snmpwalk
# --------------------------------------------------------------------------

_SNMP_FAIL = re.compile(
    r"Timeout: No Response|No Such Object|no response|Authentication failure|"
    r"snmpwalk:|Cannot find module|USM unknown", re.I)


def snmp_responded(output: str, returncode: int = 0) -> bool:
    text = strip_ansi(output).strip()
    if returncode != 0 or not text:
        return False
    if _SNMP_FAIL.search(text):
        return False
    # A real reply always carries an OID or a typed value.
    return bool(re.search(r"=\s*\w+:|::\w+", text))


# --------------------------------------------------------------------------
# ike-scan
# --------------------------------------------------------------------------

_IKE_AGGRESSIVE = re.compile(r"Aggressive Mode Handshake returned", re.I)


def ike_aggressive_mode(output: str) -> bool:
    return bool(_IKE_AGGRESSIVE.search(strip_ansi(output)))


# --------------------------------------------------------------------------
# searchsploit
# --------------------------------------------------------------------------

_CVE_IN_CODES = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def parse_searchsploit(output: str) -> list[dict]:
    """Exploit-DB hits. Tolerates the banner some builds print before the JSON."""
    text = strip_ansi(output).strip()
    if not text:
        return []
    start = text.find("{")
    if start == -1:
        return []
    try:
        data = json.loads(text[start:])
    except ValueError:
        return []
    hits = data.get("RESULTS_EXPLOIT") or []
    return [h for h in hits if isinstance(h, dict)]


def searchsploit_cves(hits: list[dict]) -> list[str]:
    found = set()
    for hit in hits:
        for value in hit.values():
            found.update(c.upper() for c in _CVE_IN_CODES.findall(str(value)))
    return sorted(found)


# --------------------------------------------------------------------------
# ldapsearch
# --------------------------------------------------------------------------

_NAMING_CONTEXT = re.compile(r"^namingContexts:\s*(.+)$", re.I | re.M)


def parse_ldap_contexts(output: str) -> list[str]:
    return [c.strip() for c in _NAMING_CONTEXT.findall(strip_ansi(output))
            if c.strip()]


def ldap_bind_succeeded(output: str, returncode: int = 0) -> bool:
    text = strip_ansi(output)
    if re.search(r"ldap_bind:|Invalid credentials|Operations error", text, re.I):
        return False
    return returncode == 0 and bool(_NAMING_CONTEXT.search(text))
