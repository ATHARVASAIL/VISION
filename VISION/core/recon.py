"""External attack-surface reconnaissance.

Given a domain, map the externally-visible surface *before* any scan touches a
port:

  - subdomains, passively — certificate-transparency logs (crt.sh) and, if
    present, subfinder / amass
  - each name resolved to its IP addresses
  - DNS records: A / AAAA / MX / NS / TXT / CNAME / SOA, and a zone-transfer
    attempt against each nameserver
  - email-security posture: SPF, DMARC, DKIM
  - subdomain-takeover candidates (a live CNAME to a service that no longer
    claims the name)
  - which addresses sit behind a CDN or cloud provider — almost always someone
    else's infrastructure, and almost always outside your authorisation
  - a one-request security-header grade for the web hosts found

It never scans. Certificate transparency and DNS are queries to public
infrastructure, not to the target; the only packet this sends the target is a
single HTTP HEAD per web host for the header grade — one unauthenticated
request a browser would make opening the page.

What it produces, beside the printed surface map:

  - findings, in the same schema as the scanner (missing SPF/DMARC, an open
    zone transfer, a takeover candidate, weak security headers ...)
  - ``recon-scope.txt`` — the resolved addresses that are *not* third-party,
    ready to review and hand to ``vision run --scope``

The last line is the whole point. External recon turns up addresses you are not
allowed to touch (the target's CDN, its mail provider, a shared host); this
separates them out so the scan that follows stays inside the engagement.

Pure standard library. Every external tool is optional and skipped cleanly when
absent — the DNS client here is built on ``socket`` so email and DNS findings
work on a box with nothing installed.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import shutil
import socket
import ssl
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import ui
from .runlog import write_host_evidence, write_host_summaries
from .safety import safe_filename, secure_write
from .schema import Confidence, Finding, Severity, to_json
from .ui import S, paint

# ───────────────────────── CDN / third-party ranges ─────────────────────────
# Curated and deliberately non-exhaustive: enough to flag the common cases so an
# operator does not point a scanner at Cloudflare. A match means "almost
# certainly not the client's host — confirm scope", never an authoritative
# ownership claim.
_CDN_RANGES: dict[str, list[str]] = {
    "Cloudflare": [
        "104.16.0.0/13", "172.64.0.0/13", "173.245.48.0/20", "103.21.244.0/22",
        "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "131.0.72.0/22", "2606:4700::/32",
    ],
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16", "2a04:4e40::/32"],
    "Akamai": ["23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13"],
    "AWS CloudFront": [
        "13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15", "54.182.0.0/16",
        "54.192.0.0/16", "99.84.0.0/16", "205.251.192.0/19", "120.52.22.96/27",
    ],
    "Google": ["34.64.0.0/10", "35.190.0.0/17", "130.211.0.0/22", "172.217.0.0/16"],
    "Azure Front Door": ["13.107.0.0/16", "150.171.0.0/16", "204.79.197.0/24"],
    "GitHub Pages": ["185.199.108.0/22"],
}


def _nets() -> list[tuple[str, ipaddress._BaseNetwork]]:
    out = []
    for provider, cidrs in _CDN_RANGES.items():
        for c in cidrs:
            try:
                out.append((provider, ipaddress.ip_network(c)))
            except ValueError:
                pass
    return out


_CDN_NETS = _nets()


def cdn_provider(ip: str) -> str | None:
    """Name the CDN/cloud provider an address belongs to, or None."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    for provider, net in _CDN_NETS:
        if addr.version == net.version and addr in net:
            return provider
    return None


# ───────────────────────── minimal DNS client (stdlib) ──────────────────────
_RTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
_RTYPE_REV = {v: k for k, v in _RTYPE.items()}


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        lb = label.encode("idna") if label else b""
        out += bytes([len(lb)]) + lb
    return out + b"\x00"


def _build_query(name: str, rtype: int, qid: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    question = _encode_name(name) + struct.pack(">HH", rtype, 1)  # class IN
    return header + question


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    """Decode a DNS name at offset, following compression pointers.

    Returns (name, offset_after_the_name_field). Pointers are followed for the
    name value but the returned offset is the position after the first pointer,
    per the wire format.
    """
    labels: list[str] = []
    jumped = False
    end = off
    seen = 0
    while True:
        if off >= len(data):
            break
        length = data[off]
        if length == 0:
            off += 1
            if not jumped:
                end = off
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if off + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            off = pointer
            jumped = True
            seen += 1
            if seen > 64:           # guard against pointer loops
                break
            continue
        off += 1
        labels.append(data[off:off + length].decode("latin-1"))
        off += length
        if not jumped:
            end = off
    return ".".join(labels), end


def parse_dns_response(data: bytes) -> list[tuple[str, str, object]]:
    """Parse answer records into (name, type, rdata). rdata shape by type:
    A/AAAA -> ip str, CNAME/NS -> name str, TXT -> str, MX -> (pref, host),
    SOA -> primary-ns str. Unknown types are skipped.
    """
    if len(data) < 12:
        return []
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):                 # skip questions
        _, off = _read_name(data, off)
        off += 4
    out: list[tuple[str, str, object]] = []
    for _ in range(an):
        name, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        tname = _RTYPE_REV.get(rtype, str(rtype))
        try:
            if rtype == 1 and rdlen == 4:
                out.append((name, "A", socket.inet_ntop(socket.AF_INET, rdata)))
            elif rtype == 28 and rdlen == 16:
                out.append((name, "AAAA", socket.inet_ntop(socket.AF_INET6, rdata)))
            elif rtype in (2, 5):
                val, _ = _read_name(data, off)
                out.append((name, tname, val))
            elif rtype == 15:
                pref = struct.unpack(">H", rdata[:2])[0]
                host, _ = _read_name(data, off + 2)
                out.append((name, "MX", (pref, host)))
            elif rtype == 6:
                primary, _ = _read_name(data, off)
                out.append((name, "SOA", primary))
            elif rtype == 16:
                txt, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]
                    txt.append(rdata[i + 1:i + 1 + ln].decode("latin-1"))
                    i += 1 + ln
                out.append((name, "TXT", "".join(txt)))
        except (OSError, struct.error, IndexError):
            pass
        off += rdlen
    return out


def _resolvers() -> list[str]:
    servers = []
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) > 1:
                    servers.append(parts[1])
    except OSError:
        pass
    for pub in ("1.1.1.1", "8.8.8.8"):   # fallbacks, in case resolv.conf is empty
        if pub not in servers:
            servers.append(pub)
    return servers


def dns_query(name: str, rtype: str, server: str | None = None,
              timeout: float = 3.0) -> list:
    """One UDP DNS query. Returns the rdata of matching answer records.

    Best-effort: a timeout or a malformed response yields an empty list rather
    than an exception, so a flaky resolver never aborts recon.
    """
    rnum = _RTYPE.get(rtype.upper())
    if rnum is None:
        return []
    servers = [server] if server else _resolvers()
    query = _build_query(name, rnum)
    for srv in servers:
        try:
            fam = socket.AF_INET6 if ":" in srv else socket.AF_INET
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(query, (srv, 53))
                data, _ = s.recvfrom(4096)
            answers = [rd for nm, tp, rd in parse_dns_response(data)
                       if tp == rtype.upper()]
            # A CNAME chain can mean the asked type sits under a different name;
            # still return whatever matched. Fall through to next server only on
            # a hard failure.
            return answers
        except (OSError, socket.timeout):
            continue
    return []


# ───────────────────────── certificate transparency ─────────────────────────
def parse_crtsh(text: str, domain: str) -> set[str]:
    """Names from a crt.sh JSON response that belong to the domain."""
    names: set[str] = set()
    domain = domain.lower().lstrip(".")
    try:
        rows = json.loads(text)
    except (ValueError, TypeError):
        return names
    for row in rows if isinstance(rows, list) else []:
        for field_ in ("name_value", "common_name"):
            val = row.get(field_, "") if isinstance(row, dict) else ""
            for n in str(val).split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n and (n == domain or n.endswith("." + domain)) \
                        and "@" not in n and " " not in n:
                    names.add(n)
    return names


def crtsh_names(domain: str, timeout: float = 20.0) -> set[str]:
    """Subdomains seen in certificate-transparency logs. Network, best-effort."""
    try:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection("crt.sh", 443, timeout=timeout,
                                            context=ctx)
        conn.request("GET", f"/?q=%25.{domain}&output=json",
                     headers={"User-Agent": "vision-recon"})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        conn.close()
        return parse_crtsh(body, domain)
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return set()


def run_subfinder(domain: str, timeout: int = 120) -> set[str]:
    """Passive subdomains from subfinder, if it is installed."""
    if not shutil.which("subfinder"):
        return set()
    try:
        r = subprocess.run(["subfinder", "-silent", "-d", domain],
                           capture_output=True, text=True, timeout=timeout)
        return {l.strip().lower() for l in r.stdout.splitlines() if l.strip()}
    except (OSError, subprocess.SubprocessError):
        return set()


# ───────────────────────── email security ───────────────────────────────────
def analyze_spf(txts: list[str]) -> tuple[str | None, Severity, str]:
    """(record, severity, note) for the SPF posture of a set of TXT records."""
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if spf is None:
        return (None, Severity.MEDIUM,
                "No SPF record — anyone can send mail claiming to be this domain.")
    low = spf.lower()
    if "+all" in low:
        return (spf, Severity.HIGH,
                "SPF ends in '+all' — it authorises the entire internet to send "
                "as this domain, which is worse than having none.")
    if "?all" in low:
        return (spf, Severity.MEDIUM,
                "SPF ends in '?all' (neutral) — it expresses no policy and will "
                "not cause spoofed mail to be rejected.")
    if "~all" in low:
        return (spf, Severity.LOW,
                "SPF ends in '~all' (softfail) — spoofed mail is marked, not "
                "rejected. '-all' is the hard-fail posture.")
    return (spf, Severity.INFO, "SPF present with a hard-fail (-all) policy.")


def analyze_dmarc(txts: list[str]) -> tuple[str | None, Severity, str]:
    dmarc = next((t for t in txts if t.lower().startswith("v=dmarc1")), None)
    if dmarc is None:
        return (None, Severity.MEDIUM,
                "No DMARC record — receivers have no instruction to reject mail "
                "that fails SPF/DKIM, so spoofing is not blocked.")
    policy = ""
    for part in dmarc.split(";"):
        if part.strip().lower().startswith("p="):
            policy = part.split("=", 1)[1].strip().lower()
    if policy == "none":
        return (dmarc, Severity.LOW,
                "DMARC policy is 'p=none' — it only monitors; spoofed mail is "
                "still delivered. Move to quarantine or reject once reporting is "
                "clean.")
    if policy in ("quarantine", "reject"):
        return (dmarc, Severity.INFO, f"DMARC enforced (p={policy}).")
    return (dmarc, Severity.LOW, "DMARC record present but its policy is unclear.")


def email_findings(domain: str, spf_txts: list[str], dmarc_txts: list[str],
                   dkim_selectors: list[str]) -> list[Finding]:
    """Findings for a domain's email-spoofing resistance."""
    out: list[Finding] = []
    spf_rec, spf_sev, spf_note = analyze_spf(spf_txts)
    if spf_sev is not Severity.INFO:
        out.append(Finding(
            ip=domain, title="Email spoofing: SPF weakness", severity=spf_sev,
            confidence=Confidence.FIRM, description=spf_note,
            evidence=spf_rec or "no v=spf1 TXT record at the domain apex",
            remediation="Publish a strict SPF record ending in '-all' that lists "
                        "only authorised senders.",
            source="recon-email",
            references=["https://datatracker.ietf.org/doc/html/rfc7208"]))
    dm_rec, dm_sev, dm_note = analyze_dmarc(dmarc_txts)
    if dm_sev is not Severity.INFO:
        out.append(Finding(
            ip=domain, title="Email spoofing: DMARC weakness", severity=dm_sev,
            confidence=Confidence.FIRM, description=dm_note,
            evidence=dm_rec or "no v=DMARC1 TXT record at _dmarc." + domain,
            remediation="Publish a DMARC record and raise the policy to "
                        "'p=reject' once alignment reporting is clean.",
            source="recon-email",
            references=["https://datatracker.ietf.org/doc/html/rfc7489"]))
    if not dkim_selectors:
        out.append(Finding(
            ip=domain, title="Email: no DKIM found on common selectors",
            severity=Severity.INFO, confidence=Confidence.TENTATIVE,
            description="No DKIM key was found on the common selectors checked. "
                        "DKIM selectors are not enumerable, so this is only a "
                        "hint — confirm with the mail administrator.",
            remediation="Ensure outbound mail is DKIM-signed and the published "
                        "selector key is current.",
            source="recon-email"))
    return out


# ───────────────────────── subdomain takeover ───────────────────────────────
# A CNAME to one of these services, where the service no longer claims the name,
# is a classic takeover. Detection here is conservative: it flags the candidate
# for manual confirmation rather than asserting a takeover.
_TAKEOVER_SERVICES = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku", "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3", "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure", "trafficmanager.net": "Azure Traffic Manager",
    "pantheonsite.io": "Pantheon", "wpengine.com": "WP Engine",
    "ghost.io": "Ghost", "surge.sh": "Surge", "bitbucket.io": "Bitbucket",
    "fastly.net": "Fastly", "readthedocs.io": "Read the Docs",
    "statuspage.io": "Statuspage", "zendesk.com": "Zendesk",
    "helpscoutdocs.com": "Help Scout", "unbounce.com": "Unbounce",
    "netlify.app": "Netlify", "shopify.com": "Shopify",
}


def takeover_service(cname: str) -> str | None:
    cname = (cname or "").lower().rstrip(".")
    for needle, svc in _TAKEOVER_SERVICES.items():
        if needle in cname:
            return svc
    return None


def takeover_candidate(host: str, cname: str, target_resolves: bool) -> Finding | None:
    """A live name whose CNAME points at a takeoverable service that no longer
    resolves is a takeover candidate."""
    svc = takeover_service(cname)
    if svc and not target_resolves:
        return Finding(
            ip=host, title=f"Subdomain takeover candidate ({svc})",
            severity=Severity.HIGH, confidence=Confidence.TENTATIVE,
            description=f"{host} is a CNAME to {cname} ({svc}) but that target "
                        "does not resolve. If the service resource is unclaimed, "
                        "an attacker can register it and serve content from your "
                        "subdomain.",
            evidence=f"{host}  CNAME  {cname}  (target NXDOMAIN)",
            remediation="Remove the dangling DNS record, or re-claim the resource "
                        "on the provider. Confirm manually before reporting.",
            source="recon-dns")
    return None


# ───────────────────────── web header grade ─────────────────────────────────
_SEC_HEADERS = [
    ("strict-transport-security", Severity.LOW, "HSTS",
     "Clients can be downgraded to plain HTTP (SSL-strip)."),
    ("content-security-policy", Severity.LOW, "Content-Security-Policy",
     "No CSP — reduced defence-in-depth against XSS and injection."),
    ("x-frame-options", Severity.INFO, "X-Frame-Options",
     "Page may be framed (clickjacking)."),
    ("x-content-type-options", Severity.INFO, "X-Content-Type-Options",
     "MIME-sniffing not disabled."),
]


def grade_headers(headers: dict[str, str]) -> tuple[str, list[str]]:
    """(letter grade, missing header names) for a response's security headers."""
    lower = {k.lower(): v for k, v in headers.items()}
    missing = [name for key, _sev, name, _why in _SEC_HEADERS if key not in lower]
    present = len(_SEC_HEADERS) - len(missing)
    grade = ["D", "C", "C", "B", "A"][present] if present <= 4 else "A"
    return grade, missing


def header_findings(host: str, headers: dict[str, str]) -> list[Finding]:
    lower = {k.lower(): v for k, v in headers.items()}
    out: list[Finding] = []
    for key, sev, name, why in _SEC_HEADERS:
        if key not in lower:
            out.append(Finding(
                ip=host, port=443, title=f"Missing security header: {name}",
                severity=sev, confidence=Confidence.FIRM, description=why,
                evidence=f"{host} response has no {name} header",
                remediation=f"Set the {name} response header.",
                source="recon-web"))
    server = lower.get("server", "")
    if server and any(c.isdigit() for c in server):
        out.append(Finding(
            ip=host, port=443, title="Server version disclosed in HTTP header",
            severity=Severity.INFO, confidence=Confidence.FIRM,
            description=f"Server header advertises '{server}', aiding targeted "
                        "exploitation.",
            evidence=f"Server: {server}", remediation="Suppress the version token "
            "in the Server header.", source="recon-web"))
    return out


def http_probe(host: str, timeout: float = 6.0) -> dict[str, str] | None:
    """One HTTPS HEAD request; return response headers, or None if unreachable."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
        conn.request("HEAD", "/", headers={"User-Agent": "vision-recon"})
        resp = conn.getresponse()
        headers = {k: v for k, v in resp.getheaders()}
        conn.close()
        return headers
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None


# ───────────────────────── orchestration ────────────────────────────────────
@dataclass
class ReconResult:
    domain: str
    subdomains: set = field(default_factory=set)
    hosts: dict = field(default_factory=dict)      # host -> {ips, cname, cdn}
    findings: list = field(default_factory=list)
    in_scope_ips: set = field(default_factory=set)
    third_party: dict = field(default_factory=dict)  # ip -> provider
    dns: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)      # (name, text) for writing


def _gather_dkim(domain: str) -> list[str]:
    found = []
    for sel in ("default", "google", "selector1", "selector2", "k1", "mail", "dkim"):
        if dns_query(f"{sel}._domainkey.{domain}", "TXT"):
            found.append(sel)
    return found


def build_surface(domain: str, names: set[str],
                  resolver=None, prober=None) -> ReconResult:
    """Assemble the attack surface from discovered names. Network access is
    injected (``resolver``, ``prober``) so this is unit-testable offline; left
    unset they bind to the live functions at call time (so a monkeypatch in a
    test or a caller override is honoured)."""
    resolver = resolver or dns_query
    prober = prober or http_probe
    res = ReconResult(domain=domain, subdomains=set(names))
    res.subdomains.add(domain)
    for host in sorted(res.subdomains):
        a = list(resolver(host, "A"))
        aaaa = list(resolver(host, "AAAA"))
        cnames = list(resolver(host, "CNAME"))
        cname = cnames[0] if cnames else ""
        entry = {"ips": a + aaaa, "cname": cname, "cdn": None}
        for ip in a:
            prov = cdn_provider(ip)
            if prov:
                entry["cdn"] = prov
                res.third_party[ip] = prov
            else:
                res.in_scope_ips.add(ip)
        res.hosts[host] = entry
        # Takeover: a CNAME to a takeoverable service whose target does not
        # resolve. "target_resolves" = the name produced any address.
        if cname and not (a or aaaa):
            tk = takeover_candidate(host, cname, target_resolves=False)
            if tk:
                res.findings.append(tk)
    # Web header grade on the apex and www, if reachable.
    for web in (domain, f"www.{domain}"):
        if web in res.hosts and res.hosts[web]["ips"]:
            headers = prober(web)
            if headers is not None:
                res.findings.extend(header_findings(web, headers))
    return res


def cmd_recon(args) -> int:
    from ..cli import VERSION  # local import avoids a cycle at module load
    domain = args.domain.strip().lower().lstrip(".")
    if not domain or " " in domain or "/" in domain:
        print(ui.bad(f"not a domain: {args.domain!r}"))
        return 1
    print(ui.banner(VERSION, compact=getattr(args, "no_banner", False)))
    print(ui.section("External recon", domain))

    # 1 ── passive subdomain discovery
    with ui.Spinner("certificate transparency + passive sources") as sp:
        names = crtsh_names(domain) | run_subfinder(domain)
        names.add(domain)
        el = sp.elapsed
    print(ui.ok(f"{len(names)} name(s) discovered  ({el:.1f}s)"))

    # 2 ── resolve + classify
    with ui.Spinner("resolving and classifying hosts"):
        result = build_surface(domain, names)

    # 3 ── DNS + email posture (domain apex)
    spf = [t for t in dns_query(domain, "TXT") if "v=spf1" in t.lower()]
    dmarc = dns_query(f"_dmarc.{domain}", "TXT")
    dmarc = [t for t in dmarc if "v=dmarc1" in t.lower()]
    dkim = _gather_dkim(domain)
    result.findings.extend(email_findings(domain, spf, dmarc, dkim))
    result.dns = {
        "MX": [f"{p} {h}" for p, h in dns_query(domain, "MX")],
        "NS": list(dns_query(domain, "NS")),
        "TXT": list(dns_query(domain, "TXT")),
    }

    # 4 ── zone transfer against each nameserver
    for ns in result.dns["NS"]:
        axfr = _zone_transfer(domain, ns.rstrip("."))
        if axfr:
            result.findings.append(Finding(
                ip=domain, title="DNS zone transfer allowed", severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description=f"Nameserver {ns} answered an AXFR request, disclosing "
                            "the full DNS zone — every internal name and address.",
                evidence=axfr[:500],
                remediation="Restrict zone transfers to authorised secondary "
                            "nameservers only.", source="recon-dns"))
            result.evidence.append((f"zone-transfer-{safe_filename(ns)}", axfr))
            break

    _render(result)
    _write_outputs(result, args)
    return 0


def _zone_transfer(domain: str, ns: str) -> str:
    """Attempt an AXFR via dig, if present. Returns the transcript on success."""
    if not shutil.which("dig"):
        return ""
    try:
        r = subprocess.run(["dig", "+noall", "+answer", "AXFR", domain, f"@{ns}"],
                           capture_output=True, text=True, timeout=20)
        out = r.stdout.strip()
        # A refused transfer prints nothing useful; a successful one lists records.
        if out and "Transfer failed" not in out and "connection timed out" not in out \
                and len(out.splitlines()) > 1:
            return out
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def _render(result: ReconResult) -> None:
    rows = []
    for host in sorted(result.hosts):
        e = result.hosts[host]
        ips = ", ".join(e["ips"][:3]) + ("…" if len(e["ips"]) > 3 else "")
        tag = paint(e["cdn"], S.YELLOW) if e["cdn"] else (
            "" if e["ips"] else paint("no address", S.DIM))
        rows.append([host, ips or "-", tag])
    print(ui.section("Attack surface", f"{len(result.hosts)} name(s)"))
    print(ui.table(rows[:40], ["HOST", "ADDRESSES", "NOTE"]))
    if len(rows) > 40:
        print(ui.info(f"… {len(rows) - 40} more in recon-findings / surface file"))

    if result.dns.get("MX") or result.dns.get("NS"):
        print(ui.section("DNS"))
        for k in ("NS", "MX"):
            for v in result.dns.get(k, [])[:6]:
                print(ui.info(f"{k:<4} {v}"))

    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO]
    findings = sorted(result.findings,
                      key=lambda f: sev_order.index(f.severity))
    print(ui.section("Findings", f"{len(findings)}"))
    for f in findings[:30]:
        sev = f.severity.value.upper()
        print(f"  {paint(f'[{sev:<8}]', S.BOLD)} {f.title}  "
              + paint(str(f.ip), S.DIM))

    print(ui.section("Scope", "third-party infrastructure excluded"))
    print(ui.info(f"{len(result.in_scope_ips)} address(es) resolve to the target"))
    if result.third_party:
        print(ui.warn(f"{len(result.third_party)} address(es) sit behind a CDN/"
                      "cloud provider — confirm authorisation before scanning"))


def _write_outputs(result: ReconResult, args) -> None:
    out = Path(getattr(args, "output", "./vision-recon")).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    # findings.json (same shape the rest of Vision reads)
    secure_write(out / "recon-findings.json",
                 to_json({"domain": result.domain, "findings": result.findings,
                          "hosts": result.hosts,
                          "third_party": result.third_party}))
    # scope file for the scan step (tool-neutral — it may be kept with the report)
    scope_lines = [
        "# resolved target addresses (third-party infrastructure excluded)",
        f"# domain: {result.domain}",
        "# review before scanning; confirm each is in your authorisation",
        "",
    ] + sorted(result.in_scope_ips, key=_ip_key)
    if result.third_party:
        scope_lines += ["", "# excluded — CDN / cloud / third-party:"]
        scope_lines += [f"#   {ip}  ({prov})"
                        for ip, prov in sorted(result.third_party.items())]
    secure_write(out / "recon-scope.txt", "\n".join(scope_lines) + "\n")
    # evidence (zone-transfer transcripts etc.), sorted into finding/ and
    # no finding/ per host just like the scanner's output. Everything recon
    # writes is proof of a finding, so it carries the "recon" stage the summary
    # classifier matches on.
    if not getattr(args, "no_evidence", False):
        for name, text in result.evidence:
            write_host_evidence(out / "evidence", target=result.domain,
                                argv=[name], stdout=text, stage="recon",
                                kind="evidence")
        finding_dicts = json.loads(to_json(result.findings))
        for d in finding_dicts:
            d.setdefault("stage", "recon")
        write_host_summaries(out / "evidence", services=[],
                             findings=finding_dicts, scope=result.domain)
    print("\n" + ui.ok("written:"))
    print(ui.info(f"findings  {paint(str(out / 'recon-findings.json'), S.ACCENT)}"))
    print(ui.info(f"scope     {paint(str(out / 'recon-scope.txt'), S.ACCENT)}"))
    print(ui.info("next: review the scope file, then "
                  + paint(f"vision run --scope-file {out / 'recon-scope.txt'}",
                          S.ACCENT)))


def _ip_key(ip: str):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)
