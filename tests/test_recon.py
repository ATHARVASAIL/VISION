"""External recon tests: the stdlib DNS client, CT parsing, CDN classification,
email-security analysis, subdomain-takeover detection, header grading, and the
end-to-end `vision recon` command with the network mocked out."""
import struct
import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vision.core import recon as r
from vision.core.pipeline import Pipeline
from vision.core.schema import Severity

fails = []
def check(label, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {label}" + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        fails.append(label)


# ---------------------------------------------------------------- DNS packets
def _name(s):
    out = b""
    for lb in s.split("."):
        out += bytes([len(lb)]) + lb.encode()
    return out + b"\x00"


def _packet(qtype, answers):
    """Build a DNS response: question at offset 12, answers use a pointer to it."""
    hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, len(answers), 0, 0)
    q = _name("example.com") + struct.pack(">HH", qtype, 1)
    body = b""
    for rtype, rdata in answers:
        body += b"\xc0\x0c" + struct.pack(">HHI", rtype, 1, 300) \
            + struct.pack(">H", len(rdata)) + rdata
    return hdr + q + body


print("--- stdlib DNS client ---")
a = r.parse_dns_response(_packet(1, [(1, bytes([93, 184, 216, 34]))]))
check("parses A record", a == [("example.com", "A", "93.184.216.34")], str(a))

aaaa_rdata = bytes.fromhex("20010db8000000000000000000000001")
aaaa = r.parse_dns_response(_packet(28, [(28, aaaa_rdata)]))
check("parses AAAA record", aaaa and aaaa[0][2] == "2001:db8::1", str(aaaa))

cname = r.parse_dns_response(_packet(5, [(5, b"\x03www\xc0\x0c")]))
check("parses CNAME with compression",
      cname == [("example.com", "CNAME", "www.example.com")], str(cname))

mx = r.parse_dns_response(_packet(15, [(15, struct.pack(">H", 10) + b"\x04mail\xc0\x0c")]))
check("parses MX (pref, host)", mx == [("example.com", "MX", (10, "mail.example.com"))], str(mx))

txt = r.parse_dns_response(_packet(16, [(16, b"\x0bv=spf1 -all")]))
check("parses TXT", txt == [("example.com", "TXT", "v=spf1 -all")], str(txt))

ns = r.parse_dns_response(_packet(2, [(2, b"\x03ns1\xc0\x0c")]))
check("parses NS", ns == [("example.com", "NS", "ns1.example.com")], str(ns))

check("empty/short packet is safe", r.parse_dns_response(b"\x00\x01") == [])
# a pointer loop must terminate rather than hang
loop = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + _name("example.com") \
    + struct.pack(">HH", 1, 1) + b"\xc0\x0c" + struct.pack(">HHI", 5, 1, 300) \
    + struct.pack(">H", 2) + b"\xc0\x1f"   # CNAME rdata points at itself
check("pointer loop terminates", isinstance(r.parse_dns_response(loop), list))

check("query builds with RD set", r._build_query("example.com", 1)[2:4] == b"\x01\x00")
check("unknown record type -> no query", r.dns_query("x.com", "WKS") == [])


# ---------------------------------------------------------------- CT parsing
print("\n--- certificate transparency parsing ---")
j = '[{"name_value":"a.example.com\\n*.example.com"},{"common_name":"b.example.com"},{"name_value":"evil.com"}]'
names = r.parse_crtsh(j, "example.com")
check("extracts in-scope names", {"a.example.com", "b.example.com"} <= names, str(names))
check("strips wildcard to apex", "example.com" in names)
check("rejects out-of-scope names", "evil.com" not in names)
check("rejects email addresses in SAN",
      "user@example.com" not in r.parse_crtsh('[{"name_value":"user@example.com"}]', "example.com"))
check("malformed JSON is safe", r.parse_crtsh("not json", "example.com") == set())


# ---------------------------------------------------------------- CDN / scope
print("\n--- CDN / third-party classification ---")
check("Cloudflare range detected", r.cdn_provider("104.16.1.1") == "Cloudflare")
check("Fastly range detected", r.cdn_provider("151.101.1.1") == "Fastly")
check("GitHub Pages range detected", r.cdn_provider("185.199.108.153") == "GitHub Pages")
check("ordinary address is not CDN", r.cdn_provider("93.184.216.34") is None)
check("garbage address is safe", r.cdn_provider("not-an-ip") is None)
check("IPv6 CDN detected", r.cdn_provider("2606:4700::1") == "Cloudflare")


# ---------------------------------------------------------------- email security
print("\n--- email security analysis ---")
check("no SPF -> medium", r.analyze_spf([])[1] is Severity.MEDIUM)
check("SPF +all -> high", r.analyze_spf(["v=spf1 +all"])[1] is Severity.HIGH)
check("SPF ?all -> medium", r.analyze_spf(["v=spf1 ?all"])[1] is Severity.MEDIUM)
check("SPF ~all -> low", r.analyze_spf(["v=spf1 ~all"])[1] is Severity.LOW)
check("SPF -all -> info (ok)", r.analyze_spf(["v=spf1 include:x -all"])[1] is Severity.INFO)
check("no DMARC -> medium", r.analyze_dmarc([])[1] is Severity.MEDIUM)
check("DMARC p=none -> low", r.analyze_dmarc(["v=DMARC1; p=none"])[1] is Severity.LOW)
check("DMARC p=reject -> info", r.analyze_dmarc(["v=DMARC1; p=reject;"])[1] is Severity.INFO)

fs = r.email_findings("example.com", [], [], [])
titles = {f.title for f in fs}
check("email_findings covers SPF+DMARC+DKIM when all weak", len(fs) == 3, str(titles))
check("email findings carry remediation", all(f.remediation for f in fs))
check("strong posture yields no email findings",
      r.email_findings("x.com", ["v=spf1 -all"], ["v=DMARC1; p=reject"], ["default"]) == [])


# ---------------------------------------------------------------- takeover
print("\n--- subdomain takeover ---")
check("github.io recognised", r.takeover_service("foo.github.io") == "GitHub Pages")
check("herokuapp recognised", r.takeover_service("x.herokuapp.com") == "Heroku")
check("ordinary CNAME not flagged", r.takeover_service("www.example.com") is None)
tk = r.takeover_candidate("dead.example.com", "gone.github.io", target_resolves=False)
check("dangling CNAME is a candidate", tk is not None and tk.severity is Severity.HIGH)
check("resolving CNAME is not a candidate",
      r.takeover_candidate("live.example.com", "x.github.io", target_resolves=True) is None)


# ---------------------------------------------------------------- header grade
print("\n--- web security headers ---")
g_all, miss_all = r.grade_headers({})
check("no security headers -> grade D", g_all == "D", g_all)
g_full, miss_full = r.grade_headers({
    "Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"})
check("all headers present -> grade A", g_full == "A" and miss_full == [], g_full)
hf = r.header_findings("example.com", {"Server": "nginx/1.18.0"})
check("missing headers produce findings", any("Missing security header" in f.title for f in hf))
check("versioned Server header flagged", any("Server version disclosed" in f.title for f in hf))
check("clean host header produces no server-disclosure",
      not any("version disclosed" in f.title
              for f in r.header_findings("x.com", {"Server": "cloudflare"})))


# ---------------------------------------------------------------- build_surface
print("\n--- surface assembly (offline, injected resolver) ---")
DNS = {
    ("example.com", "A"): ["93.184.216.34"],
    ("www.example.com", "A"): ["104.16.1.1"],          # Cloudflare -> excluded
    ("dead.example.com", "CNAME"): ["gone.github.io"],  # no address -> takeover
}
resolver = lambda name, rtype, server=None, timeout=3.0: DNS.get((name, rtype.upper()), [])
surface = r.build_surface(
    "example.com", {"www.example.com", "dead.example.com"},
    resolver=resolver, prober=lambda h, timeout=6.0: None)
check("apex always included", "example.com" in surface.hosts)
check("direct address is in scope", "93.184.216.34" in surface.in_scope_ips)
check("CDN address excluded from scope", "104.16.1.1" not in surface.in_scope_ips)
check("CDN address recorded as third-party", surface.third_party.get("104.16.1.1") == "Cloudflare")
check("dangling CNAME became a finding",
      any("takeover" in f.title.lower() for f in surface.findings))


# ---------------------------------------------------------------- end to end
print("\n--- cmd_recon end to end (mocked network) ---")
_orig = (r.crtsh_names, r.run_subfinder, r.dns_query, r.http_probe,
         r._gather_dkim, r._zone_transfer)
r.crtsh_names = lambda d, timeout=20.0: {"www.example.com"}
r.run_subfinder = lambda d, timeout=120: set()
E2E = {("example.com", "A"): ["93.184.216.34"], ("example.com", "TXT"): ["v=spf1 ?all"],
       ("example.com", "NS"): ["ns1.example.com"], ("www.example.com", "A"): ["104.16.1.1"]}
r.dns_query = lambda name, rtype, server=None, timeout=3.0: E2E.get((name, rtype.upper()), [])
r.http_probe = lambda host, timeout=6.0: None
r._gather_dkim = lambda d: ["default"]
r._zone_transfer = lambda d, ns: ""
try:
    out = Path(tempfile.mkdtemp()) / "vision-recon"
    args = types.SimpleNamespace(domain="example.com", output=str(out),
                                 no_evidence=True, no_banner=True)
    rc = r.cmd_recon(args)
    check("cmd_recon returns 0", rc == 0)
    import json
    data = json.loads((out / "recon-findings.json").read_text())
    check("findings.json written with domain", data["domain"] == "example.com")
    check("SPF ?all produced a finding",
          any("SPF" in f["title"] for f in data["findings"]))
    scope_txt = (out / "recon-scope.txt").read_text()
    check("scope file lists the in-scope address", "93.184.216.34" in scope_txt)
    check("scope file excludes the CDN address from the live list",
          "\n104.16.1.1" not in scope_txt)
    check("scope file names the excluded provider", "Cloudflare" in scope_txt)
    check("cmd_recon rejects a non-domain",
          r.cmd_recon(types.SimpleNamespace(domain="1.2.3.4/24", output=str(out),
                                            no_evidence=True, no_banner=True)) == 1)
finally:
    (r.crtsh_names, r.run_subfinder, r.dns_query, r.http_probe,
     r._gather_dkim, r._zone_transfer) = _orig


# ---------------------------------------------------------------- integration
print("\n--- integration with the scanner ---")
check("external mode skips SMB", "smb-enumeration" in Pipeline.EXTERNAL_SKIP)
check("external mode skips Kerberos", "auth-kerberoast" in Pipeline.EXTERNAL_SKIP)
check("external mode keeps web assessment", "web-assessment" not in Pipeline.EXTERNAL_SKIP)
check("external mode keeps port scan", "port-scan" not in Pipeline.EXTERNAL_SKIP)
check("external mode keeps nuclei", "nuclei" not in Pipeline.EXTERNAL_SKIP)
# IKE/ISAKMP VPN endpoints are internet-facing, so external mode must keep the
# stage; it self-gates on UDP 500 being discovered, so it stays quiet otherwise.
check("external mode keeps ike-vpn (VPN gateways are external)",
      "ike-vpn" not in Pipeline.EXTERNAL_SKIP)
check("every EXTERNAL_SKIP name is a real stage",
      set(Pipeline.EXTERNAL_SKIP) <= {s for s, _ in Pipeline.STAGES})
check("every LAN/AD stage except ike-vpn is skipped externally",
      all(s in Pipeline.EXTERNAL_SKIP for s in
          ("smb-enumeration", "smb-shares", "rpc-enumeration", "snmp-enumeration",
           "nfs-exports", "ldap-anonymous-bind", "netbios-scan", "arp-discovery",
           "kerberos-userenum", "auth-kerberoast", "auth-password-policy",
           "auth-share-access", "auth-admin-sprawl")))

from vision.cli import build_parser
_p = build_parser()
_ns = _p.parse_args(["recon", "example.com"])
check("`vision recon` command is registered", _ns.func is r.cmd_recon)
check("`vision run --external` flag parses", _p.parse_args(
    ["run", "--external", "--scope", "1.1.1.1"]).external is True)

print("\n" + "=" * 52)
print("ALL PASS" if not fails else f"FAILURES ({len(fails)}): " + ", ".join(fails))
sys.exit(1 if fails else 0)
