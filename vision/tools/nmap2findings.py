#!/usr/bin/env python3
"""nmap XML -> vision findings JSON.

    sudo nmap -sV -sC --script vuln -oX scan.xml 10.10.0.0/24
    python3 tools/nmap2findings.py scan.xml > run.json

Extracts:
  - open services (product/version/cpe) -> services[]
  - NSE script output containing CVE ids -> findings[] (confidence: firm)
  - version-only detections with no CVE  -> findings[] (confidence: tentative)

The tentative ones matter: they feed the advisor's product-name fallback, which
is how you catch things nmap has no NSE script for.
"""
from __future__ import annotations

import json
import re
import sys

RE_CVE = re.compile(r"\bCVE[-–](\d{4}-\d{4,7})\b", re.I)

# NSE scripts whose output means "this host is vulnerable", not just "info"
VULN_SCRIPTS = {
    "vulners", "vuln", "smb-vuln-ms17-010", "smb-vuln-ms08-067",
    "http-vuln-cve2017-5638", "ssl-heartbleed", "ssl-poodle", "ssl-dh-params",
    "rdp-vuln-ms12-020", "smb-vuln-cve-2017-7494", "http-shellshock",
}


# vulners prints one finding per line: IDENTIFIER<tab>SCORE<tab>URL
RE_VULNERS_ROW = re.compile(
    r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}\.\d)\b", re.I)


def _cvss_per_cve(output: str) -> dict:
    """Pair each CVE with the score printed on its own line.

    Falls back to nothing rather than guessing: a CVE with no score of its own
    gets rated by whether the script flagged the service vulnerable, which is
    honest, instead of inheriting the worst score in the block.
    """
    out = {}
    for cve, score in RE_VULNERS_ROW.findall(output or ""):
        try:
            value = float(score)
        except ValueError:
            continue
        if 0.0 <= value <= 10.0:
            key = cve.upper()
            # Keep the highest score seen for that specific CVE only.
            if value > out.get(key, -1):
                out[key] = value
    return out


def sev_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def parse(path: str) -> dict:
    try:
        from ..core.safety import parse_xml_safely, safe_display
    except ImportError:  # running as a standalone script
        import sys as _s, pathlib as _p
        _s.path.insert(0, str(_p.Path(__file__).resolve().parent.parent.parent))
        from vision.core.safety import parse_xml_safely, safe_display
    # A killed nmap leaves a truncated file; an empty one is common when the
    # scan was interrupted before any host completed. Neither should traceback
    # — callers get empty results and decide what to do.
    import xml.etree.ElementTree as _ET
    try:
        root = parse_xml_safely(path).getroot()
    except (_ET.ParseError, OSError, ValueError):
        return {"services": [], "findings": []}
    services, findings = [], []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue

        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            pnum = int(port.get("portid"))
            proto = port.get("protocol", "tcp")
            svc = port.find("service")

            product = version = name = extra = None
            cpes = []
            if svc is not None:
                name = svc.get("name")
                product = svc.get("product")
                version = svc.get("version")
                extra = svc.get("extrainfo")
                cpes = [c.text for c in svc.findall("cpe") if c.text]

            services.append({
                "ip": ip, "port": pnum, "proto": proto, "state": "open",
                "name": name, "product": product, "version": version,
                "extrainfo": extra, "cpe": cpes, "source": "nmap",
            })

            # NSE script output on this port
            port_had_cve = False
            for script in port.findall("script"):
                sid = script.get("id", "")
                out = script.get("output", "") or ""
                cves = sorted({f"CVE-{m}" for m in RE_CVE.findall(out)})
                if not cves:
                    continue
                port_had_cve = True

                is_vuln = any(v in sid for v in VULN_SCRIPTS) or "VULNERABLE" in out

                # Each CVE carries its own score on its own line. Taking
                # max(scores) across the whole block and applying it to every
                # CVE turned one 10.0 into 147 criticals on a single host in a
                # real run — a report nobody reads past the first page.
                per_cve = _cvss_per_cve(out)

                # One finding per SERVICE, not per CVE.
                #
                # vulners lists every CVE ever associated with a product
                # version. A real run produced 163 separate findings for one
                # PostgreSQL instance, 55 for one OpenSSH — 414 in total on a
                # single host. Every one of them has the same remediation
                # ("upgrade the service"), so listing them individually turns
                # one job into 163 rows and buries the findings that need
                # separate action.
                #
                # The full CVE list stays on the finding, so the exploit
                # advisor's CVE join still works exactly as before.
                if cves:
                    scored = [(per_cve.get(c), c) for c in cves]
                    rated = [(v, c) for v, c in scored if v is not None]
                    worst_cvss, worst_cve = (max(rated) if rated
                                             else (None, cves[0]))
                    label = f"{product or name or 'service'}" \
                            f"{' ' + version if version else ''}"
                    if len(cves) == 1:
                        title = f"{cves[0]} — {label}"
                    else:
                        title = (f"{label} — {len(cves)} known CVEs"
                                 + (f", worst {worst_cve}" if worst_cve else ""))
                    findings.append({
                        "ip": ip, "port": pnum, "proto": proto,
                        "title": title,
                        "severity": (sev_from_cvss(worst_cvss)
                                     if worst_cvss is not None
                                     else ("high" if is_vuln else "medium")),
                        "confidence": "firm" if is_vuln else "tentative",
                        # Every CVE is preserved: the advisor joins on these,
                        # and the report lists them under the finding.
                        "cves": sorted(cves),
                        "cvss": worst_cvss,
                        "description": (
                            f"{len(cves)} published CVEs affect {label} as "
                            "detected. They are grouped because a single "
                            "upgrade addresses all of them; the full list is "
                            "recorded below."
                            if len(cves) > 1 else ""),
                        "evidence": safe_display(out, 1500),
                        "remediation": (
                            f"Upgrade {product or name or 'this service'} to a "
                            "supported release. Version-based detection may "
                            "include CVEs already fixed by distribution "
                            "backports — confirm against the vendor's "
                            "advisory before reporting individual CVEs."),
                        "source": f"nmap:{sid}",
                    })

            # No CVE found but we know the product — keep it as a lead so the
            # advisor's product fallback can still match a module.
            if not port_had_cve and product:
                findings.append({
                    "ip": ip, "port": pnum, "proto": proto,
                    "title": f"{product} {version or ''}".strip() + " detected",
                    "severity": "info", "confidence": "tentative",
                    "cves": [],
                    "evidence": safe_display(f"{name or ''} {product or ''} {version or ''}", 200),
                    "source": "nmap:version",
                })

        # host-level scripts (e.g. smb-vuln-* run via --script)
        for hs in host.findall("./hostscript/script"):
            out = hs.get("output", "") or ""
            cves = sorted({f"CVE-{m}" for m in RE_CVE.findall(out)})
            for cve in cves:
                findings.append({
                    "ip": ip, "title": f"{cve} — {hs.get('id')}",
                    "severity": "high" if "VULNERABLE" in out else "medium",
                    "confidence": "firm" if "VULNERABLE" in out else "tentative",
                    "cves": [cve], "evidence": safe_display(out, 1500),
                    "source": f"nmap:{hs.get('id')}",
                })

    # dedupe identical (ip, port, cve)
    seen, uniq = set(), []
    for f in findings:
        k = (f["ip"], f.get("port"), tuple(f["cves"]), f["title"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)

    return {"services": services, "findings": uniq}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 1
    data = parse(sys.argv[1])
    print(json.dumps(data, indent=2))
    print(f"  {len(data['services'])} services, {len(data['findings'])} findings",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
