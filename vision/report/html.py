"""HTML report generation.

Design constraints, all from how this artefact actually gets used:

  - **Self-contained.** No CDN fonts, no external CSS, no JS dependencies. The
    report gets emailed to a client, opened on an air-gapped review box, and
    printed to PDF. Anything that needs the network is a broken report.
  - **Everything is escaped.** The document embeds service banners, share
    names, and script output — all attacker-controlled. An unescaped finding
    is stored XSS against the client's own security team. This is the one
    thing in this file that must never regress.
  - **Print is a first-class target.** Most of these end up as PDF, so page
    breaks, ink-friendly backgrounds, and expanded link targets are handled.

Visual direction: severity is ordinal data, so it gets a proper sequential
ramp (oxblood → orange → ochre → olive → slate) rather than a traffic-light
palette. Typography follows one rule taken from the subject — anything the
reader could paste into a terminal is set in monospace, everything they read
as prose is set in a serif. That makes identifiers scannable without needing
decoration around them.
"""

from __future__ import annotations

import html
import re
import time
from pathlib import Path
from typing import Any, Iterable

from ..core.safety import safe_display, secure_write

# NVD's own identifier format. Anything else is not linked.
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}

CONFIDENCE_NOTE = {
    "confirmed": "Verified against the target",
    "firm": "Active check by a scanner",
    "tentative": "Inferred from version or banner",
}


def e(value: Any) -> str:
    """Escape for HTML text and attribute context.

    Findings carry remote-controlled text. safe_display strips terminal escape
    sequences; html.escape stops the rest from becoming markup.
    """
    return html.escape(safe_display(value, 4000), quote=True)


CSS = """
:root{
  --paper:#FAFAF8; --ink:#14161A; --ink-soft:#4A4F57; --ink-faint:#7C828C;
  --rule:#DEDFDA; --rule-soft:#EDEEE9; --field:#F2F2EE;
  --accent:#1E3A5F;
  --sev-critical:#8B1A1A; --sev-high:#C2410C; --sev-medium:#A16207;
  --sev-low:#3F6212;      --sev-info:#64748B;
  --serif:Charter,"Bitstream Charter","Sitka Text",Cambria,Georgia,serif;
  --sans:ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,"SF Mono","Cascadia Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--paper); color:var(--ink);
  font-family:var(--serif); font-size:16px; line-height:1.6;
}
.wrap{max-width:60rem; margin:0 auto; padding:3rem 1.5rem 6rem}

/* ---- masthead ---- */
.masthead{border-bottom:2px solid var(--ink); padding-bottom:1.5rem; margin-bottom:2.5rem}
.eyebrow{
  font-family:var(--sans); font-size:.6875rem; font-weight:600;
  letter-spacing:.14em; text-transform:uppercase; color:var(--ink-faint);
}
.masthead h1{
  font-family:var(--sans); font-size:clamp(1.9rem,4.5vw,2.75rem);
  font-weight:680; letter-spacing:-.022em; line-height:1.1; margin:.4rem 0 1.25rem;
}
.meta{
  display:grid; grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));
  gap:1rem 1.75rem; margin:0;
}
.meta dt{
  font-family:var(--sans); font-size:.6875rem; font-weight:600;
  letter-spacing:.1em; text-transform:uppercase; color:var(--ink-faint);
  margin-bottom:.15rem;
}
.meta dd{margin:0; font-family:var(--mono); font-size:.8125rem; word-break:break-word}

/* ---- section ---- */
section{margin:3.5rem 0}
h2{
  font-family:var(--sans); font-size:.8125rem; font-weight:660;
  letter-spacing:.12em; text-transform:uppercase; color:var(--ink-soft);
  padding-bottom:.5rem; border-bottom:1px solid var(--rule); margin:0 0 1.5rem;
}
h3{font-family:var(--sans); font-size:1.0625rem; font-weight:640; margin:0 0 .5rem;
   letter-spacing:-.01em}
p{margin:0 0 1rem; max-width:38rem}
.lede{font-size:1.0625rem; color:var(--ink-soft)}

/* ---- posture bar: the severity distribution as one continuous rule ---- */
.posture{margin:0 0 1.75rem}
.posture-bar{display:flex; height:.6rem; border-radius:1px; overflow:hidden;
             background:var(--rule-soft)}
.posture-bar span{display:block}
.posture-key{
  display:flex; flex-wrap:wrap; gap:1.25rem; margin-top:.85rem;
  font-family:var(--sans); font-size:.75rem;
}
.posture-key b{
  font-family:var(--mono); font-size:.9375rem; font-weight:600;
  display:block; line-height:1.2;
}
.posture-key i{
  display:inline-block; width:.5rem; height:.5rem; border-radius:50%;
  margin-right:.4rem; vertical-align:.02rem;
}
.posture-key span{color:var(--ink-faint); font-style:normal}

/* ---- tables ---- */
table{width:100%; border-collapse:collapse; font-size:.8125rem}
caption{
  font-family:var(--sans); font-size:.75rem; color:var(--ink-faint);
  text-align:left; padding-bottom:.6rem;
}
th{
  font-family:var(--sans); font-size:.6875rem; font-weight:600;
  letter-spacing:.08em; text-transform:uppercase; color:var(--ink-faint);
  text-align:left; padding:.45rem .75rem .45rem 0; border-bottom:1px solid var(--rule);
  white-space:nowrap;
}
td{padding:.5rem .75rem .5rem 0; border-bottom:1px solid var(--rule-soft);
   vertical-align:top}
tbody tr:last-child td{border-bottom:0}
td.data,th.data{font-family:var(--mono)}
td.num{text-align:right; font-family:var(--mono)}

/* ---- findings ---- */
.finding{
  border-left:3px solid var(--rule); padding:0 0 0 1.25rem; margin:0 0 2.5rem;
  break-inside:avoid;
}
.finding-head{display:flex; flex-wrap:wrap; align-items:baseline;
              gap:.6rem; margin-bottom:.35rem}
.chip{
  font-family:var(--sans); font-size:.625rem; font-weight:660;
  letter-spacing:.1em; text-transform:uppercase;
  padding:.18rem .45rem; border-radius:2px; color:#fff; white-space:nowrap;
}
.chip.ghost{background:none; color:var(--ink-faint); border:1px solid var(--rule);
            padding:.13rem .4rem}
.target{font-family:var(--mono); font-size:.8125rem; color:var(--ink-soft)}
.finding p{font-size:.9375rem}

/* provenance: which tool said this, and how sure it is */
.provenance{
  display:flex; flex-wrap:wrap; gap:.4rem 1.5rem; margin:.75rem 0;
  font-family:var(--sans); font-size:.75rem; color:var(--ink-faint);
}
.provenance b{color:var(--ink-soft); font-family:var(--mono); font-weight:500}
.cvssvec{font-family:var(--mono); font-size:.6875rem; color:var(--ink-faint);
  letter-spacing:-.01em; white-space:nowrap}

.evidence{
  font-family:var(--mono); font-size:.75rem; line-height:1.55;
  background:var(--field); border:1px solid var(--rule-soft); border-radius:2px;
  padding:.7rem .85rem; margin:.75rem 0; overflow-x:auto;
  white-space:pre-wrap; word-break:break-word; color:var(--ink-soft);
}
.fix{
  border-top:1px solid var(--rule-soft); padding-top:.7rem; margin-top:.85rem;
  font-size:.875rem;
}
.fix strong{
  font-family:var(--sans); font-size:.6875rem; font-weight:600;
  letter-spacing:.1em; text-transform:uppercase; color:var(--ink-faint);
  display:block; margin-bottom:.2rem;
}
.cve-list{font-family:var(--mono); font-size:.75rem}
.cve-list a{color:var(--accent); text-decoration:none;
            border-bottom:1px solid var(--rule)}
.cve-list a:hover,.cve-list a:focus{border-bottom-color:var(--accent)}
a:focus-visible,summary:focus-visible{outline:2px solid var(--accent);
                                      outline-offset:2px}

.chain{margin:.75rem 0; padding-left:1.15rem; font-size:.875rem;
       color:var(--ink-soft)}
.chain li{margin:.2rem 0}
.chain b{font-family:var(--sans); font-size:.8125rem; color:var(--ink)}
.engagement{margin:0 0 2.5rem; padding:1.1rem 1.25rem; background:var(--field);
            border:1px solid var(--rule-soft); border-radius:3px}
.draft-note{font-size:.8125rem; color:var(--ink-faint); font-style:italic;
            border-left:2px solid var(--rule); padding-left:.85rem; margin-top:1rem}
section h2 + p, .lede{max-width:40rem}
.empty{color:var(--ink-faint); font-style:italic}
details summary{
  cursor:pointer; font-family:var(--sans); font-size:.8125rem;
  color:var(--ink-soft); padding:.3rem 0;
}
footer{
  margin-top:5rem; padding-top:1.25rem; border-top:1px solid var(--rule);
  font-family:var(--sans); font-size:.75rem; color:var(--ink-faint);
}

@media (max-width:34rem){
  .wrap{padding:2rem 1.1rem 4rem}
  table{font-size:.75rem}
  th,td{padding-right:.5rem}
}
@media print{
  :root{--paper:#fff; --field:#F5F5F2}
  .wrap{max-width:none; padding:0}
  section{margin:2rem 0}
  .finding{break-inside:avoid; page-break-inside:avoid}
  h2{break-after:avoid}
  details{display:block}
  details summary{display:none}
  a[href^="http"]::after{content:" (" attr(href) ")"; font-size:.6875rem;
                         color:var(--ink-faint); word-break:break-all}
}
@media (prefers-reduced-motion:reduce){*{animation:none!important;
                                         transition:none!important}}
"""


def _counts(findings: list[dict]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in out:
            out[sev] += 1
    return out


def _posture(counts: dict[str, int], total: int) -> str:
    if not total:
        return '<p class="empty">No findings recorded.</p>'
    segments = "".join(
        f'<span style="width:{counts[s] / total * 100:.4f}%;'
        f'background:var(--sev-{s})" title="{SEVERITY_LABEL[s]}: {counts[s]}"></span>'
        for s in SEVERITY_ORDER if counts[s]
    )
    keys = "".join(
        f'<div><b>{counts[s]}</b>'
        f'<span><i style="background:var(--sev-{s})"></i>{SEVERITY_LABEL[s]}</span></div>'
        for s in SEVERITY_ORDER
    )
    return (f'<div class="posture"><div class="posture-bar">{segments}</div>'
            f'<div class="posture-key">{keys}</div></div>')


def _services_table(services: list[dict]) -> str:
    if not services:
        return '<p class="empty">No open services were identified.</p>'
    rows = []
    for s in sorted(services, key=lambda x: (x.get("ip", ""), x.get("port", 0))):
        version = " ".join(filter(None, [s.get("product"), s.get("version")]))
        rows.append(
            f'<tr><td class="data">{e(s.get("ip"))}</td>'
            f'<td class="data">{e(s.get("port"))}/{e(s.get("proto", "tcp"))}</td>'
            f'<td class="data">{e(s.get("name") or "—")}</td>'
            f'<td class="data">{e(version or "—")}</td></tr>'
        )
    return (
        f'<table><caption>{len(services)} open service(s) across '
        f'{len({s.get("ip") for s in services})} host(s)</caption>'
        '<thead><tr><th>Host</th><th>Port</th><th>Service</th>'
        '<th>Product and version</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _host_summary(findings: list[dict], services: list[dict]) -> str:
    hosts: dict[str, dict[str, int]] = {}
    for f in findings:
        ip = f.get("ip")
        if not ip:
            continue
        hosts.setdefault(ip, {s: 0 for s in SEVERITY_ORDER})
        sev = f.get("severity", "info")
        if sev in hosts[ip]:
            hosts[ip][sev] += 1
    if not hosts:
        return ""

    def risk(counts: dict[str, int]) -> tuple:
        return tuple(-counts[s] for s in SEVERITY_ORDER)

    svc_count: dict[str, int] = {}
    for s in services:
        svc_count[s.get("ip")] = svc_count.get(s.get("ip"), 0) + 1

    rows = []
    for ip, counts in sorted(hosts.items(), key=lambda kv: risk(kv[1])):
        cells = "".join(
            f'<td class="num" style="color:var(--sev-{s})">{counts[s] or "·"}</td>'
            for s in SEVERITY_ORDER
        )
        rows.append(f'<tr><td class="data">{e(ip)}</td>'
                    f'<td class="num">{svc_count.get(ip, 0)}</td>{cells}</tr>')
    heads = "".join(f'<th class="num">{SEVERITY_LABEL[s][:4]}</th>'
                    for s in SEVERITY_ORDER)
    return (
        '<table><caption>Hosts ordered by highest severity present</caption>'
        f'<thead><tr><th>Host</th><th class="num">Svcs</th>{heads}</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _cve_links(cves: Iterable[str]) -> str:
    """Render CVE identifiers, linking only the ones that are genuinely CVEs.

    CVE values arrive from tool output and are therefore untrusted. Escaping
    stops them becoming markup, but building an href out of arbitrary text
    still produces a link to an attacker-chosen path — so anything that isn't
    a well-formed CVE ID is rendered as plain text instead. A malformed CVE
    shouldn't yield a broken NVD link either way.
    """
    items = [str(c).strip() for c in cves if c]
    if not items:
        return ""
    rendered = []
    for c in items:
        if CVE_ID.fullmatch(c):
            rendered.append(
                f'<a href="https://nvd.nist.gov/vuln/detail/{e(c)}" '
                f'rel="noopener noreferrer">{e(c)}</a>'
            )
        else:
            rendered.append(f'<span title="not a valid CVE identifier">{e(c)}</span>')
    return f'<div class="cve-list">{", ".join(rendered)}</div>'


def _finding_block(f: dict) -> str:
    sev = f.get("severity", "info")
    conf = f.get("confidence", "tentative")
    target = e(f.get("ip", ""))
    if f.get("port"):
        target += f':{e(f["port"])}'

    parts = [
        f'<article class="finding" style="border-left-color:var(--sev-{sev})">',
        '<div class="finding-head">',
        f'<span class="chip" style="background:var(--sev-{sev})">'
        f'{SEVERITY_LABEL.get(sev, sev)}</span>',
        f'<h3>{e(f.get("title", "Untitled finding"))}</h3>',
        f'<span class="target">{target}</span>',
        '</div>',
    ]
    if f.get("description"):
        parts.append(f'<p>{e(f["description"])}</p>')

    manual = bool(f.get("manual")) or str(f.get("source", "")).startswith("manual:")
    who = str(f.get("source", "")).split(":", 1)[-1] if manual else ""
    # A reviewer needs to tell tool output from analyst judgement: the
    # follow-up question is different for each.
    reporter = (f'<b>{e(who)}</b> — recorded manually'
                if manual else f'<b>{e(f.get("source", "unknown"))}</b>')
    prov = [f'Reported by {reporter}',
            f'Confidence <b>{e(conf)}</b> — {e(CONFIDENCE_NOTE.get(conf, ""))}']
    if f.get("cvss") is not None:
        _vec = f.get("cvss_vector")
        if _vec:
            prov.append(f'CVSS <b>{e(f["cvss"])}</b> '
                        f'<span class="cvssvec">{e(_vec)}</span>')
        else:
            prov.append(f'CVSS <b>{e(f["cvss"])}</b>')
    parts.append('<div class="provenance">'
                 + "".join(f"<div>{p}</div>" for p in prov) + '</div>')

    parts.append(_cve_links(f.get("cves") or []))

    if f.get("evidence"):
        parts.append(f'<pre class="evidence">{e(f["evidence"])}</pre>')
    if f.get("remediation"):
        parts.append('<div class="fix"><strong>Remediation</strong>'
                     f'{e(f["remediation"])}</div>')
    parts.append('</article>')
    return "".join(parts)


def _excluded_section(excluded: list[dict]) -> str:
    if not excluded:
        return ""
    rows = []
    for f in excluded:
        t = f.get("triage") or {}
        target = e(f.get("ip", "")) + (f':{e(f["port"])}' if f.get("port") else "")
        rows.append(
            f'<tr><td>{e(t.get("status", ""))}</td>'
            f'<td class="data">{target}</td>'
            f'<td>{e(f.get("title", ""))}</td>'
            f'<td>{e(t.get("note", ""))}</td></tr>'
        )
    return (
        f'<section><h2>Excluded findings &middot; {len(excluded)}</h2>'
        '<p class="lede">Issues the assessor reviewed and held back from the '
        'findings above, with the reason for each. They are listed so the '
        'judgement can be checked rather than taken on trust.</p>'
        '<table><thead><tr><th>Decision</th><th>Target</th><th>Finding</th>'
        f'<th>Reason</th></tr></thead><tbody>{"".join(rows)}</tbody></table>'
        '</section>'
    )


def _coverage(services: list[dict], findings: list[dict],
              stages: list[dict]) -> str:
    """What was examined, not just what was found.

    A finding count says nothing about whether every service was looked at. A
    real run had three RPC-related services open with no finding of any kind —
    present in the services table, absent from the report.
    """
    try:
        from ..analysis.coverage import audit
    except ImportError:
        return ""
    if not services:
        return ""
    a = audit(services, findings, stages)
    rows = ""
    if a.unassessed:
        rows = "".join(
            f'<tr><td class="data">{e(s.ip)}:{e(s.port)}</td>'
            f'<td>{e(s.name)}</td><td>{e(s.why)}</td></tr>'
            for s in a.unassessed)
        rows = ('<table><thead><tr><th>Service</th><th>Name</th>'
                f'<th>Status</th></tr></thead><tbody>{rows}</tbody></table>')
    notes = []
    if a.skipped_for_tools:
        notes.append("Stages that did not run because the tooling was "
                     f"unavailable: {e(', '.join(a.skipped_for_tools))}.")
    if a.incomplete_stages:
        notes.append("Stages that did not finish, so part of the target set "
                     f"was never examined: {e(', '.join(a.incomplete_stages))}.")
    note_html = "".join(f"<p>{n}</p>" for n in notes)
    return (
        f'<section><h2>Coverage &middot; {a.percent}%</h2>'
        f'<p class="lede">{len(a.services) - len(a.unassessed)} of '
        f'{len(a.services)} discovered services were covered by an assessment '
        'stage that ran. Anything listed below was seen but not assessed — it '
        'is neither a finding nor a clean result.</p>'
        f'{rows}{note_html}</section>'
    )


def _methodology(stages: list[dict]) -> str:
    if not stages:
        return ""
    rows = []
    for s in stages:
        if s.get("skipped"):
            status, note = "Not run", s.get("reason", "")
        elif not s.get("ok"):
            status, note = "Failed", s.get("reason", "")
        else:
            status = "Completed"
            note = s.get("reason", "") or (
                f'{s.get("findings", 0)} finding(s)' if s.get("findings") else "")
        rows.append(
            f'<tr><td class="data">{e(s.get("name"))}</td>'
            f'<td>{e(status)}</td>'
            f'<td class="num">{s.get("duration", 0):.1f}s</td>'
            f'<td>{e(note)}</td></tr>'
        )
    return (
        '<table><caption>Every stage attempted, including those skipped for '
        'missing tooling</caption>'
        '<thead><tr><th>Stage</th><th>Status</th><th class="num">Time</th>'
        '<th>Detail</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _summary_prose(counts: dict[str, int], hosts: int, services: int) -> str:
    total = sum(counts.values())
    urgent = counts["critical"] + counts["high"]
    if not total:
        return ("The assessment completed without identifying any issues in the "
                "scoped range. Review the methodology table below to confirm the "
                "intended checks actually ran.")
    if urgent:
        lead = (f"{urgent} finding{'s' if urgent != 1 else ''} rated high or "
                "critical require attention before the next review cycle.")
    else:
        lead = ("No high or critical findings were identified. The issues below "
                "are hardening opportunities rather than immediate exposures.")
    return (f"{lead} In total, {total} finding{'s' if total != 1 else ''} "
            f"across {services} open service{'s' if services != 1 else ''} on "
            f"{hosts} host{'s' if hosts != 1 else ''}. Findings marked "
            "<em>tentative</em> were inferred from a version banner and have not "
            "been verified against the running service; treat them as leads for "
            "manual confirmation rather than as confirmed exposures.")


def _attack_paths(findings: list[dict]) -> str:
    """Attack paths lead the report because they are what the reader acts on
    first: a chain says which findings, taken together, actually reach data."""
    try:
        from ..analysis.correlate import correlate
    except ImportError:
        return ""
    paths = correlate(findings)
    if not paths:
        return ""
    blocks = []
    for p in paths:
        steps = "".join(
            f'<li><b>{e(label)}</b> — {e(f.get("title", ""))}</li>'
            for label, f in p.matched_steps
        )
        refs = "".join(
            f'<a href="{e(r)}" rel="noopener noreferrer">{e(r)}</a> '
            for r in p.rule.references if str(r).startswith("https://")
        )
        blocks.append(
            f'<article class="finding path" '
            f'style="border-left-color:var(--sev-{p.severity})">'
            '<div class="finding-head">'
            f'<span class="chip" style="background:var(--sev-{p.severity})">'
            f'{SEVERITY_LABEL.get(p.severity, p.severity)}</span>'
            f'<h3>{e(p.title)}</h3></div>'
            f'<p>{e(p.rule.narrative)}</p>'
            f'<div class="provenance"><div>Outcome <b>{e(p.rule.outcome)}</b></div>'
            f'<div>Confidence <b>{e(p.confidence)}</b></div></div>'
            f'<ol class="chain">{steps}</ol>'
            f'<div class="fix"><strong>Remediation</strong>'
            f'{e(p.rule.remediation)}</div>'
            + (f'<div class="cve-list">{refs}</div>' if refs else "")
            + '</article>'
        )
    return ('<section><h2>Attack paths &middot; '
            f'{len(paths)}</h2><p class="lede">These findings combine into '
            'the sequences below. Breaking any one step in a chain breaks the '
            f'chain.</p>{"".join(blocks)}</section>')


FRAMEWORK_TITLES = {
    "attack": "MITRE ATT&CK", "cis": "CIS Controls v8",
    "pci": "PCI DSS v4.0", "owasp": "OWASP Top 10 (2021)",
}


def _executive(meta, findings: list[dict], services: list[dict],
               hosts: int, stages: list[dict]) -> str:
    """The page a manager reads before deciding whether to fund the fix."""
    try:
        from ..core.engagement import resolve_summary
        from ..analysis.correlate import correlate
    except ImportError:
        return ""
    paths = len(correlate(findings))
    text, is_draft = resolve_summary(meta, findings, services, hosts,
                                     stages, paths)
    if not text:
        return ""
    paras = "".join(f"<p>{e(p)}</p>" for p in text.split("\n\n") if p.strip())
    note = ""
    if is_draft:
        # Labelled so nobody ships a machine-written narrative unread.
        note = ('<p class="draft-note">Drafted automatically from the findings '
                'below. Replace it with your own assessment before issuing '
                'this report.</p>')
    return (f'<section><h2>Executive summary</h2>{paras}{note}</section>')


def _engagement_meta(meta) -> str:
    """Client, authority and dates. Without these the document is a scan
    output rather than something a client can file."""
    if not meta or not getattr(meta, "is_configured", False):
        return ""
    rows = [("Client", meta.client), ("Assessor", meta.tester),
            ("Authorisation", meta.reference), ("Dates", meta.dates),
            ("Contact", meta.contact)]
    cells = "".join(
        f'<div><dt>{e(label)}</dt><dd>{e(value)}</dd></div>'
        for label, value in rows if value)
    return f'<dl class="meta engagement">{cells}</dl>' if cells else ""


def _remediation(findings: list[dict]) -> str:
    """The plan, ordered for whoever has to act on it.

    Placed before the findings detail because that is the reading order for the
    person who has to schedule the work: what to change, then why.
    """
    try:
        from ..analysis.remediation import plan, quick_wins
    except ImportError:
        return ""
    actions = plan(findings)
    if not actions:
        return ""
    rows = "".join(
        f'<tr><td class="num">{i}</td>'
        f'<td><span class="chip" style="background:var(--sev-{a.severity})">'
        f'{SEVERITY_LABEL.get(a.severity, a.severity)}</span></td>'
        f'<td class="num">{len(a.hosts)}</td>'
        f'<td class="num">{len(a.findings)}</td>'
        f'<td>{e(a.text)}</td></tr>'
        for i, a in enumerate(actions, 1)
    )
    wins = quick_wins(actions)
    win_html = ""
    if wins:
        items = "".join(
            f'<li><b>{len(a.hosts)} hosts</b> — {e(a.text)}</li>' for a in wins)
        win_html = (f'<h3>One change, several hosts</h3><ol class="chain">'
                    f'{items}</ol>')
    return (
        f'<section><h2>Remediation plan &middot; {len(actions)}</h2>'
        '<p class="lede">The findings below reduce to these actions, ordered by '
        'the worst issue each one closes. One change often resolves the same '
        'issue on several hosts, so the number of jobs is smaller than the '
        'number of findings.</p>'
        '<table><thead><tr><th class="num">#</th><th>Worst</th>'
        '<th class="num">Hosts</th><th class="num">Fixes</th>'
        f'<th>Action</th></tr></thead><tbody>{rows}</tbody></table>'
        f'{win_html}</section>'
    )


def _controls(findings: list[dict]) -> str:
    """Control coverage.

    Deliberately framed as evidence gathered, not as a compliance verdict: a
    pass/fail claim needs scope definition, compensating controls and an
    assessor, none of which a scanner has.
    """
    try:
        from ..analysis.frameworks import coverage
    except ImportError:
        return ""
    cov = coverage(findings)
    if not cov:
        return ""
    blocks = []
    for framework in ("attack", "cis", "pci", "owasp"):
        entries = cov.get(framework)
        if not entries:
            continue
        rows = "".join(
            '<tr><td class="data">'
            + (f'<a href="{e(c.url)}" rel="noopener noreferrer">{e(c.id)}</a>'
               if c.url.startswith("https://") else e(c.id))
            + f'</td><td>{e(c.title)}</td><td class="num">{n}</td></tr>'
            for c, n in entries
        )
        blocks.append(
            f'<h3>{e(FRAMEWORK_TITLES.get(framework, framework))}</h3>'
            '<table><thead><tr><th>Control</th><th>Title</th>'
            '<th class="num">Findings</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )
    return ('<section><h2>Control coverage</h2>'
            '<p class="lede">Controls for which this assessment gathered '
            'evidence, and how many findings relate to each. This is an '
            'indicative mapping to support review — it is not a compliance '
            'determination, which requires defined scope, consideration of '
            'compensating controls, and a qualified assessor.</p>'
            + "".join(blocks) + '</section>')


def build_report(
    findings: list[dict],
    services: list[dict],
    scope: str = "",
    operator: str = "",
    live_hosts: list[str] | None = None,
    stages: list[dict] | None = None,
    engagement: str = "Network vulnerability assessment",
    tool_version: str = "0.1.0",
    meta=None,
) -> str:
    findings = list(findings or [])
    services = list(services or [])
    stages = list(stages or [])
    counts = _counts(findings)
    total = sum(counts.values())
    host_count = len(live_hosts or {f.get("ip") for f in findings} | {
        s.get("ip") for s in services})
    generated = time.strftime("%d %B %Y, %H:%M %Z")

    # Findings the analyst excluded are disclosed in an appendix rather than
    # dropped: a report that silently omits findings is indistinguishable from
    # a scan that missed them, and the reviewer cannot check the reasoning.
    def _status(f):
        return (f.get("triage") or {}).get("status", "new")

    excluded = [f for f in findings if _status(f) not in ("new", "confirmed")]
    findings = [f for f in findings if _status(f) in ("new", "confirmed")]
    counts = _counts(findings)
    total = sum(counts.values())

    ordered = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(f.get("severity", "info"))
                       if f.get("severity") in SEVERITY_ORDER else 99,
                       f.get("ip", ""), f.get("port") or 0),
    )

    groups = []
    for sev in SEVERITY_ORDER:
        block = [f for f in ordered if f.get("severity") == sev]
        if not block:
            continue
        body = "".join(_finding_block(f) for f in block)
        if sev == "info" and len(block) > 6:
            # Informational findings are context, not action items. Collapsed so
            # they don't bury the results that need a decision.
            body = (f'<details><summary>Show {len(block)} informational '
                    f'findings</summary>{body}</details>')
        groups.append(f'<h2 id="sev-{sev}">{SEVERITY_LABEL[sev]} '
                      f'&middot; {len(block)}</h2>{body}')

    findings_html = "".join(groups) or '<p class="empty">No findings recorded.</p>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(engagement)} — Vision report</title>
<meta name="generator" content="Vision {e(tool_version)}">
<style>{CSS}</style>
</head>
<body>
<div class="wrap">

<header class="masthead">
  <div class="eyebrow">Vulnerability assessment report</div>
  <h1>{e(engagement)}</h1>
  <dl class="meta">
    <div><dt>Scope</dt><dd>{e(scope or "—")}</dd></div>
    <div><dt>Operator</dt><dd>{e(operator or "—")}</dd></div>
    <div><dt>Generated</dt><dd>{e(generated)}</dd></div>
    <div><dt>Hosts / services</dt><dd>{host_count} / {len(services)}</dd></div>
  </dl>
</header>

{_engagement_meta(meta)}

{_executive(meta, findings, services, host_count, stages)}

<section>
  <h2>Summary</h2>
  {_posture(counts, total)}
  <p class="lede">{_summary_prose(counts, host_count, len(services))}</p>
</section>

{_attack_paths(findings)}

{_remediation(findings)}

<section>
  <h2>Findings by host</h2>
  {_host_summary(findings, services) or '<p class="empty">No per-host findings.</p>'}
</section>

<section>
  <h2>Findings</h2>
  {findings_html}
</section>

<section>
  <h2>Open services</h2>
  {_services_table(services)}
</section>

{_excluded_section(excluded)}

{_controls(findings)}

{_coverage(services, findings, stages)}

<section>
  <h2>Methodology</h2>
  {_methodology(stages) or '<p class="empty">No stage record available.</p>'}
</section>

<footer>
  Generated by Vision {e(tool_version)} on {e(generated)}.
  Findings marked tentative were inferred from service banners and require
  manual confirmation. Exploitation was not performed as part of this scan.
</footer>

</div>
</body>
</html>
"""


def write_report(path: Path | str, **kwargs) -> Path:
    """Render and write the report with restrictive permissions."""
    return secure_write(path, build_report(**kwargs))
