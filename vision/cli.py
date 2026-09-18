"""vision — network VAPT orchestration.

  vision doctor    what's installed, what's missing, what you can do
  vision setup     install the missing toolchain
  vision index     build the offline Metasploit module index
  vision run       automated discovery -> enum -> vuln -> advisory
  vision advise    map findings to exploit modules, ranked
  vision exploit   interactive verify / execute, one target at a time
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .core import ui
from .core.ui import S, paint
from .core.schema import Finding, Service, Severity, Confidence, Proto, to_json
from .core.scope import Scope, ScopeViolation
from .core.doctor import cmd_doctor, cmd_setup
from .core.selfcheck import audit as _selfcheck_audit
from .core.pipeline import Pipeline, RunState
from .core.runlog import RunLog
from .core.profiles import PROFILES, get as get_profile
from .core.console import cmd_menu
from .analysis.correlate import correlate, summary as path_summary
from .analysis.diff import compare
from .analysis.frameworks import coverage, summary as fw_summary, FRAMEWORK_VERSIONS
from .analysis.rules import all_chains
from .analysis.msf_index import MsfIndex
from .analysis.exploit_advisor import (
    ExploitAdvisor, ExploitLauncher, ExploitBlocked, SafetyTier,
)

VERSION = "0.1.0"

TIER_STYLE = {
    SafetyTier.VERIFY_ONLY: S.GREEN,
    SafetyTier.STANDARD: S.CYAN,
    SafetyTier.RISKY: S.YELLOW,
    SafetyTier.DESTRUCTIVE: S.RED,
}
SEV_STYLE = {
    Severity.CRITICAL: S.RED, Severity.HIGH: S.MAGENTA,
    Severity.MEDIUM: S.YELLOW, Severity.LOW: S.CYAN, Severity.INFO: S.GREY,
}


# ------------------------------------------------------------------ helpers

def load_findings(path: str) -> tuple[list[Finding], list[Service]]:
    data = json.loads(Path(path).read_text())
    findings, services = [], []
    for d in data.get("findings", []):
        d = {k: v for k, v in d.items() if k in Finding.__dataclass_fields__}
        d["severity"] = Severity(d.get("severity") or "info")
        d["confidence"] = Confidence(d.get("confidence") or "tentative")
        if d.get("proto"):
            d["proto"] = Proto(d["proto"])
        findings.append(Finding(**d))
    for d in data.get("services", []):
        d = {k: v for k, v in d.items() if k in Service.__dataclass_fields__}
        d["proto"] = Proto(d.get("proto") or "tcp")
        services.append(Service(**d))
    return findings, services


def make_scope(args) -> Scope:
    path = getattr(args, "scope_file", None) or getattr(args, "targets", None)
    if path:
        scope = Scope.from_file(path, deny_path=None,
                                allow_private_only=args.rfc1918_only)
        # Report skipped lines rather than silently narrowing the engagement:
        # a typo that removes ten hosts from a 200-host list is exactly the
        # kind of thing nobody notices until the retest.
        for problem in getattr(scope, "load_problems", []):
            print(ui.warn(f"target file: {problem}"))
        unreachable = scope.unreachable_entries()
        if unreachable:
            print(ui.warn(f"{len(unreachable)} public address(es) will not be "
                          "scanned under --rfc1918-only: "
                          + ", ".join(unreachable[:5])))
        print(ui.ok(f"loaded {scope.address_count} address(es) from {path}"))
        return scope
    if getattr(args, "scope", None):
        return Scope.from_lists(args.scope, deny=args.exclude or [],
                                allow_private_only=args.rfc1918_only)
    raise SystemExit(ui.bad("--scope or --scope-file is required. "
                            "vision never assumes a scope."))


def candidate_table(cands) -> str:
    rows = []
    for i, cd in enumerate(cands, 1):
        tgt = f"{cd.rhost}:{cd.rport}" if cd.rport else cd.rhost
        mark = paint("LOCK", S.RED) if cd.locked else (
            paint("chk", S.GREEN) if cd.module.has_check else "")
        # Why this module was suggested for this finding. Without it the
        # operator sees a module name and has to take the match on faith —
        # and a CVE match and a fuzzy product-name guess deserve very
        # different levels of trust before anything is fired.
        reason = cd.match_reason or ""
        if reason.startswith("cve:"):
            why = paint(reason[4:], S.GREEN)
        elif reason.startswith("product:"):
            why = paint(f"~{reason[8:]}", S.YELLOW)
        else:
            why = paint(reason, S.DIM)
        rows.append([
            paint(str(i), S.DIM),
            paint(cd.effective_severity.value, SEV_STYLE[cd.effective_severity]),
            cd.module.rank,
            paint(cd.tier.value, TIER_STYLE[cd.tier]),
            tgt,
            cd.module.fullname,
            why,
            mark,
        ])
    return ui.table(rows, ["#", "SEV", "RANK", "SAFETY", "TARGET", "MODULE",
                           "WHY", ""],
                    aligns=["r", "l", "l", "l", "l", "l", "l", "l"])


def legend() -> str:
    return (paint("  chk", S.GREEN) + paint(" = verifiable without exploiting", S.DIM)
            + paint("    LOCK", S.RED)
            + paint(" = needs --allow-destructive", S.DIM))


# ------------------------------------------------------------------ commands

def cmd_index(args) -> int:
    print(ui.banner(VERSION, compact=args.no_banner))
    print(ui.section("Metasploit module index"))
    with ui.Spinner("parsing module tree") as sp:
        idx = MsfIndex.build(args.msf_path or None)
        idx.save(args.cache)
        el = sp.elapsed
    print(ui.box([
        f"modules indexed  {paint(str(len(idx)), S.BOLD, S.WHITE)}",
        f"with CVE refs    {sum(1 for m in idx.modules if m.cves)}",
        f"with check()     {paint(str(sum(1 for m in idx.modules if m.has_check)), S.GREEN)}",
        f"destructive      {paint(str(sum(1 for m in idx.modules if m.destructive)), S.RED)}",
        f"elapsed          {el:.1f}s",
    ], title="index"))
    print("\n" + ui.info(f"cached to {paint(args.cache, S.ACCENT)}"))
    return 0


def cmd_run(args) -> int:
    scope = make_scope(args)
    workdir = Path(args.output).expanduser()
    # Resolved before it is printed: this was referenced in the engagement
    # summary twenty lines above where it was assigned, so `vision run` raised
    # NameError before it scanned anything.
    profile = get_profile("aggressive" if args.aggressive else args.intensity)
    print(ui.banner(VERSION, compact=args.no_banner))

    print(ui.section("Engagement"))
    print(ui.info(f"scope    {paint(scope.summary(), S.ACCENT)}"))
    print(ui.info(f"output   {workdir}"))
    print(ui.info(f"intensity {paint(profile.name, S.ACCENT)}"))
    for line in profile.describe():
        print(paint(f"      {line}", S.DIM))
    for imp in profile.impacts:
        render = {"info": ui.info, "caution": ui.warn}.get(imp.level, ui.bad)
        print(render(imp.text))
    if profile.needs_typed_confirmation and not args.yes:
        print()
        print(ui.blocked(f"the {profile.name} profile can take fragile "
                         "devices offline"))
        word = profile.name.upper()
        try:
            if input(f"  type {word} to confirm> ").strip() != word:
                print(ui.info("cancelled — nothing was scanned"))
                return 1
        except (EOFError, KeyboardInterrupt):
            print()
            return 130

    state_file = workdir / "state.json"
    if args.resume and state_file.exists():
        state = RunState.load(state_file)
        print(ui.ok(f"resuming — {len(state.completed())} stage(s) already complete"))
    else:
        state = RunState(scope=scope.summary(), workdir=str(workdir))

    workdir.mkdir(parents=True, exist_ok=True)
    runlog = RunLog(workdir / "run.jsonl", debug=args.debug,
                    evidence_dir=workdir / "evidence" if not args.no_evidence else None)
    runlog.event("run-start", scope=scope.summary(), operator=args.operator or "",
                 aggressive=args.aggressive)
    credential = None
    if getattr(args, "user", None):
        # Deliberately no --password flag. A password in argv is visible in
        # `ps`, in shell history and in the parent process's logs, none of
        # which Vision controls.
        from .core.credentials import prompt as _cred_prompt
        credential = _cred_prompt(username=args.user, domain=args.domain)
        if credential is None:
            print(ui.bad("no credential supplied — aborting"))
            return 1
        print(ui.ok(f"authenticated as {credential.display}"))

    pipe = Pipeline(scope, workdir, state, timeout=args.timeout,
                    resume=args.resume, log=runlog, profile=profile)

    print(ui.section("Scanning", "recon and enumeration only — nothing is exploited"))
    t0 = time.time()
    stages = [s for s in Pipeline.STAGES if s[0] not in set(args.skip or [])]
    for i, (name, method) in enumerate(stages, 1):
        if args.resume and name in state.completed():
            print(ui.step(i, len(stages), name + paint("  already done", S.DIM)))
            continue
        print(ui.step(i, len(stages), name))
        with ui.Spinner(f"running {name}"):
            res = pipe.run_stage(name, method)
        if res.skipped:
            print(ui.warn(f"skipped — {res.reason}"))
        elif not res.ok:
            print(ui.bad(f"failed — {res.reason}"))
        else:
            bits = []
            if res.hosts:
                bits.append(f"{res.hosts} hosts")
            if res.services:
                bits.append(f"{res.services} services")
            if res.findings:
                bits.append(f"{res.findings} findings")
            print(ui.ok(", ".join(bits) or "complete")
                  + paint(f"  {res.duration:.1f}s", S.DIM))

    findings_file = pipe.export()
    runlog.event("run-end", **runlog.summary())

    print(ui.section("Scan summary"))
    sev_count = {}
    for f in state.findings:
        k = f.get("severity", "info")
        sev_count[k] = sev_count.get(k, 0) + 1
    lines = [
        f"live hosts   {paint(str(len(state.live_hosts)), S.BOLD, S.WHITE)}",
        f"services     {len(state.services)}",
        f"findings     {len(state.findings)}",
        "",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev_count.get(sev):
            lines.append(f"  {paint(sev.ljust(9), SEV_STYLE[Severity(sev)])} "
                         f"{sev_count[sev]}")
    lines += ["", f"elapsed      {time.time() - t0:.0f}s"]
    print(ui.box(lines, title="results"))

    try:
        idx = MsfIndex.load_or_build(args.cache, args.msf_path or None)
    except FileNotFoundError:
        print("\n" + ui.warn("Metasploit not found — skipping exploit advisory"))
        print(ui.info(f"findings written to {paint(str(findings_file), S.ACCENT)}"))
        return 0

    findings, services = load_findings(str(findings_file))
    adv = ExploitAdvisor(idx, scope)
    cands = adv.advise(findings, services, min_rank=args.min_rank)

    print(ui.section("Exploit advisory",
                     "recommendations only — nothing has been run"))
    if not cands:
        print(ui.info("no exploit candidates matched the current findings"))
    else:
        s = adv.summary(cands)
        print(candidate_table(cands[:args.top]))
        print(legend())
        print("\n" + ui.info(f"{s['candidates']} candidates · "
                             f"{s['verifiable']} verifiable · {s['locked']} locked"))

    # Failed commands are the first thing an operator needs when a stage
    # produced nothing — surface them instead of burying them in the log.
    failures = runlog.failures()
    if failures:
        print(ui.section("Command failures",
                         f"{len(failures)} command(s) exited non-zero"))
        rows = [[f.get("stage", "")[:22],
                 (f.get("command") or "")[:44],
                 str(f.get("returncode")),
                 (f.get("stderr") or "")[:34]] for f in failures[:12]]
        print(ui.table(rows, ["STAGE", "COMMAND", "RC", "STDERR"]))
        if len(failures) > 12:
            print(paint(f"  … {len(failures) - 12} more in the run log", S.DIM))

    print(ui.section("Next"))
    print(ui.info("findings   " + paint(str(findings_file), S.ACCENT)))
    lg = runlog.summary()
    print(ui.info("run log    " + paint(lg["log"], S.ACCENT)
                  + paint(f"  ({lg['commands']} commands)", S.DIM)))
    if lg["evidence"]:
        print(ui.info("evidence   " + paint(lg["evidence"], S.ACCENT)))
    if cands:
        sc = args.scope[0] if args.scope else "<scope>"
        print(ui.info("verify     " + paint(
            f"vision exploit --findings {findings_file} --scope {sc}", S.ACCENT)))
        print(paint("             starts in check-only mode — no payloads delivered",
                    S.DIM))
    return 0


def cmd_diff(args) -> int:
    """Retest comparison. The question after remediation is not what was found
    but what was actually fixed."""
    base_f, _ = load_findings(args.baseline)
    curr_f, _ = load_findings(args.current)
    base = [_finding_dict(f) for f in base_f]
    curr = [_finding_dict(f) for f in curr_f]
    delta = compare(base, curr)

    print(ui.banner(VERSION, compact=args.no_banner))
    print(ui.section("Retest comparison",
                     f"{Path(args.baseline).name} → {Path(args.current).name}"))
    c = delta.counts
    print(ui.box([
        f"resolved     {paint(str(c['resolved']), S.GREEN, S.BOLD)}",
        f"still open   {c['unchanged']}",
        f"new          {paint(str(c['new']), S.YELLOW if c['new'] else S.GREY)}",
        f"worsened     {paint(str(c['worsened']), S.RED) if c['worsened'] else '0'}",
        f"improved     {c['improved']}",
        "",
        f"remediation  {paint(f'{delta.remediation_rate():.0f}%', S.BOLD, S.WHITE)}",
    ], title="delta"))

    regressions = delta.regressions
    if regressions:
        # A good remediation rate means little if the retest surfaced fresh
        # criticals, so this is stated next to the number, not buried below it.
        print("\n" + ui.warn(paint(
            f"{len(regressions)} new high/critical finding(s) since the baseline",
            S.BOLD)))

    for label, bucket, style in (("Resolved", delta.resolved, S.GREEN),
                                 ("New", delta.new, S.YELLOW),
                                 ("Still open", delta.unchanged, S.GREY)):
        if not bucket or (label == "Still open" and not args.all):
            continue
        print(ui.section(f"{label} · {len(bucket)}"))
        rows = [[paint(f.get("severity", "info"),
                       SEV_STYLE.get(Severity(f.get("severity", "info")), S.GREY)),
                 f.get("ip", "") + (f":{f['port']}" if f.get("port") else ""),
                 (f.get("title") or "")[:56]] for f in bucket[:30]]
        print(ui.table(rows, ["SEV", "TARGET", "FINDING"]))
        if len(bucket) > 30:
            print(paint(f"  … {len(bucket) - 30} more", S.DIM))

    if delta.worsened:
        print(ui.section(f"Worsened · {len(delta.worsened)}"))
        rows = [[old.get("ip", ""),
                 f"{old.get('severity')} → {paint(new.get('severity'), S.RED)}",
                 (new.get("title") or "")[:52]]
                for old, new in delta.worsened[:20]]
        print(ui.table(rows, ["TARGET", "CHANGE", "FINDING"]))
    return 0


def _finding_dict(f) -> dict:
    return {"ip": f.ip, "port": f.port, "title": f.title,
            "severity": f.severity.value, "confidence": f.confidence.value,
            "cves": f.cves, "evidence": f.evidence, "source": f.source,
            "remediation": f.remediation}


def cmd_paths(args) -> int:
    findings, _ = load_findings(args.findings)
    rules, rule_errors = all_chains(args.rules or [])
    for err in rule_errors:
        print(ui.warn(f"rule: {err}"))
    paths = correlate([_finding_dict(f) for f in findings], rules=rules)
    print(ui.banner(VERSION, compact=args.no_banner))
    if not paths:
        print(ui.section("Attack paths"))
        print(ui.info("no chains matched these findings"))
        return 0
    if args.json:
        print(to_json([p.as_finding() for p in paths]))
        return 0
    s = path_summary(paths)
    print(ui.section("Attack paths",
                     f"{s['paths']} chain(s) across {s['hosts']} host(s)"))
    for i, p in enumerate(paths, 1):
        style = SEV_STYLE.get(Severity(p.severity), S.GREY)
        print(f"\n  {paint(str(i) + '.', S.DIM)} "
              f"{paint(p.severity.upper(), style)}  {paint(p.title, S.BOLD)}")
        print(paint(f"      outcome    {p.rule.outcome}", S.DIM))
        print(paint("      chain      "
                    + " → ".join(l for l, _ in p.matched_steps), S.DIM))
        print(paint(f"      confidence {p.confidence}", S.DIM))
    return 0


def cmd_frameworks(args) -> int:
    findings, _ = load_findings(args.findings)
    data = [_finding_dict(f) for f in findings]
    cov = coverage(data)
    print(ui.banner(VERSION, compact=args.no_banner))
    if not cov:
        print(ui.section("Control coverage"))
        print(ui.info("no findings mapped to a control"))
        return 0
    s = fw_summary(data)
    print(ui.section("Control coverage",
                     f"{s['mapped']}/{s['findings']} findings mapped to "
                     f"{s['controls_touched']} control(s)"))
    for key in ("attack", "cis", "pci", "owasp"):
        entries = cov.get(key)
        if not entries:
            continue
        print("\n" + paint(f"  {FRAMEWORK_VERSIONS[key]}", S.BOLD))
        rows = [[paint(c.id, S.ACCENT), c.title[:52], str(n)] for c, n in entries]
        print(ui.table(rows, ["CONTROL", "TITLE", "N"], aligns=["l", "l", "r"]))
    print("\n" + ui.warn("indicative mapping to support review — not a "
                          "compliance determination"))
    return 0


def cmd_advise(args) -> int:
    scope = make_scope(args)
    idx = MsfIndex.load_or_build(args.cache, args.msf_path or None)
    findings, services = load_findings(args.findings)
    adv = ExploitAdvisor(idx, scope)
    cands = adv.advise(findings, services, min_rank=args.min_rank,
                       hide_destructive=args.hide_destructive,
                       per_finding=args.per_finding)

    if args.json:
        print(to_json([{
            "module": cd.module.fullname, "rank": cd.module.rank,
            "target": cd.rhost, "port": cd.rport, "tier": cd.tier.value,
            "locked": cd.locked, "has_check": cd.module.has_check,
            "finding": cd.finding.title, "cves": cd.finding.cves,
            "score": round(cd.score, 1), "match": cd.match_reason,
        } for cd in cands]))
        return 0

    print(ui.banner(VERSION, compact=args.no_banner))
    print(ui.section("Exploit advisory", scope.summary()))
    if not cands:
        print(ui.info("no candidates — findings have no CVEs or matching services"))
        return 0
    s = adv.summary(cands)
    print(candidate_table(cands))
    print(legend())
    print("\n" + ui.box([
        f"candidates   {paint(str(s['candidates']), S.BOLD, S.WHITE)}",
        f"hosts        {s['hosts']}",
        f"verifiable   {paint(str(s['verifiable']), S.GREEN)}",
        f"locked       {paint(str(s['locked']), S.RED)}",
    ], title="summary"))
    return 0


class _NullCtx:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def cmd_exploit(args) -> int:
    scope = make_scope(args)
    idx = MsfIndex.load_or_build(args.cache, args.msf_path or None)
    findings, services = load_findings(args.findings)
    adv = ExploitAdvisor(idx, scope)
    cands = adv.advise(findings, services, min_rank=args.min_rank,
                       per_finding=args.per_finding)
    if not cands:
        print(ui.info("No exploit candidates for the current findings and scope."))
        return 0

    launcher = ExploitLauncher(scope, audit_log=args.audit,
                               allow_destructive=args.allow_destructive,
                               operator=args.operator)

    print(ui.banner(VERSION, compact=args.no_banner))
    while True:
        print(ui.section("Candidates", scope.summary()))
        print(candidate_table(cands))
        print(legend())
        print("\n" + paint("  [N] run   [c N] check only   [s N] details   [q] quit",
                           S.DIM))
        try:
            raw = input(paint("  vision> ", S.BOLD, S.ACCENT)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not raw or raw in ("q", "quit", "exit"):
            return 0

        parts = raw.split()
        verb, num = ("run", parts[0]) if len(parts) == 1 else (parts[0], parts[1])
        try:
            cd = cands[int(num) - 1]
        except (ValueError, IndexError):
            print(ui.bad("invalid selection"))
            continue

        if verb == "s":
            print("\n" + ui.box(cd.describe().splitlines(),
                                title=cd.module.fullname))
            print(ui.info("check   "
                          + paint(launcher.manual_command(cd, "check"), S.ACCENT)))
            print(ui.info("exploit "
                          + paint(launcher.manual_command(cd, "exploit"), S.ACCENT)))
            continue

        action = "check" if verb == "c" else args.default_action
        if action == "check" and not cd.module.has_check:
            print(ui.warn(f"{cd.module.fullname} has no check method — "
                          "use the bare number to run it for real"))
            continue

        ctx = _NullCtx() if args.dry_run else ui.Spinner(f"msf {action} -> {cd.rhost}")
        try:
            with ctx:
                res = launcher.run(cd, action=action, timeout=args.timeout,
                                   dry_run=args.dry_run)
        except (ExploitBlocked, ScopeViolation) as e:
            print(ui.blocked(str(e)))
            continue

        if args.dry_run:
            print("\n" + ui.box(
                res.stdout.strip().splitlines(),
                title="resource script (dry run — nothing executed)"))
            continue

        print(ui.info(f"exit {res.returncode} · {res.duration:.1f}s"
                      + (f" · verdict {res.verdict}" if res.verdict else "")))
        if res.verdict == "vulnerable":
            print(ui.ok(paint("CONFIRMED VULNERABLE", S.BOLD, S.GREEN)
                        + paint(" — recorded to audit log", S.DIM)))
            cd.confidence = Confidence.CONFIRMED
        elif res.verdict == "not-vulnerable":
            print(ui.warn("target reports NOT vulnerable"))
        if args.verbose:
            print(paint(res.stdout[-4000:], S.DIM))


# ------------------------------------------------------------------ parser

def cmd_selfcheck(args) -> int:
    """Verify Vision's own claims about itself are true.

    Compares stage/tool/chain counts, and every place they are quoted in the
    docs and the header graphic, against what the running code actually
    registers. Exists because a generated SVG or a hand-edited README line is
    not something a person rereads on every change — this caught a real
    drift (20 vs 32 stages, 1022 vs 1564 tests) that several rounds of manual
    review had missed.
    """
    root = Path(__file__).resolve().parent.parent
    print(ui.banner(VERSION, compact=args.no_banner))
    print(ui.section("Self-check", "does Vision agree with itself?"))
    report = _selfcheck_audit(root, run_tests=args.full)
    for drift in report.drifts:
        print(ui.bad(str(drift)))
    if report.ok:
        print(ui.ok(report.summary()))
        return 0
    print(ui.warn(report.summary()))
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        "vision", description="Network VAPT orchestration — verify before you fire")
    p.add_argument("--version", action="version", version=f"VISION {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=False)

    def base(sp):
        sp.add_argument("--no-banner", action="store_true")
        sp.add_argument("--theme", choices=["default", "stark"],
                        default="default",
                        help="console display theme. 'stark' renders the VISION "
                             "HUD (cinematic severity labels); the client report "
                             "is unaffected either way")

    def msf(sp):
        sp.add_argument("--cache", default="~/.vision/msf_index.json")
        sp.add_argument("--msf-path", nargs="+")

    def scoped(sp):
        sp.add_argument("--scope", nargs="+", help="CIDR / IP / range")
        sp.add_argument("--scope-file",
                        help="file of targets, one per line (same as --targets "
                             "on 'run'); '#' comments, blank lines and comma/"
                             "space separators handled")
        sp.add_argument("--exclude", nargs="+")
        sp.add_argument("--rfc1918-only", action="store_true",
                        help="hard refuse any public address")

    sm = sub.add_parser("menu", help="interactive console (default)")
    base(sm); msf(sm)
    sm.add_argument("-o", "--output", default="./vision-run")
    sm.add_argument("--operator")
    sm.add_argument("--audit", default="./vision-audit.jsonl")
    sm.add_argument("--allow-destructive", action="store_true")
    sm.add_argument("--timeout", type=int, default=1800)
    sm.add_argument("--debug", action="store_true")
    sm.add_argument("--no-evidence", action="store_true")
    sm.add_argument("--no-preflight", action="store_true",
                    help="skip the readiness check on start")
    sm.add_argument("--no-wizard", action="store_true",
                    help="go straight to the menu instead of the guided flow")
    sm.add_argument("--intensity", choices=sorted(PROFILES), default=None,
                    help="preselect the scan intensity")
    sm.set_defaults(func=cmd_menu)

    ssc = sub.add_parser("selfcheck",
                         help="verify Vision's own numbers agree with its code")
    ssc.add_argument("--no-banner", action="store_true")
    ssc.add_argument("--full", action="store_true",
                     help="also re-run the full test suite to check the "
                          "quoted test count (slower)")
    ssc.set_defaults(func=cmd_selfcheck)

    sd = sub.add_parser("doctor", help="check installed tooling")
    base(sd)
    sd.add_argument("--versions", action="store_true")
    sd.set_defaults(func=cmd_doctor)

    ss = sub.add_parser("setup", help="install missing tooling")
    base(ss)
    ss.add_argument("--need", choices=["core", "standard", "optional"],
                    default="standard")
    ss.add_argument("--only", nargs="+", help="install specific tools by name")
    ss.add_argument("--dry-run", action="store_true")
    ss.add_argument("--no-metapackages", action="store_true",
                    help="on Kali, install tools individually instead")
    ss.add_argument("--timeout", type=int, default=900)
    ss.add_argument("--verbose", action="store_true")
    ss.set_defaults(func=cmd_setup)

    si = sub.add_parser("index", help="build the Metasploit module index")
    base(si)
    msf(si)
    si.set_defaults(func=cmd_index)

    sr = sub.add_parser("run", help="automated scan then advisory")
    base(sr)
    msf(sr)
    scoped(sr)
    sr.add_argument("-o", "--output", default="./vision-run")
    sr.add_argument("--intensity", choices=sorted(PROFILES), default="normal",
                    help="scan intensity: coverage, speed and noise")
    sr.add_argument("--aggressive", action="store_true",
                    help="alias for --intensity aggressive")
    sr.add_argument("--resume", action="store_true")
    sr.add_argument("--skip", nargs="+")
    sr.add_argument("--timeout", type=int, default=1800)
    sr.add_argument("--min-rank", type=int, default=2)
    sr.add_argument("--top", type=int, default=25)
    sr.add_argument("--operator")
    sr.add_argument("--targets", "--target-file", metavar="FILE",
                    dest="targets",
                    help="file of targets, one per line (alias of --scope-file); "
                         "'#' comments, blank lines and comma/space separators "
                         "are handled")
    sr.add_argument("--user", help="username for authenticated enumeration; "
                                   "the password is prompted, never taken as "
                                   "an argument")
    sr.add_argument("--domain", default="", help="domain for --user")
    sr.add_argument("--debug", action="store_true",
                    help="print every command as it runs")
    sr.add_argument("--yes", action="store_true",
                    help="skip the intensity confirmation (for scripted runs "
                         "where authorisation is already established)")
    sr.add_argument("--no-evidence", action="store_true",
                    help="skip saving raw tool output")
    sr.set_defaults(func=cmd_run)

    sp = sub.add_parser("paths", help="attack paths derived from findings")
    base(sp)
    sp.add_argument("--findings", required=True)
    sp.add_argument("--rules", nargs="+", help="extra rule files (JSON or YAML)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_paths)

    sk = sub.add_parser("frameworks", help="map findings to control frameworks")
    base(sk)
    sk.add_argument("--findings", required=True)
    sk.set_defaults(func=cmd_frameworks)

    sf = sub.add_parser("diff", help="compare a retest against a baseline")
    base(sf)
    sf.add_argument("baseline")
    sf.add_argument("current")
    sf.add_argument("--all", action="store_true", help="also list still-open findings")
    sf.set_defaults(func=cmd_diff)

    sa = sub.add_parser("advise", help="ranked exploit recommendations")
    base(sa)
    msf(sa)
    scoped(sa)
    sa.add_argument("--findings", required=True)
    sa.add_argument("--min-rank", type=int, default=2)
    sa.add_argument("--per-finding", type=int, default=5)
    sa.add_argument("--hide-destructive", action="store_true")
    sa.add_argument("--json", action="store_true")
    sa.set_defaults(func=cmd_advise)

    se = sub.add_parser("exploit", help="interactive verify / execute")
    base(se)
    msf(se)
    scoped(se)
    se.add_argument("--findings", required=True)
    se.add_argument("--audit", default="./vision-audit.jsonl")
    se.add_argument("--operator")
    se.add_argument("--allow-destructive", action="store_true")
    se.add_argument("--default-action", choices=["check", "exploit"],
                    default="check")
    se.add_argument("--dry-run", action="store_true")
    se.add_argument("--min-rank", type=int, default=2)
    se.add_argument("--per-finding", type=int, default=5)
    se.add_argument("--timeout", type=int, default=300)
    se.add_argument("--verbose", action="store_true")
    se.set_defaults(func=cmd_exploit)
    return p


def main(argv=None) -> int:
    import sys as _s
    raw = list(argv if argv is not None else _s.argv[1:])
    # Bare `vision` drops into the interactive console rather than printing
    # usage — the menu is the primary interface for most operators.
    #
    # `vision -o dir` should too. The documentation says bare `vision` is the way
    # in, so adding a flag to it is the obvious next thing to type, and the
    # bare-only version failed with "invalid choice: 'dir'" — an error that
    # points at the output directory rather than at the missing subcommand.
    if not raw or (raw[0].startswith("-") and raw[0] not in ("-h", "--help",
                                                            "--version")):
        raw = ["menu"] + raw
    args = build_parser().parse_args(raw)
    if hasattr(args, "cache"):
        args.cache = str(Path(args.cache).expanduser())
    try:
        return args.func(args) or 0
    except (ScopeViolation, ExploitBlocked) as e:
        print(ui.blocked(str(e)), file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(ui.bad(str(e)), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n" + ui.info("interrupted"))
        return 130


if __name__ == "__main__":
    sys.exit(main())
