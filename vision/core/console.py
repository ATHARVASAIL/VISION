"""Interactive console — `vision` with no arguments, or `vision menu`.

The workflow the operator actually wants:

    scan a target -> see open ports -> see which services are outdated
    -> see which are exploitable -> pick one -> verify it -> exploit it
    -> export the report

Each of those is a numbered choice. Nothing advances on its own.

The exploit gates from exploit_advisor are unchanged and unchangeable from
here: destructive modules stay locked, scope is re-checked at fire time, and
firing an exploit still requires typing the target IP.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from . import ui
from .ui import S, paint
from ..analysis import playbook as _playbook
from .pipeline import Pipeline, RunState
from .profiles import get as get_profile
from .runlog import RunLog
from . import credentials as _creds
from .engagement import Engagement, resolve_summary
from . import manual as _manual
from . import manualrun as _mrun
from .safety import safe_display, secure_open, secure_write
from .triage import Triage, NEW, CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK
from .schema import Confidence
from .scope import Scope, ScopeViolation
from .toolchain import TOOLS

SEV_STYLE = {
    "critical": S.RED, "high": S.MAGENTA, "medium": S.YELLOW,
    "low": S.CYAN, "info": S.GREY,
}

# The Stark/VISION HUD theme (opt-in via --theme stark). This is console flavour
# only: it renames how a severity is *displayed* in the live cockpit. It never
# reaches the client report — build_report imports nothing from this module, and
# a test asserts the report stays in plain professional English regardless of
# theme. The underlying severity value ("critical") is unchanged; only its label
# on screen differs, so ordering, filtering and the report are all unaffected.
STARK_SEV_LABEL = {
    "critical": "SYSTEM COLLAPSE IMMINENT",
    "high": "CRITICAL OVERHEATING",
    "medium": "PROPULSION INTERFERENCE",
    "low": "ATMOSPHERIC DRIFT",
    "info": "AMBIENT TELEMETRY",
}


def sev_label(sev: str, theme: str = "default") -> str:
    """The display label for a severity under the active console theme.

    Default returns the plain uppercase severity the console has always shown.
    'stark' returns the VISION HUD label. This is the single place theme naming
    is decided, so no call site has to know which theme is active.
    """
    if theme == "stark":
        return STARK_SEV_LABEL.get(sev, sev.upper())
    return sev.upper()


# Service versions worth flagging as outdated even without a CVE match.
STALE_HINTS = [
    ("vsftpd", "2.3.4", "backdoored release"),
    ("OpenSSH", "7.0", "pre-7.0 has known issues"),
    ("Apache httpd", "2.4.50", "path traversal era"),
    ("Samba", "4.0", "pre-4.0 is long EOL"),
    ("MySQL", "5.6", "5.5 and earlier are EOL"),
    ("ProFTPD", "1.3.5", "mod_copy RCE era"),
]


def _prompt(text: str = "select") -> str:
    try:
        return input(paint(f"  {text}> ", S.BOLD, S.ACCENT)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return "0"


def _menu(title: str, options: list[tuple[str, str]], subtitle: str = "") -> str:
    """Render a numbered menu. Option '0' is always the exit/back row."""
    print(ui.section(title, subtitle))
    for key, label in options:
        marker = paint(f"  [{key}]", S.ACCENT if key != "0" else S.GREY)
        print(f"{marker}  {label}")
    print()
    return _prompt()


def _wrap(text: str, width_: int = 76) -> list[str]:
    import textwrap
    out = []
    for para in str(text).split("\n"):
        out.extend(textwrap.wrap(para, width_) or [""])
    return out


def _matches(f: dict, needle: str, triage) -> bool:
    """Filter on severity, host, triage state, or any text in the finding.

    One box rather than four: on a large scan the analyst is usually looking
    for `critical`, a host, or `false-positive`, and typing that directly is
    faster than choosing a field first.
    """
    if not needle:
        return True
    haystack = " ".join(str(f.get(k, "")) for k in
                        ("ip", "title", "severity", "source", "description"))
    haystack += " " + " ".join(f.get("cves") or [])
    haystack += " " + triage.status(f)
    return needle in haystack.lower()


def _pause() -> None:
    try:
        input(paint("\n  press enter to continue ", S.DIM))
    except (EOFError, KeyboardInterrupt):
        print()


class Console:
    def __init__(self, args):
        self.args = args
        self.theme = getattr(args, "theme", "default") or "default"
        self.scope: Optional[Scope] = None
        self.state: Optional[RunState] = None
        self.workdir = Path(args.output).expanduser()
        self.findings_file: Optional[Path] = None
        self.operator = args.operator or "operator"
        self._live = None
        self.triage = Triage(operator=self.operator)
        # In memory for the life of the process. Never written anywhere.
        self.credentials = _creds.CredentialStore()
        self.engagement = Engagement()
        # Opened lazily and kept for the life of the console. It used to be
        # created inside scan() only, so a resumed session logged nothing: a
        # real engagement ran a manual smbclient command the day after the
        # scan, saved the evidence, and left no trace in run.jsonl — exactly
        # the audit gap the tool runner exists to close.
        self._runlog = None
        self._filter = ""

    # ---------------------------------------------------------------- state

    @property
    def services(self) -> list[dict]:
        return self.state.services if self.state else []

    @property
    def findings(self) -> list[dict]:
        return self.state.findings if self.state else []

    def _status_line(self) -> str:
        if not self.scope:
            return paint("no target set", S.YELLOW)
        bits = [paint(self.scope.summary(), S.ACCENT)]
        if self.state:
            bits.append(f"{len(self.state.live_hosts)} hosts")
            bits.append(f"{len(self.services)} services")
            crit = sum(1 for f in self.findings
                       if f.get("severity") in ("critical", "high"))
            if crit:
                bits.append(paint(f"{crit} high/critical", S.RED))
        return "  ·  ".join(bits)

    # ---------------------------------------------------------------- preflight

    def resume_previous(self) -> bool:
        """Offer to reload the last run from this output directory.

        Quitting the console used to discard everything — the findings, and the
        triage decisions that took longest to make. The state file was already
        being written; nothing was reading it back.
        """
        state_file = self.workdir / "state.json"
        if not state_file.exists():
            return False
        try:
            state = RunState.load(state_file)
        except (ValueError, OSError):
            return False
        if not state.findings and not state.services:
            return False

        age = time.time() - (state.started or time.time())
        when = (f"{age / 3600:.0f}h ago" if age > 3600
                else f"{age / 60:.0f}m ago" if age > 60 else "just now")
        print(ui.section("Previous session found", str(state_file)))
        print(ui.kv("scope", paint(state.scope or "unknown", S.ACCENT)))
        print(ui.kv("scanned", when))
        print(ui.kv("hosts", str(len(state.live_hosts))))
        print(ui.kv("findings", str(len(state.findings))))
        if state.triage:
            print(ui.kv("triaged", f"{len(state.triage)} decision(s) recorded"))
        print()
        if not ui.ask("Reload it?", default=True):
            return False

        self.state = state
        self.triage = Triage(state.triage, operator=self.operator)
        self.engagement = Engagement.from_dict(state.engagement)
        try:
            self.scope = Scope.from_lists(
                [state.scope.split("allow=[")[1].split("]")[0]
                 .replace("'", "").split(",")[0].strip()]
            ) if "allow=[" in (state.scope or "") else None
        except (ValueError, IndexError):
            self.scope = None
        self.findings_file = (self.workdir / "findings.json"
                              if (self.workdir / "findings.json").exists() else None)
        print(ui.ok(f"reloaded {len(state.findings)} finding(s)"))
        return True

    def preflight(self) -> None:
        """Check what the run needs and offer to fix it here.

        Previously the operator had to discover missing pieces one command at a
        time — run `vision`, find the advisory empty, quit, run `vision index`,
        start again. Anything that can be fixed is offered inline instead.
        """
        from ..analysis.msf_index import MsfIndex
        from .toolchain import TOOLS, Need, detect_environment

        env = detect_environment()
        missing_core = [t for t in TOOLS if not t.installed and t.need is Need.CORE]
        present = sum(1 for t in TOOLS if t.installed)

        print(ui.section("Readiness", f"{present}/{len(TOOLS)} tools installed"))

        if missing_core:
            print(ui.bad("missing core tools: "
                         + ", ".join(t.name for t in missing_core)))
            print(paint("      Vision will run, but these stages cannot: "
                        + ", ".join(sorted({t.phase.value for t in missing_core})),
                        S.DIM))
            if ui.ask("Install them now?", default=True):
                import argparse
                from .doctor import cmd_setup
                cmd_setup(argparse.Namespace(
                    no_banner=True, inline=True, need="core", only=None,
                    dry_run=False, no_metapackages=False, timeout=900,
                    verbose=False))
        else:
            print(ui.ok("all core tools present"))

        # The module index is the difference between an advisory and silence.
        cache = Path(self.args.cache).expanduser()
        if cache.exists():
            print(ui.ok("Metasploit module index ready"))
        else:
            print(ui.warn("no Metasploit module index — exploit advisory unavailable"))
            try:
                MsfIndex.build(self.args.msf_path or None)
                can_build = True
            except FileNotFoundError:
                can_build = False
            if not can_build:
                print(paint("      Metasploit is not installed; scanning and "
                            "reporting still work.", S.DIM))
            elif ui.ask("Build it now? (about 10 seconds)", default=True):
                with ui.Spinner("parsing Metasploit modules"):
                    idx = MsfIndex.build(self.args.msf_path or None)
                    idx.save(str(cache))
                print(ui.ok(f"indexed {len(idx)} modules"))

        if env.is_kali:
            print(ui.info("Kali detected — most of the toolchain ships with the distro"))
        print()

    # ---------------------------------------------------------------- guided

    def guided(self) -> bool:
        """Target, depth, confirm, scan — in one pass.

        Returns True when a scan actually ran, so the caller can go straight to
        the results rather than dropping the operator back at a cold menu.
        """
        print(ui.section("New assessment",
                         "three questions, then Vision does the rest"))
        if not self.set_target(inline=True):
            return False
        return self.scan(inline=True)

    # ---------------------------------------------------------------- next steps

    def next_steps(self) -> None:
        """Contextual actions after a scan.

        A static main menu makes the operator work out what is worth doing next.
        This offers the things that are actually available, with counts, so the
        useful path is obvious.
        """
        from ..analysis.correlate import correlate
        while True:
            counts = {}
            for f in self.findings:
                counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
            urgent = counts.get("critical", 0) + counts.get("high", 0)
            paths = correlate(self.findings) if self.findings else []

            print(ui.section("Results", self._status_line()))
            print(ui.severity_bar(counts))
            print()

            tri = self.triage.counts(self.findings)
            reviewed = len(self.findings) - tri.get(NEW, 0)
            options = [
                ("1", "Findings", f"{len(self.findings)} total, {urgent} need attention"),
                ("2", "Hosts", f"{len({f.get('ip') for f in self.findings})} with findings"),
                ("3", "Attack paths", f"{len(paths)} chain(s) derived" if paths
                 else "no chains matched"),
                ("4", "Open ports", f"{len(self.services)} service(s)"),
                ("5", "Exploit advisory", "verify or run, one target at a time"),
                ("6", "Coverage", "what was assessed, and what was not"),
                ("7", "Remediation plan", "what to fix, in what order"),
                ("8", "Manual playbook", "what to run by hand next"),
                ("9", "Run a tool", "pick a command and run it here"),
                ("10", "Add a finding", "record what you found by hand"),
                ("11", "Export report",
                 f"{reviewed}/{len(self.findings)} triaged" if self.findings
                 else "HTML, JSON, Markdown, CSV"),
                ("12", "Scan again", "same target, different depth"),
                ("0", "Main menu", ""),
            ]
            choice = ui.choose("What next?", options)
            handler = {
                "1": self.show_findings, "2": self.hosts_view,
                "3": self.attack_paths, "4": self.show_ports,
                "5": self.exploit_menu, "6": self.coverage_report,
                "7": self.remediation_plan, "8": self.manual_playbook,
                "9": self.tool_runner, "10": self.add_manual_finding,
                "11": self.export,
            }.get(choice)
            if choice in ("0", "", "q"):
                return
            if choice == "12":
                self.scan(inline=True)
                continue
            if handler is None:
                print(ui.bad("invalid choice"))
                continue
            handler()

    # ---------------------------------------------------------------- 1. target

    def set_target(self, inline: bool = False) -> bool:
        print(ui.section("Set target", "CIDR, single IP, or range"))
        print(ui.info("examples: " + paint("192.168.56.0/24", S.ACCENT)
                      + paint("   192.168.56.101", S.ACCENT)
                      + paint("   10.0.0.1-50", S.ACCENT)))
        print(ui.warn("only scan systems you own or have written authorisation to test"))
        print(paint("      a file of targets also works: type 'file /path/to/"
                    "targets.txt'", S.DIM))
        raw = _prompt("target")
        if not raw or raw == "0":
            return False

        if raw.split()[0].lower() in ("file", "f", "@") or raw.startswith("@"):
            path = raw.lstrip("@").split(None, 1)[-1].strip()
            # Private-only by default, exactly like a typed target. A file is
            # a more convenient way to say the same thing, not a way around
            # the check.
            try:
                self.scope = Scope.from_file(path, allow_private_only=True)
            except ValueError as e:
                if "outside" not in str(e).lower() and "private" not in str(e).lower():
                    raise
                print(ui.warn("the file contains public addresses"))
                if not ui.ask("Do you have written authorisation for those?",
                              default=False):
                    print(ui.info("target not set"))
                    return False
                self.scope = Scope.from_file(path, allow_private_only=False)
            except OSError as e:
                print(ui.bad(str(e)))
                if not inline:
                    _pause()
                return False
            for problem in getattr(self.scope, "load_problems", []):
                print(ui.warn(f"skipped — {problem}"))
            unreachable = self.scope.unreachable_entries()
            if unreachable:
                print(ui.warn(f"{len(unreachable)} public address(es) in the "
                              "file will not be scanned under the private-only "
                              "rule: " + ", ".join(unreachable[:5])))
                if not ui.ask("Do you have written authorisation for those?",
                              default=False):
                    print(ui.info("keeping the private-only restriction"))
                else:
                    self.scope = Scope.from_file(path, allow_private_only=False)
                    print(ui.ok("public addresses included"))
            self.state = None
            self.findings_file = None
            n = self.scope.address_count
            print(ui.ok(f"loaded {n} address{'es' if n != 1 else ''} from {path}"))
            if not inline:
                _pause()
            return True
        private_only = True
        try:
            probe = Scope.from_lists([raw])
        except ValueError as e:
            print(ui.bad(f"invalid target: {e}"))
            if not inline:
                _pause()
            return False

        # Public targets are almost always a mistake in a lab context. Make the
        # operator opt in rather than discovering it mid-scan. Sample the first
        # address directly — expanding the scope would blow up on a /24.
        first_net = probe.allow[0]
        sample = str(next(iter(first_net.hosts()), first_net.network_address))
        if not sample.startswith(("10.", "192.168.", "172.")) and \
                not Scope.from_lists([raw], allow_private_only=True).contains(sample):
            print("\n" + ui.warn(paint("that is a public internet address", S.BOLD)))
            print(paint("      Scanning hosts you don't own is a criminal offence in most", S.DIM))
            print(paint("      jurisdictions. Use a lab target on a host-only adapter.", S.DIM))
            if _prompt("type CONFIRM if you have written authorisation") != "CONFIRM":
                print(ui.info("target not set"))
                if not inline:
                    _pause()
                return False
            private_only = False

        self.scope = Scope.from_lists([raw], allow_private_only=private_only)
        self.state = RunState(scope=self.scope.summary(), workdir=str(self.workdir))
        self.findings_file = None
        print(ui.ok(f"target set: {paint(self.scope.summary(), S.ACCENT)}"))
        if not inline:
            _pause()
        return True

    # ---------------------------------------------------------------- 2. scan

    def scan(self, inline: bool = False) -> bool:
        if not self.scope:
            print(ui.bad("no target set — choose 'New assessment' first"))
            _pause()
            return False

        choice = ui.choose("Scan depth", [
            ("1", "Quick", "3 stages — ports, services, banner rules  ~1 min"),
            ("2", "Standard", "17 stages — the full assessment  ~5-15 min"),
            ("3", "Deep", "every stage including testssl and NSE vuln scripts"),
            ("0", "Back", ""),
        ], self._status_line())

        allowed = {
            "1": Pipeline.QUICK,
            "2": Pipeline.STANDARD,
            "3": {n for n, _ in Pipeline.STAGES},
        }.get(choice)
        if allowed is None:
            print(ui.bad("invalid choice"))
            return False
        # Depth is which stages run; intensity is how hard each one pushes.
        # They are separate questions and conflating them hid the trade-off.
        preset = getattr(self.args, "intensity", None)
        if preset:
            profile = get_profile(preset)
        else:
            ichoice = ui.choose("Scan intensity", [
                ("1", "Stealth", "slow and quiet — stays under rate-based detection"),
                ("2", "Normal", "top 1000 ports, standard probing  (recommended)"),
                ("3", "Aggressive", "all 65535 ports, wider UDP, double concurrency"),
                ("0", "Back", ""),
            ], "how hard each stage pushes")
            profile = {"1": get_profile("stealth"), "2": get_profile("normal"),
                       "3": get_profile("aggressive")}.get(ichoice)
            if profile is None:
                return False

        print()
        print(ui.kv("intensity", paint(profile.name, S.ACCENT)))

        # How long this will take, and which stages are worth skipping. An
        # operator choosing a profile is really asking "do I wait, or go and do
        # something else" — a fixed phrase per profile cannot answer that once
        # the host count changes.
        from .estimate import estimate as _estimate, describe as _describe
        _hosts = (len(self.state.live_hosts)
                  if self.state and self.state.live_hosts
                  else min(self.scope.address_count, 256))
        _est = _estimate(sorted(allowed), hosts=_hosts,
                         services=len(self.services),
                         intensity=profile.name.lower())
        _lines = _describe(_est)
        print(ui.kv("time", paint(_lines[0].replace("estimated ", ""), S.ACCENT)
                    + paint("   estimate, not a guarantee", S.DIM)))
        for _extra in _lines[1:]:
            print(paint(f"      {_extra}", S.DIM))
        for line in profile.describe():
            print(paint(f"      {line}", S.DIM))

        # Impacts are itemised for every profile, so the quiet ones read as a
        # deliberate choice rather than as the absence of a warning.
        if profile.impacts:
            print()
            for imp in profile.impacts:
                render = {"info": ui.info, "caution": ui.warn}.get(imp.level, ui.bad)
                body = _wrap(imp.text, 70)
                print(render(body[0]))
                for extra in body[1:]:
                    print(paint("      " + extra,
                                S.DIM if imp.level == "info" else S.RESET))

        if profile.needs_typed_confirmation:
            print()
            print(ui.blocked(f"the {profile.name} profile can take fragile "
                             "devices offline"))
            print(paint("      Proceed only with written authorisation that "
                        "covers intensive scanning.", S.DIM))
            word = profile.name.upper()
            # Typing the word is a deliberate act; a y/N is muscle memory, and
            # this profile has caused outages in the real world.
            if _prompt(f"type {paint(word, S.RED, S.BOLD)} to confirm").strip() != word:
                print(ui.info("cancelled — nothing was scanned"))
                return False
        elif profile.is_loud:
            if not ui.ask("This scan will be noisy. Continue?", default=False):
                print(ui.info("cancelled"))
                return False
        if choice == "3":
            if not ui.ask("Deep runs nmap --script vuln, which can take 20+ "
                          "minutes per host. Continue?", default=False):
                return False

        self.workdir.mkdir(parents=True, exist_ok=True)
        runlog = self.runlog
        # Dates come from the run itself rather than being typed twice.
        self.engagement.stamp_start()
        runlog.event("run-start", scope=self.scope.summary(), operator=self.operator)
        pipe = Pipeline(self.scope, self.workdir, self.state,
                        timeout=self.args.timeout, log=runlog, profile=profile)
        # Announce findings as they land rather than only in the stage tally.
        # `live` is set to the running spinner so the two do not overwrite
        # each other on the same line.
        self._live = None
        pipe.on_finding = self._announce
        selected = [n for n, _ in Pipeline.STAGES if n in allowed]
        by_method = dict(Pipeline.STAGES)

        print(ui.section("Assessment plan",
                         f"{len(selected)} stage(s) across "
                         f"{sum(1 for _,_,ns in Pipeline.PHASES if set(ns) & allowed)} phase(s)"))
        for pi, (title, desc, names) in enumerate(Pipeline.PHASES, 1):
            active = [n for n in names if n in allowed]
            if not active:
                continue
            print(f"  {paint(ui.callsign(title).ljust(9), S.ACCENT)}"
                  f"{paint(title, S.BOLD)}")
            print(paint(f"           {desc}", S.DIM))
            print(paint(f"           {', '.join(active)}", S.DIM))
        print("\n" + ui.warn("this phase performs no exploitation"))
        if not ui.ask(f"Begin the assessment against {self.scope.summary()}?",
                      default=True):
            print(ui.info("cancelled"))
            return False

        t0 = time.time()
        done = 0
        for pi, (title, desc, names) in enumerate(Pipeline.PHASES, 1):
            active = [n for n in names if n in allowed]
            if not active:
                continue
            phase_start = time.time()
            before_findings = len(self.findings)
            print(ui.phase_header(pi, len(Pipeline.PHASES), title, desc))

            for name in active:
                done += 1
                print(ui.step(done, len(selected), name))
                what = _playbook.describe(name)
                if what:
                    # Say what the stage is about to try. "[7/20]
                    # snmp-enumeration" teaches the operator nothing.
                    for line in _wrap(what, 74):
                        print(paint(f"        {line}", S.DIM))
                with ui.Spinner(f"running {name}") as sp:
                    self._live = sp
                    pipe.on_command = self._show_command
                    pipe.on_output = self._show_tool_line
                    res = pipe.run_stage(name, by_method[name])
                    pipe.on_command = None
                    pipe.on_output = None
                    self._live = None
                if res.skipped:
                    print(ui.warn(f"skipped — {res.reason}"))
                elif not res.ok:
                    print(ui.bad(f"failed — {res.reason}"))
                else:
                    bits = [f"{v} {k}" for k, v in
                            (("hosts", res.hosts), ("services", res.services),
                             ("findings", res.findings)) if v]
                    line = ui.ok(", ".join(bits) or "no findings")
                    line += paint(f"  {res.duration:.1f}s", S.DIM)
                    if res.reason:
                        line += paint(f"  ({res.reason})", S.YELLOW)
                    print(line)

            gained = len(self.findings) - before_findings
            print(paint(f"  └─ phase complete · {gained} new finding(s) · "
                        f"{time.time() - phase_start:.0f}s", S.DIM))
            # How much of the assessment is left, not just which stage is
            # current — on a long run that is the question being asked.
            print(ui.progress_line(done, len(selected), time.time() - t0))

            # Reconnaissance finding nothing means every later phase is a
            # no-op. Say so rather than grinding through 12 empty stages.
            if pi == 1 and not self.state.live_hosts:
                print("\n" + ui.bad("no live hosts in scope — stopping"))
                print(ui.info("check the target is up and you're on the right adapter: "
                              + paint("ip -brief addr", S.ACCENT)))
                break

        self.findings_file = pipe.export()
        self.engagement.stamp_finish()
        runlog.event("run-end", **runlog.summary())
        print("\n" + ui.ok(f"scan complete in {time.time() - t0:.0f}s")
              + paint(f"   ·   {len(self.findings)} finding(s) across "
                      f"{len(self.state.live_hosts)} host(s)", S.DIM))
        failures = runlog.failures()
        if failures:
            print(ui.warn(f"{len(failures)} command(s) failed — see "
                          + paint(str(runlog.path), S.ACCENT)))
        if not inline:
            self.show_ports(pause=False)
            _pause()
        return True

    @staticmethod
    def _verdict_line(res) -> str:
        style = {"vulnerable": S.RED, "likely-vulnerable": S.YELLOW,
                 "not-vulnerable": S.GREEN}.get(res.verdict, S.GREY)
        return ("    " + paint(f"{(res.verdict or 'inconclusive'):<18}", S.BOLD, style)
                + paint(f"{res.candidate.rhost:<18}", S.ACCENT)
                + paint(res.candidate.module.fullname, S.WHITE))

    @property
    def runlog(self):
        """The engagement's run log, opened on first use."""
        if self._runlog is None:
            self.workdir.mkdir(parents=True, exist_ok=True)
            self._runlog = RunLog(
                self.workdir / "run.jsonl",
                debug=getattr(self.args, "debug", False),
                evidence_dir=None if getattr(self.args, "no_evidence", False)
                else self.workdir / "evidence")
        return self._runlog

    def _show_tool_line(self, stage: str, line: str) -> None:
        """Show what a tool is doing right now, as it prints it.

        This is the `nmap -v` behaviour applied to every tool: instead of a
        spinner and a climbing number, the operator sees "Discovered open port
        445/tcp" or "Completed SYN Stealth Scan" while it happens. A slow tool
        and a stuck one produce very different output here, which a countdown
        alone can never distinguish.

        The line replaces the spinner's label rather than scrolling, because a
        verbose tool emits thousands of lines and printing them all would bury
        the findings the scan is actually for — the run log keeps the complete
        output either way.
        """
        text = line.strip()
        if not text or self._live is None:
            return
        # Skip banners and blank separators that say nothing about progress.
        if text.startswith(("Starting Nmap", "NSE:", "Initiating")) and \
                "Timing" not in text:
            return
        self._live.update(f"{stage}: {safe_display(text, 64)}")

    def _show_command(self, argv: list, rc: int, duration: float) -> None:
        """Print each command as it completes, with its result."""
        from .runlog import redact
        line = ui.command_line(redact(argv))
        tail = paint(f"  {duration:.1f}s", S.DIM)
        if rc != 0:
            tail += paint(f"  exit {rc}", S.YELLOW)
        if self._live is not None:
            self._live.write(line + tail)
        else:
            print(line + tail)

    def _announce(self, f: dict) -> None:
        """Print a finding the moment it is discovered.

        Only medium and above: announcing every informational banner would
        bury the two lines that matter under forty that do not.
        """
        sev = f.get("severity", "info")
        if sev not in ("medium", "high", "critical"):
            return
        style = SEV_STYLE.get(sev, S.GREY)
        target = f.get("ip", "")
        if f.get("port"):
            target += f":{f['port']}"
        _sevw = 24 if self.theme == "stark" else 9
        line = ("    " + paint(f"{sev_label(sev, self.theme):<{_sevw}}", S.BOLD, style)
                + paint(f"{target:<21}", S.ACCENT)
                + paint(safe_display(f.get("title", ""), 60), S.WHITE))
        detail = []
        if f.get("cves"):
            detail.append(", ".join(f["cves"][:3]))
        if f.get("evidence"):
            detail.append(safe_display(f["evidence"], 70).replace("\n", " "))
        if detail:
            line += "\n" + paint("              " + "  ·  ".join(detail)[:96], S.DIM)
        if self._live is not None:
            self._live.write(line)
        else:
            print(line)

    # ---------------------------------------------------------------- 3. ports

    def show_ports(self, pause: bool = True) -> None:
        if not self.services:
            print(ui.info("no services yet — run 'New assessment' first"))
            if pause:
                _pause()
            return

        print(ui.section("Open ports", f"{len(self.services)} service(s)"))
        rows = []
        for s in sorted(self.services, key=lambda x: (x["ip"], x["port"])):
            ver = " ".join(filter(None, [s.get("product"), s.get("version")])) or "—"
            stale = ""
            for prod, floor, why in STALE_HINTS:
                if s.get("product") and prod.lower() in s["product"].lower():
                    if s.get("version") and s["version"] < floor:
                        stale = paint("outdated", S.YELLOW)
                    break
            rows.append([s["ip"], str(s["port"]) + "/" + s.get("proto", "tcp"),
                         s.get("name") or "—", ver, stale])
        print(ui.table(rows, ["HOST", "PORT", "SERVICE", "VERSION", ""]))
        if pause:
            _pause()

    # ---------------------------------------------------------------- 4. findings

    def show_findings(self) -> None:
        if not self.findings:
            self._explain_no_findings()
            return

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        fs = sorted(self.findings,
                    key=lambda f: (order.get(f.get("severity", "info"), 5),
                                   f.get("ip", ""), f.get("port") or 0))
        counts = {}
        for f in fs:
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

        while True:
            print(ui.section("Findings", f"{len(fs)} total"))
            print(ui.severity_bar(counts))
            print()
            shown = [f for f in fs if _matches(f, self._filter, self.triage)]
            rows = []
            for i, f in enumerate(shown[:40], 1):
                sev = f.get("severity", "info")
                tgt = f["ip"] + (f":{f['port']}" if f.get("port") else "")
                st = self.triage.status(f)
                mark = paint(" ✎", S.CYAN) if _manual.is_manual(f) else ""
                rows.append([
                    paint(str(i), S.DIM),
                    paint(sev, SEV_STYLE.get(sev, S.GREY)),
                    tgt + mark,
                    paint("—" if st == NEW else st,
                          S.GREEN if st == CONFIRMED else
                          S.DIM if st == NEW else S.YELLOW),
                    safe_display(f.get("title", ""), 44),
                ])
            print(ui.table(rows, ["#", "SEV", "TARGET", "TRIAGE", "FINDING"]))
            if len(shown) > 40:
                print(paint(f"  … {len(shown) - 40} more — export for the full list", S.DIM))
            if self._filter:
                print(paint(f"  filter: {self._filter}   "
                            f"({len(shown)} of {len(fs)} shown)", S.YELLOW))
            print("\n" + paint("  [number] full detail   [f] filter   "
                               "[c] clear filter   [0] back", S.DIM))
            raw = _prompt()
            if raw in ("0", "", "b", "back"):
                return
            if raw == "c":
                self._filter = ""
                continue
            if raw == "f":
                print(paint("  filter by severity (critical/high/…), a host, "
                            "a triage state, or any text", S.DIM))
                self._filter = _prompt("filter").strip().lower()
                continue
            try:
                self._finding_detail(shown[int(raw) - 1])
            except (ValueError, IndexError):
                print(ui.bad("invalid selection"))

    def _finding_detail(self, f: dict) -> None:
        """Everything known about one finding, including which controls it maps
        to — so the operator can write it up without leaving the console."""
        from ..analysis.frameworks import map_finding
        sev = f.get("severity", "info")
        conf = f.get("confidence", "tentative")
        target = f.get("ip", "") + (f":{f['port']}" if f.get("port") else "")

        print(ui.section(safe_display(f.get("title", "Finding"), 70),
                         f"{sev} · {conf}"))
        print(ui.kv("target", paint(target, S.ACCENT)))
        print(ui.kv("severity", paint(sev_label(sev, self.theme),
                                       SEV_STYLE.get(sev, S.GREY))))
        print(ui.kv("confidence", conf + paint(
            {"tentative": "   inferred from a banner, not verified",
             "firm": "   active check by a scanner",
             "confirmed": "   verified against the target"}.get(conf, ""), S.DIM)))
        if _manual.is_manual(f):
            who = _manual.author(f)
            print(ui.kv("reported by", paint(f"{who} (manual)", S.CYAN)
                        + paint("   recorded by hand, not by a tool", S.DIM)))
        else:
            print(ui.kv("reported by", f.get("source", "unknown")))
        if f.get("cvss") is not None:
            _vec = f.get("cvss_vector")
            print(ui.kv("CVSS", f'{f["cvss"]}  {_vec}' if _vec
                        else str(f["cvss"])))
        if f.get("cves"):
            print(ui.kv("CVEs", ", ".join(f["cves"])))

        if f.get("description"):
            print()
            for line in _wrap(safe_display(f["description"], 600)):
                print("  " + line)

        if f.get("evidence"):
            print("\n" + paint("  evidence", S.GREY))
            print(ui.box([safe_display(l, 92) for l in
                          str(f["evidence"]).splitlines()[:8] if l.strip()]))

        if f.get("remediation"):
            print("\n" + paint("  remediation", S.GREY))
            for line in _wrap(safe_display(f["remediation"], 400)):
                print("  " + paint(line, S.GREEN))

        controls = map_finding(f)
        if controls:
            print("\n" + paint("  maps to", S.GREY))
            for c in controls[:6]:
                print(f"    {paint(c.id.ljust(12), S.ACCENT)}{c.title}")
            print(paint("    indicative mapping, not a compliance determination",
                        S.DIM))
        print()
        self._triage_prompt(f)

    def _triage_prompt(self, f: dict) -> None:
        """Record a judgement on this finding."""
        current = self.triage.status(f)
        d = self.triage.decision(f)
        if d and d.note:
            print(ui.kv("triage", paint(current, S.YELLOW)
                        + paint(f"   {d.note}", S.DIM)))
        choice = ui.choose("Record a decision?", [
            ("1", "Confirmed", "real — keep it in the report"),
            ("2", "False positive", "excluded, with the reason disclosed"),
            ("3", "Accepted risk", "real, but the client has accepted it"),
            ("4", "Clear", "back to not reviewed"),
            ("0", "Skip", "leave it as it is"),
        ], f"currently: {current}")
        status = {"1": CONFIRMED, "2": FALSE_POSITIVE,
                  "3": ACCEPTED_RISK}.get(choice)
        if choice == "4":
            self.triage.clear(f)
            print(ui.ok("cleared"))
        elif status:
            note = ""
            if status in (FALSE_POSITIVE, ACCEPTED_RISK):
                # Required: an unexplained exclusion is what a reviewer
                # questions first, and the reason is gone in six weeks.
                note = _prompt("reason (required)")
                if not note.strip():
                    print(ui.bad("a reason is required — nothing recorded"))
                    return
            try:
                self.triage.set(f, status, note)
            except ValueError as e:
                print(ui.bad(str(e)))
                return
            self._persist_triage()
            print(ui.ok(f"marked {status}"))
        _pause()

    def _persist_triage(self) -> None:
        if self.state:
            self.state.triage = self.triage.as_dict()
            self.state.engagement = self.engagement.as_dict()
            try:
                self.state.save(self.workdir / "state.json")
            except OSError:
                pass

    def hosts_view(self) -> None:
        """Everything known about one host, gathered in one place.

        Findings arrive grouped by stage, but remediation happens per machine —
        the person fixing 192.168.56.101 wants its services, its findings and
        its attack paths together, not scattered across five tables.
        """
        from ..analysis.correlate import correlate
        hosts = sorted({f["ip"] for f in self.findings if f.get("ip")}
                       | {s["ip"] for s in self.services if s.get("ip")})
        if not hosts:
            print(ui.info("no hosts yet — run 'New assessment' first"))
            _pause()
            return
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        while True:
            rows = []
            for i, ip in enumerate(hosts, 1):
                hf = [f for f in self.findings if f.get("ip") == ip]
                worst = min((order.get(f.get("severity", "info"), 5) for f in hf),
                            default=5)
                label = ["critical", "high", "medium", "low", "info", "—"][worst]
                rows.append([
                    paint(str(i), S.DIM), ip,
                    str(sum(1 for s in self.services if s.get("ip") == ip)),
                    str(len(hf)),
                    paint(label, SEV_STYLE.get(label, S.GREY)),
                ])
            print(ui.section("Hosts", f"{len(hosts)} in scope"))
            print(ui.table(rows, ["#", "HOST", "SVCS", "FINDINGS", "WORST"]))
            print("\n" + paint("  [number] host detail   [0] back", S.DIM))
            raw = _prompt()
            if raw in ("0", "", "b"):
                return
            try:
                ip = hosts[int(raw) - 1]
            except (ValueError, IndexError):
                print(ui.bad("invalid selection"))
                continue

            svcs = [s for s in self.services if s.get("ip") == ip]
            hf = sorted([f for f in self.findings if f.get("ip") == ip],
                        key=lambda f: order.get(f.get("severity", "info"), 5))
            paths = [p for p in correlate(self.findings) if p.host == ip]

            print(ui.section(ip, f"{len(svcs)} service(s) · {len(hf)} finding(s)"))
            if svcs:
                print(ui.table(
                    [[str(s["port"]) + "/" + s.get("proto", "tcp"),
                      s.get("name") or "—",
                      " ".join(filter(None, [s.get("product"), s.get("version")])) or "—"]
                     for s in sorted(svcs, key=lambda x: x["port"])],
                    ["PORT", "SERVICE", "VERSION"]))
            if hf:
                print()
                print(ui.table(
                    [[paint(f.get("severity", "info"),
                            SEV_STYLE.get(f.get("severity", "info"), S.GREY)),
                      paint(self.triage.status(f), S.DIM),
                      safe_display(f.get("title", ""), 56)] for f in hf],
                    ["SEV", "TRIAGE", "FINDING"]))
            if paths:
                print("\n" + paint("  attack paths", S.GREY))
                for p in paths:
                    print(f"    {paint(p.severity.upper(), SEV_STYLE.get(p.severity, S.GREY))}"
                          f"  {p.rule.name}")
                    print(paint(f"      {p.rule.outcome}", S.DIM))
            _pause()

    def coverage_report(self) -> None:
        """Which discovered services were actually assessed.

        A finding count answers "what did you find". It does not answer "did
        you look everywhere" — and the second is what a client is really
        asking. A real run had rpcbind, nlockmgr and mountd open with no
        finding of any kind: visible in the services table, invisible in the
        report.
        """
        from ..analysis.coverage import audit
        if not self.services:
            print(ui.info("nothing scanned yet — run 'New assessment' first"))
            _pause()
            return
        stages = self.state.stages if self.state else []
        a = audit(self.services, self.findings, stages)

        print(ui.section("Coverage", a.summary()))
        bar = ui.progress_line(len(a.services) - len(a.unassessed),
                               len(a.services), 0, unit="services")
        print(bar.split("  ·")[0])
        print()

        if a.unassessed:
            print(ui.warn(f"{len(a.unassessed)} service(s) no stage covers — "
                          "assess these by hand or they are simply unexamined"))
            print(ui.table(
                [[f"{s.port}/{s.name}", s.ip, s.why] for s in a.unassessed],
                ["SERVICE", "HOST", "WHY"]))
        if a.skipped_for_tools:
            print("\n" + ui.warn("stages skipped for missing tools: "
                                  + ", ".join(a.skipped_for_tools)))
            print(paint("      install them from the Toolchain menu — a clean "
                        "result here is not full coverage", S.DIM))
        if a.incomplete_stages:
            print("\n" + ui.bad("stages that did not finish: "
                                 + ", ".join(a.incomplete_stages)))
            print(paint("      part of the target set was never examined", S.DIM))
        if a.silent:
            print("\n" + paint(f"  {len(a.silent)} service(s) assessed with "
                                "nothing found:", S.GREY))
            for s in a.silent[:12]:
                print(paint(f"    {s.port}/{s.name:<16} {s.why}", S.DIM))
        if a.is_clean:
            print(ui.ok("every discovered service was covered by a stage that ran"))
        _pause()

    def remediation_plan(self) -> None:
        """Findings ordered for whoever has to fix them."""
        from ..analysis.remediation import plan, summary, quick_wins
        reportable = self.triage.reportable(self.findings)
        if not reportable:
            print(ui.info("nothing to plan — no reportable findings"))
            _pause()
            return
        actions = plan(reportable)
        s = summary(actions)
        print(ui.section("Remediation plan",
                         f"{s['findings_covered']} finding(s) reduce to "
                         f"{s['actions']} action(s)"))
        rows = []
        for i, a in enumerate(actions, 1):
            rows.append([
                paint(str(i), S.DIM),
                paint(a.severity, SEV_STYLE.get(a.severity, S.GREY)),
                str(len(a.hosts)),
                str(len(a.findings)),
                safe_display(a.text, 52),
            ])
        print(ui.table(rows, ["#", "WORST", "HOSTS", "FIXES", "ACTION"]))

        wins = quick_wins(actions)
        if wins:
            print("\n" + paint("  one change, several hosts", S.GREY))
            for a in wins:
                print(f"    {paint(str(len(a.hosts)) + ' hosts', S.ACCENT)}"
                      f"   {safe_display(a.text, 60)}")
        weak = [a for a in actions if a.confidence == "tentative"]
        if weak:
            print("\n" + ui.warn(f"{len(weak)} action(s) rest on tentative "
                                  "findings — verify before spending a change "
                                  "window on them"))
        print("\n" + paint("  [number] which findings it closes   [0] back", S.DIM))
        while True:
            raw = _prompt()
            if raw in ("0", "", "b"):
                return
            try:
                a = actions[int(raw) - 1]
            except (ValueError, IndexError):
                print(ui.bad("invalid selection"))
                continue
            print(ui.section(safe_display(a.text, 70), a.summary()))
            print(ui.table(
                [[paint(f.get("severity", "info"),
                        SEV_STYLE.get(f.get("severity", "info"), S.GREY)),
                  f.get("ip", "") + (f":{f['port']}" if f.get("port") else ""),
                  safe_display(f.get("title", ""), 50)] for f in a.findings],
                ["SEV", "TARGET", "FINDING"]))
            if a.cves:
                print("\n" + ui.kv("CVEs", ", ".join(a.cves[:10])))
            _pause()
            return

    def manual_playbook(self) -> None:
        """What to run by hand next.

        Vision automates the parts of an assessment that should be automated.
        The part where an analyst sits down with a shell is not one of them, and
        an automated tool that says "assessment complete" is claiming the easy
        half is the whole job. This marks the boundary instead of hiding it.
        """
        hosts = sorted({s["ip"] for s in self.services if s.get("ip")})
        if not hosts:
            print(ui.info("no services yet — run 'New assessment' first"))
            _pause()
            return
        while True:
            rows = []
            for i, ip in enumerate(hosts, 1):
                svcs = [x for x in self.services if x.get("ip") == ip]
                steps = sum(len(_playbook.for_service(x)) for x in svcs)
                steps += sum(len(_playbook.for_finding(f))
                             for f in self.findings if f.get("ip") == ip)
                rows.append([paint(str(i), S.DIM), ip, str(len(svcs)), str(steps)])
            print(ui.section("Manual testing playbook",
                             "hands-on follow-up Vision does not automate"))
            print(ui.table(rows, ["#", "HOST", "SERVICES", "SUGGESTED STEPS"]))
            print("\n" + paint("  [number] per-host commands   [s] by situation "
                               "(pivoting, cracking, AD…)   [0] back", S.DIM))
            raw = _prompt()
            if raw in ("0", "", "b"):
                return
            if raw == "s":
                self._playbook_situations()
                continue
            try:
                ip = hosts[int(raw) - 1]
            except (ValueError, IndexError):
                print(ui.bad("invalid selection"))
                continue
            self._playbook_for_host(ip)

    def _playbook_situations(self) -> None:
        """Follow-up organised by what you are trying to do rather than by what
        is listening — pivoting, cracking, AD work. These need a foothold or
        credentials, so no stage can automate them."""
        sits = _playbook.situations()
        opts = [(str(i), title, key.replace("-", " "))
                for i, (key, title, _s) in enumerate(sits, 1)]
        opts.append(("0", "Back", ""))
        choice = ui.choose("What are you trying to do?", opts,
                           "operator-driven work Vision does not automate")
        if choice in ("0", "", "b"):
            return
        try:
            key, title, steps = sits[int(choice) - 1]
        except (ValueError, IndexError):
            print(ui.bad("invalid selection"))
            return
        ip = self.state.live_hosts[0] if (self.state and self.state.live_hosts) else ""
        print(ui.section(title, "copy, read, then run · Vision runs none of these"))
        for step, cmd in _playbook.render(
                steps, ip, None, self.scope.summary() if self.scope else ""):
            mark = paint(" ⚠", S.YELLOW) if step.intrusive else ""
            print(paint(f"    {step.label}{mark}", S.WHITE))
            for line in str(cmd).split("\n"):
                print(paint(f"      $ {line}", S.GREEN))
            for line in _wrap(step.why, 70):
                print(paint(f"      {line}", S.DIM))
        print("\n" + ui.warn("steps marked ⚠ are intrusive or affect hosts "
                              "beyond your target — confirm your engagement "
                              "terms cover them"))
        _pause()

    def _playbook_for_host(self, ip: str) -> None:
        scope = self.scope.summary() if self.scope else ""
        svcs = sorted([x for x in self.services if x.get("ip") == ip],
                      key=lambda x: x.get("port", 0))
        print(ui.section(f"Manual follow-up — {ip}",
                         "copy, read, then run · Vision runs none of these"))
        shown = 0
        for svc in svcs:
            steps = _playbook.for_service(svc)
            if not steps:
                continue
            label = svc.get("name") or "service"
            print("\n" + paint(f"  {svc['port']}/{svc.get('proto','tcp')}  {label}",
                                S.BOLD, S.ACCENT))
            for step, cmd in _playbook.render(steps, ip, svc.get("port"), scope):
                mark = paint(" ⚠", S.YELLOW) if step.intrusive else ""
                print(paint(f"    {step.label}{mark}", S.WHITE))
                print(paint(f"      $ {cmd}", S.GREEN))
                for line in _wrap(step.why, 70):
                    print(paint(f"      {line}", S.DIM))
                shown += 1

        seen = set()
        for f in self.findings:
            if f.get("ip") != ip:
                continue
            steps = _playbook.for_finding(f)
            if not steps:
                continue
            title = safe_display(f.get("title", ""), 60)
            if title in seen:
                continue
            seen.add(title)
            print("\n" + paint(f"  finding: {title}", S.BOLD, S.MAGENTA))
            for step, cmd in _playbook.render(steps, ip, f.get("port"), scope):
                mark = paint(" ⚠", S.YELLOW) if step.intrusive else ""
                print(paint(f"    {step.label}{mark}", S.WHITE))
                print(paint(f"      $ {cmd}", S.GREEN))
                for line in _wrap(step.why, 70):
                    print(paint(f"      {line}", S.DIM))
                shown += 1

        if not shown:
            print(ui.info("no specific follow-up for this host's services"))
        else:
            print("\n" + ui.warn("steps marked ⚠ are intrusive — confirm they "
                                  "are inside your engagement terms first"))
        _pause()

    def edit_engagement(self) -> None:
        """Client, authority, dates and the executive summary.

        Without these the HTML is a scan output with good typography. A client
        receives a document, and its first page is read by someone who will
        never reach the findings table.
        """
        while True:
            m = self.engagement
            print(ui.section("Engagement details",
                             "what turns findings into a deliverable"))
            for label, value in [
                    ("client", m.client), ("assessment", m.name),
                    ("assessor", m.tester or self.operator),
                    ("authorisation", m.reference), ("dates", m.dates),
                    ("contact", m.contact)]:
                print(ui.kv(label, paint(value, S.ACCENT) if value
                            else paint("— not set", S.DIM)))
            summary_state = ("written by you" if m.executive_summary.strip()
                             else "auto-drafted from findings")
            print(ui.kv("summary", paint(summary_state, S.DIM)))

            choice = ui.choose("Edit", [
                ("1", "Client", "organisation the report is for"),
                ("2", "Assessment name", "appears as the report title"),
                ("3", "Assessor", "who performed the work"),
                ("4", "Authorisation", "SOW or written-permission reference"),
                ("5", "Contact", "who to call if something falls over"),
                ("6", "Executive summary", "replace the generated draft"),
                ("7", "Preview the draft", "see what would be published"),
                ("0", "Back", ""),
            ])
            if choice in ("0", "", "b"):
                self._persist_state()
                return
            try:
                if choice == "1":
                    m.client = _prompt("client").strip() or m.client
                elif choice == "2":
                    m.name = _prompt("assessment name").strip() or m.name
                elif choice == "3":
                    m.tester = _prompt("assessor").strip() or m.tester
                elif choice == "4":
                    m.reference = _prompt("authorisation reference").strip() or m.reference
                elif choice == "5":
                    m.contact = _prompt("client contact").strip() or m.contact
                elif choice == "6":
                    print(paint("\n  Write the summary. Blank line to finish, "
                                "or finish empty to go back to the draft.", S.DIM))
                    lines = []
                    while True:
                        line = input(paint("  > ", S.ACCENT))
                        if not line.strip():
                            break
                        lines.append(line)
                    m.executive_summary = "\n\n".join(lines)
                    print(ui.ok("summary set" if lines
                                else "cleared — the draft will be used"))
                elif choice == "7":
                    text, is_draft = resolve_summary(
                        m, self.findings, self.services,
                        len(self.state.live_hosts) if self.state else 0,
                        self.state.stages if self.state else [],
                        len(__import__("vision.analysis.correlate", fromlist=["correlate"]).correlate(self.findings)))
                    print(ui.section("Executive summary",
                                     "draft" if is_draft else "yours"))
                    for para in text.split("\n\n"):
                        for line in _wrap(para, 74):
                            print("  " + line)
                        print()
                    _pause()
                    continue
            except (EOFError, KeyboardInterrupt):
                print()
                return
            self._persist_state()

    def manage_credentials(self) -> None:
        """Supply a credential for authenticated enumeration.

        Most internal engagements hand you an account on day one, and an
        unauthenticated-only scan throws that away. Authenticated enumeration
        finds a different class of problem entirely — admin sprawl, share
        permissions, real password policy, Kerberoastable accounts.
        """
        while True:
            print(ui.section("Credentials",
                             "held in memory only · never written to disk"))
            if self.credentials:
                for i, c in enumerate(self.credentials.all(), 1):
                    print(f"  {paint(str(i), S.DIM)}  {paint(c.display, S.ACCENT)}"
                          + paint(f"   {c.kind}", S.DIM))
            else:
                print(ui.info("none supplied — the authenticated phase will skip"))
            print(paint("\n      Vision never writes a credential to the state "
                        "file, the run log, the\n      evidence directory or the "
                        "report. Closing Vision loses them, which is\n      the "
                        "right behaviour for something the client lent you.", S.DIM))
            choice = ui.choose("Credentials", [
                ("1", "Add a password", "prompted, not echoed, not in argv"),
                ("2", "Add an NT hash", "for pass-the-hash enumeration"),
                ("3", "Clear all", "forget them now"),
                ("0", "Back", ""),
            ])
            if choice in ("0", "", "b"):
                return
            if choice == "3":
                self.credentials.clear()
                print(ui.ok("cleared"))
                continue
            kind = "nthash" if choice == "2" else "password"
            if choice not in ("1", "2"):
                print(ui.bad("invalid choice"))
                continue
            cred = _creds.prompt(kind=kind)
            if cred is None:
                print(ui.info("cancelled"))
                continue
            try:
                self.credentials.add(cred)
            except ValueError as e:
                print(ui.bad(str(e)))
                continue
            print(ui.ok(f"stored {cred.display} — the authenticated phase will "
                        "now run"))
            _pause()

    def tool_runner(self) -> None:
        """Pick a tool, edit the command, run it here.

        Everything runs through the same scope check, run log and evidence
        directory as an automated stage — an assessment where half the work
        happened in an untracked terminal is one you cannot reconstruct later.
        """
        if not self.scope:
            print(ui.bad("no target set — choose 'New assessment' first"))
            _pause()
            return
        tools = _mrun.installed_tools()
        if not tools:
            print(ui.bad("no known tools are installed"))
            _pause()
            return

        while True:
            print(ui.section("Run a tool",
                             f"{len(tools)} installed · scope-checked, logged, "
                             "output saved as evidence"))
            rows = [[paint(str(i), S.DIM), t.name, t.phase.value,
                     safe_display(t.purpose, 46)]
                    for i, t in enumerate(tools, 1)]
            print(ui.table(rows, ["#", "TOOL", "PHASE", "PURPOSE"]))
            print("\n" + paint("  [number] pick a tool   [t] type a command "
                               "directly   [0] back", S.DIM))
            raw = _prompt()
            if raw in ("0", "", "b"):
                return
            if raw == "t":
                self._run_typed_command()
                continue
            try:
                tool = tools[int(raw) - 1]
            except (ValueError, IndexError):
                print(ui.bad("invalid selection"))
                continue
            self._run_tool(tool)

    def _run_tool(self, tool) -> None:
        ip = ""
        if self.state and self.state.live_hosts:
            ip = self.state.live_hosts[0]
        sugg = _mrun.suggestions_for(
            tool.name, ip, None, self.scope.summary() if self.scope else "")
        print(ui.section(tool.name, safe_display(tool.purpose, 70)))
        if sugg:
            print(paint("  starting points from the playbook:", S.GREY))
            for i, (label, cmd) in enumerate(sugg[:6], 1):
                print(f"    {paint(str(i), S.ACCENT)}  {paint(label, S.WHITE)}")
                print(paint(f"       {cmd}", S.GREEN))
            print("\n" + paint("  [number] use it as a starting point   "
                               "[t] write your own   [0] back", S.DIM))
            pick = _prompt()
            if pick in ("0", "", "b"):
                return
            if pick == "t":
                base = tool.binary
            else:
                try:
                    base = sugg[int(pick) - 1][1].lstrip("#").strip()
                except (ValueError, IndexError):
                    print(ui.bad("invalid selection"))
                    return
        else:
            base = tool.binary
        self._run_typed_command(prefill=base)

    def _run_typed_command(self, prefill: str = "") -> None:
        if prefill:
            print(paint("\n  edit and press enter, or blank to cancel:", S.DIM))
            print(paint(f"    {prefill}", S.GREEN))
        try:
            entered = input(paint("  $ ", S.GREEN)).strip() or prefill
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not entered:
            return

        try:
            argv = _mrun.parse(entered)
            _mrun.validate(argv, self.scope)
        except _mrun.CommandRejected as e:
            print(ui.blocked(str(e)))
            _pause()
            return

        targets = _mrun.targets_in(argv)
        print(ui.kv("command", paint(" ".join(argv), S.WHITE)))
        print(ui.kv("targets", paint(", ".join(targets) or "none in argv",
                                     S.ACCENT)))
        if not ui.ask("Run it?", default=True):
            print(ui.info("cancelled"))
            return

        with ui.Spinner(f"running {Path(argv[0]).name}"):
            res = _mrun.run(argv, self.scope, self.workdir,
                            timeout=self.args.timeout, log=self.runlog)

        status = (paint("exit 0", S.GREEN) if res.ok
                  else paint(f"exit {res.returncode}", S.YELLOW))
        print(f"\n  {status}" + paint(f"   {res.duration:.1f}s", S.DIM))
        body = res.stdout.strip() or res.stderr.strip()
        if body:
            lines = safe_display(body, 8000).splitlines()
            for line in lines[:40]:
                print(paint(f"    {line[:150]}", S.WHITE))
            if len(lines) > 40:
                print(paint(f"    … {len(lines) - 40} more line(s)", S.DIM))
        else:
            print(ui.info("no output"))
        if res.evidence_path:
            print(ui.kv("saved", paint(res.evidence_path, S.ACCENT)))

        if body and ui.ask("Record a finding from this?", default=False):
            self.add_manual_finding(prefill_evidence=safe_display(body, 3000))
        else:
            _pause()

    def add_manual_finding(self, prefill_evidence: str = "") -> None:
        """Record something found by hand.

        The playbook says what to run; this is where the result goes. Without
        it the report contains only what the automation caught, and the analyst
        keeps a second list somewhere Vision never sees.
        """
        if not self.scope:
            print(ui.bad("no target set — choose 'New assessment' first"))
            _pause()
            return

        print(ui.section("Record a manual finding",
                         "what you found by hand, in your own words"))
        print(paint("      Leave a field blank to skip it. Ctrl-C to abandon.",
                    S.DIM))
        try:
            ip = _prompt("target IP").strip()
            if not ip:
                print(ui.info("cancelled"))
                return
            port_raw = _prompt("port (blank if not port-specific)").strip()
            title = _prompt("title").strip()

            sev = ui.choose("Severity", [
                ("1", "Critical", "immediate compromise or data exposure"),
                ("2", "High", "serious, exploitable with modest effort"),
                ("3", "Medium", "meaningful weakness, conditions apply"),
                ("4", "Low", "hardening gap"),
                ("5", "Informational", "context, not a weakness"),
                ("0", "Cancel", ""),
            ])
            if sev in ("0", ""):
                print(ui.info("cancelled"))
                return
            severity = dict(zip("12345", _manual.SEVERITIES)).get(sev)
            if not severity:
                print(ui.bad("invalid severity"))
                return

            conf = ui.choose("How sure are you?", [
                ("1", "Confirmed", _manual.CONFIDENCE_HELP["confirmed"]),
                ("2", "Firm", _manual.CONFIDENCE_HELP["firm"]),
                ("3", "Tentative", _manual.CONFIDENCE_HELP["tentative"]),
            ])
            confidence = {"1": "confirmed", "2": "firm",
                          "3": "tentative"}.get(conf, "confirmed")

            if prefill_evidence:
                print(paint("\n  Evidence carried over from the command you "
                            "just ran.", S.DIM))
                evidence_lines = prefill_evidence.splitlines()
            else:
                print(paint("\n  Evidence — paste the output that proves it. "
                            "Blank line to finish.", S.DIM))
                evidence_lines = []
            while not prefill_evidence:
                line = input(paint("  > ", S.ACCENT))
                if not line.strip():
                    break
                evidence_lines.append(line)

            remediation = _prompt("remediation (how should they fix it)").strip()
            cve_raw = _prompt("CVEs, comma separated (blank if none)").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n" + ui.info("abandoned — nothing recorded"))
            return

        try:
            finding = _manual.build(
                ip=ip, title=title, severity=severity, confidence=confidence,
                port=int(port_raw) if port_raw.isdigit() else None,
                evidence="\n".join(evidence_lines),
                remediation=remediation,
                cves=[c for c in cve_raw.replace(" ", "").split(",") if c],
                operator=self.operator, scope=self.scope)
        except _manual.InvalidFinding as e:
            print(ui.bad(str(e)))
            _pause()
            return

        if not remediation:
            # A finding a client cannot act on is half a finding.
            print(ui.warn("no remediation recorded — the client will ask what "
                          "to do about it"))

        if self.state is None:
            self.state = RunState(scope=self.scope.summary(),
                                  workdir=str(self.workdir))
        before = len(self.state.findings)
        self._merge_manual(finding)
        if len(self.state.findings) == before:
            print(ui.warn("a finding with the same target and title already "
                          "exists — nothing added"))
        else:
            print(ui.ok(f"recorded: [{severity}] {title}"))
            self._persist_state()
        _pause()

    def _merge_manual(self, finding: dict) -> None:
        """Add through the same dedupe rule the stages use, so a manual entry
        cannot silently duplicate something the scan already found."""
        def fp(d):
            return "|".join([d.get("ip", ""), str(d.get("port") or ""),
                             ",".join(sorted(d.get("cves") or []))
                             or (d.get("title") or "").lower().strip()])
        existing = {fp(f) for f in self.state.findings}
        if fp(finding) not in existing:
            self.state.findings.append(finding)

    def _persist_state(self) -> None:
        if self.state:
            self.state.engagement = self.engagement.as_dict()
            try:
                self.state.save(self.workdir / "state.json")
                if self.findings_file:
                    secure_write(self.findings_file, json.dumps(
                        {"services": self.services,
                         "findings": self.findings}, indent=2))
            except OSError:
                pass

    def _explain_no_findings(self) -> None:
        """An empty result is ambiguous: it can mean a clean network or a scan
        that never ran the relevant stages. Say which."""
        print(ui.section("Findings", "nothing recorded"))
        if not self.state or not self.state.stages:
            print(ui.info("no scan has run yet — choose 'New assessment' first"))
            _pause()
            return
        ran = [s for s in self.state.stages if not s.get("skipped")]
        skipped = [s for s in self.state.stages if s.get("skipped")]
        print(ui.ok(f"{len(ran)} stage(s) ran and found nothing"))
        if skipped:
            print(ui.warn(f"{len(skipped)} stage(s) did not run:"))
            for st in skipped[:8]:
                print(paint(f"      {st['name']:<24}{st.get('reason', '')}", S.DIM))
            missing_tools = [s for s in skipped if "not installed" in
                             str(s.get("reason", ""))]
            if missing_tools:
                print("\n" + ui.info(
                    f"{len(missing_tools)} stage(s) were skipped for missing "
                    "tools — a clean result here is not full coverage."))
                print(paint("      Run 'Toolchain' from the main menu to install "
                            "them.", S.DIM))
        _pause()

    # ---------------------------------------------------------------- 5. paths
    # ---------------------------------------------------------------- 5. paths

    def attack_paths(self) -> None:
        from ..analysis.correlate import correlate, summary
        if not self.findings:
            print(ui.info("no findings yet — run 'New assessment' first"))
            _pause()
            return
        paths = correlate(self.findings)
        if not paths:
            print(ui.section("Attack paths"))
            print(ui.info("no chains matched — findings do not currently "
                          "combine into a known path"))
            _pause()
            return

        s = summary(paths)
        print(ui.section("Attack paths",
                         f"{s['paths']} chain(s) across {s['hosts']} host(s)"))
        for i, p in enumerate(paths, 1):
            style = SEV_STYLE.get(p.severity, S.GREY)
            print(f"\n  {paint(str(i) + '.', S.DIM)} "
                  f"{paint(p.severity.upper(), style)}  "
                  f"{paint(p.title, S.BOLD)}")
            print(paint(f"      outcome    {p.rule.outcome}", S.DIM))
            print(paint("      chain      "
                        + " → ".join(l for l, _ in p.matched_steps), S.DIM))
            print(paint(f"      confidence {p.confidence}", S.DIM))
        print("\n" + ui.info("full narrative and remediation appear in the "
                             "HTML report"))
        _pause()

    # ---------------------------------------------------------------- 6. exploit

    def exploit_menu(self) -> None:
        from ..analysis.msf_index import MsfIndex
        from ..analysis.exploit_advisor import (
            ExploitAdvisor, ExploitLauncher, ExploitBlocked, classify_phase,
        )
        from ..cli import load_findings, candidate_table, legend

        if not self.findings_file or not Path(self.findings_file).exists():
            print(ui.info("no scan results yet — run 'New assessment' first"))
            _pause()
            return
        try:
            idx = MsfIndex.load_or_build(self.args.cache, self.args.msf_path or None)
        except FileNotFoundError:
            print(ui.bad("Metasploit not found — exploit advisory unavailable"))
            print(ui.info("install it: " + paint("vision setup --only metasploit", S.ACCENT)))
            _pause()
            return

        findings, services = load_findings(str(self.findings_file))
        adv = ExploitAdvisor(idx, self.scope)
        cands = adv.advise(findings, services)
        if not cands:
            # "No candidates" reads the same whether every unmatched finding
            # is low-severity noise, or a critical brand-new CVE that
            # Metasploit simply has not published a module for yet — those
            # are completely different situations for an operator, and the
            # flat message treated them identically. A critical finding with
            # zero exploit coverage is exactly the case that most needs
            # flagging, not the case most likely to be silently dropped.
            #
            # advise() stores the same Finding objects it was given (never a
            # copy), so identity comparison correctly tells matched from
            # unmatched without needing a separate equality key.
            matched_ids = {id(c.finding) for c in cands}
            urgent_unmatched = [
                f for f in findings
                if id(f) not in matched_ids
                and f.severity.value in ("critical", "high")
            ]
            if urgent_unmatched:
                print(ui.warn(
                    f"no exploit module exists yet for "
                    f"{len(urgent_unmatched)} critical/high finding"
                    f"{'s' if len(urgent_unmatched) != 1 else ''} — "
                    "this does not mean they are safe, it means Metasploit "
                    "has no automated module for them"))
                for f in urgent_unmatched[:8]:
                    print(paint(f"    [{f.severity.value:<8}] "
                                f"{f.ip}:{f.port or '-'} "
                                f"{f.title[:56]}", S.YELLOW))
                print(paint("      verify these by hand — the manual "
                            "playbook (option 8) has commands for exactly "
                            "this situation", S.DIM))
            else:
                print(ui.info("no exploit modules matched these findings"))
            _pause()
            return

        launcher = ExploitLauncher(self.scope, audit_log=self.args.audit,
                                   allow_destructive=self.args.allow_destructive,
                                   operator=self.operator)
        while True:
            s = adv.summary(cands)
            print(ui.section("Exploitable services",
                             f"{s['candidates']} candidates · "
                             f"{s['verifiable']} verifiable · {s['locked']} locked"))
            print(candidate_table(cands))
            print(legend())
            verifiable = [c for c in cands if c.module.has_check]
            print("\n" + paint(f"  [v] verify all {len(verifiable)} in one pass   "
                               "[w] worklist (ordered plan)   "
                               "[c N] verify one   [x N] exploit   "
                               "[d N] details   [0] back", S.DIM))
            raw = _prompt()
            if raw in ("0", "", "b", "back"):
                return
            if raw == "v":
                if not verifiable:
                    print(ui.info("no candidates support check()"))
                    continue
                # Filtering and confirmation happen BEFORE the spinner starts.
                # verify_many used to do both internally, including the
                # blocking input() prompt, while the console had it wrapped in
                # a spinner — the spinner's background thread repaints the
                # same terminal line every 80ms, so the prompt was there but
                # invisible. A real run sat for over 17 minutes on exactly
                # this before the operator gave up and suspended the process.
                runnable = launcher.filter_runnable(verifiable)
                if not runnable:
                    print(ui.info("no in-scope candidates support check()"))
                    continue
                try:
                    if not launcher.confirm_many(runnable):
                        print(ui.info("cancelled"))
                        continue
                except (EOFError, KeyboardInterrupt):
                    print("\n" + ui.info("cancelled"))
                    continue
                # One msfconsole boot instead of one per candidate. Checks
                # deliver no payload, so batching them changes nothing about
                # what reaches the target — only how long it takes.
                try:
                    with ui.Spinner(f"verifying {len(runnable)} module(s) "
                                    "in one session") as sp:
                        def _batch_line(line, _sp=sp, _n=len(runnable)):
                            phase = classify_phase(line)
                            if phase:
                                _sp.update(f"verifying {_n} module(s): {phase}")

                        results = launcher.verify_many(
                            runnable, timeout=self.args.timeout,
                            require_confirm=False,
                            on_line=_batch_line,
                            on_result=lambda r: sp.write(self._verdict_line(r)))
                except (ExploitBlocked, ScopeViolation) as e:
                    print(ui.blocked(str(e)))
                    continue
                hits = [r for r in results if r.verdict == "vulnerable"]
                print("\n" + ui.ok(f"{len(results)} verified · "
                                    f"{len(hits)} confirmed vulnerable"))
                self._persist_state()
                _pause()
                continue

            if raw == "w":
                # The ordered plan across every host. Prints only — nothing is
                # fired. Verified candidates first if any check has run, so a
                # natural flow is [v] to confirm, then [w] to see what to work.
                any_confirmed = any(
                    c.confidence is Confidence.CONFIRMED for c in cands)
                plan = adv.worklist(cands, verified_only=any_confirmed)
                if any_confirmed:
                    print(ui.info("showing verified-vulnerable candidates "
                                  "first — run [v] again to widen"))
                print(adv.render_worklist(plan))
                print("\n" + paint("  work top-down. each exploit is still one "
                                   "typed confirmation — [x N] to fire one.",
                                   S.DIM))
                _pause()
                continue

            parts = raw.split()
            if len(parts) != 2 or parts[0] not in ("c", "x", "d"):
                print(ui.bad("format: v  /  w  /  c 1  /  x 1  /  d 1"))
                continue
            try:
                cd = cands[int(parts[1]) - 1]
            except (ValueError, IndexError):
                print(ui.bad("invalid number"))
                continue

            if parts[0] == "d":
                print("\n" + ui.box(cd.describe().splitlines(),
                                    title=cd.module.fullname))
                print(ui.info("manual: " + paint(
                    launcher.manual_command(cd, "check"), S.ACCENT)))
                _pause()
                continue

            action = "check" if parts[0] == "c" else "exploit"
            if action == "check" and not cd.module.has_check:
                print(ui.warn("this module has no check method — "
                              "use [x] to run it for real"))
                continue

            # The typed-IP confirmation must happen BEFORE the spinner starts,
            # never inside it. `input()` and the spinner's background thread
            # were both writing to the same stdout line at the same time — the
            # spinner repainted over the prompt every 80ms, so `confirm()`
            # appeared to hang with no visible question. A real run sat on
            # this for over 17 minutes before the operator gave up and
            # suspended the process; it was not slow, it was stuck waiting on
            # a prompt nobody could see.
            try:
                if not launcher.confirm(cd, action):
                    print(ui.info("cancelled — target IP did not match"))
                    continue
            except (EOFError, KeyboardInterrupt):
                print("\n" + ui.info("cancelled"))
                continue


            try:
                with ui.Spinner(f"msf {action} -> {cd.rhost}") as sp:
                    def _on_line(line, _sp=sp, _target=cd.rhost):
                        phase = classify_phase(line)
                        if phase:
                            _sp.update(f"msf {action} -> {_target}: {phase}")
                    res = launcher.run(cd, action=action,
                                       timeout=self.args.timeout,
                                       require_confirm=False,
                                       on_line=_on_line)
            except (ExploitBlocked, ScopeViolation) as e:
                print(ui.blocked(str(e)))
                continue

            print(ui.info(f"exit {res.returncode} · {res.duration:.1f}s"
                          + (f" · {res.verdict}" if res.verdict else "")))
            if res.verdict == "vulnerable":
                print(ui.ok(paint("CONFIRMED VULNERABLE", S.BOLD, S.GREEN)))
                cd.confidence = Confidence.CONFIRMED
            elif res.verdict == "not-vulnerable":
                print(ui.warn("target reports NOT vulnerable"))

            # What the exploit actually achieved. Vision used to stop at
            # "session opened" and record nothing, leaving the operator to
            # reconstruct impact from memory — the exact part a client disputes.
            proof = getattr(res, "proof", None)
            if action == "exploit":
                if proof is not None and proof.obtained:
                    self._show_proof(proof)
                    finding = getattr(res, "finding", None)
                    if finding:
                        before = len(self.findings)
                        self._merge_manual(finding)
                        if len(self.findings) > before:
                            print(ui.ok("recorded as a confirmed finding with "
                                        "the transcript as evidence"))
                            self._persist_state()
                    self._save_proof_evidence(proof, cd)
                elif res.returncode == 0:
                    print(ui.warn("exploit ran but no session was opened — "
                                  "the service may be patched or the payload "
                                  "unsuitable"))
            _pause()

    def _show_proof(self, proof) -> None:
        """Display what was obtained, framed as evidence rather than a trophy."""
        style = S.RED if proof.is_root else S.YELLOW
        print()
        print("  " + paint("╭─ ACCESS OBTAINED ", S.BOLD, style)
              + paint("─" * 42, S.DIM))
        print("  " + paint("│ ", S.DIM) + ui.kv("session",
              paint(f"{proof.session_type} #{proof.session_id}", S.ACCENT)).strip())
        print("  " + paint("│ ", S.DIM) + ui.kv("identity",
              paint(proof.user or "unknown", S.BOLD, style)).strip())
        if proof.host:
            print("  " + paint("│ ", S.DIM) + ui.kv("host",
                  paint(proof.host, S.ACCENT)).strip())
        print("  " + paint("│ ", S.DIM) + ui.kv("privilege",
              paint(proof.privilege, S.BOLD, style)).strip())
        print("  " + paint("╰" + "─" * 60, S.DIM))
        print(paint("      identity captured with read-only commands; "
                    "session closed afterwards", S.DIM))

    def _save_proof_evidence(self, proof, candidate) -> None:
        """Write the transcript where every other piece of evidence lives."""
        try:
            from .safety import safe_filename, secure_write
            d = self.workdir / "evidence" / "exploit"
            d.mkdir(parents=True, exist_ok=True)
            name = safe_filename(
                f"{candidate.rhost}-{candidate.module.fullname.split('/')[-1]}",
                "exploit")
            path = d / f"{name}.txt"
            n = 1
            while path.exists():
                path = d / f"{name}-{n}.txt"
                n += 1
            header = (
                "# vision exploitation proof\n"
                f"# module:   {candidate.module.fullname}\n"
                f"# target:   {candidate.rhost}:{candidate.rport or ''}\n"
                f"# obtained: {proof.summary()}\n"
                f"# time:     {time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
                + "#" + "-" * 60 + "\n")
            secure_write(path, header + proof.transcript)
            print(ui.kv("evidence", paint(str(path), S.ACCENT)))
        except (OSError, ValueError):
            pass

    # ---------------------------------------------------------------- 6. export

    def export(self) -> None:
        if not self.findings:
            print(ui.info("nothing to export — run 'New assessment' first"))
            _pause()
            return
        choice = _menu("Export results", [
            ("1", "HTML        " + paint("client-ready report, prints to PDF", S.DIM)),
            ("2", "JSON        " + paint("machine-readable, full detail", S.DIM)),
            ("3", "Markdown    " + paint("readable report", S.DIM)),
            ("4", "CSV         " + paint("findings table for spreadsheets", S.DIM)),
            ("5", "All formats"),
            ("0", "Back"),
        ])
        if choice in ("0", ""):
            return
        self.workdir.mkdir(parents=True, exist_ok=True)
        made = []
        if choice in ("1", "5"):
            made.append(self._write_html())
        if choice in ("2", "5"):
            p = secure_write(self.workdir / "findings.json", json.dumps(
                {"services": self.services, "findings": self.findings}, indent=2))
            made.append(p)
        if choice in ("3", "5"):
            made.append(self._write_markdown())
        if choice in ("4", "5"):
            made.append(self._write_csv())
        if not made:
            print(ui.bad("invalid choice"))
            return
        print()
        for p in made:
            print(ui.ok(f"wrote {paint(str(p), S.ACCENT)}"))
        _pause()

    def _write_html(self) -> Path:
        from ..report.html import write_report
        return write_report(
            self.workdir / "report.html",
            findings=self.triage.annotate(self.findings),
            services=self.services, meta=self.engagement,
            engagement=self.engagement.name,
            scope=self.scope.summary() if self.scope else "",
            operator=self.operator,
            live_hosts=self.state.live_hosts if self.state else [],
            stages=self.state.stages if self.state else [],
        )

    def _write_markdown(self) -> Path:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        fs = sorted(self.findings, key=lambda f: order.get(f.get("severity", "info"), 5))
        lines = [
            "# Vision scan report", "",
            f"- **Scope:** {self.scope.summary() if self.scope else 'n/a'}",
            f"- **Operator:** {self.operator}",
            f"- **Date:** {time.strftime('%Y-%m-%d %H:%M %Z')}",
            f"- **Hosts:** {len(self.state.live_hosts) if self.state else 0}",
            f"- **Services:** {len(self.services)}",
            f"- **Findings:** {len(fs)}", "",
            "## Open services", "",
            "| Host | Port | Service | Version |", "|---|---|---|---|",
        ]
        for s in sorted(self.services, key=lambda x: (x["ip"], x["port"])):
            ver = " ".join(filter(None, [s.get("product"), s.get("version")])) or "—"
            lines.append(f"| {s['ip']} | {s['port']}/{s.get('proto','tcp')} | "
                         f"{s.get('name') or '—'} | {ver} |")
        lines += ["", "## Findings", ""]
        for f in fs:
            tgt = f["ip"] + (f":{f['port']}" if f.get("port") else "")
            lines += [
                f"### [{f.get('severity','info').upper()}] {f['title']}", "",
                f"- **Target:** {tgt}",
                f"- **CVEs:** {', '.join(f.get('cves') or []) or 'none'}",
                f"- **Confidence:** {f.get('confidence','tentative')}",
                f"- **Source:** {f.get('source','')}",
            ]
            if f.get("remediation"):
                lines.append(f"- **Remediation:** {f['remediation']}")
            lines.append("")
        return secure_write(self.workdir / "report.md", "\n".join(lines))

    def _write_csv(self) -> Path:
        import csv
        p = self.workdir / "findings.csv"
        cols = ["ip", "port", "severity", "confidence", "title", "cves", "source"]
        with secure_open(p, "w") as fh:
            w = csv.writer(fh)
            w.writerow([c.upper() for c in cols])
            for f in self.findings:
                w.writerow([f.get("ip", ""), f.get("port", ""),
                            f.get("severity", ""), f.get("confidence", ""),
                            f.get("title", ""), ";".join(f.get("cves") or []),
                            f.get("source", "")])
        return p

    # ---------------------------------------------------------------- 7. tools

    def tools(self) -> None:
        present = [t for t in TOOLS if t.installed]
        print(ui.section("Toolchain", f"{len(present)}/{len(TOOLS)} installed"))
        missing_core = [t.name for t in TOOLS
                        if not t.installed and t.need.value == "core"]
        if missing_core:
            print(ui.bad("missing core tools: " + ", ".join(missing_core)))
            print(ui.info("install: " + paint("vision setup --need core", S.ACCENT)))
        else:
            print(ui.ok("all core tools present"))
        print(ui.info("full audit: " + paint("vision doctor", S.ACCENT)))
        _pause()

    # ---------------------------------------------------------------- loop

    def run(self) -> int:
        print(ui.banner(compact=self.args.no_banner))
        if not self.args.no_banner:
            print(ui.boot_sequence())

        # One command should get you to a result. On a cold start Vision checks
        # what it needs, offers to fix what is missing, then walks straight into
        # target and depth — rather than making the operator find out one
        # command at a time that the index was never built.
        if not getattr(self.args, "no_preflight", False):
            self.preflight()
        resumed = self.resume_previous()
        if resumed:
            self.next_steps()
        if (self.scope is None and not resumed
                and not getattr(self.args, "no_wizard", False)):
            if ui.ask("Start a new assessment?", default=True):
                if self.guided():
                    self.next_steps()
            print()

        while True:
            has_results = bool(self.findings)
            choice = ui.choose("Main menu", [
                ("1", "New assessment",
                 "target, depth, scan — in one pass"),
                ("2", "Results",
                 f"{len(self.findings)} finding(s)" if has_results
                 else "nothing scanned yet"),
                ("3", "Exploit advisory",
                 "verify or run, one target at a time"),
                ("4", "Export report",
                 "HTML, JSON, Markdown, CSV"),
                ("5", "Credentials",
                 self.credentials.summary() if self.credentials
                 else "add one to unlock the authenticated phase"),
                ("6", "Engagement details",
                 self.engagement.client or "client, authority, summary"),
                ("7", "Toolchain",
                 "what is installed and what it unlocks"),
                ("0", "Exit", ""),
            ], self._status_line())

            if choice in ("0", "q", "exit", ""):
                print(ui.info("bye"))
                return 0
            try:
                if choice == "1":
                    if self.guided():
                        self.next_steps()
                elif choice == "2":
                    if has_results:
                        self.next_steps()
                    else:
                        print(ui.info("nothing scanned yet — choose 'New assessment' to start"))
                        _pause()
                elif choice == "3":
                    self.exploit_menu()
                elif choice == "4":
                    self.export()
                elif choice == "5":
                    self.manage_credentials()
                elif choice == "6":
                    self.edit_engagement()
                elif choice == "7":
                    self.tools()
                else:
                    print(ui.bad("invalid choice"))
            except ScopeViolation as e:
                print(ui.blocked(str(e)))
                _pause()
            except KeyboardInterrupt:
                print("\n" + ui.info("cancelled"))


def cmd_menu(args) -> int:
    return Console(args).run()
