"""Automated scan pipeline.

`vision run --scope 10.0.0.0/24` executes discovery → enumeration → vulnerability
scanning → exploit advisory without further input.

The automation stops at the advisory. Scanning and enumeration are safe to
automate; exploitation is not, and the boundary is enforced here rather than
left to operator discipline. `run` produces a ranked candidate list; firing
anything still requires `vision exploit` and a per-target confirmation.

Every stage is skipped gracefully when its tool is absent, so a partial
toolchain degrades instead of crashing.
"""

from __future__ import annotations

import json
import os
import select
import signal
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .scope import Scope
from .toolchain import BY_NAME
from .enrich import EnrichmentStages
from .authenticated import AuthenticatedStages
from .extra import ExtraStages
from .web import WebStages
from .concurrency import parallel_collect
from .profiles import Profile, DEFAULT as DEFAULT_PROFILE
from .parsers import (
    deprecated_enabled, parse_netexec_smb, parse_sslscan_protocols,
    signing_disabled,
)
from .runlog import NullLog, RunLog
from .safety import bounded, harden_path, safe_display, secure_write


@dataclass
class StageResult:
    name: str
    ok: bool
    skipped: bool = False
    reason: str = ""
    duration: float = 0.0
    hosts: int = 0
    services: int = 0
    findings: int = 0
    artifact: Optional[str] = None
    incomplete: bool = False


@dataclass
class RunState:
    """Written to disk after every stage. Network scans die halfway constantly;
    losing an hour of nmap because nuclei crashed is unacceptable."""
    scope: str
    started: float = field(default_factory=time.time)
    workdir: str = "."
    live_hosts: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    stages: list[dict] = field(default_factory=list)
    # Analyst decisions, keyed on finding fingerprint so they survive a rescan.
    triage: dict = field(default_factory=dict)
    # Client, authority and dates. Not secret — unlike credentials, this is
    # exactly the sort of thing that should survive a crash.
    engagement: dict = field(default_factory=dict)

    def save(self, path: Path) -> None:
        secure_write(path, json.dumps({
            "scope": self.scope, "started": self.started,
            "live_hosts": self.live_hosts, "services": self.services,
            "findings": self.findings, "stages": self.stages,
            "triage": self.triage, "engagement": self.engagement,
        }, indent=2))

    @classmethod
    def load(cls, path: Path) -> "RunState":
        """Restore a run from disk, refusing anything malformed.

        A state file is written during a live engagement and read back hours
        or days later, so it will eventually be truncated by a full disk, a
        killed process, or a copy that went wrong. Two failure modes were
        possible before this validated its input:

          * A file containing valid JSON of the wrong shape (`[1,2,3]`) raised
            AttributeError, which the console's resume path does not catch —
            so a corrupt file crashed the console instead of being skipped.
          * A field of the wrong type (`"findings": null`) loaded silently and
            crashed much later on `len(findings)`, far from the actual cause.

        Both now raise ValueError at the boundary, which every caller already
        handles as "this state file is unusable, carry on without it".
        """
        try:
            d = json.loads(path.read_text(errors="replace"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"state file is not valid JSON: {exc}") from None
        if not isinstance(d, dict):
            raise ValueError(
                f"state file must be a JSON object, found {type(d).__name__}")

        defaults = {
            "scope": "", "started": time.time(), "workdir": ".",
            "live_hosts": [], "services": [], "findings": [], "stages": [],
            "triage": {}, "engagement": {},
        }
        clean = {}
        for key, default in defaults.items():
            value = d.get(key, default)
            # A wrong-typed field is treated as absent rather than trusted.
            # Silently substituting the default keeps a partially-corrupt file
            # usable, which matters more than strictness here: losing one
            # field beats losing the whole engagement's findings.
            if value is None or not isinstance(value, type(default)):
                value = default
            clean[key] = value
        return cls(**clean)

    def completed(self) -> set[str]:
        return {s["name"] for s in self.stages if s.get("ok") and not s.get("skipped")}


def _have(tool: str) -> bool:
    t = BY_NAME.get(tool)
    return bool(t and t.installed)


# Set by Pipeline so every stage's subprocess calls land in the run log without
# each stage having to thread a logger through. Stages call the module-level
# _run, so this is the one place that needs to know about logging.
_ACTIVE_LOG: "RunLog | None" = None
_ON_COMMAND = None
# Called with (stage_name, line) for each line a tool prints, as it prints it.
# The console uses this to show what a tool is actually doing — nmap finding a
# port, nuclei matching a template — instead of only an elapsed counter.
_ON_OUTPUT = None
# Commands that timed out during the current stage. A timeout is not the same
# as "the service did not answer": the first means the host was never assessed,
# the second is a result. Reporting the first as a clean stage is the most
# dangerous failure this tool has, so it is tracked centrally rather than
# depending on fifteen call sites each remembering to check.
_STAGE_TIMEOUTS: list = []
_LOG_STAGE = threading.local()


def set_run_log(log: "RunLog | None") -> None:
    global _ACTIVE_LOG
    _ACTIVE_LOG = log


def set_command_hook(fn) -> None:
    """Display hook for executed commands. Module-level for the same reason the
    log is: stages call the module-level _run, not a bound method."""
    global _ON_COMMAND
    _ON_COMMAND = fn


def set_output_hook(fn) -> None:
    """Display hook for live tool output. Module-level for the same reason the
    command hook is: stages call the module-level _run, not a bound method."""
    global _ON_OUTPUT
    _ON_OUTPUT = fn


def current_stage(name: str | None = None) -> str:
    if name is not None:
        _LOG_STAGE.name = name
    return getattr(_LOG_STAGE, "name", "unknown")


def _target_of(argv: list[str]) -> str | None:
    """Best-effort target for evidence filenames: the last argument that parses
    as an address or host:port."""
    import ipaddress
    for arg in reversed(argv):
        candidate = arg.split(":")[0]
        try:
            ipaddress.ip_address(candidate)
            return arg
        except ValueError:
            continue
    return None


def _run(argv: list[str], timeout: int) -> tuple[int, str, str]:
    """Run one tool, streaming its output as it is produced.

    Every one of the 32 stages calls this, so it is the single place that
    decides whether an operator can see what a tool is doing. It used to be a
    blocking `subprocess.run`: nothing was visible until the tool completely
    finished, so a nine-minute nmap and a hung nmap looked identical — a
    spinner and a climbing number, with no way to tell progress from a stall.

    Now each line is handed to `_ON_OUTPUT` as the tool prints it. The console
    shows the most recent line beside the stage name, so `nmap` reporting
    "Discovered open port 445/tcp" or `nuclei` reporting a template hit
    appears while it happens, the way `nmap -v` does when run directly.

    Output is still returned in full for the parsers — streaming changes when
    it becomes visible, not what is collected.
    """
    started = time.time()
    stage = current_stage()
    out_parts: list[str] = []
    code = -1
    err = ""
    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True)
        fd = proc.stdout.fileno()
        pending = b""
        deadline = started + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.5))
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            # Raw read then split: a buffered readline() would leave later
            # lines invisible to select(), stranding output from a tool that
            # prints a burst and then goes quiet.
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            pending += chunk
            while b"\n" in pending:
                raw, pending = pending.split(b"\n", 1)
                line = raw.decode("utf-8", "replace")
                out_parts.append(line + "\n")
                if _ON_OUTPUT is not None:
                    try:
                        _ON_OUTPUT(stage, line)
                    except Exception:
                        # Display must never be the reason a scan fails.
                        pass
        if pending:
            out_parts.append(pending.decode("utf-8", "replace"))
        proc.wait(timeout=max(0, deadline - time.time()))
        code = proc.returncode
        out = "".join(out_parts)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        # Keep what the tool printed before it stalled — a partial port list
        # is worth more than nothing, and the parsers handle short input.
        out = "".join(out_parts)
        code, err = -1, f"timed out after {timeout}s"
        _STAGE_TIMEOUTS.append(Path(argv[0]).name if argv else "command")
    except OSError as exc:
        out, code, err = "".join(out_parts), -1, str(exc)

    duration = time.time() - started
    if _ACTIVE_LOG is not None:
        try:
            _ACTIVE_LOG.command(stage, argv, code, duration, out, err,
                                target=_target_of(argv))
        except Exception:
            # Logging must never be the reason a scan fails.
            pass
    if _ON_COMMAND is not None:
        try:
            _ON_COMMAND(list(argv), code, duration)
        except Exception:
            pass
    return code, out, err


def _kill_group(proc) -> None:
    """Kill a stalled tool and everything it spawned.

    Killing only the direct child leaves grandchildren holding the output
    pipe open, which is how a capped run can hang far past its timeout.
    """
    try:
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.kill()
        proc.wait(timeout=5)
    except (ProcessLookupError, PermissionError, OSError,
            subprocess.TimeoutExpired):
        try:
            if hasattr(os, "killpg"):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass


class Pipeline(EnrichmentStages, WebStages, ExtraStages,
               AuthenticatedStages):
    def __init__(self, scope: Scope, workdir: Path, state: RunState,
                 timeout: int = 1800, aggressive: bool = False,
                 resume: bool = False, script_timeout: int | None = None,
                 log: "RunLog | None" = None, credential=None, profile: "Profile | None" = None):
        self.scope = scope
        self.workdir = workdir
        self.state = state
        self.timeout = timeout
        # `--script vuln` is by far the slowest stage and the least essential;
        # cap it separately so it can't eat the whole engagement window.
        self.script_timeout = script_timeout or min(timeout, 600)
        # UDP is slow by nature; cap it separately so it cannot eat the window.
        self.udp_timeout = min(timeout, 900)
        # nuclei gets its own budget. Inheriting the full scan timeout meant it
        # could eat the whole window before later stages ran.
        self.nuclei_timeout = min(timeout, 900)
        # `aggressive=True` is kept as an alias so existing callers and the
        # --aggressive flag keep working; the profile is the real control.
        self.profile = profile or (
            __import__("vision.core.profiles", fromlist=["AGGRESSIVE"]).AGGRESSIVE
            if aggressive else DEFAULT_PROFILE)
        self.aggressive = self.profile.tcp_ports == "-p-"
        self.resume = resume
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.state_file = workdir / "state.json"
        self.log = log or NullLog()
        set_run_log(self.log)
        set_command_hook(lambda argv, rc, dur:
                         self.on_command(argv, rc, dur) if self.on_command else None)
        set_output_hook(lambda stage, line:
                        self.on_output(stage, line) if self.on_output else None)
        # Called with each genuinely new finding as it is merged, so a caller
        # can surface it immediately. On a fifteen-minute scan, learning that a
        # host is unauthenticated-Redis at minute two rather than at the end is
        # the difference between acting on it and reading about it.
        # Held in memory only. RunState has no credential field, so it cannot
        # be serialised into the state file by accident.
        self.credential = credential
        self.on_finding: "Callable[[dict], None] | None" = None
        # Called with (argv, returncode, duration) as each command completes, so
        # the console can show what actually ran. A tool that hides its commands
        # cannot be audited by the person responsible for the engagement.
        self.on_command: "Callable[[list, int, float], None] | None" = None
        # Called with (stage, line) for each line a tool prints, as it prints
        # it — what `nmap -v` shows when run by hand. Without this the console
        # could only offer an elapsed counter, which cannot distinguish a slow
        # tool from a stuck one.
        self.on_output: "Callable[[str, str], None] | None" = None
        self._finding_lock = threading.Lock()

    # ---------------- stage helpers ----------------

    def _record(self, res: StageResult) -> StageResult:
        self.state.stages.append(res.__dict__)
        self.state.save(self.state_file)
        return res

    def _skip(self, name: str, reason: str) -> StageResult:
        return self._record(StageResult(name, ok=True, skipped=True, reason=reason))

    # ---------------- 1. host discovery ----------------

    def discover_hosts(self) -> StageResult:
        name = "host-discovery"
        if not _have("nmap"):
            return self._skip(name, "nmap not installed")
        t0 = time.time()
        targets = [str(n) for n in self.scope.allow]
        out = self.workdir / "discovery.xml"

        argv = ["nmap", "-v", "-sn", "-n", "-PE", "-PS21,22,80,443,445,3389",
                "-PA80,443", *self.profile.nmap_flags(),
                "-oX", str(out), *targets]
        code, _, err = _run(argv, self.timeout)
        # nmap writes its own file at the process umask; these hold the full
        # scan record so tighten them as soon as they exist.
        harden_path(out)
        if code != 0 and not out.exists():
            return self._record(StageResult(name, False, reason=err[:200],
                                            duration=time.time() - t0))

        hosts = self._parse_hosts(out)
        hosts = [h for h in hosts if self.scope.contains(h)]
        self.state.live_hosts = sorted(set(self.state.live_hosts) | set(hosts))
        return self._record(StageResult(name, True, hosts=len(hosts),
                                        duration=time.time() - t0,
                                        artifact=str(out)))

    @staticmethod
    def _parse_hosts(xml: Path) -> list[str]:
        import xml.etree.ElementTree as ET
        from .safety import parse_xml_safely, UnsafeXMLError
        try:
            root = parse_xml_safely(xml).getroot()
        except (ET.ParseError, OSError, UnsafeXMLError):
            return []
        out = []
        for h in root.findall("host"):
            st = h.find("status")
            if st is not None and st.get("state") == "up":
                for a in h.findall("address"):
                    if a.get("addrtype") in ("ipv4", "ipv6"):
                        out.append(a.get("addr"))
                        break
        return out

    # ---------------- 2. port + service scan ----------------

    # High-value services that sit outside nmap's default top-1000. Without
    # these, `datastore-exposure` was effectively unreachable in standard mode:
    # Redis, Memcached and MongoDB are all above the cutoff, so the scan never
    # saw them and the stage skipped with "no datastore services found" — on
    # networks that had them exposed.
    #
    # nmap refuses --top-ports together with -p, so this runs as a second short
    # scan and merges. Fifteen ports across the live hosts costs a few seconds.
    EXTRA_PORTS = ("989,2375,2376,5984,6379,6380,7474,9042,9201,9300,"
                   "10250,11211,27017,27018,50070")

    def port_scan(self) -> StageResult:
        name = "port-scan"
        if not _have("nmap"):
            return self._skip(name, "nmap not installed")
        if not self.state.live_hosts:
            return self._skip(name, "no live hosts from discovery")

        t0 = time.time()
        targets_file = self.workdir / "live-hosts.txt"
        secure_write(targets_file, "\n".join(self.state.live_hosts) + "\n")
        out = self.workdir / "services.xml"

        argv = ["nmap", "-v", "--stats-every", "10s", "-sV", "-n", "-Pn"]
        if self.profile.scripts:
            argv.append("-sC")
        argv += [self.profile.tcp_ports, *self.profile.nmap_flags(),
                 "-oX", str(out), "-iL", str(targets_file)]
        code, _, err = _run(argv, self.timeout)
        harden_path(out)
        if not out.exists():
            return self._record(StageResult(name, False, reason=err[:200],
                                            duration=time.time() - t0))

        data = self._parse_nmap(out)
        self.state.services = data["services"]
        # Must go through the merge path like every other stage: a raw extend
        # meant a rescan of the same target appended duplicates of its own
        # version-detection findings instead of collapsing them.
        self._merge_findings(data["findings"])

        extra_count = 0
        if not self.aggressive:
            # -p- already covers everything, so this is only needed in the
            # default profile.
            extra_count = self._scan_extra_ports(targets_file)

        return self._record(StageResult(
            name, True, services=len(self.state.services),
            findings=len(data["findings"]), duration=time.time() - t0,
            artifact=str(out),
            reason=(f"+{extra_count} service(s) from supplementary ports"
                    if extra_count else "")))

    def _scan_extra_ports(self, targets_file: Path) -> int:
        """Second pass over high-value ports the top-1000 misses."""
        out = self.workdir / "services-extra.xml"
        argv = ["nmap", "-v", "-sV", "-n", "-Pn", "-p", self.EXTRA_PORTS,
                *self.profile.nmap_flags(),
                "-oX", str(out), "-iL", str(targets_file)]
        _run(argv, min(self.timeout, 600))
        harden_path(out)
        if not out.exists():
            return 0
        data = self._parse_nmap(out)
        known = {(s["ip"], s["port"], s.get("proto", "tcp"))
                 for s in self.state.services}
        added = [s for s in data["services"]
                 if (s["ip"], s["port"], s.get("proto", "tcp")) not in known]
        self.state.services.extend(added)
        self._merge_findings(data["findings"])
        return len(added)

    # ---------------- 3. vuln scripts ----------------

    def vuln_scripts(self) -> StageResult:
        name = "nmap-vuln-scripts"
        if not _have("nmap"):
            return self._skip(name, "nmap not installed")
        if not self.state.live_hosts:
            return self._skip(name, "no live hosts")

        t0 = time.time()
        out = self.workdir / "vuln.xml"
        targets_file = self.workdir / "live-hosts.txt"
        argv = ["nmap", "-v", "--stats-every", "15s", "-sV", "-n", "-Pn", "--script", "vuln",
                "--script-timeout", "120s", "-oX", str(out),
                "-iL", str(targets_file)]
        code, _, err = _run(argv, self.script_timeout)
        harden_path(out)
        timed_out = code == -1 and "timed out" in err
        if not out.exists():
            return self._record(StageResult(name, False, reason=err[:200],
                                            duration=time.time() - t0))
        data = self._parse_nmap(out)
        before = len(self.state.findings)
        self._merge_findings(data["findings"])
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0, artifact=str(out),
            reason=("hit time limit — partial results kept" if timed_out else "")))

    # ---------------- 4. nuclei ----------------

    def nuclei_scan(self) -> StageResult:
        name = "nuclei"
        if not _have("nuclei"):
            return self._skip(name, "nuclei not installed")
        if not self.state.services:
            return self._skip(name, "no services to scan")

        t0 = time.time()
        targets = sorted({f"{s['ip']}:{s['port']}" for s in self.state.services})
        tfile = self.workdir / "nuclei-targets.txt"
        secure_write(tfile, "\n".join(targets) + "\n")
        out = self.workdir / "nuclei.jsonl"

        # nuclei runs ~9000 templates per target by default and will happily
        # consume the entire scan window. A real run spent 32 of 50 minutes
        # here and then timed out anyway, producing 6 findings — the worst
        # possible trade: most of the budget, an incomplete result, and no
        # signal that coverage was partial.
        #
        # These caps make it finish. Per-template and per-host timeouts stop a
        # single slow template stalling the stage, and the stage gets its own
        # budget rather than inheriting the whole scan's.
        argv = ["nuclei", "-l", str(tfile), "-jsonl", "-o", str(out),
                "-severity", self.profile.nuclei_severity,
                "-silent", "-no-color",
                "-timeout", "5",            # seconds per request
                "-retries", "1",
                "-max-host-error", "20",    # stop hammering a dead host
                "-stats", "-stats-interval", "30"]
        if not self.aggressive:
            argv += ["-rate-limit", "150", "-concurrency", "25"]
        else:
            argv += ["-rate-limit", "500", "-concurrency", "50"]
        _run(argv, self.nuclei_timeout)
        harden_path(out)

        # nuclei follows redirects, so a template can report against a host we
        # never targeted. Scope is enforced everywhere else; enforce it here too
        # rather than trusting the tool's output to stay inside the engagement.
        found = self._parse_nuclei(out) if out.exists() else []
        rejected = [f for f in found if not self.scope.contains(f.get("ip", ""))]
        if rejected:
            self.log.event("scope-reject", stage=name, count=len(rejected),
                           hosts=sorted({f.get("ip") for f in rejected})[:10])
        found = [f for f in found if self.scope.contains(f.get("ip", ""))]
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0, artifact=str(out)))

    # ---------------- 5. TLS ----------------

    def tls_scan(self) -> StageResult:
        name = "tls-posture"
        if not _have("sslscan"):
            return self._skip(name, "sslscan not installed")
        tls_svcs = [s for s in self.state.services
                    if self.scope.contains(s["ip"])
                    and (s.get("tunnel") == "ssl"
                         or s["port"] in (443, 8443, 993, 995, 465, 636, 989, 990))]
        if not tls_svcs:
            return self._skip(name, "no TLS services found")

        t0 = time.time()

        def probe(svc: dict) -> list[dict]:
            # Serial, this was 40 hosts x 120s — up to 80 minutes for one
            # stage. Every sibling stage already ran its probes concurrently.
            code, out, _ = _run(
                ["sslscan", "--no-colour", f"{svc['ip']}:{svc['port']}"], 120)
            return [{
                "ip": svc["ip"], "port": svc["port"], "proto": "tcp",
                "title": f"Deprecated protocol {proto} enabled",
                "severity": sev, "confidence": "firm", "cves": [],
                "source": "sslscan",
                "remediation": f"Disable {proto} on this listener; "
                               "require TLS 1.2 or later.",
            } for proto, sev in deprecated_enabled(parse_sslscan_protocols(out))]

        found = parallel_collect(probe, bounded(tls_svcs, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            duration=time.time() - t0))


    # ---------------- 6. SMB enum ----------------

    # UDP ports worth the cost. A full -sU sweep is famously slow — nmap has
    # to wait out ICMP rate limiting on closed ports — so this is a fixed short
    # list of services that actually yield findings rather than a top-N sweep.
    UDP_PORTS = "53,67,69,123,137,161,500,623,1434,1900,5353"

    def udp_scan(self) -> StageResult:
        """Discover UDP services.

        Without this the TCP-only port scan meant `state.services` never
        contained a UDP entry, so `ike-vpn` — which filters on port 500 — could
        never fire at all, and `snmp-enumeration` fell back to blindly probing
        every live host.
        """
        name = "udp-scan"
        if not _have("nmap"):
            return self._skip(name, "nmap not installed")
        if not self.profile.udp_ports:
            return self._skip(name, f"{self.profile.name} profile skips UDP")
        if not self.state.live_hosts:
            return self._skip(name, "no live hosts from discovery")
        # nmap needs raw sockets for -sU; as a normal user it fails per-host
        # with a permissions error rather than returning empty results.
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return self._skip(name, "UDP scan needs root (run with sudo)")

        t0 = time.time()
        targets_file = self.workdir / "live-hosts.txt"
        if not targets_file.exists():
            secure_write(targets_file, "\n".join(self.state.live_hosts) + "\n")
        out = self.workdir / "udp.xml"

        argv = ["nmap", "-v", "--stats-every", "15s", "-sU", "-sV", "-n", "-Pn", "-p", self.profile.udp_ports,
                "--max-retries", "1", "--host-timeout", "120s",
                self.profile.timing,
                "-oX", str(out), "-iL", str(targets_file)]
        code, _, err = _run(argv, self.udp_timeout)
        harden_path(out)
        if not out.exists():
            return self._record(StageResult(name, False, reason=err[:200],
                                            duration=time.time() - t0))

        data = self._parse_nmap(out)
        # Keep the protocol correct: these merge into the same service list the
        # TCP scan populates, and a UDP service mislabelled tcp would be probed
        # with the wrong stage.
        new_services = [s for s in data["services"] if s.get("proto") == "udp"]
        known = {(s["ip"], s["port"], s.get("proto")) for s in self.state.services}
        added = [s for s in new_services
                 if (s["ip"], s["port"], s.get("proto")) not in known]
        self.state.services.extend(added)
        before = len(self.state.findings)
        self._merge_findings([f for f in data["findings"]
                              if f.get("proto") == "udp"])
        return self._record(StageResult(
            name, True, services=len(added),
            findings=len(self.state.findings) - before,
            duration=time.time() - t0, artifact=str(out)))

    def smb_enum(self) -> StageResult:
        name = "smb-enumeration"
        smb = [s for s in self.state.services
               if s["port"] in (139, 445) and self.scope.contains(s["ip"])]
        if not smb:
            return self._skip(name, "no SMB services found")
        if not _have("netexec"):
            return self._skip(name, "netexec not installed")

        t0 = time.time()
        binary = BY_NAME["netexec"].which()
        hosts = sorted({s["ip"] for s in smb})

        def probe(ip: str) -> list[dict]:
            code, out, err = _run([binary, "smb", ip], 90)
            fields = parse_netexec_smb(out + err)
            # None means netexec did not report the field at all. Absent output
            # is not evidence of a secure configuration, so only an explicit
            # False becomes a finding.
            if signing_disabled(fields) is not True:
                return []
            return [{
                "ip": ip, "port": 445, "proto": "tcp",
                "title": "SMB signing not required",
                "severity": "medium", "confidence": "firm", "cves": [],
                "source": "netexec",
                "remediation": "Enforce SMB signing to prevent relay attacks.",
                "evidence": safe_display(out + err, 500),
            }]

        found = parallel_collect(probe, bounded(hosts, self.profile.max_hosts_per_stage),
                                 workers=self.profile.workers)
        before = len(self.state.findings)
        self._merge_findings(found)
        return self._record(StageResult(
            name, True, findings=len(self.state.findings) - before,
            hosts=len(hosts), duration=time.time() - t0))

    # ---------------- parsing / merging ----------------

    def _parse_nmap(self, xml: Path) -> dict:
        """Tolerant nmap XML parse.

        A killed or timed-out nmap leaves a truncated file with no closing
        </nmaprun>, which ElementTree rejects outright. Crashing the whole run
        because one optional stage ran long is unacceptable, so we repair the
        common truncation case and degrade to empty results if we can't."""
        # Proper package import. The previous sys.path.insert let any
        # nmap2findings.py earlier on the path shadow ours — a code-execution
        # foothold for anyone who can drop a file in the working directory.
        import xml.etree.ElementTree as ET
        from ..tools.nmap2findings import parse

        empty = {"services": [], "findings": []}
        try:
            raw = xml.read_text(errors="replace")
        except OSError:
            return empty
        if not raw.strip():
            return empty

        from .safety import UnsafeXMLError
        try:
            data = parse(str(xml))
        except (ET.ParseError, UnsafeXMLError):
            repaired = self._repair_nmap_xml(raw)
            if repaired is None:
                return empty
            tmp = xml.with_suffix(".repaired.xml")
            secure_write(tmp, repaired)
            try:
                data = parse(str(tmp))
            except (ET.ParseError, UnsafeXMLError):
                return empty
        data["services"] = [s for s in data["services"]
                            if self.scope.contains(s["ip"])]
        data["findings"] = [f for f in data["findings"]
                            if self.scope.contains(f["ip"])]
        return data

    @staticmethod
    def _repair_nmap_xml(raw: str) -> Optional[str]:
        """Close a truncated nmap XML document so partial results survive.

        nmap flushes a complete <host> block as it finishes each target, so a
        run killed at 80% still holds 80% of the findings. Throwing that away
        wastes the whole scan. We keep every complete <host> element and
        discard whatever was mid-write, including a cut landing inside a tag."""
        if "<nmaprun" not in raw:
            return None

        last_close = raw.rfind("</host>")
        if last_close >= 0:
            body = raw[: last_close + len("</host>")]
        else:
            # No host finished. Keep only the header, before the first <host.
            first_open = raw.find("<host")
            if first_open < 0:
                # Truncated inside the header itself — salvage nothing but a
                # well-formed empty document.
                m = re.search(r"<nmaprun[^>]*>", raw)
                return (m.group(0) + "\n</nmaprun>\n") if m else None
            body = raw[:first_open]

        # A cut can still land inside an unclosed header child (<scaninfo,
        # <verbose, <taskbegin...). Trim back to the last complete tag.
        last_gt = body.rfind(">")
        if last_gt < 0:
            return None
        body = body[: last_gt + 1]

        return body + "\n</nmaprun>\n"

    @staticmethod
    def _parse_nuclei(path: Path) -> list[dict]:
        sev_map = {"info": "info", "low": "low", "medium": "medium",
                   "high": "high", "critical": "critical"}
        out = []
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = d.get("info", {})
            host = d.get("host", "") or d.get("ip", "")
            ip = d.get("ip") or host.split("://")[-1].split(":")[0].split("/")[0]
            port = d.get("port")
            classification = info.get("classification") or {}
            out.append({
                "ip": ip,
                "port": int(port) if port else None,
                "proto": "tcp",
                "title": info.get("name", d.get("template-id", "nuclei finding")),
                "severity": sev_map.get(info.get("severity", "info"), "info"),
                "confidence": "firm",
                "cves": [c.upper() for c in (classification.get("cve-id") or [])],
                "cvss": classification.get("cvss-score"),
                "description": (info.get("description") or "")[:600],
                "references": info.get("reference") or [],
                "evidence": (d.get("matched-at") or "")[:400],
                "source": f"nuclei:{d.get('template-id', '')}",
            })
        return [f for f in out if f["ip"]]

    def _announce(self, finding: dict) -> None:
        """Notify the caller of a new finding. Serialised, because enrichment
        stages merge from a thread pool."""
        if self.on_finding is None:
            return
        with self._finding_lock:
            try:
                self.on_finding(finding)
            except Exception:
                # A display problem must never take down a scan.
                pass

    def _merge_findings(self, new: list[dict]) -> None:
        """Dedupe against existing findings using the schema fingerprint, so
        nmap NSE and nuclei reporting the same CVE collapse into one."""
        def fp(d: dict) -> str:
            return "|".join([d.get("ip", ""), str(d.get("port") or ""),
                             ",".join(sorted(d.get("cves") or []))
                             or d.get("title", "").lower().strip()])
        index = {fp(f): f for f in self.state.findings}
        for f in new:
            k = fp(f)
            if k in index:
                cur = index[k]
                order = {"tentative": 0, "firm": 1, "confirmed": 2}
                if order.get(f.get("confidence", "tentative"), 0) > \
                   order.get(cur.get("confidence", "tentative"), 0):
                    cur["confidence"] = f["confidence"]
                sev = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                if sev.get(f.get("severity", "info"), 0) > \
                   sev.get(cur.get("severity", "info"), 0):
                    cur["severity"] = f["severity"]
                cur["source"] = ",".join(sorted(
                    set(cur.get("source", "").split(",")) | {f.get("source", "")}))
            else:
                index[k] = f
                self.state.findings.append(f)
                self._announce(f)

    # ---------------- driver ----------------

    # Ordered: cheap and universal first, slow and narrow last. Every stage
    # after port-scan reads from state.services, so discovery must run first.
    STAGES: list[tuple[str, str]] = [
        ("host-discovery",        "discover_hosts"),
        ("icmp-sweep",            "fast_ping"),
        ("arp-discovery",         "arp_discovery"),
        ("port-scan",             "port_scan"),
        ("banner-analysis",       "banner_analysis"),
        ("udp-scan",              "udp_scan"),
        ("masscan-sweep",         "masscan_sweep"),
        ("netbios-scan",          "nbt_scan"),
        ("datastore-exposure",    "datastore_exposure"),
        ("web-assessment",        "web_assessment"),
        ("web-exposed-paths",     "web_paths"),
        ("tls-certificate",       "tls_certificate"),
        ("smb-enumeration",       "smb_enum"),
        ("smb-shares",            "smb_shares"),
        ("smb-deep-enum",         "enum4linux"),
        ("smb-file-listing",      "smb_readable_files"),
        ("kerberos-userenum",     "kerberos_userenum"),
        ("auth-admin-sprawl",     "auth_admin_sprawl"),
        ("auth-share-access",     "auth_share_access"),
        ("auth-password-policy",  "auth_password_policy"),
        ("auth-kerberoast",       "auth_kerberoast"),
        ("rpc-enumeration",       "rpc_enum"),
        ("snmp-enumeration",      "snmp_enum"),
        ("nfs-exports",           "nfs_enum"),
        ("ldap-anonymous-bind",   "ldap_enum"),
        ("ike-vpn",               "ike_scan"),
        ("tls-posture",           "tls_scan"),
        ("tls-structured",        "sslyze_scan"),
        ("exploitdb-correlation", "searchsploit_correlate"),
        ("nuclei",                "nuclei_scan"),
        ("tls-deep",              "testssl_scan"),
        ("nmap-vuln-scripts",     "vuln_scripts"),
    ]

    # Stages grouped by the phase of a standard VAPT methodology
    # (PTES / NIST SP 800-115). The console walks these in order and gates
    # each one, so the operator always knows which phase they're in and what
    # the next one will do before it runs.
    PHASES: list[tuple[str, str, list[str]]] = [
        ("Reconnaissance",
         "Identify live hosts within scope",
         ["host-discovery", "icmp-sweep", "arp-discovery"]),
        ("Service Enumeration",
         "Map open ports, identify services and versions",
         ["port-scan", "masscan-sweep", "banner-analysis", "udp-scan",
          "netbios-scan"]),
        ("Deep Enumeration",
         "Probe each service for anonymous access and information disclosure",
         ["smb-enumeration", "smb-shares", "smb-deep-enum",
          "smb-file-listing", "rpc-enumeration", "snmp-enumeration",
          "nfs-exports", "ldap-anonymous-bind", "ike-vpn",
          "kerberos-userenum", "datastore-exposure"]),
        ("Authenticated Assessment",
         "What a supplied credential can reach — skipped when none is given",
         ["auth-admin-sprawl", "auth-share-access", "auth-password-policy",
          "auth-kerberoast"]),
        ("Web Assessment",
         "Inspect HTTP services for misconfiguration and exposed content",
         ["web-assessment", "web-exposed-paths", "tls-certificate"]),
        ("Vulnerability Assessment",
         "Correlate versions against CVEs, templates and public exploits",
         ["tls-posture", "tls-structured", "exploitdb-correlation", "nuclei",
          "tls-deep", "nmap-vuln-scripts"]),
    ]

    # Stages that hand their whole target set to the tool in a single
    # invocation rather than spawning one process per host. That is strictly
    # better than per-host concurrency — masscan and fping are built to sweep
    # ranges — so the "must be concurrent" invariant does not apply to them.
    # Listing them explicitly means adding a stage here is a conscious choice,
    # not an accidental exemption.
    RANGE_STAGES = frozenset({
        "host-discovery", "port-scan", "udp-scan", "nmap-vuln-scripts",
        "icmp-sweep", "arp-discovery", "masscan-sweep", "netbios-scan",
        "tls-structured", "nuclei",
    })

    # Stages that query a domain-wide fact and stop at the first authoritative
    # answer. Password policy and the SPN list are properties of the domain,
    # not of a host — asking every domain controller in parallel would produce
    # the same answer N times and N times the log noise. Concurrency is the
    # wrong tool here, so the "must be concurrent" invariant does not apply.
    SINGLE_SOURCE_STAGES = frozenset({
        "auth-password-policy", "auth-kerberoast",
    })

    # Named presets the console exposes as scan-depth choices.
    QUICK = {"host-discovery", "icmp-sweep", "port-scan", "banner-analysis"}
    STANDARD = QUICK | {
        "udp-scan", "arp-discovery", "netbios-scan", "masscan-sweep",
        "smb-deep-enum", "smb-file-listing", "kerberos-userenum",
        "auth-admin-sprawl", "auth-share-access", "auth-password-policy",
        "auth-kerberoast",
        "tls-structured",
        "smb-enumeration", "smb-shares", "rpc-enumeration", "snmp-enumeration",
        "nfs-exports", "ldap-anonymous-bind", "ike-vpn", "datastore-exposure",
        "web-assessment", "web-exposed-paths", "tls-certificate",
        "tls-posture", "exploitdb-correlation", "nuclei",
    }

    def run_stage(self, name: str, method: str | None = None):
        """Run one stage with logging and stage tagging.

        Every call site goes through here. The CLI, the console and `execute`
        each used to iterate stages themselves, and only one of them tagged the
        stage name — which is why every command logged as "unknown".
        """
        method = method or dict(self.STAGES).get(name)
        if method is None or not hasattr(self, method):
            raise KeyError(f"unknown stage: {name}")
        current_stage(name)
        _STAGE_TIMEOUTS.clear()
        self.log.event("stage-start", stage=name)
        result = getattr(self, method)()
        if _STAGE_TIMEOUTS:
            # The stage produced whatever it produced, but part of the target
            # set was never actually examined. Say so rather than letting a
            # partial pass read as a clean one.
            timed_out = sorted(set(_STAGE_TIMEOUTS))
            result.incomplete = True
            note = (f"{len(_STAGE_TIMEOUTS)} command(s) timed out "
                    f"({', '.join(timed_out[:3])}) — coverage is partial")
            result.reason = (result.reason + "; " + note) if result.reason else note
            self.log.event("stage-incomplete", stage=name,
                           timeouts=len(_STAGE_TIMEOUTS), tools=timed_out)
        self.log.event("stage-end", stage=name, ok=result.ok,
                       skipped=result.skipped, findings=result.findings,
                       duration_s=round(result.duration, 2), reason=result.reason)
        return result

    def execute(self, skip: set[str] | None = None,
                on_stage: Callable[[str, int, int], None] | None = None
                ) -> list[StageResult]:
        skip = skip or set()
        done = self.state.completed() if self.resume else set()
        results = []
        stages = [s for s in self.STAGES if s[0] not in skip]
        for i, (name, method) in enumerate(stages, 1):
            if name in done:
                results.append(StageResult(name, True, skipped=True,
                                           reason="already done (resumed)"))
                continue
            if on_stage:
                on_stage(name, i, len(stages))
            results.append(self.run_stage(name, method))
        return results

    def export(self) -> Path:
        out = self.workdir / "findings.json"
        secure_write(out, json.dumps({
            "services": self.state.services,
            "findings": self.state.findings,
        }, indent=2))
        return out
