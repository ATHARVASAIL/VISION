"""Run logging and evidence preservation.

Two problems this solves, both of which only bite on a real engagement.

**Diagnosis.** When a stage fails against a client's network, the operator
currently sees `reason[:200]` and nothing else. Was the command wrong? Did the
tool exit non-zero with a useful message on stderr? Was it a timeout or a
refused connection? Without the actual argv and the actual stderr there is no
way to tell, and the scan window is usually not long enough to reproduce.

**Defensibility.** A finding is only as good as the evidence behind it. Six
weeks after delivery, "smbmap said the share was writable" is much weaker than
the raw smbmap output with a timestamp. Peer reviewers ask for it, clients
disputing a finding ask for it, and reconstructing it later is impossible.

Both are solved by recording what actually ran. The run log is JSONL — one
object per command — so it greps, it diffs between engagements, and it survives
a crashed run because it is flushed per line rather than buffered.

Credentials are redacted before anything is written. Vision does not send
passwords today, but `-p`, `-w` and `--password` appear in the tools it drives,
and a log file that captures one is a liability that outlives the engagement.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .safety import safe_display, safe_filename, secure_open, secure_write

# Flags whose *following* argument is a secret.
_SECRET_FLAGS = {
    "-p", "--password", "-w", "--pass", "--passwd", "--secret",
    "-P", "--pass-file", "--api-key", "--token", "-c", "--community",
    "-H", "--hash", "--hashes", "-k", "--key",
}

# Tools where a short flag means something harmless rather than a credential.
# `-p` is a password to smbmap and hydra but a port list to nmap, and `-c` is a
# community string to snmpwalk but a command to rpcclient. Redacting those
# blindly destroys the diagnostic value of the log — the port list is often the
# first thing you need to see when a scan found nothing.
#
# The mapping is an allowlist keyed on the binary: an unrecognised tool keeps
# the cautious default, so a new tool cannot leak a credential by being unknown.
_BENIGN_FLAGS = {
    "nmap":      {"-p"},
    "smbmap":    {"-H"},        # -H is a host to smbmap, a hash to netexec
    "masscan":   {"-p"},
    "rustscan":  {"-p"},
    "naabu":     {"-p"},
    "rpcclient": {"-c"},
    "ike-scan":  {"-p"},
}

# Inline forms: --password=hunter2
_INLINE_SECRET = re.compile(
    r"^(--?(?:password|pass|passwd|secret|token|api-key|community))=(.*)$", re.I)

# impacket takes credentials inside a target string: DOMAIN/USER:PASS@HOST.
# No flag precedes the secret, so flag-based redaction never sees it — this is
# the shape that would otherwise walk a live password straight into the log.
_IMPACKET_TARGET = re.compile(
    r"^((?:[^/@\s]+/)?[^:@\s]+):([^@\s]+)(@\S+)$")

REDACTED = "«redacted»"

# Evidence from a single command is capped: a tool that dumps a 500 MB packet
# trace should not fill the operator's disk mid-engagement.
MAX_EVIDENCE_BYTES = 512 * 1024

# Commands that target a subnet, a URL, or nothing in particular (a sweep of
# the whole scope) have no single host to file under. They go here so the
# per-host folders stay one-host-each and easy to read.
SCOPE_BUCKET = "_scope"


def redact(argv: list[str]) -> list[str]:
    """Remove secrets from an argv before it is written anywhere.

    Empty-string values are left alone: `smbmap -u '' -p ''` is a null-session
    probe, and redacting it would hide what the tool actually did.
    """
    if not argv:
        return []
    tool = Path(str(argv[0])).name.lower()
    benign = _BENIGN_FLAGS.get(tool, frozenset())
    secret_flags = _SECRET_FLAGS - benign

    out: list[str] = []
    skip_next = False
    for arg in argv:
        if skip_next:
            out.append(REDACTED if arg else arg)
            skip_next = False
            continue
        inline = _INLINE_SECRET.match(arg)
        if inline:
            out.append(f"{inline.group(1)}={REDACTED if inline.group(2) else ''}")
            continue
        target = _IMPACKET_TARGET.match(arg)
        if target:
            out.append(f"{target.group(1)}:{REDACTED}{target.group(3)}")
            continue
        out.append(arg)
        if arg in secret_flags:
            skip_next = True
    return out


def host_bucket(target: str | None) -> str:
    """Folder name for a target's evidence — the bare host, or ``_scope``.

    The operator thinks in hosts: "show me everything Vision ran against
    192.168.88.128". So evidence is filed one folder per host, and this turns
    whatever a tool was pointed at — an IP, ``10.0.0.1:445``, ``[::1]:80``, a
    ``http://host/`` URL, a ``10.0.0.0/24`` range — into that folder's name.

    A subnet, a URL with a path, or a command with no host at all has no single
    host to own the output, so it lands in ``_scope`` rather than inventing a
    folder per sweep. ``safe_filename`` is the backstop: a hostile share name
    or a path-traversal attempt can reach here through a manually typed command,
    and the folder name must never escape the evidence directory.
    """
    if not target:
        return SCOPE_BUCKET
    s = str(target).strip()
    if "://" in s:                       # http://host/path -> host
        s = s.split("://", 1)[1]
    if "/" in s:                         # a path or a CIDR is scope-wide
        return SCOPE_BUCKET
    if s.startswith("[") and "]" in s:   # [v6]:port -> v6
        s = s[1:s.index("]")]
    elif s.count(":") == 1:              # host:port / v4:port -> host
        s = s.split(":", 1)[0]
    s = s.strip()
    return safe_filename(s, SCOPE_BUCKET) if s else SCOPE_BUCKET


def write_host_evidence(evidence_root: Path | str, *, target: str | None,
                        argv: list[str], stdout: str, stage: str = "",
                        stderr: str = "", kind: str = "evidence",
                        note: str = "") -> Path:
    """Write one command's terminal output under its host, named for the tool.

    Layout, from the operator's point of view::

        evidence/
          192.168.88.128/        <- one folder per host
            _host.txt            <- that host at a glance (written separately)
            nmap.txt             <- raw terminal output, one file per tool
            smbmap.txt
            enum4linux.txt
          _scope/                <- subnet sweeps and host-less commands
            nmap.txt

    The file is named for the tool (``nmap.txt``), which is what an operator
    looks for. When the same tool runs more than once against the same host —
    a discovery nmap and a vuln-script nmap — the stage is folded into the name
    (``nmap-vuln-scan.txt``) so the two stay distinguishable rather than
    silently numbered. Credentials are redacted from the command header before
    anything is written.
    """
    evidence_root = Path(evidence_root)
    host_dir = evidence_root / host_bucket(target)
    host_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(host_dir, 0o700)
    except OSError:
        pass

    tool = safe_filename(Path(str(argv[0])).name, "output") if argv else "output"
    stage_sf = safe_filename(stage, "") if stage else ""
    path = host_dir / f"{tool}.txt"
    if path.exists() and stage_sf and stage_sf != tool:
        path = host_dir / f"{tool}-{stage_sf}.txt"
    n = 1
    while path.exists():
        suffix = f"-{stage_sf}" if stage_sf and stage_sf != tool else ""
        path = host_dir / f"{tool}{suffix}-{n}.txt"
        n += 1

    body = (stdout or "")[:MAX_EVIDENCE_BYTES]
    truncated = len(stdout or "") > MAX_EVIDENCE_BYTES
    # The header is deliberately tool-neutral: these files are handed to a
    # client in a report, so they carry the host, the command and the time —
    # the facts an assessor needs — and name no scanner.
    header = (
        f"# host:    {target or '-'}\n"
        f"# tool:    {tool}\n"
        + (f"# stage:   {stage}\n" if stage else "")
        + f"# command: {' '.join(shlex.quote(a) for a in redact(argv))}\n"
        + f"# time:    {time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
        + (f"# note:    {safe_display(note, 200)}\n" if note else "")
        + (f"# NOTE: truncated at {MAX_EVIDENCE_BYTES} bytes\n" if truncated else "")
        + "#" + "-" * 60 + "\n"
    )
    content = header + safe_display(body, MAX_EVIDENCE_BYTES)
    if stderr and stderr.strip():
        content += "\n#" + "-" * 60 + "\n# stderr\n" + safe_display(stderr, 4000)
    secure_write(path, content)
    return path


@dataclass
class CommandRecord:
    stage: str
    argv: list[str]
    returncode: int
    duration: float
    stdout_bytes: int = 0
    stderr_tail: str = ""
    evidence_path: Optional[str] = None
    target: Optional[str] = None

    @property
    def command(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class RunLog:
    """Append-only JSONL record of everything a run executed.

    Thread-safe: enumeration stages run in a pool, so several commands finish
    at once and a torn line would corrupt the file.
    """

    def __init__(self, path: Path | str, debug: bool = False,
                 evidence_dir: Path | str | None = None):
        self.path = Path(path)
        self.debug = debug
        self.evidence_dir = Path(evidence_dir) if evidence_dir else None
        self._lock = threading.Lock()
        self._commands = 0
        self._failures = 0
        self._started = time.time()
        if self.evidence_dir:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.evidence_dir, 0o700)
            except OSError:
                pass

    # ------------------------------------------------------------ writing

    def _write(self, record: dict) -> None:
        record.setdefault("ts", time.time())
        record.setdefault("iso", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        line = json.dumps(record, default=str)
        with self._lock:
            with secure_open(self.path, "a") as fh:
                fh.write(line + "\n")

    def event(self, kind: str, **fields: Any) -> None:
        self._write({"kind": kind, **fields})

    def command(self, stage: str, argv: list[str], returncode: int,
                duration: float, stdout: str = "", stderr: str = "",
                target: str | None = None) -> CommandRecord:
        safe_argv = redact(list(argv))
        rec = CommandRecord(
            stage=stage, argv=safe_argv, returncode=returncode,
            duration=duration, stdout_bytes=len(stdout or ""),
            stderr_tail=safe_display(stderr, 400), target=target,
        )
        with self._lock:
            self._commands += 1
            if returncode != 0:
                self._failures += 1

        if self.evidence_dir and (stdout or stderr):
            rec.evidence_path = self._store_evidence(stage, target, argv,
                                                     stdout, stderr)

        self._write({
            "kind": "command", "stage": stage, "command": rec.command,
            "returncode": returncode, "duration_s": round(duration, 3),
            "stdout_bytes": rec.stdout_bytes, "stderr": rec.stderr_tail,
            "target": target, "evidence": rec.evidence_path,
        })
        if self.debug:
            status = "ok" if returncode == 0 else f"exit {returncode}"
            print(f"  \033[2m$ {rec.command}\033[0m")
            print(f"  \033[2m  → {status} in {duration:.1f}s"
                  f"{', ' + rec.stderr_tail[:120] if rec.stderr_tail else ''}\033[0m")
        return rec

    # ------------------------------------------------------------ evidence

    def _store_evidence(self, stage: str, target: str | None,
                        argv: list[str], stdout: str,
                        stderr: str = "") -> Optional[str]:
        try:
            path = write_host_evidence(
                self.evidence_dir, target=target, argv=argv, stdout=stdout,
                stage=stage, stderr=stderr)
            return str(path.relative_to(self.evidence_dir.parent))
        except (OSError, ValueError):
            # Evidence capture is valuable but never worth failing a scan for.
            return None

    # ------------------------------------------------------------ summary

    def summary(self) -> dict:
        with self._lock:
            return {
                "commands": self._commands,
                "failures": self._failures,
                "elapsed_s": round(time.time() - self._started, 1),
                "log": str(self.path),
                "evidence": str(self.evidence_dir) if self.evidence_dir else None,
            }

    def failures(self) -> list[dict]:
        """Commands that exited non-zero. The first thing to look at when a
        stage produced nothing and the operator wants to know why."""
        out = []
        try:
            for line in self.path.read_text(errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("kind") == "command" and rec.get("returncode", 0) != 0:
                    out.append(rec)
        except OSError:
            pass
        return out


class NullLog(RunLog):
    """Used when logging is disabled. Same interface, writes nothing, so the
    call sites stay free of `if self.log is not None` noise."""

    def __init__(self):
        self.path = Path(os.devnull)
        self.debug = False
        self.evidence_dir = None
        self._lock = threading.Lock()
        self._commands = 0
        self._failures = 0
        self._started = time.time()

    def _write(self, record: dict) -> None:
        return

    def _store_evidence(self, *a, **k) -> Optional[str]:
        return None


# --------------------------------------------------------- host summaries

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# Each host's evidence is split in two so a report writer can tell proof from
# coverage at a glance: a command that revealed something goes under finding/,
# one that came up clean goes under no finding/.
FINDING_DIR = "finding"
NOFINDING_DIR = "no finding"


def _group_by_host(items: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for it in items or []:
        ip = str(it.get("ip") or "").strip()
        if ip:
            out.setdefault(ip, []).append(it)
    return out


def _finding_tags(findings: list[dict]) -> tuple[dict, dict]:
    """Per host, the stages and tool sources that produced a finding."""
    stages: dict[str, set] = {}
    sources: dict[str, set] = {}
    for f in findings or []:
        ip = str(f.get("ip") or "").strip()
        if not ip:
            continue
        st = str(f.get("stage") or "").strip()
        if st:
            stages.setdefault(ip, set()).add(st)
        src = str(f.get("source") or "").strip().lower()
        if src:
            sources.setdefault(ip, set()).add(src)
    return stages, sources


def _read_evidence_meta(path: Path) -> tuple[str, str]:
    """The stage and tool recorded in an evidence file's header."""
    stage = tool = ""
    try:
        with open(path, "r", errors="replace") as fh:
            for _ in range(12):
                line = fh.readline()
                if not line or not line.startswith("#"):
                    break
                if line.startswith("# stage:"):
                    stage = line.split(":", 1)[1].strip()
                elif line.startswith("# tool:"):
                    tool = line.split(":", 1)[1].strip()
    except OSError:
        pass
    return stage, tool


def _evidence_has_finding(stage: str, tool: str, stages: set, sources: set,
                          use_source: bool) -> bool:
    # The stage that produced a finding is the reliable signal and tells two
    # runs of the same tool apart (a clean port scan vs. a vuln scan that hit).
    # The tool/source match is only a backstop, used when a host's findings
    # carry no stage at all (recon, manually recorded), so it never overrides a
    # stage decision.
    if stage and stage in stages:
        return True
    if use_source:
        tl = (tool or "").lower()
        return bool(tl and any(tl in s or s in tl for s in sources))
    return False


def _classify_host_dir(host_dir: Path, ip: str, fstages: dict,
                       fsources: dict) -> tuple[list[str], list[str]]:
    """Sort a host's evidence into finding/ and no finding/. Idempotent — files
    already sorted are re-read and re-placed, so a re-run corrects itself.
    Returns (finding_files, no_finding_files) as display paths."""
    find_dir = host_dir / FINDING_DIR
    nofind_dir = host_dir / NOFINDING_DIR
    stages = fstages.get(ip, set())
    sources = fsources.get(ip, set())
    use_source = not stages   # only fall back to source when no staged findings
    candidates: list[Path] = []
    for d in (host_dir, find_dir, nofind_dir):
        if d.is_dir():
            candidates += [p for p in sorted(d.glob("*.txt")) if p.name != "_host.txt"]
    finds: list[str] = []
    nofinds: list[str] = []
    for p in candidates:
        stage, tool = _read_evidence_meta(p)
        hit = _evidence_has_finding(stage, tool, stages, sources, use_source)
        dest_dir = find_dir if hit else nofind_dir
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(dest_dir, 0o700)
        except OSError:
            pass
        target = dest_dir / p.name
        try:
            if p.resolve() != target.resolve():
                p.replace(target)
        except OSError:
            target = p   # move failed; keep where it is
        (finds if hit else nofinds).append(f"{dest_dir.name}/{target.name}")
    return sorted(finds), sorted(nofinds)


def write_host_summaries(evidence_root: Path | str, services: list[dict],
                         findings: list[dict], *, scope: str = "",
                         live_hosts: list[str] | None = None) -> list[Path]:
    """Sort each host's evidence into finding/ and no finding/, then write a
    per-host ``_host.txt`` and a top-level ``INDEX.txt``.

    ``_host.txt`` is the file to open first: one host, its open services, the
    findings recorded against it, and which evidence file proves each — proof
    under finding/, everything else run under no finding/. ``INDEX.txt`` is the
    same view one level up. Both are tool-neutral, so they can go straight into
    a client report.

    Written at the end of a scan and refreshed on export. Best-effort: a summary
    that cannot be written never fails the engagement.
    """
    evidence_root = Path(evidence_root)
    written: list[Path] = []
    svc_by_host = _group_by_host(services)
    find_by_host = _group_by_host(findings)
    fstages, fsources = _finding_tags(findings)
    hosts = set(svc_by_host) | set(find_by_host) | set(live_hosts or [])
    if not hosts:
        return written
    try:
        evidence_root.mkdir(parents=True, exist_ok=True)
    except OSError:
        return written

    def _sev_counts(fs: list[dict]) -> dict[str, int]:
        c = {s: 0 for s in _SEV_ORDER}
        for f in fs:
            s = str(f.get("severity", "info")).lower()
            if s in c:
                c[s] += 1
        return c

    for ip in sorted(hosts):
        svcs = sorted(svc_by_host.get(ip, []),
                      key=lambda s: (int(s.get("port") or 0), s.get("proto", "")))
        fs = sorted(find_by_host.get(ip, []),
                    key=lambda f: _SEV_ORDER.index(str(f.get("severity", "info")).lower())
                    if str(f.get("severity", "info")).lower() in _SEV_ORDER else 9)
        host_dir = evidence_root / host_bucket(ip)
        try:
            host_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(host_dir, 0o700)
        except OSError:
            pass
        find_files, nofind_files = _classify_host_dir(host_dir, ip, fstages, fsources)
        lines = [
            "# Host summary",
            f"# host:    {ip}",
            (f"# scope:   {safe_display(scope, 120)}" if scope else "# scope:   -"),
            f"# updated: {time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
            "#" + "-" * 60,
            "",
            f"HOST  {ip}",
            "",
            f"OPEN SERVICES ({len(svcs)})",
        ]
        if svcs:
            for s in svcs:
                ver = " ".join(filter(None, [str(s.get("product") or ""),
                                             str(s.get("version") or "")])).strip()
                port = f"{s.get('port', '')}/{s.get('proto', 'tcp')}"
                lines.append(f"  {port:<10} {str(s.get('name') or '-'):<14} "
                             f"{safe_display(ver, 50) or '-'}")
        else:
            lines.append("  (none recorded)")
        lines += ["", f"FINDINGS ({len(fs)})"]
        if fs:
            for f in fs:
                sev = str(f.get("severity", "info")).upper()
                cves = ", ".join(f.get("cves") or [])
                tail = f"   {cves}" if cves else ""
                port = f":{f['port']}" if f.get("port") else ""
                lines.append(f"  [{sev:<8}] {safe_display(f.get('title', ''), 70)}"
                             f"{port}{tail}")
        else:
            lines.append("  (none recorded)")

        # Evidence split into proof (finding/) and coverage (no finding/).
        lines += ["", f"EVIDENCE — FINDINGS ({len(find_files)})"]
        lines += [f"  {n}" for n in find_files] or ["  (none)"]
        lines += ["", f"EVIDENCE — NO FINDINGS ({len(nofind_files)})"]
        lines += [f"  {n}" for n in nofind_files] or ["  (none)"]
        lines.append("")
        try:
            written.append(secure_write(host_dir / "_host.txt", "\n".join(lines)))
        except OSError:
            pass

    # Top-level index across every host.
    idx = [
        "# Evidence index",
        (f"# scope:   {safe_display(scope, 120)}" if scope else "# scope:   -"),
        f"# hosts:   {len(hosts)}",
        f"# updated: {time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
        "#" + "-" * 60,
        "",
    ]
    for ip in sorted(hosts):
        c = _sev_counts(find_by_host.get(ip, []))
        nsvc = len(svc_by_host.get(ip, []))
        nfind = len(find_by_host.get(ip, []))
        worst = next((s for s in _SEV_ORDER if c[s]), "")
        flag = f"  worst {worst}" if worst else ""
        idx.append(f"  {host_bucket(ip) + '/':<20} {nsvc:>3} services  "
                   f"{nfind:>3} findings{flag}")
    scope_dir = evidence_root / SCOPE_BUCKET
    if scope_dir.is_dir():
        idx.append(f"  {SCOPE_BUCKET + '/':<20} subnet-level and host-less scans")
    idx.append("")
    try:
        written.append(secure_write(evidence_root / "INDEX.txt", "\n".join(idx)))
    except OSError:
        pass
    return written


_RUN_README = """\
# Assessment evidence

This folder holds everything from one assessment. Nothing here leaves your
machine unless you send it — treat it as client data.

  report.html        client-ready report (open in a browser, print to PDF)
  report.md          the same report in Markdown
  findings.json      every finding and service, machine-readable
  findings.csv       findings as a spreadsheet table
  run.jsonl          every command that was run, one JSON object per line
  state.json         session state — lets you resume this assessment

  evidence/          raw terminal output, ONE FOLDER PER HOST
    INDEX.txt          every host at a glance
    <ip>/              one folder per target
      _host.txt          this host: open services, findings, evidence files
      finding/           commands that revealed a finding (the proof)
      no finding/        commands that came up clean (coverage)
    _scope/            subnet sweeps and host-less commands

Open a host's folder and read _host.txt. Credentials are redacted from every
file here, and no file names the tooling — they are ready to attach to a report.
"""


def ensure_run_readme(workdir: Path | str) -> Optional[Path]:
    """Drop a short README in the run directory so its layout is self-explaining.

    Written once; an existing README is never overwritten, so an operator who
    edits it keeps their notes.
    """
    try:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        path = workdir / "README.txt"
        if not path.exists():
            secure_write(path, _RUN_README, file_mode=0o600)
        return path
    except OSError:
        return None
