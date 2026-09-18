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

        if self.evidence_dir and stdout:
            rec.evidence_path = self._store_evidence(stage, target, argv, stdout)

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
                        argv: list[str], stdout: str) -> Optional[str]:
        try:
            stage_dir = self.evidence_dir / safe_filename(stage, "stage")
            stage_dir.mkdir(parents=True, exist_ok=True)
            base = safe_filename(target or Path(argv[0]).name, "output")
            path = stage_dir / f"{base}.txt"
            n = 1
            while path.exists():
                path = stage_dir / f"{base}-{n}.txt"
                n += 1
            body = stdout[:MAX_EVIDENCE_BYTES]
            truncated = len(stdout) > MAX_EVIDENCE_BYTES
            header = (
                f"# vision evidence\n"
                f"# stage:   {stage}\n"
                f"# target:  {target or '-'}\n"
                f"# command: {' '.join(shlex.quote(a) for a in redact(argv))}\n"
                f"# time:    {time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
                + (f"# NOTE: truncated at {MAX_EVIDENCE_BYTES} bytes\n"
                   if truncated else "")
                + "#" + "-" * 60 + "\n"
            )
            secure_write(path, header + safe_display(body, MAX_EVIDENCE_BYTES))
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
