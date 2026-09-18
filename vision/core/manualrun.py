"""Manual tool runner.

The playbook says what to run. This runs it — without leaving Vision, and
without losing the output the way a separate terminal does.

What this buys over just opening another shell: the target is scope-checked
before anything executes, the command lands in the same run log as every
automated stage, the output is written to the same evidence directory, and a
finding can be recorded from it immediately. An assessment where half the work
happened in an untracked terminal is an assessment you cannot reconstruct six
weeks later.

**Commands are argv, never a shell string.** `subprocess` is called with a list
and `shell=False`, so `;`, `|`, backticks and `$(...)` are arguments rather than
syntax. That is not paranoia about the operator — it is that a command
assembled from a playbook template plus a hostname plus a pasted share name has
several places for a metacharacter to arrive unnoticed, and a scan tool that
can be turned into a shell by a share called `; rm -rf /` is a bad tool.

Operators who genuinely want a pipeline still have a shell. This runs tools.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .safety import safe_display, secure_write
from .toolchain import TOOLS, BY_NAME

MAX_OUTPUT = 512 * 1024
DEFAULT_TIMEOUT = 300

# Anything that only means something to a shell. Present in an argv token it is
# either a mistake or an attempt, and both deserve the same answer.
_SHELL_META = re.compile(r"[;&|`$><\n]|\$\(|\)\s*\{")


class CommandRejected(ValueError):
    """The command will not be run. Always explains why."""


@dataclass
class ManualRun:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    evidence_path: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def command(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)


def installed_tools() -> list:
    """Tools actually present, so the menu never offers something absent."""
    return sorted((t for t in TOOLS if t.installed), key=lambda t: t.name)


def targets_in(argv: list[str]) -> list[str]:
    """Every IP-like token in a command, including inside host:port and URLs.

    Used to scope-check before running. Over-matching is the safe direction:
    a token that merely looks like an address gets validated, and a false
    positive costs the operator an explanation rather than costing the client
    an unauthorised packet.
    """
    found = []
    for arg in argv:
        for token in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", arg):
            try:
                ipaddress.ip_address(token)
            except ValueError:
                continue
            if token not in found:
                found.append(token)
    return found


def parse(command: str) -> list[str]:
    """Turn an edited command line into argv, refusing shell syntax."""
    command = (command or "").strip()
    if not command:
        raise CommandRejected("empty command")
    if _SHELL_META.search(command):
        raise CommandRejected(
            "shell syntax (; | & ` $() > <) is not run — Vision executes a "
            "program with arguments, not a shell line. Use a shell for "
            "pipelines and rerun the plain command here.")
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise CommandRejected(f"cannot parse the command: {exc}") from None
    if not argv:
        raise CommandRejected("empty command")
    return argv


def validate(argv: list[str], scope, allow_unknown_tool: bool = False) -> None:
    """Refuse anything that would break the engagement boundary."""
    if not argv:
        raise CommandRejected("empty command")

    binary = Path(argv[0]).name
    known = {t.binary for t in TOOLS} | {t.name for t in TOOLS}
    for t in TOOLS:
        known |= set(t.alt_binaries)
    if binary not in known and not allow_unknown_tool:
        raise CommandRejected(
            f"{binary!r} is not one of the tools Vision knows about. Run it "
            "from a shell, or add it to the toolchain first.")

    outside = [ip for ip in targets_in(argv) if not scope.contains(ip)]
    if outside:
        # The same rule the scanner follows. A boundary that applies to
        # automation but not to a typed command is not a boundary.
        raise CommandRejected(
            f"{', '.join(outside)} is outside the engagement scope — the same "
            "rule applies to commands you type as to stages Vision runs")


def run(argv: list[str], scope, workdir: Path, *,
        timeout: int = DEFAULT_TIMEOUT, log=None,
        allow_unknown_tool: bool = False) -> ManualRun:
    """Execute a validated command, capturing it exactly like a stage."""
    validate(argv, scope, allow_unknown_tool)

    started = time.time()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, shell=False)
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        code, out, err = -1, "", f"timed out after {timeout}s"
    except FileNotFoundError:
        code, out, err = -1, "", f"{argv[0]} not found on PATH"
    except OSError as exc:
        code, out, err = -1, "", str(exc)

    duration = time.time() - started
    out = out[:MAX_OUTPUT]
    result = ManualRun(argv=list(argv), returncode=code,
                       stdout=out, stderr=safe_display(err, 2000),
                       duration=duration)

    if log is not None:
        # Same log as every automated stage, so the record of the engagement
        # is complete rather than split between the tool and someone's tmux
        # scrollback.
        try:
            log.command("manual", argv, code, duration, out, err,
                        target=(targets_in(argv) or [None])[0])
        except Exception:
            pass

    result.evidence_path = _save_evidence(argv, out, err, workdir)
    return result


def _save_evidence(argv: list[str], out: str, err: str,
                   workdir: Path) -> Optional[str]:
    try:
        from .runlog import redact
        from .safety import safe_filename
        d = Path(workdir) / "evidence" / "manual"
        d.mkdir(parents=True, exist_ok=True)
        base = safe_filename(Path(argv[0]).name, "command")
        path = d / f"{base}.txt"
        n = 1
        while path.exists():
            path = d / f"{base}-{n}.txt"
            n += 1
        header = (
            "# vision manual command\n"
            f"# command: {' '.join(shlex.quote(a) for a in redact(argv))}\n"
            f"# time:    {time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
            + "#" + "-" * 60 + "\n"
        )
        secure_write(path, header + safe_display(out + ("\n" + err if err else ""),
                                                 MAX_OUTPUT))
        return str(path)
    except (OSError, ValueError):
        return None


def suggestions_for(tool_name: str, ip: str = "", port: int | None = None,
                    scope: str = "") -> list[tuple[str, str]]:
    """Playbook commands that use this tool, as (label, command).

    Gives the operator a correct starting point to edit rather than a blank
    prompt — most mistakes in manual testing are typos in flags, not choices.
    """
    from ..analysis import playbook
    binary = (BY_NAME.get(tool_name).binary if BY_NAME.get(tool_name)
              else tool_name)
    out: list[tuple[str, str]] = []
    groups = ([steps for _n, _p, steps in playbook.SERVICE_PLAYBOOK]
              + [steps for _p, steps in playbook.FINDING_PLAYBOOK]
              + [steps for _k, _t, steps in playbook.SITUATION_PLAYBOOK])
    for steps in groups:
        for step, cmd in playbook.render(steps, ip, port, scope):
            first = cmd.strip().lstrip("#").strip().split()
            if first and (first[0] == binary or first[0] == tool_name):
                if not any(c == cmd for _l, c in out):
                    out.append((step.label, cmd))
    return out
