"""Proof of impact.

Vision used to stop at `exploit -z`. A session opened, msfconsole exited, and
nothing was captured — no user, no privilege level, no host identity, no
finding. The operator was left to reconstruct from memory what an exploit had
actually achieved, which is exactly the part a client disputes.

This closes that. When a session opens, Vision runs a short fixed sequence of
**read-only identity commands** inside it, captures the output verbatim as
evidence, and records a `confirmed` finding describing what was obtained.

That turns three different report sentences into one defensible one:

    "vsftpd 2.3.4 is vulnerable to CVE-2011-2523"        (a version string)
    "the check reported the target as vulnerable"        (a tool's opinion)
    "root shell obtained; uid=0(root) captured 14:22"    (a fact)

**Why these commands and no others.** `id`, `whoami`, `hostname`, `uname -a`,
`sysinfo`, `getuid` answer one question — *what did we get* — and change
nothing on the target. They are the minimum needed to prove impact and the
maximum that can be run without judgement about the client's environment.
Anything that reads user data, dumps credentials, moves laterally or persists
is a decision an operator makes with the engagement terms in front of them, and
the manual playbook is where those live.

The session is closed afterwards. Leaving shells open on a client's estate
after a test is how an assessment becomes an incident.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..core.safety import safe_display

# Read-only identity commands, per session type. Nothing here writes, reads
# user data, or persists.
UNIX_PROOF = [
    "id",
    "whoami",
    "hostname",
    "uname -a",
]

METERPRETER_PROOF = [
    "getuid",
    "sysinfo",
]

# Markers so the combined transcript can be split back per command.
MARK = "___VISION_PROOF_"

_ROOT_PATTERNS = [
    # uid=0 in any id/getuid shape: uid=0(root), uid=0, gid=0, or bare uid=0.
    # Anchored to a token boundary so uid=1000 and uid=0333 never match, and a
    # trailing \b or ( so the 0 must stand alone. This is the reliable signal
    # on a raw Unix shell and on a Linux meterpreter alike.
    re.compile(r"(?:^|\s)uid=0(?:\b|\()", re.M),
    re.compile(r"\bNT AUTHORITY\\+SYSTEM\b", re.I),
    re.compile(r"Server username:\s*(?:NT AUTHORITY\\+)?SYSTEM", re.I),
    # A Linux meterpreter's getuid prints "Server username: root" — a real
    # privileged session that the SYSTEM-only pattern above missed, silently
    # downgrading a demonstrated root compromise to an unprivileged finding.
    re.compile(r"Server username:\s*root\s*$", re.I | re.M),
    re.compile(r"^root$", re.M),
    # A shell prompt ending in '#' is root; a normal user gets '$'. On a raw
    # bind shell (the vsftpd 2.3.4 backdoor is the canonical case) the `id`
    # output can arrive mangled or not at all, and the prompt itself —
    # "sh-3.2#", "root@host:~#", or a bare "#" — is the only clean evidence of
    # root. Anchored to end-of-line so a '#' inside a comment, a path, or
    # mid-command never matches, and paired with the '$' non-root prompt it
    # mirrors the universal Unix convention. This was found when the first real
    # proof-of-impact transcript (a genuine root shell) was scored as
    # unprivileged because it proved root by prompt, not by uid=0.
    re.compile(
        r"(?:^|\n)"
        r"(?:\[?[\w.\-]*@?[\w.\-]*[\]:~/ ]*|sh-[\d.]+|bash-[\d.]+)?"
        r"#[ \t]*$",
        re.M),
]

_USER_PATTERNS = [
    re.compile(r"uid=\d+\(([^)]+)\)"),
    # Windows accounts are DOMAIN\USER and the whole thing is the identity —
    # splitting on the backslash reported "NT" as the user, which is wrong and
    # would read as a real account name in a report.
    re.compile(r"Server username:\s*([^\r\n]+?)\s*$", re.I | re.M),
    # `whoami` prints a bare name on its own line. Bounded to a plausible
    # username: without a length cap, 200KB of padding in a transcript was
    # extracted as the account name.
    re.compile(r"^([A-Za-z0-9_.\\$-]{1,32})$", re.M),
]

# A run of one repeated character is padding or corruption, not an account.
_IMPLAUSIBLE_USER = re.compile(r"^(.)\1{7,}$")

# Shell transcripts are full of echoed commands, separators and banner text. The
# last-resort `whoami`/`hostname` patterns match any short line, so on a real
# raw shell they scooped up whatever happened to be there: the first genuine
# field transcript produced user='-----' and host='exit', which would have gone
# into a client report as "shell as user ----- on host exit". These reject the
# noise without narrowing what counts as a real account or hostname.
_SHELL_NOISE = frozenset({
    "exit", "logout", "id", "whoami", "hostname", "uname", "ls", "pwd", "cd",
    "echo", "sh", "bash", "zsh", "quit", "clear", "exec", "su", "sudo",
    "shell", "banner", "help", "true", "false", "yes", "no", "ok", "done",
    "null", "none", "command", "session", "mkdir", "cat", "ps", "df",
})
_PUNCT_ONLY = re.compile(r"^[^A-Za-z0-9]+$")
_REPEATED_RUN = re.compile(r"^(.)\1{3,}$")


def _plausible_identity(text: str, limit: int) -> bool:
    """Whether a captured string could really be an account or hostname.

    Rejects separators (-----), repeated-character runs, and echoed shell
    commands. Deliberately permissive about *shape* — real accounts vary wildly
    — and strict only about the specific noise a shell transcript produces.
    """
    t = (text or "").strip()
    if not t or len(t) > limit:
        return False
    if _PUNCT_ONLY.match(t) or _REPEATED_RUN.match(t):
        return False
    if t.lower() in _SHELL_NOISE:
        return False
    return bool(re.search(r"[A-Za-z0-9]", t))

_HOST_PATTERNS = [
    re.compile(r"Computer\s*:\s*(\S+)", re.I),          # meterpreter sysinfo
    # `uname -a` output: "Linux <host> 2.6.24 ..." — the second field is the
    # hostname, and it is the most reliable source in a raw shell.
    re.compile(r"^(?:Linux|Darwin|FreeBSD|SunOS)\s+(\S+)\s", re.M),
    # A bare hostname on its own line, from `hostname`.
    re.compile(r"^([a-z0-9][a-z0-9.\-]{2,60})$", re.M | re.I),
]

# msfconsole prefixes status lines with [*]. Requiring it matters: without the
# prefix, any text merely *containing* the phrase — documentation, a target
# echoing input back, a pasted transcript — was parsed as a real session and
# produced a "remote code execution confirmed" finding for a shell that never
# existed. Claiming compromise that did not happen is the worst false positive
# this tool can produce.
_SESSION_OPENED = re.compile(
    r"^\s*\[[*+]\]\s.*?(Command shell|Meterpreter) session (\d+) opened",
    re.I | re.M)


@dataclass
class Proof:
    """What a session actually demonstrated."""
    session_id: Optional[str] = None
    session_type: str = ""
    user: str = ""
    host: str = ""
    is_root: bool = False
    transcript: str = ""
    commands: list = field(default_factory=list)

    @property
    def obtained(self) -> bool:
        return bool(self.session_id)

    @property
    def privilege(self) -> str:
        if not self.obtained:
            return "none"
        return "privileged" if self.is_root else "user"

    def summary(self) -> str:
        if not self.obtained:
            return "no session opened"
        who = self.user or "unknown user"
        where = f" on {self.host}" if self.host else ""
        level = "privileged (root/SYSTEM)" if self.is_root else "unprivileged"
        return f"{self.session_type or 'session'} as {who}{where} — {level}"


def proof_script(session_id: str, session_type: str) -> list[str]:
    """Resource-script lines that capture identity inside an open session.

    Meterpreter and a raw command shell need different syntax, so the caller
    passes the type msfconsole reported rather than guessing.
    """
    lines = [f"sessions -i {session_id}"]
    if session_type.lower().startswith("meterpreter"):
        for i, cmd in enumerate(METERPRETER_PROOF):
            lines.append(f"sessions -c 'echo {MARK}{i}' -i {session_id}")
            lines.append(f"sessions -c '{cmd}' -i {session_id}")
    else:
        for i, cmd in enumerate(UNIX_PROOF):
            lines.append(
                f"sessions -c 'echo {MARK}{i}; {cmd}' -i {session_id}")
    return lines


def build_proof_commands(session_type: str) -> list[str]:
    return (METERPRETER_PROOF
            if session_type.lower().startswith("meterpreter") else UNIX_PROOF)


def parse(output: str) -> Proof:
    """Read what the exploit achieved out of the msfconsole transcript."""
    output = output or ""
    p = Proof(transcript=safe_display(output, 8000))

    opened = _SESSION_OPENED.search(output)
    if opened:
        p.session_id = opened.group(2)
        p.session_type = ("meterpreter"
                          if "meterpreter" in opened.group(1).lower()
                          else "command shell")
    if not p.obtained:
        return p

    p.is_root = any(pat.search(output) for pat in _ROOT_PATTERNS)

    for pat in _USER_PATTERNS:
        matched = False
        for m in pat.finditer(output):
            candidate = m.group(1).strip()
            # Filter obvious msfconsole noise that a loose pattern would catch,
            # plus shell-transcript noise (separators, echoed commands) that a
            # real raw shell produces and a hand-written fixture never does.
            if (candidate
                    and candidate.lower() not in (
                        "msf", "exploit", "payload", "session", "started")
                    and not _IMPLAUSIBLE_USER.match(candidate)
                    and _plausible_identity(candidate, 32)):
                p.user = candidate[:64]
                matched = True
                break
        if matched:
            break
    if p.is_root and not p.user:
        p.user = "root"

    for pat in _HOST_PATTERNS:
        matched = False
        for m in pat.finditer(output):
            candidate = m.group(1).strip()
            if (candidate and not candidate.startswith("[")
                    and candidate.lower() != p.user.lower()
                    and _plausible_identity(candidate, 60)):
                p.host = candidate[:64]
                matched = True
                break
        if matched:
            break

    p.commands = build_proof_commands(p.session_type)
    return p


def to_finding(proof: Proof, candidate) -> Optional[dict]:
    """A finding recording what was actually obtained.

    Severity is critical for a privileged session and high otherwise, and
    confidence is always `confirmed` — this is the one place in Vision where
    that word is earned by demonstration rather than inference.
    """
    if not proof.obtained:
        return None
    if candidate is None:
        # A proof with no candidate cannot be tied to a target or module; there
        # is nothing safe to report. Return nothing rather than crash on
        # candidate.module — a real session with no candidate is a caller error,
        # not a finding.
        return None
    module = getattr(candidate.module, "fullname", "unknown module")
    return {
        "ip": candidate.rhost,
        "port": candidate.rport,
        "proto": "tcp",
        "title": ("Remote code execution confirmed — privileged session"
                  if proof.is_root
                  else "Remote code execution confirmed — user session"),
        "severity": "critical" if proof.is_root else "high",
        "confidence": "confirmed",
        "cves": list(getattr(candidate.module, "cves", []) or []),
        "source": f"exploit:{module}",
        "description": (
            f"An interactive {proof.session_type or 'session'} was obtained "
            f"against {candidate.rhost} using {module}. "
            f"{proof.summary()}. Identity was captured with read-only "
            "commands and the session was then closed."),
        "evidence": safe_display(proof.transcript, 4000),
        "remediation": (
            "Patch or remove the affected service. This is not a theoretical "
            "exposure — code execution was demonstrated and the resulting "
            "access is recorded above."),
        "exploited": True,
        "exploited_at": time.time(),
    }
