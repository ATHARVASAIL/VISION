"""Credentials for authenticated assessment.

Most internal engagements hand you a domain account on day one, and an
unauthenticated-only tool throws that away. Authenticated enumeration finds a
different and larger class of problem — over-permissive shares, weak policy,
delegation, local admin sprawl — none of which is visible anonymously.

The hard rule in this module is that **a credential never reaches disk**. Not
the state file, not the run log, not the evidence directory, not the report.
Everything Vision writes is designed to be kept: state files survive a crash,
run logs get attached to reports, evidence is archived for months. A password
that leaks into any of them outlives the engagement it belonged to, and the
client never agreed to that.

So credentials live in memory for the life of the process and nowhere else:

  - entered interactively via getpass, never as an argv the process list shows
  - held in a Credential object whose repr and str are redacted
  - excluded from RunState entirely — the field does not exist, so it cannot
    be serialised by accident
  - passed to tools through a file descriptor or environment variable where
    the tool supports it, and redacted from the run log where it does not

`--user` is accepted on the command line; `--password` deliberately is not. A
password in argv is visible in `ps`, in shell history and in the parent
process's logs, none of which Vision controls.
"""

from __future__ import annotations

import getpass
import os
from dataclasses import dataclass, field
from typing import Optional

REDACTED = "«redacted»"


@dataclass
class Credential:
    """One set of credentials. Never serialised, never logged, never printed.

    `_secret` carries a leading underscore so that any well-meaning
    `asdict()` or `vars()` call downstream still produces something obviously
    private rather than a plausible-looking field.
    """
    username: str
    _secret: str = field(repr=False, default="")
    domain: str = ""
    kind: str = "password"          # password | nthash | kerberos

    # ---- deliberately unhelpful representations ----

    def __repr__(self) -> str:
        return f"Credential({self.display!r}, {self.kind}, secret={REDACTED})"

    def __str__(self) -> str:
        return self.display

    @property
    def display(self) -> str:
        """Safe to print anywhere: identity without the secret."""
        return f"{self.domain}\\{self.username}" if self.domain else self.username

    @property
    def secret(self) -> str:
        """The actual secret. Every call site that touches this is responsible
        for making sure the result does not reach disk."""
        return self._secret

    @property
    def is_hash(self) -> bool:
        return self.kind == "nthash"

    def __bool__(self) -> bool:
        return bool(self.username and self._secret)

    # ---- serialisation is refused, not merely avoided ----

    def __getstate__(self):
        raise TypeError(
            "Credential objects are deliberately not serialisable — a "
            "credential written to disk outlives the engagement")

    def as_dict(self) -> dict:
        """Identity only. There is no method that returns the secret in a
        serialisable form, because there is no reason to want one."""
        return {"username": self.username, "domain": self.domain,
                "kind": self.kind, "secret": REDACTED}


class CredentialStore:
    """In-memory credentials for the life of the process.

    Not a keyring, not a cache, not written anywhere. Closing Vision loses them,
    which is the correct behaviour for something the client lent you.
    """

    def __init__(self):
        self._creds: list[Credential] = []

    def add(self, cred: Credential) -> None:
        if not cred:
            raise ValueError("a credential needs both a username and a secret")
        self._creds = [c for c in self._creds
                       if not (c.username == cred.username
                               and c.domain == cred.domain)]
        self._creds.append(cred)

    def primary(self) -> Optional[Credential]:
        return self._creds[0] if self._creds else None

    def all(self) -> list[Credential]:
        return list(self._creds)

    def clear(self) -> None:
        for c in self._creds:
            # Overwrite before dropping the reference. Python strings are
            # immutable so this is not a guarantee, only a reduction in the
            # window — worth doing, not worth trusting.
            object.__setattr__(c, "_secret", "")
        self._creds.clear()

    def __len__(self) -> int:
        return len(self._creds)

    def __bool__(self) -> bool:
        return bool(self._creds)

    def summary(self) -> str:
        if not self._creds:
            return "none — running unauthenticated"
        return ", ".join(c.display for c in self._creds)


def prompt(username: str = "", domain: str = "",
           kind: str = "password") -> Optional[Credential]:
    """Collect a credential without it appearing in argv or shell history."""
    try:
        username = username or input("  username> ").strip()
        if not username:
            return None
        domain = domain or input("  domain (blank for local)> ").strip()
        label = "NT hash" if kind == "nthash" else "password"
        # getpass reads from the tty with echo off and never touches argv.
        secret = getpass.getpass(f"  {label} (not echoed, never written)> ")
        if not secret:
            return None
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return Credential(username=username, _secret=secret, domain=domain, kind=kind)


def nxc_args(cred: Optional[Credential]) -> list[str]:
    """netexec arguments for a credential, or the null session when there is
    none. The secret appears in argv here because netexec offers no file or
    environment alternative — which is exactly why `redact()` in runlog.py
    strips it before anything is written."""
    if not cred:
        return ["-u", "", "-p", ""]
    args = ["-u", cred.username]
    args += ["-H", cred.secret] if cred.is_hash else ["-p", cred.secret]
    if cred.domain:
        args += ["-d", cred.domain]
    return args


def smb_env(cred: Optional[Credential]) -> dict:
    """Environment for smbclient and friends, which read USER and PASSWD
    rather than requiring the secret on the command line. Preferred wherever
    the tool supports it: an environment variable is not in `ps` output."""
    env = dict(os.environ)
    if cred and not cred.is_hash:
        env["USER"] = cred.username
        env["PASSWD"] = cred.secret
        if cred.domain:
            env["DOMAIN"] = cred.domain
    return env


def impacket_target(cred: Optional[Credential], host: str) -> str:
    """impacket's DOMAIN/USER:PASS@HOST form. Callers must pass the result
    through redact() before logging it."""
    if not cred:
        return host
    prefix = f"{cred.domain}/" if cred.domain else ""
    return f"{prefix}{cred.username}:{cred.secret}@{host}"
