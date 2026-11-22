"""Scope enforcement.

This is deliberately the most paranoid file in the codebase. Every module call
and every exploit launch passes through `Scope.assert_in_scope()`. A parser
hallucinating an IP, a redirect pointing off-net, or an operator typo must not
be able to send a single packet outside the engagement boundary.

Denies win over allows, always.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from dataclasses import dataclass, field
from typing import Iterable, Union

IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class ScopeViolation(Exception):
    """Raised whenever anything tries to act on an out-of-scope target."""


def _parse_entry(entry: str) -> list[IPNet]:
    """Accepts: 10.0.0.5, 10.0.0.0/24, 10.0.0.1-10.0.0.50, 2001:db8::/32"""
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return []

    if "-" in entry and "/" not in entry:
        lo_s, hi_s = (p.strip() for p in entry.split("-", 1))
        lo = ipaddress.ip_address(lo_s)
        # allow shorthand "10.0.0.1-50"
        if "." not in hi_s and ":" not in hi_s:
            octets = lo_s.rsplit(".", 1)
            hi_s = f"{octets[0]}.{hi_s}"
        hi = ipaddress.ip_address(hi_s)
        if int(hi) < int(lo):
            raise ValueError(f"range end before start: {entry}")
        return list(ipaddress.summarize_address_range(lo, hi))

    return [ipaddress.ip_network(entry, strict=False)]


@dataclass
class Scope:
    allow: list[IPNet] = field(default_factory=list)
    deny: list[IPNet] = field(default_factory=list)
    allow_private_only: bool = False

    @classmethod
    def from_lists(
        cls,
        allow: Iterable[str],
        deny: Iterable[str] = (),
        allow_private_only: bool = False,
    ) -> "Scope":
        a: list[IPNet] = []
        d: list[IPNet] = []
        for e in allow:
            a.extend(_parse_entry(e))
        for e in deny:
            d.extend(_parse_entry(e))
        if not a:
            raise ValueError("scope requires at least one allow entry")
        return cls(allow=a, deny=d, allow_private_only=allow_private_only)

    @classmethod
    def from_file(cls, path: str, deny_path: str | None = None,
                  **kw) -> "Scope":
        """Load targets from a file, one entry per line.

        Accepts anything `from_lists` accepts — addresses, CIDR, ranges — with
        blank lines and `#` comments ignored so an operator can annotate the
        list, and commas or spaces treated as separators.

        A bad line is reported with its line number and skipped rather than
        failing the whole file: a typo on line 40 of a 200-host list should not
        cost you the other 199. The problems are kept on the scope so the
        caller can show them instead of silently narrowing the engagement.
        """
        allow, problems = cls._read_entries(path)
        deny: list[str] = []
        if deny_path:
            deny, deny_problems = cls._read_entries(deny_path)
            problems += [f"exclude file: {p}" for p in deny_problems]
        if not allow:
            detail = f" ({len(problems)} unusable line(s))" if problems else ""
            raise ValueError(f"no valid targets in {path}{detail}")
        scope = cls.from_lists(allow, deny, **kw)
        scope.load_problems = problems
        return scope

    @staticmethod
    def _read_entries(path: str) -> tuple[list[str], list[str]]:
        try:
            raw = Path(path).expanduser().read_text(errors="replace")
        except OSError as exc:
            raise ValueError(f"cannot read {path}: {exc}") from None
        entries, problems = [], []
        for lineno, line in enumerate(raw.splitlines(), 1):
            text = line.split("#", 1)[0].strip()
            if not text:
                continue
            for token in text.replace(",", " ").split():
                try:
                    _parse_entry(token)
                except ValueError as exc:
                    problems.append(f"line {lineno}: {token!r} — {exc}")
                else:
                    entries.append(token)
        return entries, problems

    def contains(self, target: str) -> bool:
        try:
            addr = ipaddress.ip_address(target.strip())
        except ValueError:
            return False  # hostnames must be resolved before scope check

        if self.allow_private_only and not (addr.is_private or addr.is_loopback):
            return False
        if any(addr in net for net in self.deny):
            return False
        return any(addr in net for net in self.allow)

    def assert_in_scope(self, target: str, action: str = "action") -> None:
        if not self.contains(target):
            raise ScopeViolation(
                f"BLOCKED: {action} against {target!r} — outside engagement scope"
            )

    @property
    def address_count(self) -> int:
        """Exactly how many addresses this scope permits. Shown before a scan
        so the operator can confirm the boundary rather than trust it."""
        return sum(n.num_addresses for n in self.allow) - sum(
            n.num_addresses for n in self.deny
            if any(n.subnet_of(a) for a in self.allow))

    def unreachable_entries(self) -> list[str]:
        """Allowed networks that `contains()` will nonetheless refuse.

        Under `--rfc1918-only` a public address can sit in the allow list and
        still never be scanned. Loading such a file used to look like success
        and then find nothing, which reads as a broken scan rather than a
        refused one.
        """
        if not self.allow_private_only:
            return []
        return [str(n) for n in self.allow if not n.is_private]

    def summary(self) -> str:
        parts = [f"allow={[str(n) for n in self.allow]}"]
        if self.deny:
            parts.append(f"deny={[str(n) for n in self.deny]}")
        if self.allow_private_only:
            parts.append("rfc1918-only")
        return " ".join(parts)
