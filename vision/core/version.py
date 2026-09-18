"""Version comparison.

Service versions were being compared as strings, which is wrong in ways that
silently produce bad findings:

    "2.3.10" < "2.3.4"   -> True   (10 sorts before 4)
    "10.0"   < "7.0"     -> True   (1 sorts before 7)

A VAPT report that claims a patched host is vulnerable costs the analyst their
credibility, so comparison here is numeric, with a defined answer for the messy
version strings real services emit: `2.3.4-Debian`, `7.2p2`, `1.0.2k-fips`,
`5.5.28-0ubuntu0.12`.
"""

from __future__ import annotations

import re
from functools import total_ordering

# Leading numeric run, then an optional alphanumeric tail we treat as a
# pre-release / patch-letter marker.
_NUM = re.compile(r"\d+")
_VERSION_CORE = re.compile(r"^[^\d]*(\d[\d.]*)(.*)$")

# Tails that mean "older than the plain release" (release candidates, betas).
_PRE_RELEASE = ("alpha", "beta", "rc", "pre", "dev", "snapshot", "a", "b")


@total_ordering
class Version:
    """A comparable version.

    Parsing is deliberately lenient: anything unparseable compares as unknown
    and is never claimed to be vulnerable. Silence beats a false positive.
    """

    __slots__ = ("raw", "parts", "tail", "valid")

    def __init__(self, raw: str | None):
        self.raw = (raw or "").strip()
        self.parts: tuple[int, ...] = ()
        self.tail: str = ""
        self.valid = False

        m = _VERSION_CORE.match(self.raw)
        if not m:
            return
        core, tail = m.group(1), m.group(2).lower()
        nums = [int(n) for n in core.split(".") if n.isdigit()]
        if not nums:
            return
        # OpenSSH-style "7.2p2": the patch letter carries ordering info.
        extra = _NUM.findall(tail)
        if tail and tail[0].isalpha() and extra:
            nums.extend(int(x) for x in extra[:1])
        self.parts = tuple(nums)
        self.tail = tail
        self.valid = True

    def _padded(self, n: int) -> tuple[int, ...]:
        return self.parts + (0,) * (n - len(self.parts))

    @property
    def _pre_rank(self) -> int:
        """Pre-release sorts below the plain release of the same number."""
        for marker in _PRE_RELEASE:
            if re.search(rf"[-_.]?{marker}\d*$", self.tail):
                return -1
        return 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            other = Version(str(other))
        if not (self.valid and other.valid):
            return self.raw == other.raw
        n = max(len(self.parts), len(other.parts))
        return (self._padded(n), self._pre_rank) == (other._padded(n), other._pre_rank)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            other = Version(str(other))
        if not (self.valid and other.valid):
            return False  # unknown never claims to be older
        n = max(len(self.parts), len(other.parts))
        return (self._padded(n), self._pre_rank) < (other._padded(n), other._pre_rank)

    def __repr__(self) -> str:
        return f"Version({self.raw!r})"

    def __str__(self) -> str:
        return self.raw

    def __bool__(self) -> bool:
        return self.valid

    def __hash__(self) -> int:
        return hash((self.parts, self._pre_rank))


def parse(raw: str | None) -> Version:
    return Version(raw)


def older_than(candidate: str | None, floor: str) -> bool:
    """True only when we can prove candidate < floor.

    Unparseable input returns False. A finding that says "this host is
    vulnerable" must be defensible; if we can't read the version we say
    nothing rather than guessing.
    """
    v = Version(candidate)
    return bool(v) and v < Version(floor)


def major_minor(raw: str | None) -> str:
    """First two components — what Exploit-DB and most advisories index on."""
    v = Version(raw)
    if not v:
        return ""
    return ".".join(str(p) for p in v.parts[:2])
