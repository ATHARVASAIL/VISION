"""Offline Metasploit module index.

Shelling out to `msfconsole -x "search cve:..."` costs ~20s of boot time per
lookup and is unusable inside a scan loop. Instead we parse the module source
tree once and cache it.

What we extract per module, and why:
  - full name        -> what the operator will `use`
  - Rank             -> MSF's own reliability estimate
  - CVE references   -> the join key against our findings
  - has `check`      -> module can VERIFY exploitability without exploiting.
                        This is the single most useful safety property and no
                        other tool surfaces it prominently.
  - destructive      -> DoS / memory-corruption / overwrite modules that can
                        take a production host down. Gated separately.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator, Optional

RANK_ORDER = {
    "Manual": 0,
    "Low": 1,
    "Average": 2,
    "Normal": 3,
    "Good": 4,
    "Great": 5,
    "Excellent": 6,
}

# MSF's on-disk directories are plural but the module namespace used by `use`
# is singular: modules/exploits/foo.rb  ->  use exploit/foo
DIR_TO_NAMESPACE = {
    "exploits": "exploit",
    "auxiliary": "auxiliary",
    "post": "post",
    "payloads": "payload",
    "encoders": "encoder",
    "nops": "nop",
    "evasion": "evasion",
}

DEFAULT_MSF_PATHS = [
    "/usr/share/metasploit-framework/modules",
    "/opt/metasploit-framework/embedded/framework/modules",
    "~/.msf4/modules",
]

_RE_RANK = re.compile(r"^\s*Rank\s*=\s*(\w+?)Ranking\s*$", re.M)
_RE_CVE = re.compile(r"""['"]CVE['"]\s*,\s*['"]([\d]{4}-[\d]{4,7})['"]""")
_RE_CVE_BARE = re.compile(r"\bCVE[-–](\d{4}-\d{4,7})\b", re.I)
_RE_NAME = re.compile(r"""['"]Name['"]\s*=>\s*['"](.+?)['"]""", re.S)
_RE_DISCLOSURE = re.compile(r"""['"]DisclosureDate['"]\s*=>\s*['"](.+?)['"]""")
_RE_CHECK = re.compile(r"^\s*def\s+check\b", re.M)
# A module can define `def check` and have that method simply return
# CheckCode::Unsupported — the method exists, so the naive regex above sees it,
# but at runtime msfconsole answers "This module does not support check." An
# advisory that labels such a module "verify-only / chk" is making a promise the
# module cannot keep: the operator runs check and gets an error, not a verdict.
# This pattern catches a check method whose body is only an Unsupported return.
_RE_CHECK_UNSUPPORTED = re.compile(
    r"def\s+check\b[^\n]*\n"          # the def line
    r"(?:\s*#[^\n]*\n)*"              # optional comment lines
    r"\s*(?:Exploit::)?(?:CheckCode::)?"
    r"(?:return\s+)?(?:Exploit::)?CheckCode::Unsupported",
    re.M)


def _module_has_usable_check(src: str) -> bool:
    """True only if the module defines a check method that is not a bare
    Unsupported stub. Mirrors what msfconsole will actually do at runtime, so
    the advisory's 'verifiable' claim matches reality."""
    if not _RE_CHECK.search(src):
        return False
    if _RE_CHECK_UNSUPPORTED.search(src):
        return False
    return True

_RE_PRIV = re.compile(r"""['"]Privileged['"]\s*=>\s*(true|false)""")
_RE_DESC = re.compile(r"""['"]Description['"]\s*=>\s*%q[{\[](.+?)[}\]]""", re.S)

# Signals that firing this module may knock the target over.
_DESTRUCTIVE_HINTS = (
    "denial of service", "denial-of-service", "crash the", "will crash",
    "reboot", "bluescreen", "blue screen", "kernel panic", "wipe",
    "overwrite the", "destroy", "bricks", "corrupt",
)

# Service families, used to keep a no-CVE fuzzy match honest. A finding on
# 3306 is a MySQL finding; a module living under modules/.../http/ is a web
# module. Matching the two on a shared product word (the WordPress-vs-MySQL
# bug) is a false lead. Names alone can't catch it — the structural fact is
# the port on one side and the module's own path segment on the other. Each
# family lists (a) the ports that speak it and (b) the path tokens Metasploit
# files it under. An unlisted port means "unknown family": we never *block*
# on unknown, only *prefer* a same-family match and flag a cross-family one.
_SERVICE_FAMILIES: dict[str, tuple[frozenset, frozenset]] = {
    "web":    (frozenset({80, 443, 591, 3000, 8000, 8008, 8080, 8081, 8443,
                          8888, 9000, 9090, 10000}),
               frozenset({"http", "https", "www"})),
    "ftp":    (frozenset({21, 2121}), frozenset({"ftp", "tftp"})),
    "ssh":    (frozenset({22}), frozenset({"ssh"})),
    "smtp":   (frozenset({25, 465, 587}), frozenset({"smtp"})),
    "dns":    (frozenset({53}), frozenset({"dns"})),
    "smb":    (frozenset({139, 445}), frozenset({"smb", "cifs", "netbios"})),
    "rpc":    (frozenset({111, 135}), frozenset({"dcerpc", "sunrpc", "msrpc"})),
    "snmp":   (frozenset({161}), frozenset({"snmp"})),
    "ldap":   (frozenset({389, 636}), frozenset({"ldap"})),
    "mysql":  (frozenset({3306}), frozenset({"mysql"})),
    "mssql":  (frozenset({1433}), frozenset({"mssql"})),
    "postgres": (frozenset({5432}), frozenset({"postgres", "postgresql"})),
    "oracle": (frozenset({1521}), frozenset({"oracle", "tns"})),
    "mongodb": (frozenset({27017}), frozenset({"mongodb"})),
    "redis":  (frozenset({6379}), frozenset({"redis"})),
    "rdp":    (frozenset({3389}), frozenset({"rdp"})),
    "vnc":    (frozenset({5900, 5901}), frozenset({"vnc"})),
    "telnet": (frozenset({23}), frozenset({"telnet"})),
    "nfs":    (frozenset({2049}), frozenset({"nfs"})),
    "irc":    (frozenset({6667, 6697}), frozenset({"irc"})),
    "sip":    (frozenset({5060, 5061}), frozenset({"sip"})),
}


def family_for_port(port):
    """Which service family speaks this port, if we recognise it."""
    if port is None:
        return None
    for fam, (ports, _tokens) in _SERVICE_FAMILIES.items():
        if port in ports:
            return fam
    return None


def _module_families(fullname: str) -> frozenset:
    """Which service families a module's own path places it in. May be more
    than one (a generic auxiliary) or none (family-neutral: a pure payload,
    or a scanner not tied to a protocol)."""
    segs = set(fullname.lower().split("/"))
    fams = set()
    for fam, (_ports, tokens) in _SERVICE_FAMILIES.items():
        if segs & tokens:
            fams.add(fam)
    return frozenset(fams)


# Platform tokens that appear as a path segment (exploit/windows/...) or in the
# module's Platform => field. Mapped to a normalised OS family so a module and a
# target can be compared. A CVE can be cross-platform (the same Apache flaw on
# Linux and Windows) while the *exploit module* for it is single-platform — so a
# precise CVE join can still hand the operator a Windows module for a Linux host.
_PLATFORM_TOKENS = {
    "windows": "windows", "win": "windows",
    "linux": "linux",
    "unix": "unix", "bsd": "unix", "solaris": "unix", "aix": "unix",
    "osx": "osx", "macos": "osx", "apple_ios": "osx",
    "android": "android",
}
_RE_PLATFORM = re.compile(
    r"""['"]?Platform['"]?\s*=>\s*(\[[^\]]*\]|['"][^'"]*['"])""", re.M)


def _module_platforms(fullname: str, src: str = "") -> frozenset:
    """The OS families a module targets, from its path and Platform field.

    Empty means platform-neutral or undeclared — a scanner, a protocol
    auxiliary, a pure payload — and must never be treated as a mismatch, only a
    concrete declared platform can conflict with a concrete target OS.
    'unix' and 'linux' are treated as compatible with each other, since a great
    many unix modules run fine on linux; 'windows' vs 'linux' is a hard clash.
    """
    plats = set()
    for seg in fullname.lower().split("/"):
        if seg in _PLATFORM_TOKENS:
            plats.add(_PLATFORM_TOKENS[seg])
    m = _RE_PLATFORM.search(src)
    if m:
        blob = m.group(1).lower()
        for tok, fam in _PLATFORM_TOKENS.items():
            if re.search(rf"\b{re.escape(tok)}\b", blob):
                plats.add(fam)
    return frozenset(plats)


# Product words that carry no discriminating signal — matching on them alone
# pulls in half the tree. Kept deliberately small: these are words nmap emits
# as a bare `product` often enough to matter.
_STOPWORD_TERMS = frozenset({
    "server", "service", "daemon", "http", "httpd", "ftpd", "sshd",
    "version", "unix", "linux", "windows", "microsoft", "open", "the",
})


@dataclass
class MsfModule:
    fullname: str                       # exploit/multi/mysql/mysql_authbypass_hashdump
    path: str
    name: str = ""                      # human title
    rank: str = "Normal"
    cves: list[str] = field(default_factory=list)
    disclosure_date: Optional[str] = None
    has_check: bool = False
    privileged: bool = False
    destructive: bool = False
    description: str = ""
    platforms: frozenset = field(default_factory=frozenset)

    @property
    def rank_score(self) -> int:
        return RANK_ORDER.get(self.rank, 3)

    @property
    def kind(self) -> str:
        return self.fullname.split("/", 1)[0]

    @property
    def is_dos(self) -> bool:
        return "/dos/" in self.fullname or self.fullname.startswith("auxiliary/dos")

    @property
    def families(self) -> frozenset:
        """Service families this module's path places it in (may be empty)."""
        return _module_families(self.fullname)


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _parse_module(path: Path, root: Path) -> Optional[MsfModule]:
    try:
        src = path.read_text(errors="replace")
    except OSError:
        return None

    rel = path.relative_to(root).with_suffix("").as_posix()
    head, _, tail = rel.partition("/")
    ns = DIR_TO_NAMESPACE.get(head)
    if ns is None:
        return None  # not a recognised module tree (docs, lib, etc.)
    rel = f"{ns}/{tail}" if tail else ns

    m_rank = _RE_RANK.search(src)
    rank = m_rank.group(1) if m_rank else "Normal"

    cves = sorted({f"CVE-{c}" for c in _RE_CVE.findall(src)})
    if not cves:
        cves = sorted({f"CVE-{c}" for c in _RE_CVE_BARE.findall(src)})

    m_name = _RE_NAME.search(src)
    m_desc = _RE_DESC.search(src)
    desc = _clean(m_desc.group(1))[:600] if m_desc else ""

    haystack = (desc + " " + (m_name.group(1) if m_name else "")).lower()
    # Scanners and gatherers describe what the *target* is vulnerable to, not
    # what the module does. Their descriptions routinely mention the target's
    # DoS/crash/overwrite characteristics (e.g. "enables password spraying"
    # or "allows remote code execution"). Flagging them destructive from
    # keywords would lock every scanner behind --allow-destructive, which is
    # wrong: a username enumerator is not a DoS module. Only exploit modules
    # (and modules whose own path marks them as DoS) earn the flag from
    # keywords.
    kind_is_destructive = rel.split("/")[0] == "exploit"
    path_dos = "/dos/" in rel or rel.startswith("auxiliary/dos")
    destructive = (kind_is_destructive or path_dos) and any(
        h in haystack for h in _DESTRUCTIVE_HINTS)

    m_priv = _RE_PRIV.search(src)
    m_disc = _RE_DISCLOSURE.search(src)

    mod = MsfModule(
        fullname=rel,
        path=str(path),
        name=_clean(m_name.group(1)) if m_name else path.stem,
        rank=rank,
        cves=cves,
        disclosure_date=m_disc.group(1) if m_disc else None,
        has_check=_module_has_usable_check(src),
        privileged=bool(m_priv and m_priv.group(1) == "true"),
        destructive=destructive,
        description=desc,
        platforms=_module_platforms(rel, src),
    )
    if mod.is_dos:
        mod.destructive = True
    return mod


def _walk(roots: list[Path]) -> Iterator[tuple[Path, Path]]:
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if fn.endswith(".rb"):
                    yield Path(dirpath) / fn, root


class MsfIndex:
    def __init__(self, modules: list[MsfModule] | None = None):
        self.modules: list[MsfModule] = modules or []
        self._by_cve: dict[str, list[MsfModule]] = {}
        self._reindex()

    def _reindex(self) -> None:
        self._by_cve.clear()
        for m in self.modules:
            for cve in m.cves:
                self._by_cve.setdefault(cve, []).append(m)

    # ---------- build / cache ----------

    @classmethod
    def build(cls, paths: list[str] | None = None) -> "MsfIndex":
        roots = [Path(p).expanduser() for p in (paths or DEFAULT_MSF_PATHS)]
        found = [r for r in roots if r.is_dir()]
        if not found:
            raise FileNotFoundError(
                "No Metasploit module tree found. Searched: "
                + ", ".join(str(r) for r in roots)
            )
        mods: list[MsfModule] = []
        for fpath, root in _walk(found):
            mod = _parse_module(fpath, root)
            if mod:
                mods.append(mod)
        return cls(mods)

    def save(self, path: str) -> None:
        def _serialisable(m: MsfModule) -> dict:
            d = asdict(m)
            # frozenset is not JSON-serialisable; store platforms as a sorted
            # list and rebuild the frozenset on load.
            d["platforms"] = sorted(m.platforms)
            return d
        payload = {
            "built_at": time.time(),
            "count": len(self.modules),
            "modules": [_serialisable(m) for m in self.modules],
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(payload))

    @classmethod
    def load(cls, path: str, max_age_days: int = 30) -> "MsfIndex":
        data = json.loads(Path(path).read_text())
        age = (time.time() - data.get("built_at", 0)) / 86400

        def _rebuild(m: dict) -> MsfModule:
            m = dict(m)
            if "platforms" in m:
                m["platforms"] = frozenset(m["platforms"])
            return MsfModule(**m)
        idx = cls([_rebuild(m) for m in data["modules"]])
        idx.stale = age > max_age_days
        return idx

    @classmethod
    def load_or_build(cls, cache: str, paths: list[str] | None = None) -> "MsfIndex":
        try:
            return cls.load(cache)
        except (OSError, ValueError, KeyError, TypeError):
            idx = cls.build(paths)
            idx.save(cache)
            return idx

    # ---------- query ----------

    def by_cve(self, cve: str) -> list[MsfModule]:
        return sorted(
            self._by_cve.get(cve.upper().strip(), []),
            key=lambda m: (-m.rank_score, m.destructive, m.fullname),
        )

    def by_cves(self, cves: list[str]) -> list[MsfModule]:
        seen: dict[str, MsfModule] = {}
        for c in cves:
            for m in self.by_cve(c):
                seen[m.fullname] = m
        return sorted(
            seen.values(), key=lambda m: (-m.rank_score, m.destructive, m.fullname)
        )

    def search(self, *terms: str, kind: str | None = None,
               port: int | None = None) -> list[MsfModule]:
        """Fallback for findings with no CVE — match on product/service words.

        Matches only the module's own name and path, never its description. A
        real run against Metasploitable matched WordPress and Pandora FMS
        exploits to a bare MySQL service on 3306, because both modules'
        descriptions mention storing credentials in MySQL — the search was
        finding the word "mysql" in prose about an unrelated product, not in
        the product this module actually targets.

        Two refinements on top of that, both aimed at fewer false leads and
        more real ones:

        * Each term is split into words and matched token-by-token, so a
          qualified product string like "Apache httpd 2.2.8 ((Ubuntu))" still
          finds the `apache` modules instead of silently matching nothing —
          the old whole-string `in` test required the module to contain the
          version and the OS too. Purely numeric/stopword tokens are ignored
          so we still match on something discriminating.
        * When `port` is given, its service family (3306 -> mysql, 445 -> smb,
          80 -> web ...) reorders results so same-family modules come first,
          and a module that belongs to a *different, known* family than the
          port is dropped: a `web` exploit has no business being offered for a
          finding on 3306. Modules with no family of their own (generic
          scanners, payloads) are never dropped — only demoted below in-family
          hits. An unrecognised port imposes no family constraint at all.
        """
        # A "term" may be a whole product string; split into discriminating
        # tokens. Fall back to the raw term if splitting leaves nothing.
        token_sets: list[list[str]] = []
        for t in terms:
            if not t:
                continue
            words = [w for w in re.split(r"[^a-z0-9]+", t.lower()) if w]
            keep = [w for w in words
                    if w not in _STOPWORD_TERMS and not w.isdigit()
                    and len(w) >= 2]
            token_sets.append(keep or [t.lower().strip()])
        needles = [tok for ts in token_sets for tok in ts]
        if not needles:
            return []

        want_family = family_for_port(port)
        out = []
        for m in self.modules:
            if kind and m.kind != kind:
                continue
            hay = f"{m.fullname} {m.name}".lower()
            if not all(n in hay for n in needles):
                continue
            fams = m.families
            # Drop a module that positively belongs to a *different* known
            # family than the port speaks. Never drop a family-neutral module.
            if want_family and fams and want_family not in fams:
                continue
            out.append(m)

        def _rank(m: MsfModule):
            in_family = bool(want_family and want_family in m.families)
            # same-family first, then MSF rank desc, then non-destructive,
            # then name for stability
            return (not in_family, -m.rank_score, m.destructive, m.fullname)

        return sorted(out, key=_rank)[:25]

    def __len__(self) -> int:
        return len(self.modules)
