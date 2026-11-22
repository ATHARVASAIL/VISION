"""Unified schema. Every parser (nmap, nuclei, smbmap, testssl...) normalizes
into these two types — `Service` for what is listening, `Finding` for what is
wrong with it. Live hosts are tracked as plain addresses in `RunState`, so
there is no separate host record to keep in sync. This is the contract that keeps the tool from becoming a pile
of format-specific special cases."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Confidence(str, Enum):
    """How sure are we the finding is real? Version-banner guesses are not the
    same as a module `check` returning Vulnerable."""
    TENTATIVE = "tentative"      # banner/version inference only
    FIRM = "firm"                # active check by a scanner
    CONFIRMED = "confirmed"      # verified (e.g. msf check said Vulnerable)


class Proto(str, Enum):
    TCP = "tcp"
    UDP = "udp"


@dataclass
class Service:
    ip: str
    port: int
    proto: Proto = Proto.TCP
    state: str = "open"
    name: Optional[str] = None          # "mysql", "http", "microsoft-ds"
    product: Optional[str] = None       # "MySQL"
    version: Optional[str] = None       # "5.5.28"
    extrainfo: Optional[str] = None
    cpe: list[str] = field(default_factory=list)
    tunnel: Optional[str] = None        # "ssl"
    banner: Optional[str] = None
    source: str = "unknown"             # which module produced this
    first_seen: str = field(default_factory=_utcnow)

    @property
    def key(self) -> str:
        return f"{self.ip}:{self.port}/{self.proto.value}"

    @property
    def product_version(self) -> Optional[str]:
        if self.product and self.version:
            return f"{self.product} {self.version}"
        return self.product


@dataclass
class Finding:
    """A single normalized issue. `fingerprint` dedupes across tools that both
    report the same thing (nmap NSE and nuclei will overlap constantly)."""
    ip: str
    title: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.TENTATIVE
    port: Optional[int] = None
    proto: Optional[Proto] = None
    description: str = ""
    cves: list[str] = field(default_factory=list)
    cvss: Optional[float] = None
    cvss_vector: Optional[str] = None
    references: list[str] = field(default_factory=list)
    evidence: str = ""
    remediation: str = ""
    source: str = "unknown"
    raw: dict[str, Any] = field(default_factory=dict)
    discovered_at: str = field(default_factory=_utcnow)

    def __post_init__(self) -> None:
        self.cves = sorted({c.upper().strip() for c in self.cves if c})
        # A CVSS vector is a stronger statement than a bare score: it carries
        # the reasoning. When one is supplied and parses, let it set the score
        # (and thus the severity) so the three never disagree. A malformed
        # vector is dropped rather than trusted — see cvss.try_parse.
        if self.cvss_vector:
            from ..analysis.cvss import try_parse
            _c = try_parse(self.cvss_vector)
            if _c is not None:
                self.cvss_vector = _c.vector      # canonicalised
                if self.cvss is None:
                    self.cvss = _c.base_score
            else:
                self.cvss_vector = None           # do not carry a bad vector
        if self.cvss is not None and self.severity is Severity.INFO:
            self.severity = Severity.from_cvss(self.cvss)

    @property
    def fingerprint(self) -> str:
        basis = "|".join([
            self.ip,
            str(self.port or ""),
            (self.proto.value if self.proto else ""),
            ",".join(self.cves) or self.title.lower().strip(),
        ])
        return hashlib.sha256(basis.encode()).hexdigest()[:16]


def to_json(obj: Any) -> str:
    def _enc(o: Any) -> Any:
        if isinstance(o, Enum):
            return o.value
        if hasattr(o, "__dataclass_fields__"):
            return asdict(o)
        raise TypeError(f"not serializable: {type(o)}")

    return json.dumps(obj, default=_enc, indent=2)
