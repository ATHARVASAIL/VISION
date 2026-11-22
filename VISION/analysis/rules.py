"""User-defined rules.

Every engagement has checks that matter to that client and nobody else — a
legacy appliance, an internal service, a naming convention that signals a
deprecated build. Requiring a Python edit for those means they never get
written, so rules can be declared in a file instead.

Rules load from `~/.vision/rules/` or a path given with `--rules`. JSON always
works; YAML is used when PyYAML is installed, since it's easier to hand-write
but is not worth a hard dependency for a tool that has none.

The loader is deliberately restrictive: rule files describe *patterns*, never
code. There is no `eval`, no import hook, and no callable field. A rule file is
data that Vision interprets, so a malicious or mistaken rule can produce a wrong
finding but cannot execute anything.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from ..core.safety import safe_display

DEFAULT_RULES_DIR = "~/.vision/rules"

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_SCOPES = {"host", "network"}

# A rule file is untrusted input like anything else on disk. Cap the pattern
# length so a pathological regex can't be smuggled in, and cap file size so a
# huge file can't exhaust memory during load.
MAX_PATTERN = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_RULES_PER_FILE = 500


class RuleError(ValueError):
    """A rule file is malformed. Always names the file and the problem."""


@dataclass
class LoadResult:
    chains: list = None
    errors: list[str] = None

    def __post_init__(self):
        self.chains = self.chains or []
        self.errors = self.errors or []


def _read(path: Path) -> Any:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise RuleError(f"{path.name}: larger than {MAX_FILE_BYTES} bytes")
    text = path.read_text(errors="replace")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:
            raise RuleError(
                f"{path.name}: YAML rules need PyYAML (pip install pyyaml), "
                "or convert the file to JSON") from exc
        # safe_load never constructs arbitrary Python objects.
        return yaml.safe_load(text)
    return json.loads(text)


def _require(obj: dict, key: str, path: Path, kind: type = str) -> Any:
    if key not in obj:
        raise RuleError(f"{path.name}: rule is missing required field '{key}'")
    value = obj[key]
    if not isinstance(value, kind):
        raise RuleError(f"{path.name}: field '{key}' should be "
                        f"{kind.__name__}, got {type(value).__name__}")
    return value


def _compile(pattern: str, path: Path) -> re.Pattern:
    if len(pattern) > MAX_PATTERN:
        raise RuleError(f"{path.name}: pattern longer than {MAX_PATTERN} chars")
    try:
        return re.compile(pattern, re.I)
    except re.error as exc:
        raise RuleError(f"{path.name}: invalid pattern {pattern!r} — {exc}") from exc


def _build_chain(raw: dict, path: Path):
    """Turn a declarative rule into a ChainRule."""
    from .correlate import ChainRule, Step, title_matches, has_cve, on_port, any_of

    rule_id = _require(raw, "id", path)
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", rule_id):
        raise RuleError(f"{path.name}: id {rule_id!r} must be lowercase "
                        "alphanumeric with . _ or -")

    severity = raw.get("severity", "medium")
    if severity not in VALID_SEVERITIES:
        raise RuleError(f"{path.name}: severity {severity!r} must be one of "
                        f"{sorted(VALID_SEVERITIES)}")
    scope = raw.get("scope", "host")
    if scope not in VALID_SCOPES:
        raise RuleError(f"{path.name}: scope {scope!r} must be host or network")

    raw_steps = _require(raw, "steps", path, list)
    if not raw_steps:
        raise RuleError(f"{path.name}: rule {rule_id!r} has no steps")

    steps = []
    for i, rs in enumerate(raw_steps, 1):
        if not isinstance(rs, dict):
            raise RuleError(f"{path.name}: step {i} of {rule_id!r} is not a mapping")
        label = rs.get("label") or f"step {i}"
        predicates = []
        if "title" in rs:
            rx = _compile(str(rs["title"]), path)
            predicates.append(title_matches(rx.pattern))
        if "cve" in rs:
            cves = rs["cve"] if isinstance(rs["cve"], list) else [rs["cve"]]
            predicates.append(has_cve(*[str(c) for c in cves]))
        if "port" in rs:
            ports = rs["port"] if isinstance(rs["port"], list) else [rs["port"]]
            try:
                predicates.append(on_port(*[int(p) for p in ports]))
            except (TypeError, ValueError) as exc:
                raise RuleError(f"{path.name}: step {i} of {rule_id!r} has a "
                                f"non-numeric port") from exc
        if not predicates:
            raise RuleError(f"{path.name}: step {i} of {rule_id!r} needs at "
                            "least one of: title, cve, port")

        # Within a step, multiple criteria are alternatives — "this OR that
        # indicates the precondition" is what rule authors mean in practice.
        match = predicates[0] if len(predicates) == 1 else any_of(*predicates)
        steps.append(Step(str(label), match,
                          load_bearing=bool(rs.get("load_bearing", True))))

    return ChainRule(
        id=rule_id,
        name=str(raw.get("name") or rule_id),
        outcome=str(raw.get("outcome") or "Impact not described by the rule"),
        severity=severity,
        steps=tuple(steps),
        narrative=safe_display(raw.get("narrative")
                               or "No narrative supplied by the rule author.", 2000),
        remediation=safe_display(raw.get("remediation")
                                 or "No remediation supplied by the rule author.", 2000),
        scope=scope,
        references=tuple(str(r) for r in (raw.get("references") or [])
                         if str(r).startswith("https://")),
    )


def load_file(path: Path | str) -> LoadResult:
    path = Path(path).expanduser()
    result = LoadResult()
    try:
        data = _read(path)
    except (OSError, json.JSONDecodeError, RuleError) as exc:
        result.errors.append(str(exc) if isinstance(exc, RuleError)
                             else f"{path.name}: {exc}")
        return result

    raw_rules = data.get("chains", data) if isinstance(data, dict) else data
    if not isinstance(raw_rules, list):
        result.errors.append(f"{path.name}: expected a list of chains")
        return result
    if len(raw_rules) > MAX_RULES_PER_FILE:
        result.errors.append(f"{path.name}: more than {MAX_RULES_PER_FILE} rules")
        return result

    for raw in raw_rules:
        if not isinstance(raw, dict):
            result.errors.append(f"{path.name}: entry is not a mapping")
            continue
        try:
            result.chains.append(_build_chain(raw, path))
        except RuleError as exc:
            # One bad rule must not discard the rest of the file.
            result.errors.append(str(exc))
    return result


def load_dir(directory: Path | str = DEFAULT_RULES_DIR) -> LoadResult:
    directory = Path(directory).expanduser()
    result = LoadResult()
    if not directory.is_dir():
        return result
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() not in (".json", ".yaml", ".yml"):
            continue
        sub = load_file(path)
        result.chains.extend(sub.chains)
        result.errors.extend(sub.errors)
    return result


def all_chains(extra: Iterable[str] = ()) -> tuple[list, list[str]]:
    """Built-in chains plus any user rules. User rules with a colliding id
    replace the built-in, so a team can correct a shipped rule without
    forking."""
    from .correlate import CHAINS

    result = load_dir()
    for path in extra:
        sub = load_file(path)
        result.chains.extend(sub.chains)
        result.errors.extend(sub.errors)

    by_id = {c.id: c for c in CHAINS}
    for custom in result.chains:
        by_id[custom.id] = custom
    return list(by_id.values()), result.errors


EXAMPLE_RULE = {
    "chains": [
        {
            "id": "example.legacy-appliance",
            "name": "Legacy appliance with a management interface exposed",
            "outcome": "Administrative access to an unsupported device",
            "severity": "high",
            "scope": "host",
            "steps": [
                {"label": "Unsupported firmware identified",
                 "title": "Outdated .*(ApplianceOS|LegacyFW)"},
                {"label": "Management interface reachable",
                 "port": [443, 8443, 10000],
                 "load_bearing": False}
            ],
            "narrative": "The appliance runs firmware the vendor no longer "
                         "patches, and its management interface is reachable "
                         "from the assessed network.",
            "remediation": "Replace the appliance or move its management "
                           "interface onto an isolated network.",
            "references": ["https://attack.mitre.org/techniques/T1133/"]
        }
    ]
}
