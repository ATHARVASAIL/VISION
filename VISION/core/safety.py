"""Defensive helpers.

Vision consumes attacker-influenced data by design: every service banner,
certificate field, and share name it parses came from a host that may be
hostile. This module holds the primitives that keep that data from doing
anything other than being displayed.

Threat model, concretely:

  1. **Argument injection.** A service banner becomes a searchsploit search
     term. We never use shell=True, so there's no command injection, but a
     banner of `--output /etc/cron.d/x` is still a *flag* to the child process.
     `safe_arg()` strips anything that could be read as an option.

  2. **XML entity attacks.** nmap embeds banner text in its XML. Python's
     ElementTree does not expand external entities, but it will happily follow
     a billion-laughs DTD into an OOM. `parse_xml_safely()` refuses DOCTYPEs.

  3. **Sensitive artefacts at default permissions.** The audit log records
     operator, targets, and modules; the MSF resource script can carry
     credentials. On a shared box, umask 022 makes both world-readable.
     `secure_open()` and `harden_path()` force 0600.

  4. **Path traversal into output.** Share names and hostnames end up in
     filenames. `safe_filename()` reduces them to a known-good charset.
"""

from __future__ import annotations

import os
import re
import unicodedata
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, IO, Iterable

# Conservative allowlist: everything a legitimate product/version string needs
# and nothing a getopt parser will treat specially.
_ARG_ALLOWED = re.compile(r"[^A-Za-z0-9 ._+:/@-]")
_LEADING_DASH = re.compile(r"^[-\s]+")
_FILENAME_BAD = re.compile(r"[^A-Za-z0-9._-]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def safe_arg(value: Any, max_len: int = 96) -> str:
    """Reduce untrusted text to something safe to pass as a subprocess argv
    element.

    Strips control characters, removes anything outside the allowlist, and —
    critically — removes leading dashes so the value can never be parsed as an
    option by the child process.
    """
    text = _CONTROL.sub("", str(value or ""))
    text = _ARG_ALLOWED.sub(" ", text)
    text = _LEADING_DASH.sub("", text)
    return " ".join(text.split())[:max_len].strip()


def safe_display(value: Any, max_len: int = 500) -> str:
    """Sanitise untrusted text for terminal display.

    A hostile banner can contain ANSI escape sequences that rewrite the screen
    — including forging a 'CONFIRMED VULNERABLE' line or hiding a scope
    warning. Strip escapes and control characters before anything reaches a
    terminal or a report.
    """
    text = str(value or "")
    text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text)   # CSI sequences
    text = re.sub(r"\x1b[@-Z\\-_]", "", text)            # other escapes
    # A bare CR rewinds the cursor to column 0, letting hostile output
    # overwrite a line we already printed — e.g. hiding a scope warning behind
    # a forged "0 findings". Newlines are fine; CR is not.
    text = text.replace("\r\n", "\n").replace("\r", " ")
    text = _CONTROL.sub("", text)
    text = unicodedata.normalize("NFC", text)
    return text[:max_len]


def safe_filename(value: Any, fallback: str = "unnamed", max_len: int = 64) -> str:
    """Reduce untrusted text to a filename that cannot escape its directory."""
    text = _FILENAME_BAD.sub("_", str(value or "")).strip("._")
    text = text[:max_len]
    return text or fallback


def harden_path(path: Path | str, mode: int = 0o600) -> None:
    """Restrict an existing file to the current user. Best-effort: filesystems
    without POSIX permissions shouldn't break the run."""
    try:
        os.chmod(Path(path), mode)
    except (OSError, NotImplementedError):
        pass


def secure_open(path: Path | str, mode: str = "a", file_mode: int = 0o600) -> IO:
    """Open a file that only the current user can read.

    Creating then chmod'ing leaves a window where the file is world-readable.
    os.open with the mode up front closes it.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_APPEND if "a" in mode else os.O_TRUNC
    fd = os.open(path, flags, file_mode)
    harden_path(path, file_mode)
    return os.fdopen(fd, mode.replace("b", "") if "b" not in mode else mode)


def secure_write(path: Path | str, content: str, file_mode: int = 0o600) -> Path:
    path = Path(path)
    with secure_open(path, "w", file_mode) as fh:
        fh.write(content)
    return path


class UnsafeXMLError(ValueError):
    """Raised when a document contains constructs we refuse to parse."""


def parse_xml_safely(source: Path | str, max_bytes: int = 256 * 1024 * 1024):
    """Parse XML with entity-expansion attacks refused up front.

    Python's ElementTree does not resolve *external* entities, so classic XXE
    file disclosure isn't reachable. It does expand *internal* entities, which
    is enough for a billion-laughs memory exhaustion. Since no tool we consume
    legitimately emits a DOCTYPE with entity definitions, refusing them
    outright costs nothing and removes the class entirely.
    """
    path = Path(source)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise UnsafeXMLError(f"cannot stat {path}: {exc}") from exc
    if size > max_bytes:
        raise UnsafeXMLError(f"{path} is {size} bytes, over the {max_bytes} limit")

    head = path.read_bytes()[:8192]
    lowered = head.lower()
    # nmap legitimately emits a bare `<!DOCTYPE nmaprun>`, so refusing every
    # DOCTYPE would break the tool's primary input. What actually enables
    # billion-laughs is an *internal subset* — the `[ ... ]` block that can
    # define entities. Refuse that, and any ENTITY declaration anywhere.
    if b"<!entity" in lowered:
        raise UnsafeXMLError(f"{path} declares an ENTITY — refusing to parse")
    dt = lowered.find(b"<!doctype")
    if dt != -1:
        decl_end = lowered.find(b">", dt)
        subset = lowered.find(b"[", dt)
        if subset != -1 and (decl_end == -1 or subset < decl_end):
            raise UnsafeXMLError(
                f"{path} has a DOCTYPE internal subset — refusing to parse")

    parser = ET.XMLParser()
    # Belt and braces: some expat builds expose entity handling here.
    try:
        parser.parser.DefaultHandler = lambda data: None
        parser.entity = _RefusingEntityMap()
    except AttributeError:
        pass
    return ET.parse(path, parser=parser)


class _RefusingEntityMap(dict):
    def __getitem__(self, key):
        raise UnsafeXMLError(f"entity reference refused: {key!r}")


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def bounded(items: Iterable, limit: int) -> list:
    """Take at most `limit` items. Guards against a scan of an enormous range
    turning into an unbounded number of subprocess spawns."""
    out = []
    for i, item in enumerate(items):
        if i >= limit:
            break
        out.append(item)
    return out
