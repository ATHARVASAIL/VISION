"""Terminal presentation.

Zero dependencies — vision runs on stripped engagement boxes and jump hosts
where you can't pip install rich. Everything here is plain ANSI, degrades to
clean text when piped, and respects NO_COLOR.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from typing import Iterable, Optional

_FORCE = os.environ.get("VISION_COLOR", "").lower() in ("1", "always", "true")
_NEVER = bool(os.environ.get("NO_COLOR")) or \
    os.environ.get("VISION_COLOR", "").lower() in ("0", "never", "false")


def color_enabled(stream=None) -> bool:
    if _NEVER:
        return False
    if _FORCE:
        return True
    s = stream or sys.stdout
    return hasattr(s, "isatty") and s.isatty()


class S:
    """Palette: an arc-reactor HUD.

    Cyan is the reactor glow and carries anything live or in progress. Gold is
    the armour and marks what the operator must read — targets, headings,
    values. Crimson is reserved strictly for danger: critical findings and
    blocked actions, nothing else, so it never loses its meaning.

    All 256-colour codes rather than truecolor: these render correctly over
    SSH to a jump host and in tmux, which is where this actually runs.
    """
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"; ITALIC = "\033[3m"

    # Severity and status
    RED = "\033[38;5;196m"       # repulsor crimson — danger only
    GREEN = "\033[38;5;83m"      # systems nominal
    YELLOW = "\033[38;5;220m"    # caution
    BLUE = "\033[38;5;75m"
    MAGENTA = "\033[38;5;177m"
    CYAN = "\033[38;5;51m"       # arc reactor — live, in progress
    ORANGE = "\033[38;5;208m"
    GREY = "\033[38;5;245m"
    WHITE = "\033[38;5;255m"

    # HUD identity
    ACCENT = "\033[38;5;45m"     # reactor cyan, primary chrome
    GOLD = "\033[38;5;214m"      # armour gold, secondary chrome
    STEEL = "\033[38;5;250m"     # hot-rod plating, structural lines


def paint(text: str, *styles: str) -> str:
    if not color_enabled() or not styles:
        return text
    return "".join(styles) + text + S.RESET


def width(default: int = 100) -> int:
    try:
        return min(shutil.get_terminal_size().columns, 120)
    except OSError:
        return default


# ---------------------------------------------------------------- banner

BANNER = r"""
    ██╗   ██╗ ██╗███████╗ ██╗ ██████╗ ███╗   ██╗
    ██║   ██║ ██║██╔════╝ ██║██╔═══██╗████╗  ██║
    ╚██╗ ██╔╝ ██║███████╗ ██║██║   ██║██╔██╗ ██║
     ╚████╔╝  ██║╚════██║ ██║╚██████╔╝██║╚██╗██║
      ╚═══╝   ╚═╝███████║ ╚═╝ ╚═════╝ ██║ ╚████║
"""

TAGLINE = "network vapt orchestration · verify before you fire"


def banner(version: str = "0.1.0", compact: bool = False) -> str:
    if compact or width() < 48:
        return (paint("◈ ", S.ACCENT) + paint("VISION", S.BOLD, S.GOLD)
                + paint(f" v{version}", S.GREY))

    w = min(width(), 78)
    # Two-tone wordmark: the solid blocks read as armour plating in gold, the
    # box-drawing edges as the cyan glow behind it. Colouring the whole thing
    # one shade flattens it into a wall of text.
    lines = []
    for row in BANNER.strip("\n").split("\n"):
        out = ""
        for ch in row:
            if ch in "█":
                out += paint(ch, S.GOLD)
            elif ch in "╗╔╝╚═║":
                out += paint(ch, S.ACCENT)
            else:
                out += ch
        lines.append(out)

    rule = paint("─" * w, S.STEEL)
    out = "\n" + "\n".join(lines) + "\n"
    out += "  " + paint("◈", S.ACCENT) + " " + paint(TAGLINE, S.GREY)
    out += paint(f"   v{version}", S.DIM) + "\n"
    out += "  " + rule + "\n"
    return out


# ---------------------------------------------------------------- console voice
#
# The interactive console is the operator's cockpit and reads like one. The
# report is the client's document and does not — findings, severities and
# remediation stay in plain professional language, because a deliverable that
# says "HOSTILE CONTACT" instead of "unauthenticated Redis instance" is worse
# at its job. The flavour stops at the terminal.

BOOT_LINES = [
    ("scope containment", "engagement boundary armed"),
    ("sensor array", "toolchain resolved"),
    ("payload interlocks", "exploit gates engaged"),
    ("flight recorder", "run log open"),
]

PHASE_CALLSIGN = {
    "Reconnaissance": "SWEEP",
    "Service Enumeration": "SCAN",
    "Deep Enumeration": "PROBE",
    "Authenticated Assessment": "KEYED",
    "Web Assessment": "SURFACE",
    "Vulnerability Assessment": "ANALYSIS",
}


def callsign(phase_title: str) -> str:
    """Short mission-log tag for a phase. Cosmetic; never used in a report."""
    return PHASE_CALLSIGN.get(phase_title, "PHASE")


def boot_sequence() -> str:
    """Systems check shown once at console start."""
    w = min(width(), 78)
    out = [paint("  ┌" + "─" * (w - 4) + "┐", S.STEEL)]
    for system, state in BOOT_LINES:
        out.append(
            paint("  │ ", S.STEEL)
            + paint("◈ ", S.ACCENT)
            + paint(f"{system:<22}", S.GOLD)
            + paint(state, S.GREEN)
            + paint("".ljust(max(0, w - 30 - len(state))) + "│", S.STEEL))
    out.append(paint("  └" + "─" * (w - 4) + "┘", S.STEEL))
    return "\n".join(out)


# ---------------------------------------------------------------- structure

def rule(char: str = "─", label: str = "") -> str:
    w = width()
    if not label:
        return paint(char * w, S.GREY)
    head = f"{char * 2} {label} "
    return paint(head + char * max(0, w - len(head)), S.GREY)


def phase_header(index: int, total: int, title: str, subtitle: str = "") -> str:
    """Phase banner with a mission-log callsign — console only."""
    tag = callsign(title)
    w = max(0, min(width(), 78))
    out = "\n" + paint("╭─◈ ", S.ACCENT) + paint(tag, S.BOLD, S.GOLD)
    out += paint(f"  [{index}/{total}]  ", S.DIM) + paint(title, S.BOLD, S.WHITE)
    if subtitle:
        out += "\n" + paint("│   ", S.ACCENT) + paint(subtitle, S.GREY)
    out += "\n" + paint("╰" + "─" * (w - 1), S.STEEL)
    return out


def section(title: str, subtitle: str = "") -> str:
    out = "\n" + paint("◈ ", S.ACCENT) + paint(title, S.BOLD, S.GOLD)
    if subtitle:
        out += paint(f"   {subtitle}", S.GREY)
    return out + "\n" + paint("─" * min(width(), 78), S.STEEL)


def box(lines: Iterable[str], title: str = "", style: str = S.GREY) -> str:
    lines = list(lines)
    inner = max([_vislen(l) for l in lines] + [_vislen(title) + 2, 20])
    inner = min(inner, width() - 4)
    top = f"╭─ {title} " + "─" * max(0, inner - _vislen(title) - 1) + "╮" \
        if title else "╭" + "─" * (inner + 2) + "╮"
    out = [paint(top, style)]
    for l in lines:
        pad = " " * max(0, inner - _vislen(l))
        out.append(paint("│ ", style) + l + pad + paint(" │", style))
    out.append(paint("╰" + "─" * (inner + 2) + "╯", style))
    return "\n".join(out)


def _vislen(s: str) -> int:
    """Length excluding ANSI escapes and accounting for wide glyphs."""
    import re
    plain = re.sub(r"\033\[[0-9;]*m", "", s)
    extra = sum(1 for c in plain if ord(c) > 0x2500 and c not in "─│╭╮╰╯▸")
    return len(plain) + extra


# ---------------------------------------------------------------- messages

def ok(msg: str) -> str:      return paint("  ✓ ", S.GREEN) + msg
def bad(msg: str) -> str:     return paint("  ✗ ", S.RED) + msg
def warn(msg: str) -> str:    return paint("  ! ", S.YELLOW) + msg
def info(msg: str) -> str:    return paint("  · ", S.BLUE) + msg
def lock(msg: str) -> str:    return paint("  🔒 ", S.RED) + msg
def step(n: int, total: int, msg: str) -> str:
    return (paint("  ▸ ", S.ACCENT) + paint(f"[{n}/{total}] ", S.GOLD) + msg)


def kv(label: str, value: str, width_: int = 13) -> str:
    """Aligned label/value line. Used everywhere a panel shows detail."""
    return paint(f"  {label.ljust(width_)}", S.GREY) + value


def progress_line(done: int, total: int, elapsed: float, w: int = 30,
                  unit: str = "stages") -> str:
    """Overall progress with percentage and a projected remaining time.

    The estimate is a linear projection from stages already finished, which is
    rough — stages differ wildly in cost. It is labelled `~` for that reason;
    an operator wants to know whether to wait or go for coffee, not a contract.
    """
    if total <= 0:
        return ""
    pct = done / total
    filled = round(w * pct)
    bar_ = paint("━" * filled, S.ACCENT) + paint("━" * (w - filled), S.GREY)
    out = f"  {bar_} {paint(f'{pct * 100:3.0f}%', S.BOLD, S.WHITE)}"
    out += paint(f"  {done}/{total} {unit}", S.DIM)
    out += paint(f"  ·  {_dur(elapsed)} elapsed", S.DIM)
    if 0 < done < total and elapsed > 2:
        out += paint(f"  ·  ~{_dur(elapsed / done * (total - done))} left", S.DIM)
    return out


def _dur(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


def command_line(argv: list[str], width_limit: int = 0) -> str:
    """Render a command the way the operator would type it.

    Shown during the scan because a tool that hides what it runs cannot be
    audited by the person responsible for it — and because reading the actual
    nmap invocation is how an analyst learns what the tool is doing.
    """
    import shlex
    text = " ".join(shlex.quote(a) for a in argv)
    limit = width_limit or max(40, width() - 8)
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return paint("    $ ", S.GREEN) + paint(text, S.GREY)


def progress(done: int, total: int, w: int = 26) -> str:
    """A filled bar plus counts. Shown while phases run so the operator can see
    how much of the assessment is left, not just which stage is current."""
    if total <= 0:
        return ""
    filled = round(w * done / total)
    return (paint("█" * filled, S.ACCENT) + paint("░" * (w - filled), S.GREY)
            + paint(f"  {done}/{total}", S.DIM))


def severity_bar(counts: dict, w: int = 40) -> str:
    """Severity mix as one continuous rule — the same idea as the HTML report's
    posture bar, so the terminal and the deliverable read alike."""
    order = [("critical", S.RED), ("high", S.MAGENTA), ("medium", S.YELLOW),
             ("low", S.CYAN), ("info", S.GREY)]
    total = sum(counts.get(k, 0) for k, _ in order)
    if not total:
        return paint("  (no findings)", S.DIM)
    out = "  "
    for key, style in order:
        n = counts.get(key, 0)
        if n:
            out += paint("█" * max(1, round(w * n / total)), style)
    legend = "   ".join(paint(f"{counts.get(k, 0)} {k}", st)
                        for k, st in order if counts.get(k))
    return out + "\n  " + legend


def blocked(msg: str) -> str:
    return paint("  ⛔ BLOCKED  ", S.BOLD, S.RED) + paint(msg, S.RED)


# ---------------------------------------------------------------- progress

class Spinner:
    # Reactor pulse rather than generic braille dots — reads as a power
    # source spinning up, which is the whole point of the theme.
    FRAMES = "◜◝◞◟"

    def __init__(self, text: str, stream=None):
        self.text = text
        self.stream = stream or sys.stdout
        self._stop = threading.Event()
        self._write_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._start = 0.0
        # A forced-color env var must not enable the spinner: animation needs a
        # real TTY. Otherwise `vision run > log.txt` fills the file with frames.
        self.enabled = (hasattr(self.stream, "isatty") and self.stream.isatty()
                        and not _NEVER)

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            el = time.time() - self._start
            with self._write_lock:
                self.stream.write(
                    f"\r  {paint(frame, S.ACCENT)} {self.text} "
                    f"{paint(f'{el:.0f}s', S.DIM)}   "
                )
                self.stream.flush()
            i += 1
            time.sleep(0.08)

    def __enter__(self) -> "Spinner":
        self._start = time.time()
        if self.enabled:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        else:
            self.stream.write(f"  · {self.text}\n")
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.3)
            self.stream.write("\r" + " " * (width() - 1) + "\r")
            self.stream.flush()

    def update(self, text: str) -> None:
        """Change what the spinner label shows, while it keeps animating.

        Before this, the spinner text was fixed at creation — an exploit run
        showed "msf exploit -> 10.0.0.5 1056s" with the number climbing and
        nothing else ever changing, indistinguishable from a hang. Callers
        that know what phase a long-running command is in (see
        `classify_phase` in exploit_advisor.py) can now push that update here
        as it happens, so the elapsed counter is accompanied by an answer to
        "what is it actually doing right now".
        """
        with self._write_lock:
            self.text = text

    def write(self, text: str) -> None:
        """Print above a running spinner without garbling it.

        Stages announce findings from worker threads while the spinner is
        animating on the same line. Without clearing first, the two interleave
        and the operator gets a smeared line at the moment a critical finding
        appears — exactly when it needs to be readable.
        """
        with self._write_lock:
            if self.enabled:
                self.stream.write("\r" + " " * (width() - 1) + "\r")
            self.stream.write(text.rstrip("\n") + "\n")
            self.stream.flush()

    @property
    def elapsed(self) -> float:
        return time.time() - self._start


# ---------------------------------------------------------------- tables

def ask(question: str, default: bool | None = None) -> bool:
    """Yes/no confirmation.

    The default is shown in the prompt and applied on a bare Enter, so the
    operator never has to guess what pressing return will do.
    """
    hint = {True: "[Y/n]", False: "[y/N]", None: "[y/n]"}[default]
    try:
        answer = input(paint(f"  {question} ", S.BOLD)
                       + paint(f"{hint} ", S.DIM)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not answer:
        return bool(default)
    return answer in ("y", "yes")


def choose(title: str, options: list[tuple[str, str, str]],
           subtitle: str = "", prompt: str = "select") -> str:
    """Numbered chooser.

    Each option is (key, label, hint). The hint is what makes a menu usable
    without the manual open beside it — it says what the choice will actually
    do, not just what it is called.
    """
    print(section(title, subtitle))
    for key, label, hint in options:
        marker = paint(f"  [{key}]", S.ACCENT if key != "0" else S.GREY)
        line = f"{marker}  {label}"
        if hint:
            pad = " " * max(1, 22 - _vislen(label))
            line += pad + paint(hint, S.DIM)
        print(line)
    print()
    try:
        return input(paint(f"  {prompt}> ", S.BOLD, S.ACCENT)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return "0"


def table(rows: list[list[str]], headers: list[str],
          aligns: list[str] | None = None) -> str:
    if not rows:
        return paint("  (nothing to show)", S.DIM)
    cols = len(headers)
    aligns = aligns or ["l"] * cols
    w = [max([_vislen(headers[i])] + [_vislen(r[i]) for r in rows])
         for i in range(cols)]

    def fmt(cells: list[str], style: str = "") -> str:
        parts = []
        for i, c in enumerate(cells):
            pad = " " * max(0, w[i] - _vislen(c))
            parts.append(pad + c if aligns[i] == "r" else c + pad)
        line = "  " + "  ".join(parts)
        return paint(line, style) if style else line

    out = [fmt(headers, S.BOLD), paint("  " + "─" * (sum(w) + 2 * cols), S.GREY)]
    out += [fmt(r) for r in rows]
    return "\n".join(out)
