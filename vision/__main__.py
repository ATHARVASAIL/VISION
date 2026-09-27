"""Entry point for `python -m vision`.

The console script `vision` (from pyproject.toml) is the intended way to run
the tool, but that requires an install. Without this module, a first-time
operator on a fresh checkout would have to type the longer
`python -m vision.cli`. This makes the natural command work.
"""

# Reconfigure stdout/stderr to UTF-8 on Windows before any other import can
# write Unicode. Python's default on Windows is cp1252, which cannot encode
# the HUD symbols used throughout the UI (◈, ●, ○, ►, etc.).
import sys
import os

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, Exception):
        pass

from vision.cli import main

if __name__ == "__main__":
    sys.exit(main())
