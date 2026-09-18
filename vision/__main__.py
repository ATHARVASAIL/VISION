"""Entry point for `python3 -m vision`.

The console script `vision` (from pyproject) is the intended way to run the tool,
but that requires an install. Without this module the next most natural command,
`python3 -m vision`, fails with "No module named vision.__main__" and forces the
longer `python3 -m vision.cli`. A first-time operator who has not installed the
package types `python3 -m vision` and, on a fresh checkout, was met with an
error. This makes it work.
"""

import sys

from vision.cli import main

if __name__ == "__main__":
    sys.exit(main())
