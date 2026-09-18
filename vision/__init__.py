"""VISION — Network VAPT Orchestrator.

Drives 55 security tools through 32 stages across 6 phases.
Built around the principle: verify before you fire.
Every capability check is gated, every exploit is logged, every finding
carries a confidence level the operator can trust.

Quick start::

    vision doctor        # check toolchain
    vision setup         # install what's missing
    vision index         # build the Metasploit module index
    vision check 10.0.0.0/24   # safe verification only
    vision exploit 10.0.0.0/24 --authorized yes  # advisory mode

Modules:
    cli             — entry point and subcommand dispatch
    core            — pipeline, profiles, runlog, safety, toolchain, doctor
    analysis        — proof-of-impact, exploit advisory, correlate, enrich
    report          — findings export (JSON / Markdown / CSV)
"""

__version__ = "0.1.0"
