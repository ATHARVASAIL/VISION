"""Core engine — pipeline, profiles, safety, toolchain, and console.

Submodules:
    pipeline.py     — 32-stage run pipeline with hook system
    profiles.py     — reusable tool/phase/scope combinations
    runlog.py       — execution logging with evidence capture
    safety.py       — input validation, secure defaults, caps
    schema.py       — target / scope / credential data models
    scope.py        — scope enforcement (CIDR, port, rate limits)
    ui.py           — terminal output (colours, tables, spinners)
    toolchain.py    — 55-tool registry with install and detection
    doctor.py       — `vision doctor` and `vision setup` commands
    selfcheck.py    — internal consistency audit
    console.py      — msfconsole session manager
    credentials.py  — credential attack tooling (hydra, hashcat, kerbrute)
"""
