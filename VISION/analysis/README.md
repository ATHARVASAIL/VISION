# analysis/ — reasoning about findings

Nothing here scans. Everything here takes findings that already exist and
derives something more useful from them.

| File | Role |
| :-- | :-- |
| `correlate.py` | Chains findings into attack paths — "this plus that equals a route in" |
| `remediation.py` | Groups findings into *actions*, ordered for whoever has to fix them |
| `coverage.py` | Which discovered services were actually assessed. Answers "did you look everywhere", which a finding count does not. |
| `frameworks.py` | Maps findings to ATT&CK, CIS, PCI DSS, OWASP |
| `diff.py` | Compares a retest against a baseline |
| `playbook.py` | Stage narration, plus the hands-on commands Vision deliberately does not automate |
| `msf_index.py` | Offline Metasploit module index |
| `exploit_advisor.py` | Ranks exploit candidates and enforces every firing gate. **The safety-critical file.** |
| `rules.py` | Loads user-defined attack chains from JSON/YAML — data only, never code |
