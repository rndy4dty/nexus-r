# NEXUS-R Roadmap

Legend: done / in-progress / planned

## V0.1 - Linux Enumeration Core (done)

- Project skeleton
- Evidence model & store
- CLI: scan, version
- Collectors: system, users, suid, sudo
- JSON report

## V0.2 - Rules & Findings (done)

- Finding model with severity/confidence split
- RuleEngine with dedup
- 12 detection rules (SUID, sudo, capabilities, cron, writable,
  PATH, kernel, docker, groups, SSH)
- Knowledge mapping for all rules

## V0.3 - Correlation & Attack Path (done)

- AttackPath model
- CorrelationEngine
- NEXUS-CORR-DOCKER-001
- NEXUS-CORR-LXD-001
- NEXUS-CORR-SSH-001

## V0.4 - Knowledge Engine (done, partial)

- CWE / ATT&CK mapping for every rule
- References and notes per rule
- Knowledge block in JSON and HTML
- Planned: CVE matching per-package
- Planned: GTFOBins integration beyond name matching

## V0.5 - Reporting & CI + AI Hypothesis Layer (done)

- JSON report (done)
- SARIF 2.1.0 report (done)
- HTML report (done)
- AI hypothesis layer (template / ollama / openai) (done)
- Planned: diff mode between two reports
- Planned: ignore-list / suppression file
- SARIF output for CI (done)

## V0.6 - Lab & Verification (partial)

- Core vulnerable Linux scenario (done)
- 5 scenarios with automated verification (done)
- All 5 scenarios PASS (done)
- Planned: sudo, cron, capabilities, container-escape scenarios

## V0.7 - Extended Coverage (planned)

- Packages collector + CVE hints
- Network services collector
- NFS / SMB misconfigurations
- More correlation rules

## V1.0 - Final target

Evidence-first, explainable, rule-based, attack-path-aware Linux
privilege-escalation analysis engine.

## Anti-roadmap

- No automated exploitation
- No single score for findings
- No silent rule changes
- No reliance on AI for detection
- No unaudited network calls
