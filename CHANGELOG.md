# Changelog

## [Unreleased]

### Added
- ADR-002: Detection Coverage & Finding Model
- ADR-003: Attack Path Model & Correlation
- docs/roadmap.md
- CHANGELOG.md

## [0.4.0] - 2026-10-01

### Added
- Knowledge Engine: CWE + ATT&CK mapping for every rule
- ServicesCollector (systemd services)
- SystemdCollector (systemd unit files)
- Rule NEXUS-SYSD-001: writable systemd unit file
- Lab environment: intentionally vulnerable Linux container

### Fixed
- CapabilitiesCollector: correct getcap output parsing
- CapabilitiesCollector: dedupe file capability evidence
- DockerCollector: dedupe sockets by inode
- SuidCollector: dedupe SUID/SGID by inode
- CronPathHijackRule: skip shell builtins
- PathWritableRule: skip directories owned by current user
- SudoDangerousRule: parse only command part

## [0.3.0] - 2026-09-30

### Added
- AttackPath model, AttackPathStatus
- CorrelationEngine and 3 correlation rules
- HTML report (self-contained)

## [0.2.0] - 2026-09-30

### Added
- Finding model with Severity/Confidence separation
- RuleEngine with deterministic ids and dedup
- 12 detection rules
- 7 additional collectors

## [0.1.0] - 2026-09-30

### Added
- Initial skeleton
- Evidence model and store
- CLI (scan, version)
- System, users, suid collectors
- JSON report
