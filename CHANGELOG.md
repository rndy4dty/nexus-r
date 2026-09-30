# Changelog

## [Unreleased]

(nothing yet)

## [0.5.0] - 2026-10-01

### Added
- `NEXUS-PKG-001`: installed package has known CVE
- `PackagesCollector`: reads /var/lib/dpkg/status (Debian/Ubuntu)
- Curated CVE database (7 entries):
  - CVE-2021-3156 (Baron Samedit, sudo)
  - CVE-2023-22809 (sudoedit, sudo)
  - CVE-2019-14287 (sudo -u#-1, sudo)
  - CVE-2021-4034 (PwnKit, policykit-1)
  - CVE-2014-6271 (Shellshock, bash)
  - CVE-2023-4911 (Looney Tunables, glibc)
  - CVE-2022-0778 (OpenSSL BN_mod_sqrt)
- SARIF 2.1.0 report (`output/report.sarif`)
  - Compatible with GitHub Code Scanning, GitLab SAST
  - Deduped rules, severity->level mapping, evidence locations
  - CWE + ATT&CK embedded in rule properties
- 4 new lab scenarios with automated verification:
  - `sudo-only` (NEXUS-SUDO-001, NEXUS-SUDO-002)
  - `cron-only` (NEXUS-CRON-001, NEXUS-PATH-001)
  - `capabilities-only` (NEXUS-CAP-001)
  - `container-escape` (NEXUS-GROUP-001, NEXUS-DOCKER-001, NEXUS-CORR-DOCKER-001)
- `lab/verify-all.sh` and `lab/verify_one.py`
  - Each scenario declares `expected.json`; the script builds, scans,
    and verifies every scenario, returning PASS/FAIL per scenario

### Changed
- Orchestrator now writes three reports: JSON, HTML, SARIF
- CLI prints all three report paths

### Fixed
- `container-escape` lab scenario works on Debian bookworm where
  /var/run is a symlink to /run

### Statistics
- 13 collectors
- 14 detection rules
- 3 correlation rules
- 205 unit tests
- 5 lab scenarios (all passing)

## [0.4.0] - 2026-10-01

### Added
- ADR-002: Detection Coverage & Finding Model
- ADR-003: Attack Path Model & Correlation
- docs/roadmap.md
- CHANGELOG.md
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
