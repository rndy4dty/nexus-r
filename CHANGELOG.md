# Changelog

## [Unreleased]

(nothing yet)

## [0.7.0] - 2026-10-01

### Added
- Refreshed CVE database: 26 entries focused on 2023-2024
  - 2023: sudoedit bypass (CVE-2023-22809), Looney Tunables
    (CVE-2023-4911), systemctl pager (CVE-2023-26604), curl SOCKS5
    (CVE-2023-38545), python urllib (CVE-2023-24329), OverlayFS
    (CVE-2023-0386), nf_tables UAF (CVE-2023-32233), nftables
    (CVE-2023-35001), HTTP/2 Rapid Reset, ...
  - 2024: regreSSHion (CVE-2024-6387), regreSSHion privsep
    (CVE-2024-6409), runc escape (CVE-2024-21626), xz backdoor
    (CVE-2024-3094), less (CVE-2024-32487), nf_tables UAF
    (CVE-2024-1086), glibc iconv (CVE-2024-2961), PHP CGI
    (CVE-2024-4577), CUPS chain (4 CVEs), Apache HTTP/2
    (CVE-2024-27316), ...
- `affected_above` field: entries can now express a range,
  not only an upper bound (used by the xz backdoor entry:
  `5.6.0 <= v < 5.6.2`)
- ADR-005: Version Comparison Limits
- 5 regression tests for version comparison

### Fixed
- Epoch prefix is now stripped before comparison. This fixes a
  false positive where `1:9.6p1-3ubuntu13.19` was treated as
  starting with `1`, incorrectly matching CVE-2023-38408
- `+really<version>` suffix is now honored. Ubuntu uses
  `5.6.1+really5.4.5` to mark a deliberate downgrade, so this
  is not affected by the xz backdoor

### Changed
- CVE database now stores severity as a string and is converted
  to the `Severity` enum in the rule, breaking a circular import
  between `knowledge` and `analysis`

### Statistics
- 13 collectors
- 14 detection rules
- 3 correlation rules
- 26 CVE entries (2023-2024)
- 241 unit tests
- 5 lab scenarios (all passing)
- 5 Architecture Decision Records
- 4 report formats: JSON, HTML, SARIF, Markdown

## [0.6.1] - 2026-10-01

### Added
- Markdown report format (`output/report.md`)
  - Sections: Summary, Attack Paths, Findings, Hypotheses, Disclaimer
  - Findings sorted by severity then rule_id
  - Knowledge (CWE / ATT&CK) inline per finding and per attack path
  - Escapes pipes and backticks so tables stay valid
- 9 unit tests for the Markdown builder

### Changed
- Orchestrator now writes four reports: JSON, HTML, SARIF, Markdown
- CLI prints all four report paths

## [0.6.0] - 2026-10-01

### Added
- AI hypothesis layer (src/nexus_r/ai/)
  - Hypothesis model with mode, status, finding_ids, validation_steps
  - TemplateAnalyzer: offline, deterministic, always available
  - OllamaAnalyzer: HTTP to a local Ollama server
  - OpenAIAnalyzer: HTTP to any OpenAI-compatible API
  - HypothesisAnalyzer: automatic fallback to template on error
    or empty response
- ADR-004: AI Hypothesis Layer
- CLI flags: --ai, --ai-backend (template|ollama|openai), --ai-model
- Report gains a hypotheses list; CLI prints a HYPOTHESES section

### Changed
- Orchestrator accepts an ai_backend; default remains offline template
- Report summary gains hypothesis_count

### Safety (ADR-004)
- Hypotheses never substitute for findings
- Every hypothesis references at least one existing finding
- Every hypothesis has status needs_review
- AI backend has no filesystem / evidence / collector access
- Prompt safety is enforced by the parser, not by trusting the LLM
- Fallback to template mode is automatic when the AI is offline

### Statistics
- 13 collectors
- 14 detection rules
- 3 correlation rules
- 226 unit tests
- 5 lab scenarios (all passing)
- 4 Architecture Decision Records

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
