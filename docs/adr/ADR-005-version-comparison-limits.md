# ADR-005: Version Comparison Limits

* **Status:** Accepted
* **Date:** 2026-10-01
* **Deciders:** Project Owner, Engineering
* **Depends on:** ADR-001, ADR-002
* **Supersedes:** —

---

## 1. Context

NEXUS-R rule `NEXUS-PKG-001` matches installed package versions
against a curated database of known-vulnerable version ranges.

That matching depends on comparing version strings. Linux version
strings are not semver. They follow Debian Policy §5.6.12, which is
significantly more complex:

- Epoch prefixes: `1:9.6p1-3ubuntu13.19`
- Tilde for pre-releases: `1.0~rc1 < 1.0`
- The `+really` convention: `5.6.1+really5.4.5` means "5.4.5 but
  packaged as if it were 5.6.1"
- Distro backports: Ubuntu/Debian frequently backport security fixes
  **without changing the upstream version string**

That last point is fundamental: **it is impossible to determine
whether a distro package is patched from the version string alone.**

Examples encountered during development:

- `openssh-server 1:9.6p1-3ubuntu13.19` — Ubuntu 24.04 backported the
  regreSSHion fix into a `9.6p1` package. The version string still
  says `9.6p1 < 9.8p1`, so we flag it. But the fix is already applied.
- `xz-utils 5.6.1+really5.4.5-1ubuntu0.3` — Ubuntu deliberately
  downgraded to 5.4.5 and marked it with `+really`. The version
  string looks like it starts with 5.6.1, but the actual code is 5.4.5.

---

## 2. Decision

### 2.1 Version comparison is best-effort, not authoritative

`NEXUS-PKG-001` uses a best-effort comparator that:

- Strips the epoch prefix
- Extracts the `+really` part when present
- Compares dot-separated numeric and alphabetic tokens

It does not implement Debian Policy §5.6.12 in full. It does not
query distro security trackers. It does not download changelogs.

### 2.2 Findings from `NEXUS-PKG-001` always have `confidence: medium`

Never `high`. Because the analysis is best-effort, the rule must not
claim certainty.

This is ADR-002 §2.2 applied: severity describes impact if true;
confidence describes how much the evidence supports the claim. Here,
impact can be `critical`, but confidence is `medium`.

### 2.3 `affected_above` allows a range, not just an upper bound

Each database entry has `affected_below` (mandatory) and optionally
`affected_above`. The range is `[affected_above, affected_below)`.

Example: the xz backdoor affects `5.6.0 <= v < 5.6.2`. It is not
enough to say `affected_below = 5.6.2`, because that would flag
5.4.5 and 5.5.x.

### 2.4 The database is curated and shallow

The database is intentionally small. It does not attempt to be a
complete CVE feed. Entries are added by hand, with an NVD reference.
The comparison logic is generic and does not change when entries are
added or removed.

### 2.5 Analysts must verify against the distro advisory

Every `NEXUS-PKG-001` finding includes validation steps that direct
the analyst to:

- Check the exact installed version (`dpkg -l <pkg>`)
- Consult the distribution security advisory
- Confirm exploitability before testing

NEXUS-R provides a candidate list, not a verdict.

---

## 3. Anti-goals

- **Do not** download CVE feeds at scan time. NEXUS-R is offline by
  design.
- **Do not** query distro security trackers. This would require
  network access, may leak the scan target, and is out of scope.
- **Do not** present `NEXUS-PKG-001` findings as authoritative.
- **Do not** try to detect backports from version strings. It is not
  possible in general.

---

## 4. Consequences

### Positive

- NEXUS-R works offline, deterministically, and without leaking
  target information.
- The confidence model (ADR-002) correctly reflects uncertainty.
- Analysts understand the trade-off from the finding itself.
- Adding a new CVE is 6 lines, no code change.

### Trade-offs

- False positives for backported-but-unversioned patches
  (e.g. regreSSHion on Ubuntu 24.04 after apt upgrade).
- False negatives for very new CVEs not yet in the database.
- Comparators can still be wrong for exotic version strings.

### Mitigations

- Confidence is always `medium` (never `high`).
- Validation steps always say "confirm exploitability".
- The database is curated, so entries are chosen for signal, not
  coverage.
- Analysts are expected to check the distro advisory before acting.

---

## 5. Relation to other ADRs

- ADR-001 §3.1 (evidence first) — version matching is evidence,
  not a verdict.
- ADR-002 §2.2 (severity ≠ confidence) — this ADR is the canonical
  example of why that separation matters.
- ADR-003 (attack paths) — a vulnerable package finding can be the
  start of an attack path, but only after validation.
- ADR-005 (this) — the comparison model and its limits.

---

## 6. Status in V0.7

Implemented:

- `VulnerablePackageEntry` with `affected_below` and optional
  `affected_above`.
- `_normalize_version` strips epoch and extracts `+really`.
- `find_vulnerable` returns matching entries.
- `NEXUS-PKG-001` reports severity from the database, confidence
  fixed at `medium`.
- 19 unit tests, including epoch, `+really`, and range cases.

Not yet implemented:

- Debian Policy §5.6.12 full comparison.
- Distro-specific advisory lookup.
- CVE feed ingestion.
