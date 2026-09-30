# ADR-003: Attack Path Model & Correlation

* **Status:** Accepted
* **Date:** 2026-10-01
* **Deciders:** Project Owner, Engineering
* **Depends on:** ADR-001, ADR-002
* **Supersedes:** —

---

## 1. Context

Traditional enumeration tools present findings as a flat list. The
analyst has to combine them mentally ("I am in docker group. There
is a docker socket. That means root."). That combination is not in
the tool output. It is in the analyst head. Consequences:

1. Time-consuming
2. Error-prone
3. Not portable

ADR-003 makes the combination a first-class output.

---

## 2. Decision

### 2.1 Two output types

1. Findings (ADR-002) - atomic observations.
2. AttackPaths (this ADR) - combinations of findings.

### 2.2 Attack paths must be backed by findings

Every path references at least one finding. A path without findings
is speculation, forbidden.

### 2.3 Attack paths have their own severity and confidence

Same two-axis model as findings. But the combination is usually
stronger than its weakest link, because both prerequisites are
present, not inferred.

### 2.4 Status: plausible vs hypothesis

- **plausible** — all prerequisites present, escalation well understood.
- **hypothesis** — some prerequisites inferred; needs validation.

Prevents over-claiming.

### 2.5 Entry point and target

Every path declares:

- entry_point: where the attacker is now (user, current-host)
- target: what they gain (root, remote-host)

Readable at a glance: user -> root.

### 2.6 Correlation rules are separate from detection rules

| Detection | Correlation |
|---|---|
| NEXUS-SUID-001 | NEXUS-CORR-DOCKER-001 |
| NEXUS-SUDO-001 | NEXUS-CORR-LXD-001 |
| NEXUS-CAP-001 | NEXUS-CORR-SSH-001 |

Different base classes, different inputs, different outputs.

### 2.7 Correlation rules cannot invent evidence

A correlation rule receives findings + evidence store. It must
not call external tools, read files, modify findings, or produce
paths whose findings do not exist.

---

## 3. Current correlation coverage (V0.4)

| Rule | Findings combined | Status | Severity |
|---|---|---|---|
| NEXUS-CORR-DOCKER-001 | GROUP-001 (docker) + DOCKER-001 | plausible | critical |
| NEXUS-CORR-LXD-001 | GROUP-001 (lxd/lxc) | plausible | critical |
| NEXUS-CORR-SSH-001 | SSH-001 | hypothesis | high |

---

## 4. Anti-goals

Rejected: weak-signal correlation, multi-hop speculation in V0.4,
auto-exploitation, absolute claims.

---

## 5. Consequences

Positive: analyst sees combinations, deterministic, testable,
diffable, actionable.

Trade-offs: each rule is hand-written, might miss combinations,
higher cognitive cost.

Mitigations: start with highest-value correlations; unit tests
include negative tests; model is extensible.

---

## 6. Relation to other ADRs

- ADR-001: pipeline.
- ADR-002: findings.
- ADR-003 (this): how findings combine.
- ADR-004 (future): multi-hop graphs, only if current flat model
  proves insufficient.

---

## 7. Status in V0.4

Implemented: AttackPath model, AttackPathStatus, CorrelationRule,
CorrelationEngine, 3 correlation rules, knowledge enrichment,
HTML section.

Not yet: multi-hop chaining, path prioritization, diff mode,
visualization.
