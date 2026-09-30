# ADR-002: Detection Coverage & Finding Model

* **Status:** Accepted
* **Date:** 2026-10-01
* **Deciders:** Project Owner, Engineering
* **Depends on:** ADR-001
* **Supersedes:** —

---

## 1. Context

ADR-001 establishes NEXUS-R as an evidence-driven Linux security
engine. It rejects the "count of checks" metric used by traditional
enumeration tools. This ADR answers: how does NEXUS-R find things,
and how does it talk about what it found?

---

## 2. Decision

### 2.1 Finding model

A **Finding** is the atomic unit of analysis. It is produced by a
Rule and is always backed by at least one evidence item.

Fields: id, rule_id, title, description, category, severity,
confidence, evidence_ids, validation_steps, references, tags.

### 2.2 Severity and Confidence are separate axes

| Combination | Meaning | Action |
|---|---|---|
| high + high | Almost certainly exploitable | Validate immediately |
| high + low | Impact significant, evidence incomplete | Validate manually |
| low + high | Certain but low impact | Log, monitor |
| low + low | Noise | Ignore or refute |

Collapsing into a single score loses the ability to say "we think
this matters, but we are not sure yet".

### 2.3 Only rules produce findings

Collectors cannot produce findings (ADR-001 §3.2). Correlation
engine produces AttackPaths, not findings. Knowledge engine
enriches. AI (future) produces hypotheses, not findings.

### 2.4 Deterministic rule output

Same evidence -> same findings, same order, same IDs. No
randomness, no time-dependent ordering. Deduped by
(rule_id, evidence_ids).

### 2.5 Rule IDs are stable contracts

Adding rules: fine. Changing IDs: breaking change. Removing: breaking.

---

## 3. Current rule set (V0.4)

| Rule ID | Category | Severity | Confidence |
|---|---|---|---|
| NEXUS-SUID-001 | privilege-escalation | high | medium |
| NEXUS-SGID-001 | enumeration | info | high |
| NEXUS-SUDO-001 | privilege-escalation | high | high |
| NEXUS-SUDO-002 | privilege-escalation | high | medium |
| NEXUS-CAP-001 | privilege-escalation | critical | medium |
| NEXUS-CRON-001 | privilege-escalation | high | high |
| NEXUS-CRON-002 | privilege-escalation | medium | low |
| NEXUS-WRITE-001 | privilege-escalation | critical | high |
| NEXUS-PATH-001 | privilege-escalation | high | high |
| NEXUS-KERN-001 | kernel | medium | low |
| NEXUS-DOCKER-001 | container-escape | critical | medium |
| NEXUS-GROUP-001 | privilege-escalation | critical | medium |
| NEXUS-SSH-001 | credential-exposure | high | medium |
| NEXUS-SYSD-001 | privilege-escalation | high | high |

Number is not the point. Every rule has explicit severity, explicit
confidence, and validation steps.

---

## 4. Anti-goals

Rejected: single-score, fire-and-forget detection, opaque rules,
rule churn, auto-exploitation.

---

## 5. Consequences

Positive: two-axis prioritization, machine + human readable,
stable IDs, small enough to explain in one page.

Trade-offs: two axes is more work, every rule must define confidence,
higher cost per rule.

---

## 6. Relation to other ADRs

- ADR-001: pipeline.
- ADR-002 (this): findings + scoring.
- ADR-003: findings combine into attack paths.
- ADR-004 (future): AI hypothesis layer, bounded by ADR-001 §3.4.

---

## 7. Status in V0.4

Implemented: Finding model, Rule ABC + RuleResult, RuleEngine with
dedup, 13 rules, knowledge enrichment.

Not yet: per-rule ignore-lists, validation status tracking, diff mode.
