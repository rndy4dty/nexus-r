# ADR-001: Project Architecture & Scope

* **Status:** Accepted
* **Date:** 2026-10-01
* **Deciders:** Project Owner, Engineering
* **Supersedes:** Previous NEXUS-R Web/API Red Team Assistant architecture
* **Superseded by:** —

---

## 1. Context

NEXUS-R was initially designed as a **Web/API Red Team Assistant**.
After evaluating scope, complexity, and long-term direction, the
architecture has been revised.

NEXUS-R will focus on **Linux security research, system enumeration,
evidence collection, security analysis, finding correlation,
attack-path analysis, and explainable security reasoning**.

Primary differentiation:

* Context
* Correlation
* Reasoning
* Attack-path understanding
* Explainability

---

## 2. Decision

> **Evidence-Driven Linux Security Research and Privilege-Escalation Analysis Engine**

Evidence-first approach:

```
Raw Data -> Normalization -> Structured Evidence -> Analysis -> Finding
```

---

## 3. Architectural Principles

- **3.1 Evidence First** — collectors gather facts, not verdicts.
- **3.2 Separation of Collection and Analysis** — collector != analyzer.
- **3.3 Structured Evidence** — no raw command output between modules.
- **3.4 Security Boundary** — scope guard + policy engine before operations.
- **3.5 Authorized Assessment** — only authorized scope.
- **3.6 Severity and Confidence Are Separate** — two independent axes.
- **3.7 Human Validation** — AI analyzes; humans validate.

---

## 4. System Architecture

```
CLI -> Orchestrator -> Collectors -> EvidenceStore
    -> RuleEngine -> Findings
    -> CorrelationEngine -> AttackPaths
    -> Knowledge -> Report
```

---

## 5. Scope

In scope: Linux enumeration, evidence normalization, rule-based
analysis, correlation, attack-path analysis, AI-assisted reasoning,
reporting.

Out of scope for initial release: full AI reasoning, complete
CVE/CWE/ATT&CK engine, automated exploitation, large-scale
infrastructure.

---

## 6. Version Roadmap

- V0.1 — Linux Enumeration Core
- V0.2 — Security Analysis (Rules, Findings)
- V0.3 — Correlation & Attack Path
- V0.4 — Knowledge Engine
- V0.5 — AI Research Engine
- V0.6 — Container Security
- V1.0 — Evidence-Driven Linux Security Research Engine

---

## 7. Storage Decision

V0.1: JSON / SQLite. PostgreSQL not required initially.

---

## 8. Testing Strategy

tests/unit, tests/integration, tests/security, tests/fixtures, tests/lab

---

## 9. Laboratory Environment

lab/ with docker-compose and intentionally vulnerable scenarios.

---

## 10. Consequences

Positive: clear separation, structured evidence, explainability,
correlation, attack-path representation, controlled AI.

Trade-offs: more complex than a conventional enumeration script.
Must not be implemented all at once.

---

## 11. Alternatives Considered

- Continue as Web/API Red Team Assistant: rejected.
- Build another enumeration tool: not selected.
- Build an AI-First Security Agent: not selected.
- Implement the entire architecture immediately: rejected.

---

## 12. Final Decision

NEXUS-R proceeds as an **Evidence-Driven Linux Security Research and
Privilege-Escalation Analysis Engine**.
