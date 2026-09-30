# ADR-004: AI Hypothesis Layer

* **Status:** Accepted
* **Date:** 2026-10-01
* **Deciders:** Project Owner, Engineering
* **Depends on:** ADR-001, ADR-002, ADR-003
* **Supersedes:** —

---

## 1. Context

ADR-001 §3.4 forbids the AI layer from bypassing scope or security
policy. §3.7 defines the intended reasoning flow:

    Observation -> Hypothesis -> AI Analysis -> Recommended Validation -> Human Validation

ADR-002 established the finding model: findings are evidence-backed,
deterministic, and always produced by rules.

ADR-003 established the attack-path model: attack paths are chains
of findings.

The AI layer sits **after** both. Its job is not to produce findings.
Its job is to help the analyst interpret what the rules already found.

This ADR defines exactly what the AI layer may and may not do.

---

## 2. Decision

### 2.1 AI produces hypotheses, not findings

A **Hypothesis** is a commentary on existing findings and attack
paths. It is a different model from `Finding`, with its own lifecycle.

| | Finding (ADR-002) | Hypothesis (this ADR) |
|---|---|---|
| Producer | Rule engine | Hypothesis analyzer |
| Backed by evidence | Yes, mandatory | Indirectly, via findings |
| Deterministic | Yes | No (LLM output varies) |
| Status | implicit | needs_review / accepted / rejected |
| Severity | impact | from the group it summarizes |
| Confidence | evidence quality | AI self-assessment, treated with caution |

A hypothesis that does not reference at least one existing finding is
**dropped**. This is enforced in code, not by prompt.

### 2.2 AI is optional

`nexus-r scan` (without flags) uses a template analyzer that does not
call any LLM. The template analyzer is offline, deterministic, and
always available.

`nexus-r scan --ai --ai-backend <name>` selects an AI backend.

Supported backends in V0.6:

| Backend | How it runs | Requirements |
|---|---|---|
| template | offline, in-process | none |
| ollama | HTTP to localhost:11434 | ollama serve + a model |
| openai | HTTP to an OpenAI-compatible API | OPENAI_API_KEY |

The list is a set, not a closed enum: any backend that implements the
`analyze(report) -> list[Hypothesis]` interface can be registered.

### 2.3 AI failures never break a scan

If the AI backend is unreachable, returns an error, or returns an
empty list, the analyzer silently falls back to the template
analyzer. This is done in `HypothesisAnalyzer.analyze`, not in the
CLI, so it applies everywhere.

Consequences:

- A scan never fails because of an LLM outage.
- Running `--ai --ai-backend openai` without OPENAI_API_KEY warns
  and uses the template.
- Running `--ai --ai-backend ollama` when Ollama is not running
  silently uses the template.

### 2.4 Every hypothesis requires human validation

Every hypothesis has `status = needs_review` when produced. The AI
cannot mark a hypothesis as accepted or rejected. Only a human
(via a future `nexus-r validate` command, or via the JSON report)
can change the status.

This is ADR-001 §3.7 applied literally: AI is an analysis component,
not an authority.

### 2.5 Hypotheses are advisory, never authoritative

The AI layer must never be the basis for an automated action:

- It cannot trigger a remediation.
- It cannot auto-exploit.
- It cannot suppress findings.
- It cannot modify severity or confidence of findings.
- It cannot create new findings.

It can only:

- Add a `hypotheses` list to the report.
- Reference existing findings by id.
- Provide a narrative and validation steps.

### 2.6 Prompt safety is enforced by parsing, not by trust

The prompt asks the LLM to reference only existing finding ids,
return a strict JSON array, and not claim exploitability.

But the parser does not trust the prompt. It:

- Extracts the first JSON array from the response.
- Drops any item that does not reference a valid finding id.
- Defaults invalid severity / confidence values.
- Truncates titles and narratives.
- Keeps only the first 8 validation steps.

The security boundary is in the parser, not in the prompt.

---

## 3. Architecture

    Report (findings + attack paths)
            |
            v
    HypothesisAnalyzer
            |
            +-- TemplateAnalyzer  (offline, default)
            +-- OllamaAnalyzer    (HTTP to local Ollama)
            +-- OpenAIAnalyzer    (HTTP to OpenAI-compatible API)
            |
            v
    list[Hypothesis]
            |
            v
    Report["hypotheses"]

The AI backend has no access to the filesystem, the evidence store,
or the collectors. It only sees a summarized view of the findings.
It cannot read files, run commands, or escape the process.

---

## 4. Anti-goals

- AI-produced findings. Findings are produced by rules, period.
- Auto-actions. The AI never executes anything.
- Trusting the prompt. Safety is enforced by the parser.
- Hard dependency on an external service. Template mode is always available.
- Sending evidence to a remote service. The prompt contains only
  finding summaries, not raw evidence or file contents.
- Determinism. Hypotheses are non-deterministic by design (LLM);
  findings remain deterministic (ADR-002).

---

## 5. Consequences

### Positive

- Analysts get an additional layer of context without losing
  evidence traceability.
- The AI is decoupled from the detection rules.
- Reports stay valid even when the AI backend is unavailable.
- The AI cannot silently suppress or modify findings.

### Trade-offs

- Two hypothesis sources (template vs AI) can produce different
  results for the same report. Documented and expected.
- Non-determinism of AI output conflicts with CI stability. Handled
  by leaving --ai opt-in; CI runs use template mode.
- Additional code surface that must be tested and maintained.

### Mitigations

- Template mode is the default.
- AI is opt-in via --ai.
- Fallback is automatic.
- 21 unit tests cover construction, parser, backend availability,
  and fallback behavior.
- The prompt/parser split makes it possible to change the prompt
  without weakening safety.

---

## 6. Relation to other ADRs

- ADR-001 defines the evidence-first pipeline and §3.7.
- ADR-002 defines findings; hypotheses never substitute for them.
- ADR-003 defines attack paths; hypotheses can comment on them too.
- ADR-004 (this) defines the AI hypothesis layer.
- A future ADR may define a validation workflow (accept / reject /
  annotate) on top of `needs_review`, only if it preserves the
  "AI never authorizes" rule.

---

## 7. Status in V0.6

Implemented:

- Hypothesis model with mode, status, finding_ids, validation_steps.
- TemplateAnalyzer (offline, deterministic).
- OllamaAnalyzer and OpenAIAnalyzer.
- HypothesisAnalyzer with automatic fallback.
- Orchestrator integration: report gains a `hypotheses` list.
- CLI: --ai, --ai-backend, --ai-model.
- 21 unit tests.

Not yet implemented:

- Validation workflow (`nexus-r validate`).
- Persistent hypothesis status across scans.
- Cost / token accounting for remote backends.
- Streaming responses.
