"""LLM backends: Ollama and OpenAI-compatible APIs."""

from __future__ import annotations

import json as _json
import re as _re
from typing import Any

from nexus_r.ai.client import LLMError, get_json, post_json
from nexus_r.ai.model import Hypothesis, HypothesisMode, HypothesisStatus
from nexus_r.analysis.finding import Confidence, Severity

DEFAULT_PROMPT = """\
You are a security analyst assistant. You are given a list of findings
from a Linux privilege-escalation scan.

Rules:
- Do not invent findings.
- Only comment on findings that are listed.
- Return a JSON array of objects with these keys:
  title (short), narrative (2-4 sentences), severity (critical/high/medium/low/info),
  confidence (high/medium/low), finding_ids (array of the ids you reference),
  validation_steps (array of concrete commands or actions).
- Every item MUST reference at least one finding_id from the list.
- Never claim a finding is exploitable; only describe what to check.
"""


def _summarize_findings(findings: list[dict[str, Any]], limit: int = 40) -> str:
    lines = []
    for f in findings[:limit]:
        fid = f.get("id", "?")
        sev = f.get("severity", "?")
        conf = f.get("confidence", "?")
        title = f.get("title", "")
        lines.append(f"- {fid} [{sev}/{conf}] {title}")
    return "\n".join(lines)


def _parse_hypotheses(
    raw: str,
    findings_index: dict[str, dict[str, Any]],
    mode: HypothesisMode,
    model: str,
) -> list[Hypothesis]:
    """Parse an LLM response into Hypothesis objects."""
    match = _re.search(r"\[.*\]", raw, _re.DOTALL)
    if not match:
        return []
    try:
        items = _json.loads(match.group(0))
    except _json.JSONDecodeError:
        return []
    if not isinstance(items, list):
        return []

    hypotheses: list[Hypothesis] = []
    for i, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        finding_ids = item.get("finding_ids") or []
        valid_ids = [fid for fid in finding_ids if fid in findings_index]
        if not valid_ids:
            continue
        try:
            sev = Severity(item.get("severity", "info"))
        except ValueError:
            sev = Severity.INFO
        try:
            conf = Confidence(item.get("confidence", "low"))
        except ValueError:
            conf = Confidence.LOW
        steps = item.get("validation_steps") or []
        if not isinstance(steps, list):
            steps = []
        hypotheses.append(
            Hypothesis(
                id=f"H-AI-{i:04d}",
                finding_ids=tuple(valid_ids),
                mode=mode,
                model=model,
                title=str(item.get("title", "hypothesis"))[:120],
                narrative=str(item.get("narrative", ""))[:1000],
                severity=sev,
                confidence=conf,
                status=HypothesisStatus.NEEDS_REVIEW,
                validation_steps=tuple(str(s)[:300] for s in steps[:8]),
                tags=("ai", mode.value),
            )
        )
    return hypotheses


class OllamaAnalyzer:
    """Analyze a report using a local Ollama server."""

    mode = HypothesisMode.OLLAMA

    def __init__(
        self,
        model: str = "llama3.2",
        url: str = "http://localhost:11434",
        timeout: float = 60.0,
    ) -> None:
        self.model = model
        self.url = url.rstrip("/")
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            get_json(f"{self.url}/api/tags", timeout=3.0)
            return True
        except LLMError:
            return False

    def analyze(self, report: dict[str, Any]) -> list[Hypothesis]:
        findings = report.get("findings", [])
        if not findings:
            return []
        findings_index = {f["id"]: f for f in findings if "id" in f}

        prompt = (
            DEFAULT_PROMPT
            + "\n\nFindings:\n"
            + _summarize_findings(findings)
            + "\n\nReturn only the JSON array."
        )

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
        }
        response = post_json(
            f"{self.url}/api/generate", payload, timeout=self.timeout
        )
        text = response.get("response", "")
        return _parse_hypotheses(text, findings_index, self.mode, self.model)


class OpenAIAnalyzer:
    """Analyze a report using an OpenAI-compatible chat completions API."""

    mode = HypothesisMode.OPENAI

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: str = "",
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 60.0,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def is_available(self) -> bool:
        return bool(self.api_key)

    def analyze(self, report: dict[str, Any]) -> list[Hypothesis]:
        findings = report.get("findings", [])
        if not findings:
            return []
        findings_index = {f["id"]: f for f in findings if "id" in f}

        system = DEFAULT_PROMPT
        user = "Findings:\n" + _summarize_findings(findings)

        payload = {
            "model": self.model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        response = post_json(
            f"{self.base_url}/chat/completions",
            payload,
            timeout=self.timeout,
            headers=headers,
        )
        try:
            text = response["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            text = ""
        return _parse_hypotheses(text, findings_index, self.mode, self.model)
