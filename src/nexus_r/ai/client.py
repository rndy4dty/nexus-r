"""Minimal HTTP client for LLM backends.

No external dependencies: uses urllib from the standard library so
that adding an AI backend does not pull in httpx/requests.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_TIMEOUT = 60.0


@dataclass(frozen=True)
class LLMResponse:
    """Response from an LLM backend."""

    text: str
    model: str
    raw: dict


class LLMError(RuntimeError):
    """Raised when an LLM backend cannot be reached or returns an error."""


def post_json(
    url: str,
    payload: dict,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
) -> dict:
    """POST a JSON payload and return the parsed JSON response."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise LLMError(f"HTTP {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(f"network error: {exc.reason}") from exc
    except OSError as exc:
        raise LLMError(f"io error: {exc}") from exc

    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise LLMError(f"invalid JSON response: {exc}") from exc


def get_json(
    url: str,
    *,
    timeout: float = 10.0,
    headers: dict[str, str] | None = None,
) -> dict:
    """GET a JSON document. Raises LLMError on failure."""
    req = urllib.request.Request(url, method="GET")
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise LLMError(f"HTTP {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(f"network error: {exc.reason}") from exc
    except OSError as exc:
        raise LLMError(f"io error: {exc}") from exc

    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise LLMError(f"invalid JSON response: {exc}") from exc
