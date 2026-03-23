"""Optional OpenAI-compatible LLM pass to flag likely false positives before acting on scanner output."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from appsec_crew.settings import LlmAgentConfig


def _chat_completions_url(base_url: str | None) -> str:
    b = (base_url or "https://api.openai.com/v1").rstrip("/")
    if b.endswith("/v1"):
        return f"{b}/chat/completions"
    return f"{b}/v1/chat/completions"


def _extract_json_object(text: str) -> dict[str, Any] | None:
    t = text.strip()
    m = re.search(r"\{[\s\S]*\}\s*$", t)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", t)
    if fence:
        try:
            return json.loads(fence.group(1).strip())
        except json.JSONDecodeError:
            return None
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        return None


def llm_triage_batch(
    cfg: LlmAgentConfig,
    *,
    agent_role: str,
    items: list[dict[str, Any]],
    guidance: str,
    timeout_s: float = 120.0,
) -> list[dict[str, Any]]:
    """
    Ask the LLM which item indices are likely false positives.

    Returns a list of dicts: {"index": int, "reason": str} (only dismissed items).
    On any failure, returns [] (caller keeps all findings).
    """
    if not cfg.api_key or not items:
        return []
    url = _chat_completions_url(cfg.base_url)
    system = (
        f"You are {agent_role}. Review scanner candidates and mark likely false positives only. "
        "Never request or invent secret values. Respond with JSON only."
    )
    user = (
        guidance
        + "\n\nItems (index is stable):\n"
        + json.dumps(items[:80], indent=2, ensure_ascii=False)
        + '\n\nRespond with JSON: {"dismiss": [{"index": <int>, "reason": "<short>"}]} '
        "Use empty dismiss if none apply."
    )
    try:
        r = httpx.post(
            url,
            headers={"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json"},
            json={
                "model": cfg.model,
                "temperature": min(cfg.temperature, 0.3),
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            timeout=timeout_s,
        )
        r.raise_for_status()
        data = r.json()
        content = (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        parsed = _extract_json_object(content)
        if not parsed:
            return []
        out: list[dict[str, Any]] = []
        for row in parsed.get("dismiss") or []:
            if not isinstance(row, dict):
                continue
            try:
                idx = int(row["index"])
            except (KeyError, TypeError, ValueError):
                continue
            reason = str(row.get("reason") or "dismissed by triage")[:500]
            out.append({"index": idx, "reason": reason})
        return out
    except (httpx.HTTPError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return []


def partition_by_dismiss_indices(
    findings: list[dict[str, Any]],
    dismiss_meta: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into kept vs dismissed using 0-based indices from triage."""
    reason_by_idx: dict[int, str] = {}
    for d in dismiss_meta:
        try:
            reason_by_idx[int(d["index"])] = str(d.get("reason") or "triage")[:500]
        except (KeyError, TypeError, ValueError):
            continue
    kept: list[dict[str, Any]] = []
    dismissed: list[dict[str, Any]] = []
    for i, f in enumerate(findings):
        if i in reason_by_idx:
            dismissed.append({**f, "_dismiss_reason": reason_by_idx[i]})
        else:
            kept.append(f)
    return kept, dismissed
