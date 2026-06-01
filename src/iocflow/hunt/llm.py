"""The optional LLM behavioral-hunt path.

Additive and never fatal: if a model is configured it proposes behavioral hunts
on top of the deterministic IOC-sweep queries; any failure (no model, bad
output, transport error) returns no LLM hunts and an explanatory error string,
leaving the deterministic plan intact.
"""
from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, List, Optional, Tuple

from iocflow.hunt.models import Hunt
from iocflow.hunt.prompt import build_user_prompt, system_prompt
from iocflow.severity import Severity

if TYPE_CHECKING:  # pragma: no cover - typing only
    from iocflow.ai.models import Commentary
    from iocflow.ai.protocol import CommentaryModel
    from iocflow.enrich.models import EnrichmentReport
    from iocflow.models import ExtractedEntities

logger = logging.getLogger(__name__)

_MAX_LLM_HUNTS = 8


def llm_hunts(
    report: "Optional[EnrichmentReport]",
    entities: "Optional[ExtractedEntities]",
    commentary: "Optional[Commentary]",
    dialects: list,
    model: "CommentaryModel",
) -> Tuple[List[Hunt], Optional[str]]:
    """Ask the model for behavioral hunts. Returns ``(hunts, error)``."""
    allowed = {d.key for d in dialects}
    system = system_prompt(dialects)
    user = build_user_prompt(report, entities, commentary)
    try:
        raw = model.complete(system, user, json=True)
    except Exception as exc:  # noqa: BLE001 — additive path must never be fatal
        logger.warning("Hunt model failed (%s); skipping behavioral hunts", exc)
        return [], f"behavioral hunts skipped: model error: {type(exc).__name__}: {exc}"

    try:
        hunts = _parse(raw, allowed)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return [], f"behavioral hunts skipped: unparseable model output: {exc}"
    return hunts, None


_FENCE = re.compile(r"^```[a-zA-Z0-9]*\n|\n```$")


def _extract_json(raw: str) -> str:
    s = _FENCE.sub("", raw.strip())
    start, end = s.find("{"), s.rfind("}")
    if start != -1 and end != -1 and end > start:
        return s[start : end + 1]
    return s


def _parse(raw: str, allowed: set) -> List[Hunt]:
    data = json.loads(_extract_json(raw))
    if not isinstance(data, dict):
        raise ValueError("response was not a JSON object")
    items = data.get("hunts", [])
    if not isinstance(items, list):
        raise ValueError("'hunts' was not a list")

    hunts: List[Hunt] = []
    for item in items[:_MAX_LLM_HUNTS]:
        if not isinstance(item, dict):
            continue
        dialect = str(item.get("dialect", "")).strip().lower()
        query = str(item.get("query", "")).strip()
        title = str(item.get("title", "")).strip()
        if dialect not in allowed or not query or not title:
            continue
        hunts.append(
            Hunt(
                title=title,
                dialect=dialect,
                query=query,
                rationale=str(item.get("rationale", "")).strip(),
                severity=Severity.coerce(item.get("severity"), Severity.MEDIUM),
                source="llm",
            )
        )
    return hunts
