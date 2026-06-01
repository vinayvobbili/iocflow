"""The commentary orchestrator: report -> prompt -> model -> Commentary.

``comment`` never raises. If no model is configured or a call fails, it returns
a deterministic assessment built straight from the report, so the pipeline keeps
working without an LLM (LLM is the primary path, with a guaranteed fallback).
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import TYPE_CHECKING, Any, List, Mapping, Optional

from iocflow.ai.models import Commentary, Severity
from iocflow.ai.prompt import SYSTEM_PROMPT, build_user_prompt
from iocflow.ai.protocol import CommentaryModel

if TYPE_CHECKING:  # pragma: no cover - typing only
    from iocflow.enrich.models import EnrichmentReport
    from iocflow.models import ExtractedEntities

logger = logging.getLogger(__name__)


def comment(
    report: "EnrichmentReport",
    entities: "Optional[ExtractedEntities]" = None,
    text: Optional[str] = None,
    model: Optional[CommentaryModel] = None,
) -> Commentary:
    """Produce an analyst-style :class:`Commentary` for an enriched indicator set.

    Args:
        report: The L2 enrichment report (may be empty).
        entities: Optional L1 entities, used for context when the report is empty.
        text: Optional original report text, included as context.
        model: A :class:`CommentaryModel`. Defaults to :func:`default_model`
            (built from environment config); if none is available, a
            deterministic non-LLM assessment is returned.
    """
    if model is None:
        model = default_model()
    if model is None:
        return _deterministic(report, error="no commentary model configured")

    user = build_user_prompt(report, entities, text)
    try:
        raw = model.complete(SYSTEM_PROMPT, user, json=True)
    except Exception as exc:  # noqa: BLE001 — any model failure degrades to fallback
        logger.warning("Commentary model failed (%s); using deterministic fallback", exc)
        return _deterministic(
            report, error=f"model error: {type(exc).__name__}: {exc}", model=_name(model)
        )

    return _parse(raw, report, model_name=_name(model))


def default_model(env: Optional[Mapping[str, str]] = None):
    """Build an :class:`OpenAIChatModel` from the environment, or ``None``.

    Reads ``IOCFLOW_LLM_API_KEY``, ``IOCFLOW_LLM_BASE_URL``, and
    ``IOCFLOW_LLM_MODEL``. Returns ``None`` when neither a key nor a base URL is
    set (local servers often need only a base URL, no key).
    """
    env = env if env is not None else os.environ
    key = env.get("IOCFLOW_LLM_API_KEY")
    base = env.get("IOCFLOW_LLM_BASE_URL")
    model = env.get("IOCFLOW_LLM_MODEL")
    if not key and not base:
        return None

    from iocflow.ai.openai_compat import OpenAIChatModel

    kwargs: "dict[str, str]" = {}
    if key:
        kwargs["api_key"] = key
    if base:
        kwargs["base_url"] = base
    if model:
        kwargs["model"] = model
    make: Any = OpenAIChatModel
    return make(**kwargs)


# -- parsing ---------------------------------------------------------------

def _parse(raw: str, report: "EnrichmentReport", model_name: str) -> Commentary:
    """Parse a JSON response; fall back to treating the text as narrative."""
    try:
        data = json.loads(_extract_json(raw))
        if not isinstance(data, dict):
            raise ValueError("response was not a JSON object")
        assessment = str(data.get("assessment", "")).strip()
        return Commentary(
            summary=assessment,
            severity=Severity.coerce(data.get("severity"), _severity_from_report(report)),
            assessment=assessment,
            key_findings=_str_list(data.get("key_findings")),
            recommendations=_str_list(data.get("recommendations")),
            model=model_name,
            raw=raw,
        )
    except (json.JSONDecodeError, ValueError, TypeError):
        narrative = raw.strip()
        return Commentary(
            summary=narrative,
            severity=_severity_from_report(report),
            assessment=narrative,
            model=model_name,
            raw=raw,
            error="non-JSON response; used narrative fallback",
        )


_FENCE = re.compile(r"^```[a-zA-Z0-9]*\n|\n```$")


def _extract_json(raw: str) -> str:
    """Best-effort: strip code fences and isolate the outermost JSON object."""
    s = _FENCE.sub("", raw.strip())
    start, end = s.find("{"), s.rfind("}")
    if start != -1 and end != -1 and end > start:
        return s[start : end + 1]
    return s


def _str_list(value) -> List[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if value:
        return [str(value).strip()]
    return []


# -- deterministic fallback ------------------------------------------------

def _deterministic(report: "EnrichmentReport", *, error: str, model: str = "") -> Commentary:
    """Build a usable assessment straight from the report, with no LLM."""
    malicious = report.malicious
    severity = _severity_from_report(report)

    findings: List[str] = []
    for ind in malicious[:20]:
        sources = ", ".join(
            sorted(
                {r.source for r in report.for_indicator(ind.kind, ind.value)
                 if r.ok and r.verdict.value == "malicious"}
            )
        )
        findings.append(f"{ind.kind} {ind.value} flagged malicious by {sources or 'a source'}")

    n_total = len(report.indicators())
    if malicious:
        summary = (
            f"{len(malicious)} of {n_total} enriched indicator(s) are malicious "
            f"per threat-intel sources."
        )
        recommendations = [
            "Block or sinkhole the malicious indicators at the perimeter.",
            "Hunt for the malicious indicators across endpoint and network logs.",
        ]
    elif n_total:
        summary = f"{n_total} indicator(s) enriched; none flagged malicious."
        recommendations = ["Continue monitoring; no immediate action indicated."]
    else:
        summary = "No indicators were available to assess."
        recommendations = []

    return Commentary(
        summary=summary,
        severity=severity,
        assessment=summary,
        key_findings=findings,
        recommendations=recommendations,
        model=model,
        error=error,
    )


def _severity_from_report(report: "EnrichmentReport") -> Severity:
    """Deterministic severity baseline from aggregate verdicts."""
    n_mal = len(report.malicious)
    if n_mal >= 3:
        return Severity.CRITICAL
    if n_mal >= 1:
        return Severity.HIGH
    n_susp = sum(
        1
        for ind in report.indicators()
        if report.verdict_for(ind.kind, ind.value).value == "suspicious"
    )
    if n_susp:
        return Severity.MEDIUM
    return Severity.LOW if report.indicators() else Severity.INFO


def _name(model) -> str:
    return getattr(model, "name", "") or model.__class__.__name__
