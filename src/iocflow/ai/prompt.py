"""Prompt construction for commentary.

The report and entities are duck-typed (only their public methods are used), so
this module does not import the enrichment package at load time.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from iocflow.enrich.models import EnrichmentReport
    from iocflow.models import ExtractedEntities

SYSTEM_PROMPT = (
    "You are a senior threat-intelligence analyst. You are given indicators of "
    "compromise (IOCs) extracted from a report, along with reputation verdicts "
    "from threat-intel sources. Write a concise, factual assessment grounded "
    "ONLY in the data provided — never invent indicators, verdicts, attribution, "
    "or sources beyond what is given. Respond with a SINGLE JSON object with "
    "exactly these keys:\n"
    '  "severity": one of "critical", "high", "medium", "low", "info"\n'
    '  "assessment": a 2-4 sentence narrative\n'
    '  "key_findings": array of short factual strings\n'
    '  "recommendations": array of short, actionable next steps\n'
    "Return only the JSON object, no prose or code fences."
)

_MAX_INDICATORS = 100
_MAX_TEXT_CHARS = 2000


def build_user_prompt(
    report: "EnrichmentReport",
    entities: "Optional[ExtractedEntities]" = None,
    text: Optional[str] = None,
) -> str:
    """Render the report (and optional context) into a user prompt."""
    lines: List[str] = []

    indicators = report.indicators()
    if indicators:
        lines.append("Enriched indicators (indicator — aggregate verdict — per-source findings):")
        for ind in indicators[:_MAX_INDICATORS]:
            verdict = report.verdict_for(ind.kind, ind.value).value
            findings = _render_findings(report.for_indicator(ind.kind, ind.value))
            lines.append(f"- {ind.kind} {ind.value} — {verdict} — {findings}")
        extra = len(indicators) - _MAX_INDICATORS
        if extra > 0:
            lines.append(f"- (+{extra} more indicators omitted)")
    elif entities is not None and not entities.is_empty():
        lines.append("Extracted indicators (no enrichment available):")
        for ind in list(entities.iter_indicators())[:_MAX_INDICATORS]:
            lines.append(f"- {ind.kind} {ind.value}")
    else:
        lines.append("No indicators were extracted or enriched.")

    if text:
        snippet = text.strip()[:_MAX_TEXT_CHARS]
        lines.append("\nOriginal report excerpt (for context only):")
        lines.append(snippet)

    return "\n".join(lines)


def _render_findings(records) -> str:
    parts = []
    for r in records:
        if not r.ok:
            continue
        bit = f"{r.source}={r.verdict.value}"
        if r.score is not None:
            bit += f"({r.score})"
        parts.append(bit)
    return ", ".join(parts) if parts else "no source data"
