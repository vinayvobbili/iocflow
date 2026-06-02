"""Prompt construction for LLM behavioral hunts.

The report/entities/commentary are duck-typed (only public methods are read), so
this module does not import the enrichment or commentary packages at load time.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from iocflow.ai.models import Commentary
    from iocflow.enrich.models import EnrichmentReport
    from iocflow.hunt.protocol import Dialect
    from iocflow.models import ExtractedEntities

_MAX_INDICATORS = 80


def system_prompt(dialects: List["Dialect"]) -> str:
    """Build the system prompt, naming the dialects the model may target."""
    opts = "; ".join(f'"{d.key}" ({d.label})' for d in dialects)
    return (
        "You are a senior threat-hunt engineer. You are given indicators of "
        "compromise (IOCs) with threat-intel verdicts. Propose BEHAVIORAL hunts "
        "that go beyond literal indicator matching — hunt for the tactics, "
        "techniques, and anomalies an actor using these indicators would produce "
        "(e.g. beaconing cadence, living-off-the-land execution, unusual parent/"
        "child process chains, staging and exfiltration patterns). Ground every "
        "hunt ONLY in the data provided; never invent indicators or verdicts.\n"
        f"Express each hunt's query in ONE of these dialects: {opts}.\n"
        "Respond with a SINGLE JSON object: "
        '{"hunts": [{"title": str, "dialect": one of the keys above, '
        '"query": str, "rationale": str, '
        '"severity": one of "critical","high","medium","low","info"}]}.\n'
        "Return only the JSON object, no prose or code fences."
    )


def build_user_prompt(
    report: "Optional[EnrichmentReport]" = None,
    entities: "Optional[ExtractedEntities]" = None,
    commentary: "Optional[Commentary]" = None,
) -> str:
    """Render indicators, verdicts, and optional commentary into a user prompt."""
    lines: List[str] = []

    indicators = report.indicators() if report is not None else []
    if indicators and report is not None:
        lines.append("Indicators with verdicts (indicator — aggregate verdict):")
        for ind in indicators[:_MAX_INDICATORS]:
            lines.append(f"- {ind.kind} {ind.value} — {report.verdict_for(ind.kind, ind.value).value}")
    elif entities is not None and not entities.is_empty():
        lines.append("Extracted indicators (no enrichment available):")
        for ind in list(entities.iter_indicators())[:_MAX_INDICATORS]:
            lines.append(f"- {ind.kind} {ind.value}")
    else:
        lines.append("No indicators were extracted or enriched.")

    if commentary is not None and commentary.summary:
        lines.append("\nAnalyst assessment (for context):")
        lines.append(commentary.summary)

    return "\n".join(lines)


_REPAIR_SYSTEM = (
    "You are a senior threat-hunt engineer fixing a broken hunt query. Return the "
    "corrected query and nothing else."
)


def build_repair_prompt(dialect: "Dialect", title: str, query: str, error: str) -> "tuple[str, str]":
    """Build the ``(system, user)`` prompt asking the model to fix one query.

    Used by the optional validate→repair loop: a behavioral hunt that fails its
    dialect's validation is fed back with the failure reason and the dialect's
    syntax guide so the model can rewrite it. Returns a strict-JSON instruction
    (``{"query": "..."}``) regardless of dialect.
    """
    guide = getattr(dialect, "behavioral_guide", "")
    user = (
        f"A {dialect.label} hunt query is INVALID. Fix it, keeping the SAME hunting intent.\n\n"
        f"Hunt: {title}\n\n"
        f"FAILING QUERY:\n{query}\n\n"
        f"ERROR:\n{error}\n\n"
        f"{guide}\n\n"
        'Return STRICT JSON ONLY: {"query": "<the corrected query>"}. No prose.'
    )
    return _REPAIR_SYSTEM, user
