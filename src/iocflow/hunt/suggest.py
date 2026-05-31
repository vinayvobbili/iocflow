"""The hunt orchestrator: report -> deterministic queries (+ optional LLM hunts).

``suggest`` never raises. The deterministic IOC-sweep queries are rendered with
no network and no keys; if a model is configured it adds behavioral hunts on
top, and any model failure leaves the deterministic plan intact.
"""
from __future__ import annotations

import os
from collections import OrderedDict
from typing import TYPE_CHECKING, List, Optional

from iocflow.hunt.models import Hunt, HuntPlan
from iocflow.hunt.registry import DEFAULT_DIALECTS, get_dialect
from iocflow.models import Indicator
from iocflow.severity import Severity

if TYPE_CHECKING:  # pragma: no cover - typing only
    from iocflow.ai.models import Commentary
    from iocflow.ai.protocol import CommentaryModel
    from iocflow.enrich.models import EnrichmentReport
    from iocflow.models import ExtractedEntities

# Severity -> the Sigma `level:` value.
_SIGMA_LEVEL = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "informational",
}


def suggest(
    report: "Optional[EnrichmentReport]" = None,
    *,
    entities: "Optional[ExtractedEntities]" = None,
    commentary: "Optional[Commentary]" = None,
    dialects: Optional[List[str]] = None,
    model: "Optional[CommentaryModel]" = None,
    include_benign: bool = False,
) -> HuntPlan:
    """Suggest hunt queries for an enriched (or merely extracted) indicator set.

    Args:
        report: The L2 enrichment report. Benign-verdict indicators are skipped
            unless ``include_benign`` is set.
        entities: L1 entities, used as the indicator source when ``report`` is
            empty/absent (verdicts then default to ``unknown``).
        commentary: Optional L3 commentary, passed to the LLM for context.
        dialects: Dialect keys to render (default: all — crowdstrike, cortex,
            sigma). Unknown keys raise ``ValueError``.
        model: A chat model for behavioral hunts. Defaults to
            :func:`default_model` (from the environment); if none is available,
            only deterministic hunts are produced.
        include_benign: Also hunt indicators whose verdict is benign.
    """
    dialect_objs = [get_dialect(k) for k in (dialects or DEFAULT_DIALECTS)]

    targets = _targets(report, entities, include_benign)
    by_kind = _group_by_kind(targets)

    hunts: List[Hunt] = []
    for dialect in dialect_objs:
        for kind, inds in by_kind.items():
            if not dialect.supports(kind):
                continue
            values = [i.value for i in inds]
            verdicts = [_verdict(report, kind, v) for v in values]
            severity = _severity_for(verdicts)
            extra = {"level": _SIGMA_LEVEL[severity]} if dialect.key == "sigma" else {}
            query = dialect.render(kind, values, **extra)
            hunts.append(
                Hunt(
                    title=f"{dialect.label} - {kind} sweep",
                    dialect=dialect.key,
                    query=query,
                    indicators=list(inds),
                    kinds=[kind],
                    rationale=_rationale(dialect, kind, values, verdicts),
                    severity=severity,
                )
            )

    plan = HuntPlan(hunts=hunts)

    if model is None:
        model = default_model()
    if model is not None:
        from iocflow.hunt.llm import llm_hunts

        extra_hunts, error = llm_hunts(report, entities, commentary, dialect_objs, model)
        plan.hunts.extend(extra_hunts)
        plan.error = error

    return plan


def default_model(env: Optional[dict] = None):
    """Build an :class:`~iocflow.ai.OpenAIChatModel` from the environment, or ``None``.

    Reuses the same config as Layer 3 (``IOCFLOW_LLM_API_KEY`` /
    ``IOCFLOW_LLM_BASE_URL`` / ``IOCFLOW_LLM_MODEL``).
    """
    env = env if env is not None else os.environ
    key = env.get("IOCFLOW_LLM_API_KEY")
    base = env.get("IOCFLOW_LLM_BASE_URL")
    model = env.get("IOCFLOW_LLM_MODEL")
    if not key and not base:
        return None

    from iocflow.ai.openai_compat import OpenAIChatModel

    kwargs = {}
    if key:
        kwargs["api_key"] = key
    if base:
        kwargs["base_url"] = base
    if model:
        kwargs["model"] = model
    return OpenAIChatModel(**kwargs)


# -- helpers ---------------------------------------------------------------

def _targets(report, entities, include_benign) -> List[Indicator]:
    """The indicators worth hunting, in first-seen order, de-duplicated."""
    if report is not None and report.indicators():
        out: List[Indicator] = []
        for ind in report.indicators():
            if not include_benign and report.verdict_for(ind.kind, ind.value).value == "benign":
                continue
            out.append(ind)
        return out
    if entities is not None:
        seen = set()
        out = []
        for ind in entities.iter_indicators():
            key = (ind.kind, ind.value)
            if key not in seen:
                seen.add(key)
                out.append(ind)
        return out
    return []


def _group_by_kind(indicators: List[Indicator]) -> "OrderedDict[str, List[Indicator]]":
    """Group indicators by kind, de-duplicating values within each kind."""
    groups: "OrderedDict[str, List[Indicator]]" = OrderedDict()
    seen = set()
    for ind in indicators:
        key = (ind.kind, ind.value)
        if key in seen:
            continue
        seen.add(key)
        groups.setdefault(ind.kind, []).append(ind)
    return groups


def _verdict(report, kind: str, value: str) -> str:
    """Duck-typed verdict string for one indicator (``unknown`` with no report)."""
    if report is None:
        return "unknown"
    return report.verdict_for(kind, value).value


def _severity_for(verdicts: List[str]) -> Severity:
    if "malicious" in verdicts:
        return Severity.HIGH
    if "suspicious" in verdicts:
        return Severity.MEDIUM
    return Severity.LOW


def _rationale(dialect, kind: str, values: List[str], verdicts: List[str]) -> str:
    n = len(values)
    mal = verdicts.count("malicious")
    susp = verdicts.count("suspicious")
    note = ""
    if mal or susp:
        bits = []
        if mal:
            bits.append(f"{mal} malicious")
        if susp:
            bits.append(f"{susp} suspicious")
        note = f" ({', '.join(bits)})"
    return (
        f"Sweep {dialect.label} telemetry for the {n} {kind} indicator(s)"
        f"{note} from this report."
    )
