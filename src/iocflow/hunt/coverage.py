"""ATT&CK coverage-gap analysis: "can we already detect this?".

:func:`assess_coverage` is the companion to :func:`~iocflow.hunt.suggest`.
``suggest`` says *how to hunt*; ``assess_coverage`` says *where you're blind* —
given the ATT&CK techniques in a piece of CTI and the detection rules you already
run, it returns a per-technique verdict: ``covered``, ``partial``, or ``gap``.

    from iocflow import extract
    from iocflow.hunt import assess_coverage

    entities = extract(cti_report_text)
    catalog = [
        {"name": "Encoded PowerShell", "source": "crowdstrike", "techniques": ["T1059.001"]},
        {"name": "WMI Process Create",  "source": "sigma",       "techniques": ["T1047"]},
    ]
    report = assess_coverage(entities, catalog)   # deterministic, offline, never raises
    print(report.summary())                       # "1/3 techniques covered, 2 gaps"
    for gap in report.gaps:
        print("BLIND:", gap.technique)

The deterministic core needs no network and no keys. If a chat model is
configured (``IOCFLOW_LLM_*``, the same config as Layers 3/4) an optional pass
can downgrade ``covered -> partial`` when a mapped rule looks unlikely to catch
*this* CTI's procedure; any model failure leaves the deterministic result
intact. :func:`assess_coverage` never raises.
"""
from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence

from iocflow.hunt.coverage_models import (
    CoverageItem,
    CoverageReport,
    CoverageRule,
    CoverageStatus,
)
from iocflow.hunt.suggest import default_model

if TYPE_CHECKING:  # pragma: no cover - typing only
    from iocflow.ai.protocol import CommentaryModel
    from iocflow.models import ExtractedEntities

logger = logging.getLogger(__name__)

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_MAX_LLM_ITEMS = 40  # cap how many covered techniques we send to the model


def assess_coverage(
    entities: "Optional[ExtractedEntities]" = None,
    catalog: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    techniques: Optional[Sequence[str]] = None,
    model: "Optional[CommentaryModel]" = None,
    strict: bool = False,
) -> CoverageReport:
    """Assess how well a rule inventory covers a CTI report's ATT&CK techniques.

    Args:
        entities: L1 entities; the technique set defaults to
            ``entities.mitre_techniques``. Ignored when ``techniques`` is given.
        catalog: Your rule inventory — a list of plain dicts, each declaring the
            ATT&CK techniques it covers. Accepts ``{"name", "source"|"platform",
            "techniques"|"mitre_techniques"}`` (the same loose shape detflow's
            overlap input uses, so one exported inventory feeds both).
        techniques: Explicit ATT&CK technique IDs to assess, skipping extraction.
        model: A chat model for the optional ``covered -> partial`` refinement.
            Defaults to :func:`~iocflow.hunt.default_model` (from the
            environment); with none, only the deterministic verdict is returned.
        strict: When ``False`` (default), a sub-technique in the CTI is covered
            by a rule on its parent (``T1059.001`` satisfied by a ``T1059``
            rule). Set ``True`` to require exact-ID matches.

    Returns a :class:`CoverageReport`. Never raises.
    """
    wanted = _resolve_techniques(entities, techniques)
    index = _index_catalog(catalog or [])

    items: List[CoverageItem] = []
    for tech in wanted:
        rules = _match(tech, index, lenient=not strict)
        status = CoverageStatus.COVERED if rules else CoverageStatus.GAP
        items.append(CoverageItem(technique=tech, status=status, rules=rules))

    report = CoverageReport(items=items)

    if model is None:
        model = default_model()
    if model is not None and report.covered:
        _refine_with_model(report, model)

    return report


# -- deterministic core ----------------------------------------------------

def _resolve_techniques(
    entities: "Optional[ExtractedEntities]", techniques: Optional[Sequence[str]]
) -> List[str]:
    """The technique set to assess: explicit arg, else ``entities.mitre_techniques``.

    Normalizes to canonical upper-case IDs, drops anything that isn't a
    ``Txxxx[.xxx]`` shape, and de-duplicates while preserving first-seen order.
    """
    if techniques is not None:
        raw: Sequence[str] = techniques
    elif entities is not None:
        raw = getattr(entities, "mitre_techniques", []) or []
    else:
        raw = []

    out: List[str] = []
    seen = set()
    for t in raw:
        tid = str(t).strip().upper()
        if not _TECHNIQUE_RE.match(tid) or tid in seen:
            continue
        seen.add(tid)
        out.append(tid)
    return out


def _index_catalog(catalog: Sequence[Mapping[str, Any]]) -> Dict[str, List[CoverageRule]]:
    """Index catalog rules by the (upper-cased) techniques they declare."""
    index: Dict[str, List[CoverageRule]] = {}
    for raw in catalog:
        if not isinstance(raw, Mapping):
            continue
        name = str(raw.get("name") or raw.get("title") or "").strip()
        source = str(raw.get("source") or raw.get("platform") or "").strip()
        techs = raw.get("techniques")
        if techs is None:
            techs = raw.get("mitre_techniques")
        ids = [
            str(t).strip().upper()
            for t in (techs or [])
            if _TECHNIQUE_RE.match(str(t).strip().upper())
        ]
        if not ids:
            continue
        rule = CoverageRule(name=name or "(unnamed rule)", source=source, techniques=ids)
        for tid in ids:
            index.setdefault(tid, []).append(rule)
    return index


def _match(tech: str, index: Dict[str, List[CoverageRule]], *, lenient: bool) -> List[CoverageRule]:
    """Rules that cover ``tech`` — exact, plus the parent's rules when lenient."""
    rules = list(index.get(tech, []))
    if lenient and "." in tech:
        parent = tech.split(".", 1)[0]
        for r in index.get(parent, []):
            if r not in rules:
                rules.append(r)
    return rules


# -- optional LLM refinement (never fatal) ---------------------------------

_REFINE_SYSTEM = (
    "You are a detection engineer judging whether existing detection rules truly "
    "catch a set of MITRE ATT&CK techniques seen in fresh threat intel. A rule "
    "tagged with a technique ID does not always catch every procedure under it."
)


def _refine_with_model(report: CoverageReport, model: "CommentaryModel") -> None:
    """Downgrade ``covered -> partial`` where the model doubts real coverage.

    Mutates ``report`` in place. Any model/parse failure leaves the deterministic
    verdicts untouched and records a non-fatal note in ``report.error``.
    """
    covered = report.covered[:_MAX_LLM_ITEMS]
    user = _build_refine_prompt(covered)
    try:
        raw = model.complete(_REFINE_SYSTEM, user, json=True)
    except Exception as exc:  # noqa: BLE001 — refinement must never be fatal
        logger.warning("Coverage model failed (%s); keeping deterministic verdicts", exc)
        report.error = f"coverage refinement skipped: model error: {type(exc).__name__}: {exc}"
        return

    verdicts = _parse_refine(raw)
    if verdicts is None:
        report.error = "coverage refinement skipped: unparseable model output"
        return

    by_tech = {i.technique: i for i in covered}
    for tech, (is_partial, rationale) in verdicts.items():
        item = by_tech.get(tech.strip().upper())
        if item is None or not is_partial:
            continue
        item.status = CoverageStatus.PARTIAL
        item.rationale = rationale


def _build_refine_prompt(items: Sequence[CoverageItem]) -> str:
    lines = []
    for item in items:
        rules = "; ".join(f"{r.name} [{r.source}]" if r.source else r.name for r in item.rules)
        lines.append(f"  - {item.technique}: matched rules = {rules or '(none)'}")
    return (
        "These ATT&CK techniques appeared in incoming threat intel, each with the "
        "detection rule(s) currently tagged for it:\n"
        + "\n".join(lines)
        + "\n\nFor each technique, judge whether the matched rule(s) plausibly catch "
        "the activity, or whether coverage is only PARTIAL (the rule is tagged for "
        "the technique but likely misses common procedures under it).\n\n"
        'Respond with ONLY a JSON object: {"techniques": [{"technique": "T1059.001", '
        '"partial": true, "rationale": "1 sentence why"}]}. Include ONLY techniques '
        "you judge PARTIAL; omit ones that are genuinely covered."
    )


_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _parse_refine(raw: str) -> "Optional[Dict[str, tuple]]":
    """Parse the refinement response to ``{technique: (is_partial, rationale)}`` or ``None``."""
    text = (raw or "").strip()
    if not text:
        return None
    m = _FENCE.search(text)
    if m:
        text = m.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(data, dict):
        return None
    rows = data.get("techniques")
    if not isinstance(rows, list):
        return None

    out: Dict[str, tuple] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        tid = str(row.get("technique", "")).strip().upper()
        if not tid:
            continue
        out[tid] = (bool(row.get("partial", True)), str(row.get("rationale", "")).strip())
    return out
