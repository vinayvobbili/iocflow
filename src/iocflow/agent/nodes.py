"""The specialist agent nodes.

Each node does its exact work with the deterministic L1–L5 functions and applies
LLM judgment where judgment actually helps: the supervisor routes, and the
responder recommends an action and a justification for each indicator. Every
node degrades gracefully when no model is present (deterministic behavior), and
none of them raise — the graph always completes with a populated CaseFile.
"""
from __future__ import annotations

import json
import logging
import re
from typing import List, Optional

from iocflow.agent.gate import ApprovalGate, BlockProposal, DenyAllGate, ProposedAction
from iocflow.agent.state import CaseFile
from iocflow.severity import Severity

logger = logging.getLogger(__name__)

ORDER = ["extractor", "enricher", "hunter", "responder"]


# ----------------------------- supervisor -------------------------

def supervisor_node(state: CaseFile, *, model=None) -> dict:
    """Route to the next specialist (or END). LLM-routed when a model is present."""
    from langgraph.graph import END

    remaining = [s for s in ORDER if s not in state.get("visited", [])]
    if not remaining:
        return {"next": END}

    nxt = remaining[0]
    if model is not None:
        nxt = _llm_route(model, state, remaining) or remaining[0]
    return {"next": nxt, "trace": [f"supervisor → {nxt}"]}


def _llm_route(model, state: CaseFile, remaining: List[str]) -> Optional[str]:
    from langchain_core.messages import HumanMessage, SystemMessage

    from langgraph.graph import END

    done = state.get("visited", [])
    summary = _state_summary(state)
    sys = (
        "You are the supervisor of a threat-investigation team. Given what has "
        "been done so far, choose the SINGLE next step. Steps run in order: "
        "extractor (pull IOCs), enricher (reputation + assessment), hunter "
        "(suggested hunts), responder (propose/execute blocks with approval). "
        f"Already done: {done or 'nothing'}. Remaining: {remaining}. "
        "Reply with just one of the remaining step names, or 'END' to stop "
        "(e.g. if no indicators were found and nothing more is useful)."
    )
    try:
        out = str(model.invoke([SystemMessage(content=sys),
                                HumanMessage(content=summary)]).content).strip().lower()
    except Exception as exc:  # noqa: BLE001 — routing falls back to fixed order
        logger.warning("Supervisor LLM routing failed (%s); using fixed order", exc)
        return None
    if "end" in out and not any(s in out for s in remaining):
        return END
    for s in remaining:
        if s in out:
            return s
    return None


# ----------------------------- specialists ------------------------

def extractor_node(state: CaseFile, *, model=None) -> dict:
    from iocflow import extract

    entities = extract(state.get("text", ""))
    return {"entities": entities, "visited": ["extractor"],
            "trace": [f"extractor: {entities.summary()}"]}


def enricher_node(state: CaseFile, *, model=None, enrichers=None) -> dict:
    from iocflow.ai import comment
    from iocflow.enrich import enrich

    entities = state.get("entities")
    if entities is None:
        return {"visited": ["enricher"], "trace": ["enricher: no entities; skipped"]}
    report = enrich(entities, enrichers)  # given/env sources; empty if none
    note = comment(report, entities=entities, text=state.get("text"))
    return {"enrichment": report, "commentary": note, "visited": ["enricher"],
            "trace": [f"enricher: {report.summary()}; severity={note.severity.value}"]}


def hunter_node(state: CaseFile, *, model=None) -> dict:
    from iocflow.hunt import suggest

    report = state.get("enrichment")
    entities = state.get("entities")
    plan = suggest(report, entities=entities, commentary=state.get("commentary"))
    return {"hunts": plan, "visited": ["hunter"], "trace": [f"hunter: {plan.summary()}"]}


def responder_node(state: CaseFile, *, model=None, gate: Optional[ApprovalGate] = None,
                   blockers=None) -> dict:
    from iocflow.block import block, default_blockers

    gate = gate or DenyAllGate()
    report = state.get("enrichment")
    targets = blockers if blockers is not None else default_blockers()

    # 1. Deterministic dry run (guard + selection happen inside).
    dry = block(report, blockers=targets, dry_run=True)
    actions = _proposal_from_dry(dry)

    # 2. LLM judgment: recommend action + rationale per indicator.
    if model is not None and actions:
        actions = _llm_refine(model, actions, state.get("commentary"))

    proposal = BlockProposal(actions=actions, dry_run_report=dry)

    # 3. HITL: the gate authorizes a subset.
    decision = gate.review(proposal)
    approved = decision.approved

    # 4. Execute only approved actions live; otherwise the dry run stands.
    if approved:
        inds = [(a.kind, a.value) for a in approved]
        result = block(report, indicators=inds, blockers=targets, dry_run=False)
    else:
        result = dry

    return {
        "proposal": proposal, "block_report": result, "visited": ["responder"],
        "trace": [f"responder: {len(actions)} proposed, {len(approved)} approved "
                  f"({decision.note}); {result.summary()}"],
    }


# ----------------------------- helpers ----------------------------

def _proposal_from_dry(dry) -> List[ProposedAction]:
    """Group a dry-run report into one ProposedAction per indicator."""
    from iocflow.block.models import BlockStatus

    by_ind: "dict[tuple, list]" = {}
    for r in dry.results:
        if r.target == "guard" or r.status is not BlockStatus.DRY_RUN:
            continue
        by_ind.setdefault((r.kind, r.value), []).append(r.target)
    return [ProposedAction(kind=k, value=v, targets=sorted(t))
            for (k, v), t in by_ind.items()]


def _llm_refine(model, actions: List[ProposedAction], commentary) -> List[ProposedAction]:
    from langchain_core.messages import HumanMessage, SystemMessage

    listing = "\n".join(f"- {a.kind} {a.value} (targets: {', '.join(a.targets)})" for a in actions)
    context = getattr(commentary, "summary", "") or ""
    sys = (
        "You are the response engineer on a threat-investigation team. For each "
        "indicator below, recommend an enforcement action ('prevent' to block, "
        "'detect' to alert-only) and a one-line justification grounded in the "
        "assessment. Respond with a SINGLE JSON object: "
        '{"actions":[{"value": str, "action": "prevent"|"detect", "rationale": str}]}. '
        "Return only JSON."
    )
    user = f"Assessment: {context}\n\nIndicators:\n{listing}"
    try:
        raw = str(model.invoke([SystemMessage(content=sys), HumanMessage(content=user)]).content)
        refinements = _parse_refinements(raw)
    except Exception as exc:  # noqa: BLE001 — refinement is additive; keep deterministic actions
        logger.warning("Responder LLM refinement failed (%s); using defaults", exc)
        return actions

    for a in actions:
        ref = refinements.get(a.value)
        if ref:
            a.action = ref.get("action", a.action) if ref.get("action") in ("prevent", "detect") else a.action
            a.rationale = str(ref.get("rationale", "")).strip() or a.rationale
            if a.action == "detect":
                a.severity = Severity.MEDIUM
    return actions


_FENCE = re.compile(r"^```[a-zA-Z0-9]*\n|\n```$")


def _parse_refinements(raw: str) -> dict:
    s = _FENCE.sub("", raw.strip())
    start, end = s.find("{"), s.rfind("}")
    if start != -1 and end > start:
        s = s[start:end + 1]
    data = json.loads(s)
    out = {}
    for item in data.get("actions", []):
        if isinstance(item, dict) and item.get("value"):
            out[str(item["value"])] = item
    return out


def _state_summary(state: CaseFile) -> str:
    ents = state.get("entities")
    rep = state.get("enrichment")
    parts = [f"Report text: {state.get('text', '')[:300]}"]
    if ents is not None:
        parts.append(f"Extracted: {ents.summary()}")
    if rep is not None:
        parts.append(f"Enriched: {rep.summary()}")
    return "\n".join(parts)
