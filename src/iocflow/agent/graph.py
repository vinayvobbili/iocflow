"""The LangGraph supervisor graph and the ``investigate`` entry point.

A supervisor routes to specialist agents (extractor → enricher → hunter →
responder) and back, until the case is complete. The same graph runs with or
without a model: with one, the supervisor routes adaptively and the responder
applies judgment; without one, it runs the layers in a fixed deterministic
order. The human-in-the-loop approval gate guards the one destructive step.
"""
from __future__ import annotations

from functools import partial
from typing import Optional

from iocflow.agent.gate import ApprovalGate, DenyAllGate
from iocflow.agent.nodes import (
    enricher_node,
    extractor_node,
    hunter_node,
    responder_node,
    supervisor_node,
)
from iocflow.agent.state import Case, CaseFile


def build_graph(model=None, gate: Optional[ApprovalGate] = None, blockers=None,
                enrichers=None):
    """Build and compile the investigation graph, binding model/gate/blockers/enrichers."""
    from langgraph.graph import END, START, StateGraph

    gate = gate or DenyAllGate()
    g = StateGraph(CaseFile)

    g.add_node("supervisor", partial(supervisor_node, model=model))
    g.add_node("extractor", partial(extractor_node, model=model))
    g.add_node("enricher", partial(enricher_node, model=model, enrichers=enrichers))
    g.add_node("hunter", partial(hunter_node, model=model))
    g.add_node("responder", partial(responder_node, model=model, gate=gate, blockers=blockers))

    g.add_edge(START, "supervisor")
    g.add_conditional_edges(
        "supervisor",
        lambda s: s.get("next", END),
        {"extractor": "extractor", "enricher": "enricher", "hunter": "hunter",
         "responder": "responder", END: END},
    )
    for specialist in ("extractor", "enricher", "hunter", "responder"):
        g.add_edge(specialist, "supervisor")

    return g.compile()


def investigate(
    text: str,
    *,
    model=None,
    gate: Optional[ApprovalGate] = None,
    blockers=None,
    enrichers=None,
    recursion_limit: int = 25,
) -> Case:
    """Investigate a report end to end and return a :class:`Case`.

    Runs the full L1–L5 lifecycle as a multi-agent graph: extract → enrich +
    assess → suggest hunts → propose blocks → (human approval) → execute. Safe by
    default — the default :class:`~iocflow.agent.gate.DenyAllGate` approves
    nothing, so nothing is blocked unless you pass an approving gate.

    Args:
        text: The raw threat report / advisory / alert text.
        model: A LangChain chat model. Defaults to :func:`default_agent_model`
            (built from the environment); ``None`` runs the graph deterministically.
        gate: The HITL :class:`ApprovalGate`. Defaults to ``DenyAllGate``.
        blockers: Block targets for the responder (defaults to env-configured).
        enrichers: Threat-intel sources for the enricher (defaults to env-configured).
        recursion_limit: LangGraph step budget (supervisor + 4 specialists).
    """
    if model is None:
        from iocflow.agent.model import default_agent_model
        model = default_agent_model()

    graph = build_graph(model=model, gate=gate, blockers=blockers, enrichers=enrichers)
    final = graph.invoke(
        {"text": text, "trace": [], "visited": []},
        config={"recursion_limit": recursion_limit},
    )
    return Case.from_state(final)
