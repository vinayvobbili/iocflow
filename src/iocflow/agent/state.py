"""The shared case state for the agent graph.

``CaseFile`` is the LangGraph state — a single record that accretes as control
passes between specialist agents (entities → enrichment → commentary → hunts →
proposal → block report), plus a human-readable ``trace`` of what each agent
did. ``Case`` is the friendly result object :func:`iocflow.agent.investigate`
returns.
"""
from __future__ import annotations

import operator
from dataclasses import dataclass
from typing import Annotated, List, Optional, TypedDict


class CaseFile(TypedDict, total=False):
    """LangGraph state. Domain objects are stored whole; lists accumulate."""

    text: str
    entities: object          # ExtractedEntities (L1)
    enrichment: object        # EnrichmentReport (L2)
    commentary: object        # Commentary (L3)
    hunts: object             # HuntPlan (L4)
    proposal: object          # BlockProposal (L5, pre-approval)
    block_report: object      # BlockReport (L5, post-execution)
    trace: Annotated[List[str], operator.add]
    visited: Annotated[List[str], operator.add]
    next: str


@dataclass
class Case:
    """The completed investigation — every layer's output plus the trace."""

    text: str
    entities: object = None
    enrichment: object = None
    commentary: object = None
    hunts: object = None
    proposal: object = None
    block_report: object = None
    trace: Optional[List[str]] = None

    @classmethod
    def from_state(cls, state: CaseFile) -> "Case":
        return cls(
            text=state.get("text", ""),
            entities=state.get("entities"),
            enrichment=state.get("enrichment"),
            commentary=state.get("commentary"),
            hunts=state.get("hunts"),
            proposal=state.get("proposal"),
            block_report=state.get("block_report"),
            trace=list(state.get("trace", [])),
        )

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "entities": _d(self.entities),
            "enrichment": _d(self.enrichment),
            "commentary": _d(self.commentary),
            "hunts": _d(self.hunts),
            "proposal": _d(self.proposal),
            "block_report": _d(self.block_report),
            "trace": self.trace or [],
        }

    def summary(self) -> str:
        bits = []
        if self.entities is not None:
            bits.append(self.entities.summary())
        if self.enrichment is not None:
            bits.append(self.enrichment.summary())
        if self.block_report is not None:
            bits.append(self.block_report.summary())
        return " | ".join(b for b in bits if b)


def _d(obj):
    return obj.to_dict() if hasattr(obj, "to_dict") else obj
