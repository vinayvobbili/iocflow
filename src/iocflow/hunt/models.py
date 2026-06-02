"""Result types for suggested hunts (Layer 4).

A :class:`Hunt` is one ready-to-run query in one dialect, covering a set of
indicators. A :class:`HuntPlan` collects every hunt produced for an enrichment
report (or extracted entities) and is the serializable seam for Layer 5.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from iocflow.models import Indicator
from iocflow.severity import Severity

__all__ = ["Hunt", "HuntPlan", "Severity"]


@dataclass
class Hunt:
    """A single hunt query in one dialect."""

    title: str
    dialect: str  # "crowdstrike" | "cortex" | "sigma"
    query: str  # the rendered, ready-to-run query
    indicators: List[Indicator] = field(default_factory=list)  # what it searches for
    kinds: List[str] = field(default_factory=list)  # indicator kinds covered
    rationale: str = ""  # why this hunt, in plain language
    severity: Severity = Severity.INFO
    source: str = "deterministic"  # "deterministic" | "llm"
    # Behavioral (LLM) hunts are validated against their dialect and repaired if
    # broken. Deterministic hunts are valid by construction. When a behavioral
    # hunt can't be repaired it is still surfaced with ``validated=False`` and the
    # reason — a suggestion for a human to review, never silently dropped.
    validated: bool = True
    validation_error: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "dialect": self.dialect,
            "query": self.query,
            "indicators": [{"kind": i.kind, "value": i.value} for i in self.indicators],
            "kinds": self.kinds,
            "rationale": self.rationale,
            "severity": self.severity.value,
            "source": self.source,
            "validated": self.validated,
            "validation_error": self.validation_error,
        }


@dataclass
class HuntPlan:
    """All hunts suggested for a set of indicators."""

    hunts: List[Hunt] = field(default_factory=list)
    error: Optional[str] = None  # set when the LLM-hunt path degraded (never fatal)

    def for_dialect(self, dialect: str) -> List[Hunt]:
        """Every hunt rendered in one dialect."""
        return [h for h in self.hunts if h.dialect == dialect]

    @property
    def dialects(self) -> List[str]:
        """Distinct dialects present, in first-seen order."""
        out: List[str] = []
        for h in self.hunts:
            if h.dialect not in out:
                out.append(h.dialect)
        return out

    @property
    def severity(self) -> Severity:
        """The worst severity across all hunts (INFO when empty)."""
        worst = Severity.INFO
        for h in self.hunts:
            if h.severity.rank > worst.rank:
                worst = h.severity
        return worst

    def to_dict(self) -> dict:
        return {
            "hunts": [h.to_dict() for h in self.hunts],
            "severity": self.severity.value,
            "error": self.error,
        }

    def summary(self) -> str:
        if not self.hunts:
            return "No hunts suggested"
        n_llm = sum(1 for h in self.hunts if h.source == "llm")
        parts = [f"{len(self.hunts)} hunts across {len(self.dialects)} dialects"]
        if n_llm:
            parts.append(f"{n_llm} behavioral (LLM)")
        return ", ".join(parts)
