"""Result types for ATT&CK coverage-gap analysis (Layer 4).

A :class:`CoverageItem` is one ATT&CK technique judged against a rule inventory:
``COVERED`` (a rule maps to it), ``GAP`` (nothing maps), or ``PARTIAL`` (a rule
maps, but the optional LLM pass doubts it catches *this* CTI's procedure). A
:class:`CoverageReport` collects one item per technique and is the serializable
seam for a "can we already detect this?" answer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

__all__ = ["CoverageStatus", "CoverageRule", "CoverageItem", "CoverageReport"]


class CoverageStatus(str, Enum):
    """Per-technique coverage verdict."""

    COVERED = "covered"     # >=1 catalog rule maps to this technique
    PARTIAL = "partial"     # mapped, but the LLM judged it may miss this procedure
    GAP = "gap"             # no catalog rule maps to this technique


@dataclass
class CoverageRule:
    """A catalog rule that maps to a technique (name + the platform it runs on)."""

    name: str
    source: str = ""  # "crowdstrike" | "sigma" | "cortex" | … (caller-supplied)
    techniques: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "source": self.source, "techniques": self.techniques}


@dataclass
class CoverageItem:
    """One technique's coverage verdict against the catalog."""

    technique: str  # "T1059.001"
    status: CoverageStatus
    name: str = ""  # ATT&CK technique name, best-effort (bare ID when unavailable)
    rules: List[CoverageRule] = field(default_factory=list)  # catalog rules that map
    rationale: str = ""  # set only by the optional LLM pass

    def to_dict(self) -> dict:
        return {
            "technique": self.technique,
            "name": self.name,
            "status": self.status.value,
            "rules": [r.to_dict() for r in self.rules],
            "rationale": self.rationale,
        }


@dataclass
class CoverageReport:
    """Coverage verdicts for every technique in an incoming CTI report."""

    items: List[CoverageItem] = field(default_factory=list)
    error: Optional[str] = None  # set when the LLM pass degraded (never fatal)

    @property
    def gaps(self) -> List[CoverageItem]:
        """Techniques with no mapped rule — where you are blind."""
        return [i for i in self.items if i.status is CoverageStatus.GAP]

    @property
    def covered(self) -> List[CoverageItem]:
        """Techniques with at least one mapped rule (covered or partial)."""
        return [i for i in self.items if i.status is not CoverageStatus.GAP]

    @property
    def partial(self) -> List[CoverageItem]:
        """Techniques the LLM pass downgraded from covered to partial."""
        return [i for i in self.items if i.status is CoverageStatus.PARTIAL]

    def to_dict(self) -> dict:
        return {
            "items": [i.to_dict() for i in self.items],
            "summary": self.summary(),
            "covered": len(self.covered),
            "gaps": len(self.gaps),
            "partial": len(self.partial),
            "total": len(self.items),
            "error": self.error,
        }

    def summary(self) -> str:
        total = len(self.items)
        if not total:
            return "No techniques to assess"
        parts = [f"{len(self.covered)}/{total} techniques covered"]
        n_partial = len(self.partial)
        if n_partial:
            parts.append(f"{n_partial} partial")
        parts.append(f"{len(self.gaps)} gaps")
        return ", ".join(parts)
