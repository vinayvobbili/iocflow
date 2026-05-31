"""Result types for AI commentary (Layer 3)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# Severity is a shared, dependency-light core type; re-exported here so the
# Layer 3 public API (``from iocflow.ai.models import Severity``) is unchanged.
from iocflow.severity import Severity

__all__ = ["Severity", "Commentary"]


@dataclass
class Commentary:
    """An analyst-style assessment of an enriched indicator set."""

    summary: str = ""  # short narrative
    severity: Severity = Severity.INFO
    assessment: str = ""  # fuller narrative (may equal summary)
    key_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    model: str = ""  # the model that produced this ("" when deterministic fallback)
    raw: str = ""  # the model's raw output, when any
    error: Optional[str] = None  # set when the LLM was unavailable or degraded

    @property
    def llm_generated(self) -> bool:
        """True if a model produced fully-structured output (no error/fallback)."""
        return self.error is None and bool(self.model)

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "severity": self.severity.value,
            "assessment": self.assessment,
            "key_findings": self.key_findings,
            "recommendations": self.recommendations,
            "model": self.model,
            "error": self.error,
        }
