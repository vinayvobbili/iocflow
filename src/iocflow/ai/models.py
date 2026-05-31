"""Result types for AI commentary (Layer 3)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    """Analyst severity rating for a set of indicators."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    @classmethod
    def coerce(cls, value, default: "Severity") -> "Severity":
        """Parse a model-supplied severity string, falling back to ``default``."""
        if isinstance(value, Severity):
            return value
        try:
            return cls(str(value).strip().lower())
        except (ValueError, AttributeError):
            return default


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
