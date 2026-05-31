"""The shared ``Severity`` scale.

Lives in the dependency-light core so multiple layers (AI commentary, suggested
hunts, …) can share one severity type without importing each other.
"""
from __future__ import annotations

from enum import Enum


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
