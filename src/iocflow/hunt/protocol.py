"""The ``Dialect`` protocol — render indicators into one query language.

A dialect knows which indicator kinds it can hunt for and how to render a list
of values of one kind into a runnable query. Dialects are pure and
stdlib-only — the deterministic core of Layer 4 has no external dependency.
"""
from __future__ import annotations

from typing import List, Protocol, runtime_checkable


@runtime_checkable
class Dialect(Protocol):
    """A hunt-query dialect (CrowdStrike CQL, Cortex XQL, Sigma, …)."""

    key: str  # stable identifier, e.g. "crowdstrike"
    label: str  # human label, e.g. "CrowdStrike CQL"

    def supports(self, kind: str) -> bool:
        """True if this dialect can render a hunt for ``kind``."""
        ...

    def render(self, kind: str, values: List[str]) -> str:
        """Render a query matching any of ``values`` (all of one ``kind``)."""
        ...
