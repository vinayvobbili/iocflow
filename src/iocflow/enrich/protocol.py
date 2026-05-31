"""The structural ``Enricher`` protocol (no third-party imports)."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from iocflow.enrich.models import EnrichmentRecord


@runtime_checkable
class Enricher(Protocol):
    """Anything that can look up an indicator and return a record.

    Implementations need a ``name``, a ``supports(kind)`` predicate, and an
    ``enrich(kind, value)`` that returns an :class:`EnrichmentRecord` and does
    not raise (failures are reported via the record's ``error`` field).
    """

    name: str

    def supports(self, kind: str) -> bool: ...

    def enrich(self, kind: str, value: str) -> EnrichmentRecord: ...
