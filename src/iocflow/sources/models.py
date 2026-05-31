"""Data types for the ingestion seam: a ``Trigger`` in, a ``TriageResult`` out."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class Trigger:
    """One unit of work emitted by a :class:`~iocflow.sources.protocol.Source`.

    A trigger carries free text (an advisory body, an RSS summary) and/or
    pre-parsed ``indicators``/``stix`` from a structured feed. ``source`` + ``id``
    form the dedup ``key`` — re-emitting the same id is a no-op for a poller.
    """

    source: str
    id: str
    text: str = ""
    indicators: List[Tuple[str, str]] = field(default_factory=list)  # (kind, value)
    stix: Optional[dict] = None
    title: str = ""
    url: str = ""
    ts: str = ""  # source-provided timestamp (ISO8601 if available)
    meta: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        """The stable identity used for de-duplication."""
        return f"{self.source}:{self.id}"

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "id": self.id,
            "key": self.key,
            "text": self.text,
            "indicators": [list(i) for i in self.indicators],
            "stix": self.stix,
            "title": self.title,
            "url": self.url,
            "ts": self.ts,
            "meta": self.meta,
        }


@dataclass
class TriageResult:
    """What the default poller handler returns for one trigger.

    The deterministic L1–L4 lifecycle run over the trigger's text: extracted
    entities, the enrichment report, the AI/deterministic commentary, and the
    suggested hunts. Blocking is intentionally *not* here — it stays behind the
    Layer 6 approval gate, so an unattended poller proposes but never acts.
    """

    trigger: Trigger
    entities: object = None
    enrichment: object = None
    commentary: object = None
    hunts: object = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        def _d(obj):
            return obj.to_dict() if hasattr(obj, "to_dict") else None

        return {
            "trigger": self.trigger.to_dict(),
            "entities": _d(self.entities),
            "enrichment": _d(self.enrichment),
            "commentary": _d(self.commentary),
            "hunts": _d(self.hunts),
            "error": self.error,
        }

    def summary(self) -> str:
        if self.error:
            return f"[{self.trigger.source}] {self.trigger.title or self.trigger.id}: ERROR {self.error}"
        bits = [f"[{self.trigger.source}] {self.trigger.title or self.trigger.id}"]
        if self.entities is not None and hasattr(self.entities, "summary"):
            bits.append(self.entities.summary())
        if self.commentary is not None and hasattr(self.commentary, "severity"):
            bits.append(f"severity={self.commentary.severity.value}")
        return " | ".join(bits)


@dataclass
class PollResult:
    """The outcome of handling one new trigger during a poll."""

    trigger: Trigger
    output: object = None  # whatever the handler returned (a TriageResult by default)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict:
        return {
            "trigger": self.trigger.to_dict(),
            "output": self.output.to_dict() if hasattr(self.output, "to_dict") else None,
            "error": self.error,
        }
