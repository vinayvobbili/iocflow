"""Result types for enrichment (Layer 2).

An :class:`EnrichmentRecord` is one source's verdict on one indicator. An
:class:`EnrichmentReport` collects every record produced for an
``ExtractedEntities`` and aggregates a verdict per indicator. The report is the
intended input type for Layer 3 (AI commentary).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from iocflow.models import Indicator


class Verdict(str, Enum):
    """A normalized verdict, comparable across sources."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Severity rank for aggregation (higher = worse, benign beats unknown)."""
        return {"malicious": 3, "suspicious": 2, "benign": 1, "unknown": 0}[self.value]


def aggregate_verdict(verdicts) -> Verdict:
    """Worst-wins aggregate of several verdicts (a positive signal beats none)."""
    worst = Verdict.UNKNOWN
    for v in verdicts:
        if v.rank > worst.rank:
            worst = v
    return worst


@dataclass
class EnrichmentRecord:
    """One source's lookup result for one indicator."""

    source: str
    kind: str
    value: str
    verdict: Verdict = Verdict.UNKNOWN
    score: Optional[float] = None  # 0–100 severity, when the source provides one
    reference: str = ""  # human pivot URL on the source
    raw: dict = field(default_factory=dict)  # the source's parsed payload
    error: Optional[str] = None  # set instead of raising when a lookup fails

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def indicator(self) -> Indicator:
        return Indicator(self.kind, self.value)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "kind": self.kind,
            "value": self.value,
            "verdict": self.verdict.value,
            "score": self.score,
            "reference": self.reference,
            "raw": self.raw,
            "error": self.error,
        }


@dataclass
class EnrichmentReport:
    """All enrichment records produced for a set of indicators."""

    records: List[EnrichmentRecord] = field(default_factory=list)

    def for_indicator(self, kind: str, value: str) -> List[EnrichmentRecord]:
        """Every record for one indicator."""
        return [r for r in self.records if r.kind == kind and r.value == value]

    def indicators(self) -> List[Indicator]:
        """Distinct indicators that have at least one record, in first-seen order."""
        out: List[Indicator] = []
        seen = set()
        for r in self.records:
            key = (r.kind, r.value)
            if key not in seen:
                seen.add(key)
                out.append(Indicator(r.kind, r.value))
        return out

    def verdict_for(self, kind: str, value: str) -> Verdict:
        """Aggregate (worst-wins) verdict for one indicator across sources."""
        return aggregate_verdict(
            r.verdict for r in self.for_indicator(kind, value) if r.ok
        )

    @property
    def malicious(self) -> List[Indicator]:
        """Indicators whose aggregate verdict is MALICIOUS."""
        return [
            ind
            for ind in self.indicators()
            if self.verdict_for(ind.kind, ind.value) is Verdict.MALICIOUS
        ]

    @property
    def errors(self) -> List[EnrichmentRecord]:
        """Records where a lookup failed."""
        return [r for r in self.records if not r.ok]

    def to_dict(self) -> dict:
        verdicts: Dict[str, str] = {}
        for ind in self.indicators():
            verdicts[f"{ind.kind}:{ind.value}"] = self.verdict_for(
                ind.kind, ind.value
            ).value
        return {
            "records": [r.to_dict() for r in self.records],
            "verdicts": verdicts,
        }

    def summary(self) -> str:
        inds = self.indicators()
        if not inds:
            return "No indicators enriched"
        mal = len(self.malicious)
        susp = sum(
            1
            for ind in inds
            if self.verdict_for(ind.kind, ind.value) is Verdict.SUSPICIOUS
        )
        errs = len(self.errors)
        parts = [f"{len(inds)} indicators across {len({r.source for r in self.records})} sources"]
        if mal:
            parts.append(f"{mal} malicious")
        if susp:
            parts.append(f"{susp} suspicious")
        if errs:
            parts.append(f"{errs} lookup errors")
        return ", ".join(parts)
