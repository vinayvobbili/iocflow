"""AbuseIPDB enricher — IP reputation only."""
from __future__ import annotations

from iocflow.enrich.base import HTTPEnricher
from iocflow.enrich.models import EnrichmentRecord, Verdict

_API = "https://api.abuseipdb.com/api/v2/check"
_GUI = "https://www.abuseipdb.com/check"


class AbuseIPDBEnricher(HTTPEnricher):
    """Looks up IP abuse confidence via AbuseIPDB (free key works)."""

    name = "abuseipdb"
    supported_kinds = frozenset({"ip"})
    # Free tier is generous (1000/day); a light spacing avoids bursts.
    min_interval = 1.0

    def __init__(self, *args, max_age_days: int = 90, **kw) -> None:
        super().__init__(*args, **kw)
        self.max_age_days = max_age_days

    def _lookup(self, kind: str, value: str) -> EnrichmentRecord:
        payload = self._get(
            _API,
            headers={"Key": self.api_key or "", "Accept": "application/json"},
            params={"ipAddress": value, "maxAgeInDays": self.max_age_days},
        )
        data = payload.get("data", {}) or {}
        confidence = data.get("abuseConfidenceScore", 0) or 0
        verdict = _verdict_from_confidence(confidence)
        return self._record(
            kind,
            value,
            verdict=verdict,
            score=float(confidence),
            reference=f"{_GUI}/{value}",
            raw={
                "abuseConfidenceScore": confidence,
                "totalReports": data.get("totalReports"),
                "countryCode": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
            },
        )


def _verdict_from_confidence(confidence: int) -> Verdict:
    if confidence >= 50:
        return Verdict.MALICIOUS
    if confidence >= 25:
        return Verdict.SUSPICIOUS
    return Verdict.BENIGN
