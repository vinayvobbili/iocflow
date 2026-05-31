"""VirusTotal v3 enricher — IPs, domains, URLs, and file hashes."""
from __future__ import annotations

import base64

from iocflow.enrich.base import HTTPEnricher
from iocflow.enrich.models import EnrichmentRecord, Verdict

_API = "https://www.virustotal.com/api/v3"
_GUI = "https://www.virustotal.com/gui"

# Map an indicator kind to (api path segment, gui path segment).
_ROUTES = {
    "ip": ("ip_addresses", "ip-address"),
    "domain": ("domains", "domain"),
    "url": ("urls", "url"),
    "md5": ("files", "file"),
    "sha1": ("files", "file"),
    "sha256": ("files", "file"),
}


class VirusTotalEnricher(HTTPEnricher):
    """Looks up reputation via the VirusTotal v3 API (free key works)."""

    name = "virustotal"
    supported_kinds = frozenset(_ROUTES)
    # Free tier is 4 requests/minute → ~15s between calls.
    min_interval = 15.0

    def _lookup(self, kind: str, value: str) -> EnrichmentRecord:
        api_seg, gui_seg = _ROUTES[kind]
        ident = _url_id(value) if kind == "url" else value
        data = self._get(
            f"{_API}/{api_seg}/{ident}",
            headers={"x-apikey": self.api_key or ""},
        )
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        verdict, score = _verdict_from_stats(stats)
        return self._record(
            kind,
            value,
            verdict=verdict,
            score=score,
            reference=f"{_GUI}/{gui_seg}/{ident}",
            raw={"last_analysis_stats": stats, "reputation": attrs.get("reputation")},
        )


def _url_id(url: str) -> str:
    """VirusTotal URL id: unpadded base64url of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _verdict_from_stats(stats: dict) -> "tuple[Verdict, float | None]":
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    total = sum(v for v in stats.values() if isinstance(v, int))
    if malicious > 0:
        score = round(100 * malicious / total, 1) if total else None
        return Verdict.MALICIOUS, score
    if suspicious > 0:
        score = round(100 * suspicious / total, 1) if total else None
        return Verdict.SUSPICIOUS, score
    if harmless > 0:
        return Verdict.BENIGN, 0.0
    return Verdict.UNKNOWN, None
