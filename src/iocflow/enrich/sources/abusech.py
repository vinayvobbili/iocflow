"""abuse.ch enricher — routes by kind to MalwareBazaar, URLhaus, and ThreatFox.

All three abuse.ch APIs require a free ``Auth-Key`` (one key works for all).
A hit in any of these databases means the indicator is known-bad, so a match is
reported as MALICIOUS; no match is UNKNOWN (absence of a record is not a clean
bill of health).
"""
from __future__ import annotations

from iocflow.enrich.base import HTTPEnricher
from iocflow.enrich.models import EnrichmentRecord, Verdict

_MALWAREBAZAAR = "https://mb-api.abuse.ch/api/v1/"
_URLHAUS = "https://urlhaus-api.abuse.ch/v1/url/"
_THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"

_HASH_KINDS = frozenset({"md5", "sha1", "sha256"})


class AbuseChEnricher(HTTPEnricher):
    """Looks up indicators across the abuse.ch databases."""

    name = "abuse.ch"
    supported_kinds = frozenset({"ip", "domain", "url"}) | _HASH_KINDS
    min_interval = 1.0

    @property
    def _auth(self) -> dict:
        return {"Auth-Key": self.api_key or ""}

    def _lookup(self, kind: str, value: str) -> EnrichmentRecord:
        if kind in _HASH_KINDS:
            return self._malwarebazaar(kind, value)
        if kind == "url":
            return self._urlhaus(kind, value)
        return self._threatfox(kind, value)

    # -- MalwareBazaar (hashes) --------------------------------------------

    def _malwarebazaar(self, kind: str, value: str) -> EnrichmentRecord:
        payload = self._post(
            _MALWAREBAZAAR,
            headers=self._auth,
            data={"query": "get_info", "hash": value},
        )
        if payload.get("query_status") != "ok":
            return self._miss(kind, value, payload.get("query_status"))
        entry = (payload.get("data") or [{}])[0]
        sha256 = entry.get("sha256_hash", value)
        return self._record(
            kind,
            value,
            verdict=Verdict.MALICIOUS,
            score=100.0,
            reference=f"https://bazaar.abuse.ch/sample/{sha256}/",
            raw={
                "signature": entry.get("signature"),
                "file_type": entry.get("file_type"),
                "first_seen": entry.get("first_seen"),
                "tags": entry.get("tags"),
            },
        )

    # -- URLhaus (urls) -----------------------------------------------------

    def _urlhaus(self, kind: str, value: str) -> EnrichmentRecord:
        payload = self._post(_URLHAUS, headers=self._auth, data={"url": value})
        if payload.get("query_status") != "ok":
            return self._miss(kind, value, payload.get("query_status"))
        return self._record(
            kind,
            value,
            verdict=Verdict.MALICIOUS,
            score=100.0,
            reference=payload.get("urlhaus_reference", ""),
            raw={
                "threat": payload.get("threat"),
                "url_status": payload.get("url_status"),
                "tags": payload.get("tags"),
                "blacklists": payload.get("blacklists"),
            },
        )

    # -- ThreatFox (ips, domains) ------------------------------------------

    def _threatfox(self, kind: str, value: str) -> EnrichmentRecord:
        payload = self._post(
            _THREATFOX,
            headers=self._auth,
            json={"query": "search_ioc", "search_term": value},
        )
        if payload.get("query_status") != "ok":
            return self._miss(kind, value, payload.get("query_status"))
        entry = (payload.get("data") or [{}])[0]
        confidence = entry.get("confidence_level")
        ioc_id = entry.get("id")
        return self._record(
            kind,
            value,
            verdict=Verdict.MALICIOUS,
            score=float(confidence) if confidence is not None else 100.0,
            reference=f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id else "",
            raw={
                "malware": entry.get("malware_printable"),
                "threat_type": entry.get("threat_type"),
                "confidence_level": confidence,
                "tags": entry.get("tags"),
            },
        )

    def _miss(self, kind: str, value: str, status) -> EnrichmentRecord:
        return self._record(
            kind, value, verdict=Verdict.UNKNOWN, raw={"query_status": status}
        )
