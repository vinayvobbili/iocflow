"""``MISPEnricher`` — look an indicator up in a MISP instance (Layer 2 source).

Conforms to the :class:`~iocflow.enrich.protocol.Enricher` protocol, so it drops
straight into ``enrich(entities, [MISPEnricher(...)])`` alongside VirusTotal /
AbuseIPDB / abuse.ch. A hit on an attribute flagged ``to_ids`` (an actionable,
shared IOC) is reported MALICIOUS; a non-``to_ids`` hit (context only) is
SUSPICIOUS; no hit is UNKNOWN — absence from MISP is not a clean bill of health.

Never raises: a misconfigured instance or a network error degrades to an
``EnrichmentRecord`` with ``error`` set, exactly like the HTTP enrichers.
"""
from __future__ import annotations

from typing import Optional

from iocflow.enrich.models import EnrichmentRecord, Verdict
from iocflow.misp.client import MispClient
from iocflow.misp.mapping import KIND_TO_MISP_TYPES

_SUPPORTED = frozenset({"ip", "domain", "url", "email", "md5", "sha1", "sha256"})


def _truthy(v) -> bool:
    """MISP renders ``to_ids`` as ``True``/``"1"``/``1`` depending on endpoint."""
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes")
    return bool(v)


class MISPEnricher:
    """Enrich indicators against a MISP instance via ``/attributes/restSearch``."""

    supported_kinds = _SUPPORTED

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        verify_tls: bool = True,
        timeout: float = 30.0,
        session=None,
        limit: int = 25,
        name: str = "misp",
    ) -> None:
        self.name = name
        self.limit = limit
        self.client = MispClient(
            url, api_key, verify_tls=verify_tls, timeout=timeout, session=session
        )

    # -- Enricher protocol --------------------------------------------------

    def supports(self, kind: str) -> bool:
        return kind in self.supported_kinds

    def enrich(self, kind: str, value: str) -> EnrichmentRecord:
        if not self.supports(kind):
            return self._record(kind, value, error=f"{self.name} does not support {kind}")
        if not self.client.configured:
            return self._record(kind, value, error=f"{self.name}: no instance URL/key configured")
        try:
            payload = self.client.post(
                "/attributes/restSearch",
                {
                    "returnFormat": "json",
                    "value": value,
                    "type": list(KIND_TO_MISP_TYPES.get(kind, ())),
                    "limit": self.limit,
                    "includeEventTags": True,
                },
            )
            return self._interpret(kind, value, payload)
        except Exception as exc:  # noqa: BLE001 — failures degrade to a record
            return self._record(kind, value, error=f"{type(exc).__name__}: {exc}")

    # -- internals ----------------------------------------------------------

    def _interpret(self, kind: str, value: str, payload: dict) -> EnrichmentRecord:
        attrs = ((payload or {}).get("response") or {}).get("Attribute") or []
        matches = [
            a
            for a in attrs
            if (a.get("value") or "") == value
            or value in (a.get("value") or "").split("|")
        ]
        if not matches:
            return self._record(kind, value, verdict=Verdict.UNKNOWN, raw={"misp_matches": 0})

        to_ids = any(_truthy(a.get("to_ids")) for a in matches)
        verdict = Verdict.MALICIOUS if to_ids else Verdict.SUSPICIOUS
        first = matches[0]
        event = first.get("Event") or {}
        event_id = event.get("id") or first.get("event_id") or ""
        tags = sorted(
            {t.get("name") for a in matches for t in (a.get("Tag") or []) if t.get("name")}
        )
        reference = f"{self.client.url}/events/view/{event_id}" if event_id else ""
        return self._record(
            kind,
            value,
            verdict=verdict,
            score=100.0 if to_ids else 50.0,
            reference=reference,
            raw={
                "misp_matches": len(matches),
                "to_ids": to_ids,
                "categories": sorted({a.get("category") for a in matches if a.get("category")}),
                "event_info": event.get("info"),
                "event_id": event_id,
                "tags": tags,
            },
        )

    def _record(self, kind: str, value: str, **kw) -> EnrichmentRecord:
        kw.setdefault("verdict", Verdict.UNKNOWN)
        return EnrichmentRecord(source=self.name, kind=kind, value=value, **kw)
