"""``MISPPublisher`` — share iocflow results back to MISP (the loop-closing sink).

The other MISP pieces pull intelligence *in*; this pushes a triage result back
*out* as a MISP event so the community benefits from what you found. It accepts
anything that carries indicators — ``ExtractedEntities``, an ``EnrichmentReport``
(whose verdicts decide which attributes are ``to_ids``), or a ``Case`` /
``TriageResult`` (uses ``.entities`` plus an attached ``.enrichment``).

Safe by default, like Layer 5 blocking: ``dry_run=True`` builds the event payload
and returns it WITHOUT contacting the server; ``distribution=0`` (your org only)
and ``published=False`` mean even a real call shares nothing wider until you
deliberately widen it. Never raises — failures come back as ``{"ok": False, ...}``.
"""
from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from iocflow.misp.client import MispClient
from iocflow.misp.mapping import KIND_TO_PUBLISH_TYPE, PUBLISH_CATEGORY


def _collect(source) -> Tuple[List[Tuple[str, str]], dict]:
    """Duck-type any iocflow result into ``(pairs, verdicts)``.

    ``pairs`` is an ordered, de-duplicated ``(kind, value)`` list; ``verdicts``
    maps ``(kind, value)`` to its worst verdict string when an enrichment report
    is available (drives ``to_ids``).
    """
    verdicts: dict = {}
    report = source if hasattr(source, "records") else getattr(source, "enrichment", None)
    if report is not None and hasattr(report, "records"):
        for r in report.records:
            pair = (r.kind, r.value)
            v = getattr(getattr(r, "verdict", None), "value", None)
            if v and verdicts.get(pair) != "malicious":
                verdicts[pair] = v

    if hasattr(source, "iter_indicators"):
        raw = [(i.kind, i.value) for i in source.iter_indicators()]
    elif getattr(source, "entities", None) is not None and hasattr(
        source.entities, "iter_indicators"
    ):
        raw = [(i.kind, i.value) for i in source.entities.iter_indicators()]
    elif hasattr(source, "records"):
        raw = [(r.kind, r.value) for r in source.records]
    else:
        raw = [(k, v) for k, v in source]

    seen, pairs = set(), []
    for p in raw:
        if p[1] and p not in seen:
            seen.add(p)
            pairs.append(p)
    return pairs, verdicts


class MISPPublisher:
    """Build (and optionally create) a MISP event from an iocflow result."""

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        distribution: int = 0,
        threat_level_id: int = 2,
        analysis: int = 2,
        published: bool = False,
        tags: Optional[Sequence[str]] = None,
        default_info: str = "iocflow shared indicators",
        dry_run: bool = True,
        verify_tls: bool = True,
        timeout: float = 30.0,
        session=None,
    ) -> None:
        self.distribution = distribution
        self.threat_level_id = threat_level_id
        self.analysis = analysis
        self.published = published
        self.tags = list(tags) if tags else []
        self.default_info = default_info
        self.dry_run = dry_run
        self.client = MispClient(
            url, api_key, verify_tls=verify_tls, timeout=timeout, session=session
        )

    def build_event(
        self,
        source,
        *,
        info: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        force_to_ids: Optional[bool] = None,
    ) -> dict:
        """Build the ``{"Event": {...}}`` payload without contacting the server.

        ``to_ids`` is set per attribute from its enrichment verdict (malicious →
        actionable), unless ``force_to_ids`` overrides every attribute.
        """
        pairs, verdicts = _collect(source)
        attributes = []
        for kind, value in pairs:
            mtype = KIND_TO_PUBLISH_TYPE.get(kind)
            if not mtype:
                continue
            if force_to_ids is None:
                to_ids = verdicts.get((kind, value)) == "malicious"
            else:
                to_ids = bool(force_to_ids)
            attributes.append({
                "type": mtype,
                "value": value,
                "category": PUBLISH_CATEGORY.get(kind, "Network activity"),
                "to_ids": to_ids,
            })
        event: dict = {
            "info": info or self.default_info,
            "distribution": self.distribution,
            "threat_level_id": self.threat_level_id,
            "analysis": self.analysis,
            "published": self.published,
            "Attribute": attributes,
        }
        all_tags = self.tags + list(tags or [])
        if all_tags:
            event["Tag"] = [{"name": t} for t in all_tags]
        return {"Event": event}

    def publish(
        self,
        source,
        *,
        info: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        force_to_ids: Optional[bool] = None,
        dry_run: Optional[bool] = None,
    ) -> dict:
        """Share ``source`` as a MISP event. Returns a result dict, never raises.

        With ``dry_run`` (the default), returns the would-be payload untouched.
        """
        dry = self.dry_run if dry_run is None else dry_run
        payload = self.build_event(source, info=info, tags=tags, force_to_ids=force_to_ids)
        if not payload["Event"]["Attribute"]:
            return {"ok": False, "dry_run": dry, "event": payload,
                    "error": "no shareable indicators"}
        if dry:
            return {"ok": True, "dry_run": True, "event": payload}
        if not self.client.configured:
            return {"ok": False, "dry_run": False, "event": payload,
                    "error": "misp: no instance URL/key configured"}
        try:
            resp = self.client.post("/events/add", payload)
            ev = (resp or {}).get("Event") or {}
            return {"ok": True, "dry_run": False, "event_id": ev.get("id"),
                    "uuid": ev.get("uuid"), "response": resp}
        except Exception as exc:  # noqa: BLE001 — failures degrade to a result
            return {"ok": False, "dry_run": False, "event": payload,
                    "error": f"{type(exc).__name__}: {exc}"}
