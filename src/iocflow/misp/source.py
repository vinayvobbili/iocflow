"""``MISPEventSource`` — a MISP instance as an ingestion :class:`Source`.

Polls ``/events/restSearch`` (optionally filtered by tag / published state /
recency) and turns each event into a :class:`~iocflow.sources.models.Trigger`:
the event ``info`` becomes the text, every attribute (including those nested in
MISP objects) is folded in as a structured indicator. De-dup is the poller's job,
keyed on the event UUID.
"""
from __future__ import annotations

from typing import List, Optional, Sequence

from iocflow.misp.client import MispClient
from iocflow.misp.mapping import attribute_indicators
from iocflow.sources.models import Trigger


class MISPEventSource:
    """Polls one MISP instance for events.

    Args:
        url/api_key: instance + automation key (env fallbacks via ``MispClient``).
        tags: keep only events carrying these tags (MISP tag filter).
        published: ``True`` (default) restricts to published events; ``None`` keeps all.
        last: relative recency window MISP understands, e.g. ``"7d"``, ``"24h"``.
        limit: page-size hint.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        tags: Optional[Sequence[str]] = None,
        published: Optional[bool] = True,
        last: Optional[str] = "7d",
        limit: int = 100,
        verify_tls: bool = True,
        timeout: float = 30.0,
        session=None,
        name: str = "misp",
    ) -> None:
        self.name = name
        self.tags = list(tags) if tags else None
        self.published = published
        self.last = last
        self.limit = limit
        self.client = MispClient(
            url, api_key, verify_tls=verify_tls, timeout=timeout, session=session
        )

    def _search_payload(self) -> dict:
        payload: dict = {"returnFormat": "json", "limit": self.limit}
        if self.published is not None:
            payload["published"] = self.published
        if self.tags:
            payload["tags"] = self.tags
        if self.last:
            payload["last"] = self.last
        return payload

    def poll(self) -> List[Trigger]:
        if not self.client.configured:
            return []
        data = self.client.post("/events/restSearch", self._search_payload())
        events = (data or {}).get("response") or []
        triggers: List[Trigger] = []
        for wrapper in events:
            event = wrapper.get("Event") if isinstance(wrapper, dict) else None
            if not event:
                continue
            trig = self._to_trigger(event)
            if trig is not None:
                triggers.append(trig)
        return triggers

    def _to_trigger(self, event: dict) -> Optional[Trigger]:
        eid = event.get("uuid") or event.get("id")
        if not eid:
            return None
        attrs = list(event.get("Attribute") or [])
        for obj in event.get("Object") or []:
            attrs.extend(obj.get("Attribute") or [])

        indicators: List[tuple] = []
        seen = set()
        for a in attrs:
            for pair in attribute_indicators(a.get("type"), a.get("value")):
                if pair not in seen:
                    seen.add(pair)
                    indicators.append(pair)

        info = event.get("info") or ""
        comments = " ".join(a.get("comment") for a in attrs if a.get("comment"))
        text = (info + ("\n" + comments if comments else "")).strip()
        tags = [t.get("name") for t in (event.get("Tag") or []) if t.get("name")]
        view_id = event.get("id") or eid
        return Trigger(
            source=self.name,
            id=str(eid),
            text=text,
            indicators=indicators,
            title=info,
            url=f"{self.client.url}/events/view/{view_id}" if self.client.url else "",
            ts=str(event.get("date") or event.get("timestamp") or ""),
            meta={
                "tags": tags,
                "threat_level_id": event.get("threat_level_id"),
                "org": (event.get("Orgc") or {}).get("name"),
            },
        )
