"""The poller: poll sources, skip seen triggers, handle the new ones, mark them.

Scheduling stays *out* of the library — call :meth:`Poller.run_once` from your
own cron/systemd timer (as you would a real advisory poller), or
:meth:`Poller.run_forever` for a simple long-running loop.

The default handler runs the deterministic L1–L4 lifecycle (extract → enrich →
comment → suggest) and returns a :class:`~iocflow.sources.models.TriageResult`.
It never blocks anything — blocking stays behind the Layer 6 approval gate, so an
unattended poller proposes but a human still authorizes. To get the full
multi-agent path with a gate, pass ``handler=lambda t: investigate(t.text,
gate=...)`` (needs ``iocflow[agent]``).
"""
from __future__ import annotations

import logging
import time
from typing import Callable, List, Optional, Sequence

from iocflow.sources.models import PollResult, Trigger, TriageResult
from iocflow.sources.protocol import SeenStore, Source
from iocflow.sources.store import MemorySeenStore

logger = logging.getLogger(__name__)

Handler = Callable[[Trigger], object]


_KIND_FIELD = {
    "ip": "ips", "domain": "domains", "url": "urls", "email": "emails",
    "filename": "filenames", "cve": "cves", "mitre_technique": "mitre_techniques",
    "threat_actor": "threat_actors", "malware_family": "malware_families",
}


def _merge_indicators(entities, indicators) -> None:
    """Fold a trigger's pre-parsed (kind, value) indicators into the entities.

    Structured feeds (STIX/TAXII) carry indicators directly; without this they'd
    be lost because the text is only a pattern, not prose to extract from.
    """
    for kind, value in indicators or []:
        if not value:
            continue
        if kind in ("md5", "sha1", "sha256"):
            bucket = entities.hashes.setdefault(kind, [])
            if value not in bucket:
                bucket.append(value)
        elif kind in _KIND_FIELD:
            field = getattr(entities, _KIND_FIELD[kind])
            if value not in field:
                field.append(value)


def default_handler(trigger: Trigger) -> TriageResult:
    """Run the deterministic IOC lifecycle over a trigger. Never raises.

    Extracts from the trigger's text and merges any pre-parsed structured
    indicators it carries (e.g. from a STIX/TAXII source).
    """
    from iocflow import extract

    text = trigger.text or ""
    try:
        entities = extract(text)
        _merge_indicators(entities, trigger.indicators)
    except Exception as exc:  # noqa: BLE001 — extraction should not kill the poll
        logger.warning("extract failed for %s (%s)", trigger.key, exc)
        return TriageResult(trigger=trigger, error=f"extract: {exc}")

    enrichment = commentary = hunts = None
    try:
        from iocflow.ai import comment
        from iocflow.enrich import enrich
        from iocflow.hunt import suggest

        enrichment = enrich(entities)            # empty if no keys configured
        commentary = comment(enrichment, entities=entities, text=text)
        hunts = suggest(enrichment, entities=entities, commentary=commentary)
    except Exception as exc:  # noqa: BLE001 — degrade to extraction-only
        logger.warning("triage stage failed for %s (%s)", trigger.key, exc)

    return TriageResult(trigger=trigger, entities=entities, enrichment=enrichment,
                        commentary=commentary, hunts=hunts)


class Poller:
    """Polls sources, de-duplicates with a :class:`SeenStore`, handles new triggers.

    Args:
        sources: the feeds to poll.
        store: de-dup store. Defaults to an in-memory one — pass
            :class:`~iocflow.sources.store.SqliteSeenStore` to survive restarts.
        handler: called once per new trigger; defaults to :func:`default_handler`.
        mark_on_error: if False (default), a trigger whose handler raised is left
            *unmarked* so the next poll retries it. Set True to mark-and-move-on.
    """

    def __init__(
        self,
        sources: Sequence[Source],
        *,
        store: Optional[SeenStore] = None,
        handler: Optional[Handler] = None,
        mark_on_error: bool = False,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.sources = list(sources)
        self.store = store if store is not None else MemorySeenStore()
        self.handler = handler or default_handler
        self.mark_on_error = mark_on_error
        self._sleep = sleep_fn

    def run_once(self) -> List[PollResult]:
        """One pass over every source. Returns a result per newly-handled trigger."""
        results: List[PollResult] = []
        for src in self.sources:
            name = getattr(src, "name", src.__class__.__name__)
            try:
                triggers = list(src.poll())
            except Exception as exc:  # noqa: BLE001 — one bad source can't sink the rest
                logger.warning("source %r poll failed (%s); skipping", name, exc)
                continue
            for trig in triggers:
                if self.store.seen(trig.key):
                    continue
                results.append(self._handle(trig))
        return results

    def _handle(self, trig: Trigger) -> PollResult:
        try:
            out = self.handler(trig)
        except Exception as exc:  # noqa: BLE001 — a failing handler is a result, not a crash
            logger.exception("handler failed for %s", trig.key)
            if self.mark_on_error:
                self.store.mark(trig.key, ts=trig.ts or None)
            return PollResult(trigger=trig, error=str(exc))
        self.store.mark(trig.key, ts=trig.ts or None)
        return PollResult(trigger=trig, output=out)

    def run_forever(
        self,
        interval: float,
        *,
        max_iterations: Optional[int] = None,
        on_batch: Optional[Callable[[List[PollResult]], None]] = None,
    ) -> None:
        """Poll every ``interval`` seconds. ``max_iterations`` bounds it (tests).

        ``on_batch`` is called with each non-empty batch of results — wire it to
        notify a channel, write STIX, push to a TIP, etc.
        """
        i = 0
        while max_iterations is None or i < max_iterations:
            batch = self.run_once()
            if batch and on_batch is not None:
                on_batch(batch)
            i += 1
            if max_iterations is not None and i >= max_iterations:
                break
            self._sleep(interval)
