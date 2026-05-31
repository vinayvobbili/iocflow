"""The enrichment orchestrator: route indicators to enrichers, fan out, collect."""
from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Optional, Sequence

from iocflow.enrich.cache import Cache
from iocflow.enrich.models import EnrichmentRecord, EnrichmentReport
from iocflow.enrich.protocol import Enricher
from iocflow.models import ExtractedEntities, Indicator

logger = logging.getLogger(__name__)


def enrich(
    entities: ExtractedEntities,
    enrichers: Optional[Sequence[Enricher]] = None,
    *,
    kinds: Optional[Iterable[str]] = None,
    max_workers: int = 8,
    cache: Optional[Cache] = None,
) -> EnrichmentReport:
    """Enrich every indicator in ``entities`` with the given ``enrichers``.

    Args:
        entities: The L1 extraction result to enrich.
        enrichers: Sources to query. Defaults to :func:`default_enrichers`
            (every source whose API key is present in the environment).
        kinds: Restrict to these indicator kinds (e.g. ``{"ip", "domain"}``).
        max_workers: Thread-pool size for the fan-out.
        cache: Optional cache; successful lookups are stored and reused.

    Returns:
        An :class:`EnrichmentReport`.
    """
    if enrichers is None:
        enrichers = default_enrichers()
    if not enrichers:
        logger.warning("No enrichers configured (no API keys found); report will be empty")
        return EnrichmentReport()

    wanted = set(kinds) if kinds is not None else None
    indicators = _dedup(entities.iter_indicators(), wanted)

    # One task per (enricher, indicator) where the enricher supports the kind.
    tasks = [
        (en, ind)
        for ind in indicators
        for en in enrichers
        if en.supports(ind.kind)
    ]
    if not tasks:
        return EnrichmentReport()

    records: List[EnrichmentRecord] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run_one, en, ind, cache): (en, ind) for en, ind in tasks}
        for future in as_completed(futures):
            records.append(future.result())

    report = EnrichmentReport(records=records)
    logger.info("Enrichment: %s", report.summary())
    return report


def _dedup(indicators: Iterable[Indicator], wanted: Optional[set]) -> List[Indicator]:
    out: List[Indicator] = []
    seen = set()
    for ind in indicators:
        if wanted is not None and ind.kind not in wanted:
            continue
        key = (ind.kind, ind.value)
        if key not in seen:
            seen.add(key)
            out.append(ind)
    return out


def _run_one(enricher: Enricher, ind: Indicator, cache: Optional[Cache]) -> EnrichmentRecord:
    key = (enricher.name, ind.kind, ind.value)
    if cache is not None:
        cached = cache.get(key)
        if cached is not None:
            return cached
    record = enricher.enrich(ind.kind, ind.value)
    if cache is not None and record.ok:
        cache.set(key, record)
    return record


def default_enrichers(env: Optional[dict] = None) -> List[Enricher]:
    """Build every free-tier enricher whose API key is present.

    Reads, by default, from ``os.environ``:

    - ``IOCFLOW_VT_API_KEY``        → VirusTotal
    - ``IOCFLOW_ABUSEIPDB_API_KEY`` → AbuseIPDB
    - ``IOCFLOW_ABUSECH_API_KEY``   → abuse.ch (ThreatFox / URLhaus / MalwareBazaar)

    Sources with no key are silently skipped, so the same call works whether you
    have one key or all three.
    """
    from iocflow.enrich.sources import (
        AbuseChEnricher,
        AbuseIPDBEnricher,
        VirusTotalEnricher,
    )

    env = env if env is not None else os.environ
    enrichers: List[Enricher] = []

    vt = env.get("IOCFLOW_VT_API_KEY")
    if vt:
        enrichers.append(VirusTotalEnricher(vt))

    aipdb = env.get("IOCFLOW_ABUSEIPDB_API_KEY")
    if aipdb:
        enrichers.append(AbuseIPDBEnricher(aipdb))

    abusech = env.get("IOCFLOW_ABUSECH_API_KEY")
    if abusech:
        enrichers.append(AbuseChEnricher(abusech))

    return enrichers
