"""iocflow Layer 2 — enrichment.

Take the :class:`~iocflow.models.ExtractedEntities` produced by Layer 1 and
look every indicator up against threat-intel sources, returning a normalized
:class:`EnrichmentReport`.

    from iocflow import extract
    from iocflow.enrich import enrich

    entities = extract(report_text)
    report = enrich(entities)          # uses every source whose API key is set
    print(report.summary())
    for ind in report.malicious:
        print("malicious:", ind.kind, ind.value)

Set keys via the environment (``IOCFLOW_VT_API_KEY``,
``IOCFLOW_ABUSEIPDB_API_KEY``, ``IOCFLOW_ABUSECH_API_KEY``) or pass enrichers
explicitly:

    from iocflow.enrich import enrich, VirusTotalEnricher
    report = enrich(entities, [VirusTotalEnricher("my-key")])

Needs the extra: ``pip install "iocflow[enrich]"``.
"""
from iocflow.enrich.base import EnricherError, HTTPEnricher
from iocflow.enrich.cache import Cache, MemoryCache
from iocflow.enrich.models import (
    EnrichmentRecord,
    EnrichmentReport,
    Verdict,
    aggregate_verdict,
)
from iocflow.enrich.protocol import Enricher
from iocflow.enrich.runner import default_enrichers, enrich
from iocflow.enrich.sources import (
    AbuseChEnricher,
    AbuseIPDBEnricher,
    VirusTotalEnricher,
)

__all__ = [
    # Orchestrator
    "enrich",
    "default_enrichers",
    # Result types
    "EnrichmentReport",
    "EnrichmentRecord",
    "Verdict",
    "aggregate_verdict",
    # Protocol + base
    "Enricher",
    "HTTPEnricher",
    "EnricherError",
    # Cache
    "Cache",
    "MemoryCache",
    # Sources
    "VirusTotalEnricher",
    "AbuseIPDBEnricher",
    "AbuseChEnricher",
]
