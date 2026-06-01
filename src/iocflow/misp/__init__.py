"""iocflow ↔ MISP interop.

MISP (the open-source Malware Information Sharing Platform) is where many teams
already keep their shared threat intel. This layer connects iocflow to it three
ways, each conforming to an existing iocflow seam:

* :class:`MISPEnricher` — an :class:`~iocflow.enrich.protocol.Enricher`: look an
  indicator up in MISP (``to_ids`` hit → malicious).
* :class:`MISPEventSource` — a :class:`~iocflow.sources.protocol.Source`: poll a
  MISP instance for events and feed them through the lifecycle.
* :class:`MISPPublisher` — a share-back sink: push a triage result *out* as a
  MISP event (safe by default — ``dry_run=True``, org-only distribution).

    from iocflow import extract
    from iocflow.enrich import enrich
    from iocflow.misp import MISPEnricher, MISPPublisher

    entities = extract(report_text)
    report = enrich(entities, [MISPEnricher("https://misp.example.org", key)])
    MISPPublisher("https://misp.example.org", key).publish(report)   # dry-run

Configure via the environment (``IOCFLOW_MISP_URL`` + ``IOCFLOW_MISP_KEY``) or
pass ``url``/``api_key`` explicitly. Stdlib + ``requests`` only (no ``pymisp``).

Needs the extra: ``pip install "iocflow[misp]"``.
"""
from iocflow.misp.client import MispClient
from iocflow.misp.enricher import MISPEnricher
from iocflow.misp.mapping import (
    KIND_TO_MISP_TYPES,
    KIND_TO_PUBLISH_TYPE,
    MISP_TYPE_TO_KIND,
    attribute_indicators,
)
from iocflow.misp.publish import MISPPublisher
from iocflow.misp.source import MISPEventSource

__all__ = [
    "MispClient",
    "MISPEnricher",
    "MISPEventSource",
    "MISPPublisher",
    "attribute_indicators",
    "KIND_TO_MISP_TYPES",
    "MISP_TYPE_TO_KIND",
    "KIND_TO_PUBLISH_TYPE",
]
