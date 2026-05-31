"""iocflow STIX interop — the threat-intel lingua franca, in and out.

``from_stix`` parses a STIX 2.x bundle / object(s) into ``ExtractedEntities``;
``to_stix`` emits a conformant, reproducible STIX 2.1 bundle from any iocflow
result. ``TaxiiSource`` makes a TAXII 2.1 collection an ingestion source that
plugs straight into a ``Poller``.

    from iocflow.stix import from_stix, to_stix

    entities = from_stix(bundle)              # STIX in  → extracted indicators
    bundle = to_stix(enrichment_report)       # results  → STIX out (verdict-aware)

    from iocflow.stix import TaxiiSource
    from iocflow.sources import Poller, SqliteSeenStore
    poller = Poller([TaxiiSource(api_root, collection_id, token="…")],
                    store=SqliteSeenStore("taxii.sqlite"))

``from_stix`` / ``to_stix`` are stdlib-only; the ``iocflow[stix]`` extra carries
``requests`` for ``TaxiiSource``.
"""
from iocflow.stix.build import to_stix
from iocflow.stix.parse import from_stix
from iocflow.stix.taxii import TaxiiSource

__all__ = ["from_stix", "to_stix", "TaxiiSource"]
