"""iocflow Layer 4 — suggested hunts.

Turn an enrichment report into ready-to-run hunt queries for the platforms a
SOC actually uses.

    from iocflow import extract
    from iocflow.enrich import enrich
    from iocflow.hunt import suggest

    entities = extract(report_text)
    report = enrich(entities)
    plan = suggest(report)             # deterministic queries, offline, no keys

    for hunt in plan.hunts:
        print(f"# {hunt.title}  [{hunt.severity.value}]")
        print(hunt.query)

The deterministic core renders one IOC-sweep query per indicator kind in each
dialect — **CrowdStrike CQL**, **Cortex XQL**, and **Sigma** — with no network
and no API keys. If a chat model is configured (``IOCFLOW_LLM_*``, same as Layer
3) it additionally proposes *behavioral* hunts; any model failure leaves the
deterministic plan intact. ``suggest`` never raises.

    from iocflow.hunt import suggest
    plan = suggest(report, entities=entities, commentary=note, dialects=["sigma"])

Needs the extra: ``pip install "iocflow[hunt]"`` (only the LLM path uses it; the
deterministic renderers are stdlib-only).
"""
from iocflow.hunt.models import Hunt, HuntPlan
from iocflow.hunt.protocol import Dialect
from iocflow.hunt.registry import DEFAULT_DIALECTS, all_dialects, get_dialect
from iocflow.hunt.suggest import default_model, suggest
from iocflow.severity import Severity

__all__ = [
    "suggest",
    "default_model",
    "Hunt",
    "HuntPlan",
    "Severity",
    "Dialect",
    "get_dialect",
    "all_dialects",
    "DEFAULT_DIALECTS",
]
