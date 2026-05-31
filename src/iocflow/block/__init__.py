"""iocflow Layer 5 — response / blocking.

Take the indicators an enrichment report flagged malicious and block them at the
control points you operate — Palo Alto firewalls (EDL feed or live PAN-OS API),
Zscaler ZIA, CrowdStrike Falcon, and (experimental) Abnormal Security email.

    from iocflow import extract
    from iocflow.enrich import enrich
    from iocflow.block import block

    entities = extract(report_text)
    report = enrich(entities)
    plan = block(report)               # DRY RUN by default — shows what *would* be blocked
    result = block(report, dry_run=False)   # actually push blocks

Safety is built in: ``dry_run=True`` is the default everywhere; an authoritative
allowlist guard vetoes benign/internal indicators before any target is called;
only malicious indicators are selected by default (``min_verdict=``); targets
with no credentials are skipped; and nothing raises — failures become ``FAILED``
results. Every action is reversible via :func:`unblock` where the target
supports it.

Each control point is a pluggable ``Blocker`` (``name``, ``supports(kind)``,
``block``, ``unblock``) — the flat signatures make them straightforward to
expose as agent tools. Build targets explicitly or let :func:`default_blockers`
read credentials from the environment (``IOCFLOW_PANOS_*``, ``IOCFLOW_ZSCALER_*``,
``IOCFLOW_FALCON_*``, ``IOCFLOW_PAN_EDL_PATH``, ``IOCFLOW_ABNORMAL_API_TOKEN``).

Needs the extra: ``pip install "iocflow[block]"``.
"""
from iocflow.block.guard import guard, is_allowlisted
from iocflow.block.models import BlockAction, BlockReport, BlockResult, BlockStatus
from iocflow.block.protocol import Blocker
from iocflow.block.runner import block, default_blockers, unblock
from iocflow.block.targets import (
    AbnormalBlocker,
    CrowdStrikeBlocker,
    PanEdlFeed,
    PanOsBlocker,
    ZscalerBlocker,
)

__all__ = [
    # Orchestrator
    "block",
    "unblock",
    "default_blockers",
    # Result types
    "BlockReport",
    "BlockResult",
    "BlockStatus",
    "BlockAction",
    # Protocol + guard
    "Blocker",
    "guard",
    "is_allowlisted",
    # Targets
    "PanEdlFeed",
    "PanOsBlocker",
    "ZscalerBlocker",
    "CrowdStrikeBlocker",
    "AbnormalBlocker",
]
