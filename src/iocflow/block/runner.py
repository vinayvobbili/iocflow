"""The block orchestrator: select indicators, guard, fan out to targets.

``block`` and ``unblock`` never raise and default to ``dry_run=True`` — you must
pass ``dry_run=False`` to change anything. The allowlist guard is authoritative:
benign/internal indicators are vetoed before any target is called, regardless of
verdict.
"""
from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Mapping, Optional, Sequence

from iocflow.block.guard import guard as guard_indicators
from iocflow.block.models import BlockReport, BlockResult, BlockStatus
from iocflow.block.protocol import Blocker
from iocflow.models import Indicator

logger = logging.getLogger(__name__)

# Verdict rank for the min_verdict threshold (mirrors enrich.Verdict.rank).
_RANK = {"malicious": 3, "suspicious": 2, "benign": 1, "unknown": 0}


def block(
    report=None,
    *,
    indicators: Optional[Iterable] = None,
    blockers: Optional[Sequence[Blocker]] = None,
    kinds: Optional[Iterable[str]] = None,
    min_verdict: str = "malicious",
    action: str = "prevent",
    dry_run: bool = True,
    allowlist_guard: bool = True,
    max_workers: int = 8,
) -> BlockReport:
    """Block indicators across every configured control point.

    Args:
        report: An L2 ``EnrichmentReport``; indicators whose aggregate verdict is
            at least ``min_verdict`` are selected. Ignored if ``indicators`` is given.
        indicators: An explicit iterable of ``Indicator`` / ``(kind, value)`` to
            block, bypassing verdict selection.
        blockers: Targets to push to. Defaults to :func:`default_blockers`
            (every target whose credentials are present in the environment).
        kinds: Restrict to these indicator kinds.
        min_verdict: ``"malicious"`` (default), ``"suspicious"``, etc.
        action: Enforcement action for targets that distinguish (CrowdStrike).
        dry_run: When True (default), render what *would* happen and change nothing.
        allowlist_guard: When True (default), veto benign/internal indicators.
        max_workers: Thread-pool size for the fan-out.
    """
    return _run(report, indicators, blockers, kinds, min_verdict, action,
                dry_run, allowlist_guard, max_workers, removing=False)


def unblock(
    report=None,
    *,
    indicators: Optional[Iterable] = None,
    blockers: Optional[Sequence[Blocker]] = None,
    kinds: Optional[Iterable[str]] = None,
    min_verdict: str = "malicious",
    dry_run: bool = True,
    allowlist_guard: bool = True,
    max_workers: int = 8,
) -> BlockReport:
    """Remove blocks across every configured control point (same selection as :func:`block`)."""
    return _run(report, indicators, blockers, kinds, min_verdict, "",
                dry_run, allowlist_guard, max_workers, removing=True)


def _run(report, indicators, blockers, kinds, min_verdict, action,
         dry_run, allowlist_guard, max_workers, *, removing: bool) -> BlockReport:
    targets = list(blockers) if blockers is not None else default_blockers()

    selected = _select(report, indicators, min_verdict)
    if kinds is not None:
        wanted = set(kinds)
        selected = [i for i in selected if i.kind in wanted]

    results: List[BlockResult] = []
    if allowlist_guard:
        selected, vetoed = guard_indicators(selected)
        for ind, reason in vetoed:
            results.append(BlockResult(
                target="guard", kind=ind.kind, value=ind.value,
                status=BlockStatus.SKIPPED, detail=f"allowlisted: {reason}",
            ))

    if not targets:
        logger.warning("No blockers configured (no credentials found)")
    tasks = [(b, ind) for ind in selected for b in targets if b.supports(ind.kind)]

    if tasks:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(_one, b, ind, action, dry_run, removing) for b, ind in tasks]
            for future in as_completed(futures):
                results.append(future.result())

    report_out = BlockReport(results=results, dry_run=dry_run)
    logger.info("Block (%s): %s", "dry-run" if dry_run else "live", report_out.summary())
    return report_out


def _one(blocker: Blocker, ind: Indicator, action: str, dry_run: bool,
         removing: bool) -> BlockResult:
    try:
        if removing:
            return blocker.unblock(ind.kind, ind.value, dry_run=dry_run)
        return blocker.block(ind.kind, ind.value, action=action, dry_run=dry_run)
    except Exception as exc:  # noqa: BLE001 — a misbehaving blocker can't sink the batch
        return BlockResult(
            target=getattr(blocker, "name", "?"), kind=ind.kind, value=ind.value,
            status=BlockStatus.FAILED, action=action, error=f"{type(exc).__name__}: {exc}",
        )


def _select(report, indicators, min_verdict) -> List[Indicator]:
    """Choose the indicators to act on, de-duplicated, in first-seen order."""
    if indicators is not None:
        out, seen = [], set()
        for item in indicators:
            ind = item if isinstance(item, Indicator) else Indicator(item[0], item[1])
            key = (ind.kind, ind.value)
            if key not in seen:
                seen.add(key)
                out.append(ind)
        return out

    if report is None:
        return []
    floor = _RANK.get(min_verdict, 3)
    out = []
    for ind in report.indicators():
        if _RANK.get(report.verdict_for(ind.kind, ind.value).value, 0) >= floor:
            out.append(ind)
    return out


def default_blockers(env: Optional[Mapping[str, str]] = None) -> List[Blocker]:
    """Build every blocker whose configuration is present in the environment.

    - ``IOCFLOW_PAN_EDL_PATH``                                  → PanEdlFeed
    - ``IOCFLOW_PANOS_HOST`` + ``IOCFLOW_PANOS_API_KEY``        → PanOsBlocker
    - ``IOCFLOW_ZSCALER_BASE_URL`` + ``_API_KEY`` + ``_USERNAME`` + ``_PASSWORD`` → ZscalerBlocker
    - ``IOCFLOW_FALCON_CLIENT_ID`` + ``IOCFLOW_FALCON_CLIENT_SECRET`` → CrowdStrikeBlocker
    - ``IOCFLOW_ABNORMAL_API_TOKEN``                            → AbnormalBlocker (experimental)

    Unconfigured targets are simply omitted, so the same call works with one
    control point or all of them.
    """
    from iocflow.block.targets import (
        AbnormalBlocker,
        CrowdStrikeBlocker,
        PanEdlFeed,
        PanOsBlocker,
        ZscalerBlocker,
    )

    env = env if env is not None else os.environ
    out: List[Blocker] = []

    edl = env.get("IOCFLOW_PAN_EDL_PATH")
    if edl:
        out.append(PanEdlFeed(edl))

    pan_host, pan_key = env.get("IOCFLOW_PANOS_HOST"), env.get("IOCFLOW_PANOS_API_KEY")
    if pan_host and pan_key:
        out.append(PanOsBlocker(pan_host, pan_key))

    z_url = env.get("IOCFLOW_ZSCALER_BASE_URL")
    if z_url and env.get("IOCFLOW_ZSCALER_API_KEY") and env.get("IOCFLOW_ZSCALER_USERNAME") \
            and env.get("IOCFLOW_ZSCALER_PASSWORD"):
        out.append(ZscalerBlocker(
            z_url, env["IOCFLOW_ZSCALER_API_KEY"],
            username=env["IOCFLOW_ZSCALER_USERNAME"], password=env["IOCFLOW_ZSCALER_PASSWORD"],
        ))

    fc_id, fc_secret = env.get("IOCFLOW_FALCON_CLIENT_ID"), env.get("IOCFLOW_FALCON_CLIENT_SECRET")
    if fc_id and fc_secret:
        base = env.get("IOCFLOW_FALCON_BASE_URL", "https://api.crowdstrike.com")
        out.append(CrowdStrikeBlocker(fc_id, fc_secret, base_url=base))

    abn = env.get("IOCFLOW_ABNORMAL_API_TOKEN")
    if abn:
        out.append(AbnormalBlocker(
            abn,
            base_url=env.get("IOCFLOW_ABNORMAL_BASE_URL", "https://api.abnormalsecurity.com"),
            block_path=env.get("IOCFLOW_ABNORMAL_BLOCK_PATH"),
        ))

    return out
