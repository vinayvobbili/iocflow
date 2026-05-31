"""Result types for blocking / response (Layer 5).

A :class:`BlockResult` is one target's outcome for one indicator. A
:class:`BlockReport` collects every result produced for a block (or unblock)
run. Both are JSON-serializable — the report is the audit trail an approver (and
later an agent) reads.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class BlockAction(str, Enum):
    """What enforcement to apply when a target distinguishes (e.g. CrowdStrike)."""

    PREVENT = "prevent"  # block and stop
    DETECT = "detect"  # alert only, don't stop
    MONITOR = "monitor"  # observe, no alert


class BlockStatus(str, Enum):
    """The outcome of a block/unblock for one indicator at one target."""

    BLOCKED = "blocked"  # a block was pushed
    UNBLOCKED = "unblocked"  # a block was removed
    DRY_RUN = "dry_run"  # would have acted; nothing changed
    ALREADY_BLOCKED = "already_blocked"  # the target already had it (idempotent)
    SKIPPED = "skipped"  # unsupported kind, no creds, or allowlisted
    FAILED = "failed"  # the target call errored


@dataclass
class BlockResult:
    """One target's outcome for one indicator."""

    target: str
    kind: str
    value: str
    status: BlockStatus
    action: str = ""  # the requested action, when relevant
    reference: str = ""  # human pivot URL / console link, when the target gives one
    detail: str = ""  # short human note (why skipped, what happened)
    payload: dict = field(default_factory=dict)  # what was/would be sent (dry-run visibility)
    error: Optional[str] = None  # set on FAILED

    @property
    def ok(self) -> bool:
        """True unless the target call errored."""
        return self.status is not BlockStatus.FAILED

    @property
    def changed(self) -> bool:
        """True if state actually changed (a live block or unblock landed)."""
        return self.status in (BlockStatus.BLOCKED, BlockStatus.UNBLOCKED)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "kind": self.kind,
            "value": self.value,
            "status": self.status.value,
            "action": self.action,
            "reference": self.reference,
            "detail": self.detail,
            "payload": self.payload,
            "error": self.error,
        }


@dataclass
class BlockReport:
    """Every result produced for one block (or unblock) run."""

    results: List[BlockResult] = field(default_factory=list)
    dry_run: bool = True

    @property
    def blocked(self) -> List[BlockResult]:
        return [r for r in self.results if r.status is BlockStatus.BLOCKED]

    @property
    def unblocked(self) -> List[BlockResult]:
        return [r for r in self.results if r.status is BlockStatus.UNBLOCKED]

    @property
    def failed(self) -> List[BlockResult]:
        return [r for r in self.results if r.status is BlockStatus.FAILED]

    @property
    def skipped(self) -> List[BlockResult]:
        return [r for r in self.results if r.status is BlockStatus.SKIPPED]

    def by_target(self, target: str) -> List[BlockResult]:
        return [r for r in self.results if r.target == target]

    @property
    def targets(self) -> List[str]:
        out: List[str] = []
        for r in self.results:
            if r.target not in out:
                out.append(r.target)
        return out

    def to_dict(self) -> dict:
        return {
            "dry_run": self.dry_run,
            "results": [r.to_dict() for r in self.results],
        }

    def summary(self) -> str:
        if not self.results:
            return "No indicators to block"
        counts: Dict[str, int] = {}
        for r in self.results:
            counts[r.status.value] = counts.get(r.status.value, 0) + 1
        head = "DRY RUN: " if self.dry_run else ""
        parts = [f"{n} {status}" for status, n in counts.items()]
        return head + ", ".join(parts)
