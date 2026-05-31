"""Palo Alto External Dynamic List (EDL) feed — the safe, decoupled block path.

Rather than mutating the firewall, this maintains typed text feeds (one file per
indicator kind) that a PAN-OS External Dynamic List object pulls on a schedule.
A security policy referencing those EDLs does the actual blocking, so nothing
here touches the firewall directly — it only appends/removes lines in files.
Stdlib-only (no ``requests``).

Point a PAN-OS EDL object at, e.g., ``https://you/edl/ip.txt`` and configure
``IOCFLOW_PAN_EDL_PATH`` to the directory those files live in.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from iocflow.block.models import BlockResult, BlockStatus

# Indicator kind -> the feed filename. PAN-OS EDLs are typed (IP / Domain / URL).
_FILES = {
    "ip": "ip.txt",
    "domain": "domain.txt",
    "url": "url.txt",
}


class PanEdlFeed:
    """Maintains typed Palo Alto EDL feed files (ip/domain/url)."""

    name = "pan_edl"
    supported_kinds = frozenset(_FILES)

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path).expanduser() if path else None
        self._lock = threading.Lock()

    @property
    def is_configured(self) -> bool:
        return self.path is not None

    def supports(self, kind: str) -> bool:
        return kind in _FILES

    def block(self, kind: str, value: str, *, action: str = "prevent",
              dry_run: bool = True) -> BlockResult:
        return self._edit(kind, value, action=action, dry_run=dry_run, removing=False)

    def unblock(self, kind: str, value: str, *, dry_run: bool = True) -> BlockResult:
        return self._edit(kind, value, action="", dry_run=dry_run, removing=True)

    # -- internals ----------------------------------------------------------

    def _edit(self, kind: str, value: str, *, action: str, dry_run: bool,
              removing: bool) -> BlockResult:
        verb = "remove from" if removing else "add to"
        if not self.supports(kind):
            return self._result(kind, value, BlockStatus.SKIPPED, action,
                                detail=f"{self.name} has no feed for {kind}")
        if not self.is_configured:
            return self._result(kind, value, BlockStatus.SKIPPED, action,
                                detail=f"{self.name}: IOCFLOW_PAN_EDL_PATH not set")

        entry = _entry(kind, value)
        feed = self.path / _FILES[kind]  # type: ignore[operator]
        payload = {"file": str(feed), "entry": entry}

        if dry_run:
            return self._result(kind, value, BlockStatus.DRY_RUN, action,
                                payload=payload, detail=f"dry run — would {verb} {feed.name}")
        try:
            with self._lock:
                present = self._lines(feed)
                if removing:
                    if entry not in present:
                        return self._result(kind, value, BlockStatus.SKIPPED, action,
                                            payload=payload, detail="not in feed")
                    present.remove(entry)
                    self._write(feed, present)
                    return self._result(kind, value, BlockStatus.UNBLOCKED, action,
                                        reference=str(feed), payload=payload)
                if entry in present:
                    return self._result(kind, value, BlockStatus.ALREADY_BLOCKED, action,
                                        reference=str(feed), payload=payload)
                present.append(entry)
                self._write(feed, present)
                return self._result(kind, value, BlockStatus.BLOCKED, action,
                                    reference=str(feed), payload=payload)
        except OSError as exc:
            return self._result(kind, value, BlockStatus.FAILED, action,
                                payload=payload, error=f"{type(exc).__name__}: {exc}")

    def _lines(self, feed: Path) -> list:
        if not feed.exists():
            return []
        return [ln.strip() for ln in feed.read_text().splitlines() if ln.strip()]

    def _write(self, feed: Path, lines: list) -> None:
        feed.parent.mkdir(parents=True, exist_ok=True)
        feed.write_text("\n".join(lines) + ("\n" if lines else ""))

    def _result(self, kind, value, status, action, *, reference="", detail="",
                payload=None, error=None) -> BlockResult:
        return BlockResult(target=self.name, kind=kind, value=value, status=status,
                           action=action, reference=reference, detail=detail,
                           payload=payload or {}, error=error)


def _entry(kind: str, value: str) -> str:
    """Normalize a value to its EDL line form (PAN URL lists omit the scheme)."""
    if kind == "url":
        return value.split("://", 1)[-1]
    return value
