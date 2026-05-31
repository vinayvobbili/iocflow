"""The structural protocols for the ingestion seam (no third-party imports)."""
from __future__ import annotations

from typing import Iterable, Optional, Protocol, runtime_checkable

from iocflow.sources.models import Trigger


@runtime_checkable
class Source(Protocol):
    """Anything that can yield :class:`Trigger` work items.

    Implementations need a ``name`` and a ``poll()`` that returns the current
    batch of triggers. ``poll()`` may return already-seen items — de-duplication
    is the :class:`~iocflow.sources.poller.Poller`'s job, via a :class:`SeenStore`.
    """

    name: str

    def poll(self) -> Iterable[Trigger]: ...


@runtime_checkable
class SeenStore(Protocol):
    """Remembers which trigger keys have already been handled.

    ``seen(key)`` is checked before handling; ``mark(key)`` records it after.
    Implementations should be idempotent and safe to re-open across runs.
    """

    def seen(self, key: str) -> bool: ...

    def mark(self, key: str, *, ts: Optional[str] = None) -> None: ...
