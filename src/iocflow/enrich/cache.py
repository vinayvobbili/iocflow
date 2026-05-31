"""A minimal cache seam for enrichment lookups.

The default is an in-process :class:`MemoryCache`. Implement the :class:`Cache`
protocol to back enrichment with disk, Redis, or anything else.
"""
from __future__ import annotations

from typing import Optional, Protocol, Tuple

from iocflow.enrich.models import EnrichmentRecord

# (source, kind, value)
CacheKey = Tuple[str, str, str]


class Cache(Protocol):
    def get(self, key: CacheKey) -> Optional[EnrichmentRecord]: ...

    def set(self, key: CacheKey, record: EnrichmentRecord) -> None: ...


class MemoryCache:
    """A trivial dict-backed cache."""

    def __init__(self) -> None:
        self._store: dict = {}

    def get(self, key: CacheKey) -> Optional[EnrichmentRecord]:
        return self._store.get(key)

    def set(self, key: CacheKey, record: EnrichmentRecord) -> None:
        self._store[key] = record
