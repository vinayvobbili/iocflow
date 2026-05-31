"""The ``Enricher`` protocol and a shared HTTP base class.

Concrete sources subclass :class:`HTTPEnricher`, declare which indicator kinds
they support, and implement ``_lookup``. The base class handles the session,
per-source rate limiting, and turning any exception into an error record so a
dead source never crashes a batch.
"""
from __future__ import annotations

import threading
import time
from typing import Optional, Set

try:
    import requests
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "iocflow enrichment needs the 'enrich' extra: pip install 'iocflow[enrich]'"
    ) from exc

from iocflow.enrich.models import EnrichmentRecord, Verdict
from iocflow.enrich.protocol import Enricher  # noqa: F401 — re-exported for callers


class EnricherError(Exception):
    """Raised inside ``_lookup`` for an unrecoverable source error."""


class HTTPEnricher:
    """Base for HTTP intel sources.

    Subclasses set ``name``, ``supported_kinds``, and (optionally)
    ``min_interval`` / ``timeout``, then implement ``_lookup``.
    """

    name: str = ""
    supported_kinds: Set[str] = frozenset()
    requires_key: bool = True  # most sources need an API key; skip the call without one
    min_interval: float = 0.0  # seconds between calls (per instance); 0 = no limit
    timeout: float = 20.0

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        session: "requests.Session | None" = None,
        min_interval: Optional[float] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self.api_key = api_key
        self._session = session or requests.Session()
        if min_interval is not None:
            self.min_interval = min_interval
        if timeout is not None:
            self.timeout = timeout
        self._lock = threading.Lock()
        self._last_call = 0.0

    # -- public protocol ----------------------------------------------------

    def supports(self, kind: str) -> bool:
        return kind in self.supported_kinds

    def enrich(self, kind: str, value: str) -> EnrichmentRecord:
        """Look up one indicator, never raising — failures become error records."""
        if not self.supports(kind):
            return self._record(kind, value, error=f"{self.name} does not support {kind}")
        if self.requires_key and not self.api_key:
            return self._record(kind, value, error=f"{self.name}: no API key configured")
        try:
            self._throttle()
            return self._lookup(kind, value)
        except Exception as exc:  # noqa: BLE001 — all failures degrade to a record
            return self._record(kind, value, error=f"{type(exc).__name__}: {exc}")

    # -- helpers for subclasses --------------------------------------------

    def _record(self, kind: str, value: str, **kw) -> EnrichmentRecord:
        kw.setdefault("verdict", Verdict.UNKNOWN)
        return EnrichmentRecord(source=self.name, kind=kind, value=value, **kw)

    def _get(self, url: str, **kw) -> dict:
        resp = self._session.get(url, timeout=self.timeout, **kw)
        return self._json_or_raise(resp)

    def _post(self, url: str, **kw) -> dict:
        resp = self._session.post(url, timeout=self.timeout, **kw)
        return self._json_or_raise(resp)

    @staticmethod
    def _json_or_raise(resp) -> dict:
        resp.raise_for_status()
        return resp.json()

    def _lookup(self, kind: str, value: str) -> EnrichmentRecord:
        raise NotImplementedError

    # -- internals ----------------------------------------------------------

    def _throttle(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            wait = self.min_interval - (time.monotonic() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()
