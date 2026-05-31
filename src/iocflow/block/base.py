"""A shared HTTP base for live blockers.

Subclasses set ``name`` and ``supported_kinds``, declare ``is_configured``, and
implement ``_block_payload`` / ``_do_block`` (and optionally the unblock pair).
The base owns the safety scaffolding every target shares: skip unsupported
kinds, skip when unconfigured, honour ``dry_run``, and turn any exception into a
``FAILED`` result so one dead target never crashes a batch.

(The Palo Alto EDL feed is file-based and stdlib-only, so it does not use this
base — see ``targets/pan_edl.py``.)
"""
from __future__ import annotations

from typing import Optional, Set

try:
    import requests
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "iocflow blocking needs the 'block' extra: pip install 'iocflow[block]'"
    ) from exc

from iocflow.block.models import BlockResult, BlockStatus


class HTTPBlocker:
    """Base for HTTP-API blockers (PAN-OS, Zscaler, CrowdStrike, …)."""

    name: str = ""
    supported_kinds: Set[str] = frozenset()
    supports_unblock: bool = False
    timeout: float = 20.0
    verify: bool = True  # TLS verification; some on-prem appliances need this off

    def __init__(
        self,
        *,
        session: "requests.Session | None" = None,
        timeout: Optional[float] = None,
        verify: Optional[bool] = None,
    ) -> None:
        self._session = session or requests.Session()
        if timeout is not None:
            self.timeout = timeout
        if verify is not None:
            self.verify = verify

    # -- public protocol ----------------------------------------------------

    @property
    def is_configured(self) -> bool:
        """Whether credentials/endpoint are present. Override in subclasses."""
        return True

    def supports(self, kind: str) -> bool:
        return kind in self.supported_kinds

    def block(self, kind: str, value: str, *, action: str = "prevent",
              dry_run: bool = True) -> BlockResult:
        return self._run(kind, value, action=action, dry_run=dry_run, removing=False)

    def unblock(self, kind: str, value: str, *, dry_run: bool = True) -> BlockResult:
        if not self.supports_unblock:
            return self._result(kind, value, BlockStatus.SKIPPED,
                                detail=f"{self.name}: unblock not supported")
        return self._run(kind, value, action="", dry_run=dry_run, removing=True)

    # -- shared flow --------------------------------------------------------

    def _run(self, kind: str, value: str, *, action: str, dry_run: bool,
             removing: bool) -> BlockResult:
        verb = "unblock" if removing else "block"
        if not self.supports(kind):
            return self._result(kind, value, BlockStatus.SKIPPED, action=action,
                                detail=f"{self.name} cannot {verb} {kind}")
        if not self.is_configured:
            return self._result(kind, value, BlockStatus.SKIPPED, action=action,
                                detail=f"{self.name}: not configured")
        try:
            payload = (self._unblock_payload(kind, value) if removing
                       else self._block_payload(kind, value, action))
        except Exception as exc:  # noqa: BLE001 — payload errors degrade to a record
            return self._result(kind, value, BlockStatus.FAILED, action=action,
                                error=f"{type(exc).__name__}: {exc}")
        if dry_run:
            return self._result(kind, value, BlockStatus.DRY_RUN, action=action,
                                payload=payload, detail=f"dry run — would {verb}")
        try:
            return (self._do_unblock(kind, value, payload) if removing
                    else self._do_block(kind, value, action, payload))
        except Exception as exc:  # noqa: BLE001 — all live failures degrade to a record
            return self._result(kind, value, BlockStatus.FAILED, action=action,
                                payload=payload, error=f"{type(exc).__name__}: {exc}")

    # -- subclass hooks -----------------------------------------------------

    def _block_payload(self, kind: str, value: str, action: str) -> dict:
        """Build the request body (also shown in dry-run). Override."""
        raise NotImplementedError

    def _do_block(self, kind: str, value: str, action: str, payload: dict) -> BlockResult:
        """Perform the live block. Override."""
        raise NotImplementedError

    def _unblock_payload(self, kind: str, value: str) -> dict:
        return {"kind": kind, "value": value}

    def _do_unblock(self, kind: str, value: str, payload: dict) -> BlockResult:
        raise NotImplementedError

    # -- helpers ------------------------------------------------------------

    def _result(self, kind: str, value: str, status: BlockStatus, *, action: str = "",
                reference: str = "", detail: str = "", payload: Optional[dict] = None,
                error: Optional[str] = None) -> BlockResult:
        return BlockResult(
            target=self.name, kind=kind, value=value, status=status, action=action,
            reference=reference, detail=detail, payload=payload or {}, error=error,
        )
