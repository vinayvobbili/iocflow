"""Live Abnormal Security blocker — email sender blocking (EXPERIMENTAL).

Abnormal's public API is centered on retrieving threats/cases; a stable,
documented public endpoint for proactively blocking a sender varies by tenant.
So this blocker is intentionally experimental: it builds the block payload and,
on a live run, POSTs it to a tenant-specific endpoint you supply
(``block_path``). With no endpoint configured it reports SKIPPED rather than
guessing an API shape. The dry-run payload is always available, and the
``Blocker`` seam means a confirmed endpoint is a one-line change.

Configure ``IOCFLOW_ABNORMAL_API_TOKEN`` (and optionally
``IOCFLOW_ABNORMAL_BASE_URL`` / ``IOCFLOW_ABNORMAL_BLOCK_PATH``).
"""
from __future__ import annotations

from typing import Optional

from iocflow.block.base import HTTPBlocker
from iocflow.block.models import BlockResult, BlockStatus


class AbnormalBlocker(HTTPBlocker):
    """Blocks email senders via Abnormal Security (experimental)."""

    name = "abnormal"
    supported_kinds = frozenset({"email", "domain"})
    supports_unblock = False  # remediation/removal API is not confirmed public

    def __init__(self, api_token: Optional[str] = None, *,
                 base_url: str = "https://api.abnormalsecurity.com",
                 block_path: Optional[str] = None, **kw) -> None:
        super().__init__(**kw)
        self.api_token = api_token
        self.base_url = base_url.rstrip("/")
        self.block_path = block_path  # tenant-specific; required for a live block

    @property
    def is_configured(self) -> bool:
        return bool(self.api_token)

    def _block_payload(self, kind: str, value: str, action: str) -> dict:
        field = "senderDomain" if kind == "domain" else "senderAddress"
        return {field: value, "action": "block", "source": "iocflow"}

    def _do_block(self, kind: str, value: str, action: str, payload: dict) -> BlockResult:
        if not self.block_path:
            return self._result(
                kind, value, BlockStatus.SKIPPED, action=action, payload=payload,
                detail="experimental: set IOCFLOW_ABNORMAL_BLOCK_PATH to your tenant's block endpoint",
            )
        resp = self._session.post(
            f"{self.base_url}{self.block_path}",
            headers={"Authorization": f"Bearer {self.api_token}"},
            json=payload, timeout=self.timeout, verify=self.verify,
        )
        resp.raise_for_status()
        return self._result(kind, value, BlockStatus.BLOCKED, action=action, payload=payload,
                            detail="submitted to Abnormal (experimental)")
