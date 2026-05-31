"""Live Zscaler Internet Access (ZIA) blocker — URL/domain denylist.

Adds URLs/domains to the ZIA security denylist and then activates the change
(ZIA edits are staged until activated). Uses the legacy ZIA API: an obfuscated
API key + username/password establishes a session cookie, then the denylist and
activation endpoints are called.

Configure ``IOCFLOW_ZSCALER_BASE_URL`` (e.g. ``https://zsapi.zscalerN.net/api/v1``),
``IOCFLOW_ZSCALER_API_KEY``, ``IOCFLOW_ZSCALER_USERNAME``, ``IOCFLOW_ZSCALER_PASSWORD``.
"""
from __future__ import annotations

import time
from typing import Optional

from iocflow.block.base import HTTPBlocker
from iocflow.block.models import BlockResult, BlockStatus


class ZscalerBlocker(HTTPBlocker):
    """Blocks URLs/domains via the ZIA denylist (with activation)."""

    name = "zscaler"
    supported_kinds = frozenset({"url", "domain"})
    supports_unblock = True

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None, *,
                 username: Optional[str] = None, password: Optional[str] = None, **kw) -> None:
        super().__init__(**kw)
        self.base_url = (base_url or "").strip().rstrip("/")
        self.api_key = api_key
        self.username = username
        self.password = password
        self._authed = False

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.username and self.password)

    def _block_payload(self, kind: str, value: str, action: str) -> dict:
        return {"endpoint": "/security/advanced/blacklistUrls?action=ADD_TO_LIST",
                "body": {"blacklistUrls": [_entry(kind, value)]}}

    def _unblock_payload(self, kind: str, value: str) -> dict:
        return {"endpoint": "/security/advanced/blacklistUrls?action=REMOVE_FROM_LIST",
                "body": {"blacklistUrls": [_entry(kind, value)]}}

    def _do_block(self, kind: str, value: str, action: str, payload: dict) -> BlockResult:
        self._authenticate()
        self._post(payload["endpoint"], payload["body"])
        self._activate()
        return self._result(kind, value, BlockStatus.BLOCKED, action=action, payload=payload,
                            detail="added to ZIA denylist and activated")

    def _do_unblock(self, kind: str, value: str, payload: dict) -> BlockResult:
        self._authenticate()
        self._post(payload["endpoint"], payload["body"])
        self._activate()
        return self._result(kind, value, BlockStatus.UNBLOCKED, payload=payload,
                            detail="removed from ZIA denylist and activated")

    # -- session ------------------------------------------------------------

    def _authenticate(self) -> None:
        if self._authed:
            return
        now = str(int(time.time() * 1000))
        body = {
            "apiKey": _obfuscate(self.api_key or "", now),
            "username": self.username,
            "password": self.password,
            "timestamp": now,
        }
        resp = self._session.post(f"{self.base_url}/authenticatedSession",
                                  json=body, timeout=self.timeout, verify=self.verify)
        resp.raise_for_status()
        self._authed = True

    def _activate(self) -> None:
        resp = self._session.post(f"{self.base_url}/status/activate",
                                  timeout=self.timeout, verify=self.verify)
        resp.raise_for_status()

    def _post(self, endpoint: str, body: dict) -> None:
        resp = self._session.post(f"{self.base_url}{endpoint}", json=body,
                                  timeout=self.timeout, verify=self.verify)
        resp.raise_for_status()


def _entry(kind: str, value: str) -> str:
    """ZIA denylist entries are URL/host strings without a scheme."""
    return value.split("://", 1)[-1] if kind == "url" else value


def _obfuscate(api_key: str, now: str) -> str:
    """ZIA's documented API-key obfuscation against the request timestamp."""
    n = now[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = "".join(api_key[int(c)] for c in n)
    key += "".join(api_key[int(c) + 2] for c in r)
    return key
