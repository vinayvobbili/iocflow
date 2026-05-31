"""Live CrowdStrike Falcon blocker — IOC Management API.

Adds hashes / domains / IPs as custom indicators with an enforcement action
(``prevent`` by default) applied globally across platforms. Uses OAuth2
client-credentials. Unblocking looks the indicator up by value+type and deletes
it. Note: Falcon IOCs cover md5/sha256 (not sha1), domains, and IPv4/IPv6.

Configure ``IOCFLOW_FALCON_CLIENT_ID``, ``IOCFLOW_FALCON_CLIENT_SECRET``, and
optionally ``IOCFLOW_FALCON_BASE_URL`` (region, default ``https://api.crowdstrike.com``).
"""
from __future__ import annotations

from typing import Optional

from iocflow.block.base import HTTPBlocker
from iocflow.block.models import BlockResult, BlockStatus

# Our indicator kind -> Falcon IOC type.
_TYPES = {
    "ip": "ipv4",
    "domain": "domain",
    "md5": "md5",
    "sha256": "sha256",
}
_ACTIONS = {"prevent", "detect", "monitor", "no_action"}


class CrowdStrikeBlocker(HTTPBlocker):
    """Blocks indicators via the Falcon IOC Management API."""

    name = "crowdstrike"
    supported_kinds = frozenset(_TYPES)
    supports_unblock = True

    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None, *,
                 base_url: str = "https://api.crowdstrike.com", **kw) -> None:
        super().__init__(**kw)
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self._token: Optional[str] = None

    @property
    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def _block_payload(self, kind: str, value: str, action: str) -> dict:
        act = action if action in _ACTIONS else "prevent"
        return {
            "indicators": [{
                "type": _TYPES[kind],
                "value": value,
                "action": act,
                "platforms": ["windows", "mac", "linux"],
                "applied_globally": True,
                "source": "iocflow",
                "description": "Blocked by iocflow",
            }]
        }

    def _do_block(self, kind: str, value: str, action: str, payload: dict) -> BlockResult:
        data = self._call("POST", "/iocs/entities/indicators/v1", json=payload)
        if data.get("errors"):
            raise RuntimeError(f"Falcon IOC error: {data['errors']}")
        return self._result(kind, value, BlockStatus.BLOCKED, action=payload["indicators"][0]["action"],
                            payload=payload, reference=f"{self.base_url}/iocs",
                            detail="custom IOC created")

    def _do_unblock(self, kind: str, value: str, payload: dict) -> BlockResult:
        ids = self._find_ids(kind, value)
        if not ids:
            return self._result(kind, value, BlockStatus.SKIPPED, payload=payload,
                                detail="no matching Falcon IOC to remove")
        self._call("DELETE", "/iocs/entities/indicators/v1", params={"ids": ids})
        return self._result(kind, value, BlockStatus.UNBLOCKED, payload=payload,
                            detail=f"removed {len(ids)} IOC(s)")

    # -- API ----------------------------------------------------------------

    def _find_ids(self, kind: str, value: str) -> list:
        filt = f"type:'{_TYPES[kind]}'+value:'{value}'"
        data = self._call("GET", "/iocs/queries/indicators/v1", params={"filter": filt})
        return data.get("resources", []) or []

    def _token_header(self) -> dict:
        if self._token is None:
            resp = self._session.post(
                f"{self.base_url}/oauth2/token",
                data={"client_id": self.client_id, "client_secret": self.client_secret},
                timeout=self.timeout, verify=self.verify,
            )
            resp.raise_for_status()
            self._token = resp.json()["access_token"]
        return {"Authorization": f"Bearer {self._token}"}

    def _call(self, method: str, path: str, *, json=None, params=None) -> dict:
        resp = self._session.request(
            method, f"{self.base_url}{path}", headers=self._token_header(),
            json=json, params=params, timeout=self.timeout, verify=self.verify,
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}
