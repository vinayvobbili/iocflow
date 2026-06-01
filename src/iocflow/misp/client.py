"""A thin MISP REST client — the MISP layer's shared HTTP plumbing.

Stdlib + lazy ``requests`` only (no ``pymisp``): MISP's REST API is a handful of
JSON endpoints, so a tiny client keeps the ``[misp]`` extra down to ``requests``
and matches iocflow's lean, dependency-light STIX layer.

Auth is MISP's raw API key in the ``Authorization`` header (not a Bearer token).
Self-hosted instances often present a private CA / self-signed cert; ``verify_tls``
is exposed for that, defaulting to verification on.
"""
from __future__ import annotations

import os
from typing import Optional

_JSON = "application/json"


class MispClient:
    """Minimal authenticated client for one MISP instance.

    Args:
        url: instance base URL, e.g. ``https://misp.example.org``. Falls back to
            ``IOCFLOW_MISP_URL``.
        api_key: the MISP automation key. Falls back to ``IOCFLOW_MISP_KEY`` then
            ``IOCFLOW_MISP_API_KEY``.
        verify_tls: verify the server certificate (set False for self-signed).
        session: inject a session/stub (tests); otherwise created lazily.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        verify_tls: bool = True,
        timeout: float = 30.0,
        session=None,
    ) -> None:
        self.url = (url or os.environ.get("IOCFLOW_MISP_URL", "")).rstrip("/")
        self.api_key = (
            api_key
            or os.environ.get("IOCFLOW_MISP_KEY")
            or os.environ.get("IOCFLOW_MISP_API_KEY", "")
        )
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._session = session

    @property
    def configured(self) -> bool:
        return bool(self.url and self.api_key)

    def _client(self):
        if self._session is None:
            import requests  # lazy: only the live path needs it

            self._session = requests.Session()
        return self._session

    def _headers(self) -> dict:
        return {"Authorization": self.api_key, "Accept": _JSON, "Content-Type": _JSON}

    def post(self, path: str, payload: dict) -> dict:
        resp = self._client().post(
            f"{self.url}{path}",
            json=payload,
            headers=self._headers(),
            verify=self.verify_tls,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get(self, path: str) -> dict:
        resp = self._client().get(
            f"{self.url}{path}",
            headers=self._headers(),
            verify=self.verify_tls,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()
