"""Live Palo Alto PAN-OS / Panorama blocker — registered-IP tags (DAG).

Registers an IP→tag mapping via the User-ID XML API. A Dynamic Address Group
matching that tag, referenced by a deny policy, then blocks the IP immediately —
no commit required. Only IPs are blockable this way; use the EDL feed for
domains/URLs.

Set up once on the firewall: a DAG with match ``'iocflow-block'`` (the default
tag) and a security rule denying it. Then configure ``IOCFLOW_PANOS_HOST`` and
``IOCFLOW_PANOS_API_KEY``.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

from iocflow.block.base import HTTPBlocker
from iocflow.block.models import BlockResult, BlockStatus


class PanOsBlocker(HTTPBlocker):
    """Blocks IPs by registering tags via the PAN-OS User-ID API."""

    name = "panos"
    supported_kinds = frozenset({"ip"})
    supports_unblock = True

    def __init__(self, host: Optional[str] = None, api_key: Optional[str] = None, *,
                 tag: str = "iocflow-block", **kw) -> None:
        super().__init__(**kw)
        self.host = (host or "").strip().rstrip("/")
        self.api_key = api_key
        self.tag = tag

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.api_key)

    @property
    def _url(self) -> str:
        host = self.host if "://" in self.host else f"https://{self.host}"
        return f"{host}/api/"

    def _block_payload(self, kind: str, value: str, action: str) -> dict:
        return {"op": "register", "ip": value, "tag": self.tag, "cmd": _uid("register", value, self.tag)}

    def _unblock_payload(self, kind: str, value: str) -> dict:
        return {"op": "unregister", "ip": value, "tag": self.tag,
                "cmd": _uid("unregister", value, self.tag)}

    def _do_block(self, kind: str, value: str, action: str, payload: dict) -> BlockResult:
        self._uid_call(payload["cmd"])
        return self._result(kind, value, BlockStatus.BLOCKED, action=action, payload=payload,
                            reference=self.host, detail=f"registered tag '{self.tag}'")

    def _do_unblock(self, kind: str, value: str, payload: dict) -> BlockResult:
        self._uid_call(payload["cmd"])
        return self._result(kind, value, BlockStatus.UNBLOCKED, payload=payload,
                            reference=self.host, detail=f"unregistered tag '{self.tag}'")

    def _uid_call(self, cmd: str) -> None:
        resp = self._session.post(
            self._url,
            data={"type": "user-id", "key": self.api_key, "cmd": cmd},
            timeout=self.timeout,
            verify=self.verify,
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        if root.attrib.get("status") != "success":
            raise RuntimeError(f"PAN-OS API error: {resp.text[:200]}")


def _uid(op: str, ip: str, tag: str) -> str:
    """Build a User-ID update message registering or unregistering one IP tag."""
    return (
        "<uid-message><version>1.0</version><type>update</type><payload>"
        f"<{op}><entry ip=\"{ip}\"><tag><member>{tag}</member></tag></entry></{op}>"
        "</payload></uid-message>"
    )
