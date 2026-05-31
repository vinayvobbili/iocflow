"""Cortex Query Language (XQL) — Palo Alto Cortex XSIAM / XDR.

Renders an indicator set into an ``xdr_data`` query with an ``in (...)`` filter
on the field that carries that indicator kind.
"""
from __future__ import annotations

from typing import List

# Indicator kind -> the xdr_data field that carries it.
_FIELDS = {
    "ip": "action_remote_ip",
    "domain": "action_external_hostname",
    "filename": "action_file_name",
    "md5": "action_file_md5",
    "sha1": "action_file_sha1",
    "sha256": "action_file_sha256",
}


def _dq(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class CortexDialect:
    key = "cortex"
    label = "Cortex XQL"

    def supports(self, kind: str) -> bool:
        return kind in _FIELDS

    def render(self, kind: str, values: List[str]) -> str:
        field = _FIELDS[kind]
        joined = ", ".join(_dq(v) for v in values)
        return f"dataset = xdr_data\n| filter {field} in ({joined})"
