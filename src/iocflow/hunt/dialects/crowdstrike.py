"""CrowdStrike Query Language (CQL) — Falcon LogScale / Next-Gen SIEM.

Renders an indicator set into LogScale's ``in(field, values=[...])`` form, which
matches any event whose ``field`` is one of the given values.
"""
from __future__ import annotations

from typing import List

# Indicator kind -> the LogScale event field that carries it.
_FIELDS = {
    "ip": "RemoteAddressIP4",
    "domain": "DomainName",
    "url": "HttpUrl",
    "filename": "FileName",
    "md5": "MD5HashData",
    "sha1": "SHA1HashData",
    "sha256": "SHA256HashData",
}


def _dq(value: str) -> str:
    """Double-quote a value for a LogScale string list."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class CrowdStrikeDialect:
    key = "crowdstrike"
    label = "CrowdStrike CQL"

    def supports(self, kind: str) -> bool:
        return kind in _FIELDS

    def render(self, kind: str, values: List[str]) -> str:
        field = _FIELDS[kind]
        joined = ", ".join(_dq(v) for v in values)
        return f"in({field}, values=[{joined}])"
