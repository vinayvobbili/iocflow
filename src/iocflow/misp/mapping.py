"""Translations between iocflow indicator kinds and MISP attribute types.

MISP attribute types are far more granular than iocflow's kinds (``ip-src`` vs
``ip-dst``, ``filename|md5`` composites, …), so the maps below are deliberately
many-to-one in each direction. Pure data + small helpers — no imports.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

# iocflow kind -> the MISP attribute types to *search* for that kind.
KIND_TO_MISP_TYPES = {
    "ip": ("ip-src", "ip-dst", "ip-src|port", "ip-dst|port"),
    "domain": ("domain", "hostname", "domain|ip"),
    "url": ("url", "uri", "link"),
    "email": ("email", "email-src", "email-dst", "email-reply-to"),
    "md5": ("md5", "filename|md5"),
    "sha1": ("sha1", "filename|sha1"),
    "sha256": ("sha256", "filename|sha256"),
    "filename": ("filename", "filename|md5", "filename|sha1", "filename|sha256"),
    "cve": ("vulnerability",),
}

# MISP attribute type -> iocflow kind (for ingesting MISP events as triggers).
MISP_TYPE_TO_KIND = {
    "ip-src": "ip", "ip-dst": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url", "uri": "url", "link": "url",
    "email": "email", "email-src": "email", "email-dst": "email",
    "email-reply-to": "email",
    "md5": "md5", "sha1": "sha1", "sha256": "sha256",
    "filename": "filename",
    "vulnerability": "cve",
}

# Composite MISP types whose value is ``a|b``; each part maps to a kind (or None
# to drop it, e.g. the ``port`` half of ``ip-dst|port``).
_COMPOSITE = {
    "domain|ip": ("domain", "ip"),
    "hostname|port": ("domain", None),
    "ip-src|port": ("ip", None),
    "ip-dst|port": ("ip", None),
    "filename|md5": ("filename", "md5"),
    "filename|sha1": ("filename", "sha1"),
    "filename|sha256": ("filename", "sha256"),
}

# The single MISP type to publish a kind *as* (for share-back), with a sensible
# default category.
KIND_TO_PUBLISH_TYPE = {
    "ip": "ip-dst",
    "domain": "domain",
    "url": "url",
    "email": "email-src",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "filename": "filename",
    "cve": "vulnerability",
}

PUBLISH_CATEGORY = {
    "ip": "Network activity",
    "domain": "Network activity",
    "url": "Network activity",
    "email": "Payload delivery",
    "md5": "Payload delivery",
    "sha1": "Payload delivery",
    "sha256": "Payload delivery",
    "filename": "Payload delivery",
    "cve": "External analysis",
}


def attribute_indicators(misp_type: Optional[str], value: Optional[str]) -> List[Tuple[str, str]]:
    """Turn one MISP attribute into zero or more ``(kind, value)`` indicators.

    Simple types map one-to-one; composite types (``domain|ip``,
    ``filename|sha256``) split into each meaningful component.
    """
    value = (value or "").strip()
    if not misp_type or not value:
        return []
    if misp_type in _COMPOSITE and "|" in value:
        parts = value.split("|")
        out: List[Tuple[str, str]] = []
        for part, kind in zip(parts, _COMPOSITE[misp_type]):
            part = part.strip()
            if kind and part:
                out.append((kind, part))
        return out
    kind = MISP_TYPE_TO_KIND.get(misp_type)
    return [(kind, value)] if kind else []
