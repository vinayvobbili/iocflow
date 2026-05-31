"""``from_stix`` — turn a STIX 2.x bundle / object(s) into ``ExtractedEntities``.

Stdlib only and resilient: it walks observable objects (SCOs) and indicator
patterns, pulls what it recognizes, and silently skips anything it doesn't —
real TAXII feeds are messy, so a single bad object never sinks the parse.
"""
from __future__ import annotations

import json
import re
from typing import List, Union

from iocflow.models import ExtractedEntities

# Cyber-observable object type -> indicator kind.
_SCO_KIND = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "url": "url",
    "email-addr": "email",
}

# STIX hash dictionary key -> entities hash bucket.
_HASH_ALGO = {
    "MD5": "md5",
    "SHA-1": "sha1", "SHA1": "sha1",
    "SHA-256": "sha256", "SHA256": "sha256",
}

# One comparison expression inside a STIX pattern: `<type>:<path> = '<value>'`
# (also IN (...) / != / LIKE / MATCHES).
_PATTERN_COMP = re.compile(
    r"([a-z0-9_-]+):([^\s=<>!]+)\s*(?:=|!=|IN|LIKE|MATCHES)\s*(\([^)]*\)|'(?:[^'\\]|\\.)*')",
    re.IGNORECASE,
)
_QUOTED = re.compile(r"'((?:[^'\\]|\\.)*)'")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _unescape(s: str) -> str:
    return s.replace("\\'", "'").replace("\\\\", "\\")


def _objects(data: Union[str, dict, list]) -> list:
    """Normalize any accepted input into a flat list of STIX objects."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return []
    if isinstance(data, dict):
        if data.get("type") == "bundle" or "objects" in data:
            return list(data.get("objects", []))
        return [data]
    if isinstance(data, list):
        return data
    return []


def from_stix(data: Union[str, dict, list]) -> ExtractedEntities:
    """Parse a STIX bundle, single object, list of objects, or JSON string.

    Returns an :class:`~iocflow.models.ExtractedEntities`; never raises.
    """
    ents = ExtractedEntities()
    for obj in _objects(data):
        if not isinstance(obj, dict):
            continue
        try:
            _ingest(obj, ents)
        except Exception:  # noqa: BLE001 — one malformed object can't sink the parse
            continue
    _dedup(ents)
    return ents


def _ingest(obj: dict, ents: ExtractedEntities) -> None:
    t = obj.get("type")
    if t in _SCO_KIND:
        _add_kind(ents, _SCO_KIND[t], obj.get("value", ""))
    elif t == "file":
        if obj.get("name"):
            ents.filenames.append(obj["name"])
        for algo, digest in (obj.get("hashes") or {}).items():
            bucket = _HASH_ALGO.get(str(algo).upper())
            if bucket and digest:
                ents.hashes[bucket].append(digest)
    elif t == "indicator":
        _ingest_pattern(obj.get("pattern", "") or "", ents)
    elif t == "vulnerability":
        # The CVE is the external reference; `name` is only a CVE if it looks like one
        # (feeds often use a friendly name, e.g. "Log4Shell").
        name = obj.get("name", "")
        if name and _CVE.match(name):
            ents.cves.append(name)
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "cve" and ref.get("external_id"):
                ents.cves.append(ref["external_id"])
    elif t == "malware":
        if obj.get("name"):
            ents.malware_families.append(obj["name"])
    elif t in ("threat-actor", "intrusion-set"):
        if obj.get("name"):
            ents.threat_actors.append(obj["name"])
    elif t == "attack-pattern":
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                ents.mitre_techniques.append(ref["external_id"])


def _ingest_pattern(pattern: str, ents: ExtractedEntities) -> None:
    for m in _PATTERN_COMP.finditer(pattern):
        otype, prop, raw = m.group(1).lower(), m.group(2), m.group(3)
        for value in (_unescape(q) for q in _QUOTED.findall(raw)):
            if not value:
                continue
            if otype in ("ipv4-addr", "ipv6-addr"):
                ents.ips.append(value)
            elif otype == "domain-name":
                ents.domains.append(value)
            elif otype == "url":
                ents.urls.append(value)
            elif otype == "email-addr":
                ents.emails.append(value)
            elif otype == "file":
                low = prop.lower()
                if "hashes" in low:
                    algo = prop.split(".")[-1].strip("'\"").upper()
                    bucket = _HASH_ALGO.get(algo)
                    if bucket:
                        ents.hashes[bucket].append(value)
                elif "name" in low:
                    ents.filenames.append(value)


def _add_kind(ents: ExtractedEntities, kind: str, value: str) -> None:
    if not value:
        return
    {"ip": ents.ips, "domain": ents.domains, "url": ents.urls,
     "email": ents.emails}[kind].append(value)


def _dedup(ents: ExtractedEntities) -> None:
    def uniq(seq: List[str]) -> List[str]:
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    ents.ips = uniq(ents.ips)
    ents.domains = uniq(ents.domains)
    ents.urls = uniq(ents.urls)
    ents.emails = uniq(ents.emails)
    ents.filenames = uniq(ents.filenames)
    ents.cves = uniq(ents.cves)
    ents.malware_families = uniq(ents.malware_families)
    ents.threat_actors = uniq(ents.threat_actors)
    ents.mitre_techniques = uniq(ents.mitre_techniques)
    for algo in ("md5", "sha1", "sha256"):
        ents.hashes[algo] = uniq(ents.hashes.get(algo, []))
