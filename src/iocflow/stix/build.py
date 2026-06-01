"""``to_stix`` — turn iocflow results into a conformant STIX 2.1 bundle.

Accepts anything that carries indicators: ``ExtractedEntities``, an
``EnrichmentReport`` (whose verdicts shape the ``indicator_types`` /
``confidence``), a ``Case``/``TriageResult`` (uses its ``.entities``), or a plain
iterable of ``(kind, value)`` pairs.

Object ids are deterministic (UUIDv5 over the indicator), so re-emitting the same
indicator yields the same id — bundles are reproducible and idempotent to ingest.
Stdlib only.
"""
from __future__ import annotations

import datetime
import uuid
from typing import List, Optional, Tuple

# A stable namespace so the same indicator always maps to the same STIX id.
_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "iocflow.stix")
_SPEC = "2.1"

_VERDICT_TYPES = {
    "malicious": (["malicious-activity"], 90),
    "suspicious": (["anomalous-activity"], 50),
    "benign": (["benign"], 10),
    "unknown": (["malicious-activity"], None),
}


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sid(otype: str, seed: str) -> str:
    return f"{otype}--{uuid.uuid5(_NS, seed)}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _pattern(kind: str, value: str) -> Optional[str]:
    v = _escape(value)
    if kind == "ip":
        otype = "ipv6-addr" if ":" in value else "ipv4-addr"
        return f"[{otype}:value = '{v}']"
    return {
        "domain": f"[domain-name:value = '{v}']",
        "url": f"[url:value = '{v}']",
        "email": f"[email-addr:value = '{v}']",
        "filename": f"[file:name = '{v}']",
        "md5": f"[file:hashes.'MD5' = '{v}']",
        "sha1": f"[file:hashes.'SHA-1' = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
    }.get(kind)


def _indicator_pairs(source) -> List[Tuple[str, str]]:
    """Duck-type any iocflow result into an ordered, de-duplicated (kind, value) list."""
    if hasattr(source, "iter_indicators"):
        raw = [(i.kind, i.value) for i in source.iter_indicators()]
    elif hasattr(source, "records"):  # EnrichmentReport
        raw = [(r.kind, r.value) for r in source.records]
    elif hasattr(source, "entities"):  # Case / TriageResult
        return _indicator_pairs(source.entities)
    else:
        raw = [(k, v) for k, v in source]
    seen, out = set(), []
    for pair in raw:
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
    return out


def _verdict_map(source) -> dict:
    if not hasattr(source, "records"):
        return {}
    out = {}
    for r in source.records:
        v = getattr(getattr(r, "verdict", None), "value", None)
        if v:
            out[(r.kind, r.value)] = v
    return out


def to_stix(source, *, created: Optional[str] = None) -> dict:
    """Build a STIX 2.1 ``bundle`` dict from any iocflow result.

    Args:
        source: ``ExtractedEntities``, ``EnrichmentReport``, ``Case`` /
            ``TriageResult``, or an iterable of ``(kind, value)`` pairs.
        created: ISO8601 timestamp for the SDOs (defaults to now, UTC). Pass a
            fixed value for fully-reproducible output.
    """
    ts = created or _now()
    verdicts = _verdict_map(source)
    objects, seen_ids = [], set()

    def emit(obj: dict) -> None:
        if obj["id"] not in seen_ids:
            seen_ids.add(obj["id"])
            objects.append(obj)

    for kind, value in _indicator_pairs(source):
        if not value:
            continue
        pattern = _pattern(kind, value)
        if pattern is not None:
            types, confidence = _VERDICT_TYPES.get(verdicts.get((kind, value), "unknown"),
                                                   _VERDICT_TYPES["unknown"])
            obj: dict = {
                "type": "indicator", "spec_version": _SPEC,
                "id": _sid("indicator", f"{kind}:{value}"),
                "created": ts, "modified": ts,
                "name": f"{kind}: {value}",
                "pattern": pattern, "pattern_type": "stix",
                "valid_from": ts, "indicator_types": types,
            }
            if confidence is not None:
                obj["confidence"] = confidence
            emit(obj)
        elif kind == "cve":
            emit({
                "type": "vulnerability", "spec_version": _SPEC,
                "id": _sid("vulnerability", f"cve:{value}"),
                "created": ts, "modified": ts, "name": value,
                "external_references": [{"source_name": "cve", "external_id": value}],
            })
        elif kind == "malware_family":
            emit({
                "type": "malware", "spec_version": _SPEC,
                "id": _sid("malware", f"malware:{value}"),
                "created": ts, "modified": ts, "name": value, "is_family": True,
            })
        elif kind == "threat_actor":
            emit({
                "type": "threat-actor", "spec_version": _SPEC,
                "id": _sid("threat-actor", f"actor:{value}"),
                "created": ts, "modified": ts, "name": value,
            })
        elif kind == "mitre_technique":
            emit({
                "type": "attack-pattern", "spec_version": _SPEC,
                "id": _sid("attack-pattern", f"mitre:{value}"),
                "created": ts, "modified": ts, "name": value,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": value}],
            })

    bundle_seed = "|".join(sorted(seen_ids)) or "empty"
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NS, bundle_seed)}",
        "objects": objects,
    }
