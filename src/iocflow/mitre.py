"""Optional MITRE ATT&CK malware-name provider (``iocflow[mitre]`` extra).

Fetches the public ATT&CK Enterprise STIX bundle, extracts every malware and
tool object with its aliases, and returns a ready-made
:class:`~iocflow.providers.MalwareNames`. The slim result is cached on disk
for ``CACHE_TTL_SECONDS`` so repeated calls don't re-download.

This module imports ``requests``, which is only installed with the extra::

    pip install "iocflow[mitre]"
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import List, Optional

from iocflow.providers import MalwareNames

logger = logging.getLogger(__name__)

STIX_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days


def _default_cache_path() -> Path:
    """Cache location, overridable via ``IOCFLOW_CACHE_DIR``."""
    base = os.environ.get("IOCFLOW_CACHE_DIR")
    root = Path(base) if base else Path(tempfile.gettempdir()) / "iocflow"
    return root / "attack_malware_tools.json"


def mitre_malware_names(
    *, cache_path: Optional[Path] = None, force_refresh: bool = False
) -> MalwareNames:
    """Return MITRE ATT&CK malware/tool names as a :class:`MalwareNames`.

    Args:
        cache_path: Where to read/write the slim cache. Defaults to a per-user
            temp dir (override with the ``IOCFLOW_CACHE_DIR`` env var).
        force_refresh: Ignore any fresh cache and re-fetch.
    """
    entries = _load_malware_entries(cache_path=cache_path, force_refresh=force_refresh)
    return MalwareNames.from_entries(entries)


def _load_malware_entries(
    *, cache_path: Optional[Path], force_refresh: bool
) -> List[dict]:
    path = cache_path or _default_cache_path()

    if not force_refresh and path.exists():
        try:
            data = json.loads(path.read_text())
            if time.time() - data.get("fetched_at", 0) < CACHE_TTL_SECONDS:
                return data["malware_tools"]
        except (json.JSONDecodeError, KeyError):
            logger.warning("Corrupt iocflow MITRE cache at %s, re-fetching", path)

    bundle = _fetch_stix_bundle()
    if not bundle:
        # Fall back to a stale cache if we have one rather than returning nothing.
        if path.exists():
            try:
                return json.loads(path.read_text())["malware_tools"]
            except (json.JSONDecodeError, KeyError):
                pass
        return []

    entries = _extract_malware(bundle)
    _write_cache(path, entries)
    return entries


def _fetch_stix_bundle() -> Optional[dict]:
    import requests  # imported lazily so the core install doesn't need it

    logger.info("Fetching MITRE ATT&CK Enterprise STIX bundle...")
    try:
        resp = requests.get(STIX_BUNDLE_URL, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:  # noqa: BLE001 — network/parse errors all degrade the same
        logger.error("Failed to fetch STIX bundle: %s", e)
        return None


def _extract_malware(bundle: dict) -> List[dict]:
    malware_tools = []
    for obj in bundle.get("objects", []):
        if obj.get("type") not in ("malware", "tool"):
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        mitre_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id")
                break
        if not mitre_id or not mitre_id.startswith("S"):
            continue

        name = obj.get("name", "")
        aliases = obj.get("x_mitre_aliases") or [name]
        malware_tools.append(
            {
                "id": mitre_id,
                "name": name,
                "type": obj.get("type"),
                "aliases": aliases,
            }
        )
    return malware_tools


def _write_cache(path: Path, entries: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fetched_at": time.time(),
        "count": len(entries),
        "malware_tools": entries,
    }
    path.write_text(json.dumps(payload, separators=(",", ":")))
    logger.info("Cached %d ATT&CK malware/tool entries to %s", len(entries), path)
