"""Threat-actor and malware-family extraction.

Actor extraction works with zero external data via patterns and a curated
well-known list. Pass an :class:`~iocflow.providers.ActorAliases` to also match
a custom name set, and a :class:`~iocflow.providers.MalwareNames` to enable
malware-family extraction.
"""
from __future__ import annotations

import re
from typing import List, Optional

from iocflow.allowlists import (
    MALWARE_BLOCKLIST,
    RANSOMWARE_FALSE_POSITIVES,
    SYSTEM_TOOL_BLOCKLIST,
    WELL_KNOWN_ACTORS,
)
from iocflow.providers import ActorAliases, MalwareNames

# Structured actor designators: APT28, APT-28, UNC2452, FIN7, TA505, DEV-0537,
# STORM-0558.
_ACTOR_PATTERNS = [
    re.compile(r"\bAPT[-]?\d+\b", re.IGNORECASE),
    re.compile(r"\bUNC\d+\b", re.IGNORECASE),
    re.compile(r"\bFIN\d+\b", re.IGNORECASE),
    re.compile(r"\bTA\d+\b", re.IGNORECASE),
    re.compile(r"\bDEV-\d+\b", re.IGNORECASE),
    re.compile(r"\bSTORM-\d+\b", re.IGNORECASE),
]

# "<ProperNoun> ransomware" — case-sensitive so "go-based ransomware" misses.
_RANSOMWARE = re.compile(r"\b([A-Z][a-z]+(?:[A-Z][a-z0-9]*)*)\s+ransomware\b")

# Real APT names that are common English words and cause too many false hits.
_ACTOR_NAME_BLOCKLIST = {"lead"}


def extract_threat_actors(text: str, known: Optional[ActorAliases] = None) -> List[str]:
    """Extract threat-actor names.

    Strategies, in order:

    1. Exact-match a caller-supplied known-name set (if ``known`` is given).
    2. Match APT/UNC/FIN/TA/DEV/STORM designators.
    3. Match a curated list of well-known actor and ransomware names.
    4. Catch the ``"<Name> ransomware"`` pattern.
    """
    actors = set()

    if known is not None:
        for name in known.known_names:
            if len(name) <= 3 or name.lower() in _ACTOR_NAME_BLOCKLIST:
                continue
            m = re.search(r"\b" + re.escape(name) + r"\b", text, re.IGNORECASE)
            if m:
                actors.add(m.group())

    for pattern in _ACTOR_PATTERNS:
        actors.update(m.upper() for m in pattern.findall(text))

    for actor in WELL_KNOWN_ACTORS:
        m = re.search(r"\b" + re.escape(actor) + r"\b", text, re.IGNORECASE)
        if m:
            actors.add(m.group())

    for m in _RANSOMWARE.finditer(text):
        name = m.group(1)
        if name not in RANSOMWARE_FALSE_POSITIVES and len(name) >= 4:
            actors.add(name)

    return list(actors)


def extract_malware_families(text: str, malware: Optional[MalwareNames] = None) -> List[str]:
    """Extract malware-family names by matching a caller-supplied name set.

    Returns ``[]`` when no :class:`~iocflow.providers.MalwareNames` is given.
    Three-layer false-positive defense:

    1. Skip names of 3 characters or fewer (``at``, ``cmd``, ``ftp``).
    2. Case-sensitive matching for single-word names; case-insensitive for
       multi-word names.
    3. Blocklist common English words and LOLBins.

    When an alias matches, the result is normalized to its canonical name.
    """
    if malware is None or not malware.names:
        return []

    matched = set()
    for name in malware.names:
        if len(name) <= 3:
            continue
        name_lower = name.lower()
        if name_lower in MALWARE_BLOCKLIST or name_lower in SYSTEM_TOOL_BLOCKLIST:
            continue

        flags = re.IGNORECASE if " " in name else 0
        if re.search(r"\b" + re.escape(name) + r"\b", text, flags):
            canonical = malware.alias_map.get(name_lower, name)
            canon_lower = canonical.lower()
            if canon_lower in MALWARE_BLOCKLIST or canon_lower in SYSTEM_TOOL_BLOCKLIST:
                continue
            matched.add(canonical)

    return sorted(matched)
