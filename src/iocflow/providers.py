"""Pluggable name sources for malware families and threat-actor aliases.

The core extractor has zero external-data dependencies. Two enrichment
sources are optional and supplied by the caller:

- :class:`MalwareNames` — the universe of malware/tool names (and their
  alias-to-canonical map) that :func:`iocflow.extract_malware_families`
  matches against. Without it, ``malware_families`` is empty.
- :class:`ActorAliases` — known threat-actor names (for matching) plus an
  alias index (for ``common_name`` / ``region`` / ``all_names`` enrichment).
  Without it, threat actors are still found by pattern and curated list; only
  the alias enrichment is skipped.

Both are plain data containers. Build them from any source you like — a CSV,
a spreadsheet, an internal feed, or the bundled ``iocflow[mitre]`` extra which
returns a ready-made :class:`MalwareNames`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Mapping, Optional, Set


@dataclass
class MalwareNames:
    """A set of malware/tool names plus an alias→canonical map.

    ``names`` is every surface form to match in text. ``alias_map`` maps a
    lowercased surface form to its canonical name, so that matching an alias
    (e.g. "Geodo") reports the canonical family (e.g. "Emotet").
    """

    names: Set[str] = field(default_factory=set)
    alias_map: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_entries(cls, entries: Iterable[Mapping]) -> "MalwareNames":
        """Build from records shaped ``{"name": str, "aliases": [str, ...]}``.

        This is the MITRE ATT&CK malware/tool shape, but any source producing
        the same shape works.
        """
        names: Set[str] = set()
        alias_map: Dict[str, str] = {}
        for entry in entries:
            canonical = entry["name"]
            aliases = entry.get("aliases") or [canonical]
            for alias in aliases:
                names.add(alias)
                alias_map[alias.lower()] = canonical
        return cls(names=names, alias_map=alias_map)

    @classmethod
    def from_names(cls, names: Iterable[str]) -> "MalwareNames":
        """Build from a flat iterable of names with no aliasing."""
        name_set = set(names)
        return cls(names=name_set, alias_map={n.lower(): n for n in name_set})


@dataclass
class ActorAliases:
    """Known actor names for matching, plus an alias index for enrichment.

    ``known_names`` is the set of surface forms to match in text. ``index``
    maps a lowercased name to an info dict with keys ``common_name``,
    ``region``, and ``all_names``.
    """

    known_names: Set[str] = field(default_factory=set)
    index: Dict[str, dict] = field(default_factory=dict)

    def lookup(self, name: str) -> Optional[dict]:
        """Return the info dict for ``name``, or ``None`` if unknown."""
        return self.index.get(name.lower())

    @classmethod
    def from_index(cls, index: Mapping[str, dict]) -> "ActorAliases":
        """Build from a ``{lowercased name: {common_name, region, all_names}}`` map.

        ``known_names`` is derived from every surface form in the index,
        including each entry's ``all_names`` aliases.
        """
        known: Set[str] = set()
        normalized: Dict[str, dict] = {}
        for key, info in index.items():
            normalized[key.lower()] = dict(info)
            known.add(key)
            for alias in info.get("all_names", []) or []:
                known.add(alias)
                normalized.setdefault(alias.lower(), dict(info))
        return cls(known_names=known, index=normalized)
