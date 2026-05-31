"""Data types produced by extraction.

``ExtractedEntities`` is the central type of iocflow. Layer 1 (this package)
populates it; later layers consume it. In particular it is the intended input
type for a future ``Enricher`` protocol — see ``iter_indicators`` below.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, NamedTuple


class Indicator(NamedTuple):
    """A single (type, value) indicator.

    This is the flat, enricher-friendly view of an ``ExtractedEntities`` —
    the unit a future enrichment layer iterates over. ``kind`` is one of:
    ``ip``, ``domain``, ``url``, ``email``, ``filename``, ``cve``,
    ``mitre_technique``, ``threat_actor``, ``malware_family``,
    ``md5``, ``sha1``, ``sha256``.
    """

    kind: str
    value: str


@dataclass
class ThreatActor:
    """A threat actor with optional alias / attribution information."""

    name: str  # The name as it appeared in the text
    common_name: str = ""  # Standardized common name from an alias provider
    region: str = ""  # Attribution region (e.g. "Russia", "North Korea")
    all_names: List[str] = field(default_factory=list)  # All known aliases

    def aliases_display(self, max_aliases: int = 5) -> str:
        """Return a comma-joined alias string, excluding the matched name."""
        if not self.all_names:
            return ""
        aliases = [n for n in self.all_names if n.lower() != self.name.lower()][:max_aliases]
        return ", ".join(aliases) if aliases else ""


@dataclass
class ExtractedEntities:
    """Container for all entities extracted from a piece of text."""

    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    filenames: List[str] = field(default_factory=list)
    hashes: Dict[str, List[str]] = field(
        default_factory=lambda: {"md5": [], "sha1": [], "sha256": []}
    )
    cves: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    threat_actors_enriched: List[ThreatActor] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """True if no entity of any kind was extracted."""
        return not any(
            (
                self.ips,
                self.domains,
                self.urls,
                self.filenames,
                self.hashes["md5"],
                self.hashes["sha1"],
                self.hashes["sha256"],
                self.cves,
                self.emails,
                self.threat_actors,
                self.malware_families,
                self.mitre_techniques,
            )
        )

    def iter_indicators(self) -> Iterator[Indicator]:
        """Yield every extracted value as a flat ``Indicator``.

        This is the L2 growth seam: an enricher consumes ``ExtractedEntities``
        by iterating indicators here, without having to know the field layout.
        """
        for ip in self.ips:
            yield Indicator("ip", ip)
        for domain in self.domains:
            yield Indicator("domain", domain)
        for url in self.urls:
            yield Indicator("url", url)
        for email in self.emails:
            yield Indicator("email", email)
        for filename in self.filenames:
            yield Indicator("filename", filename)
        for algo in ("md5", "sha1", "sha256"):
            for digest in self.hashes.get(algo, []):
                yield Indicator(algo, digest)
        for cve in self.cves:
            yield Indicator("cve", cve)
        for tech in self.mitre_techniques:
            yield Indicator("mitre_technique", tech)
        for actor in self.threat_actors:
            yield Indicator("threat_actor", actor)
        for family in self.malware_families:
            yield Indicator("malware_family", family)

    def to_dict(self) -> dict:
        """Convert to a plain JSON-serializable dict."""
        return {
            "ips": self.ips,
            "domains": self.domains,
            "urls": self.urls,
            "filenames": self.filenames,
            "hashes": self.hashes,
            "cves": self.cves,
            "emails": self.emails,
            "threat_actors": self.threat_actors,
            "threat_actors_enriched": [
                {
                    "name": ta.name,
                    "common_name": ta.common_name,
                    "region": ta.region,
                    "all_names": ta.all_names,
                }
                for ta in self.threat_actors_enriched
            ],
            "malware_families": self.malware_families,
            "mitre_techniques": self.mitre_techniques,
        }

    def summary(self) -> str:
        """Human-readable one-line summary of what was extracted."""
        parts = []
        if self.ips:
            parts.append(f"{len(self.ips)} IPs")
        if self.domains:
            parts.append(f"{len(self.domains)} domains")
        if self.urls:
            parts.append(f"{len(self.urls)} URLs")
        if self.filenames:
            parts.append(f"{len(self.filenames)} filenames")
        hash_count = sum(len(self.hashes[a]) for a in ("md5", "sha1", "sha256"))
        if hash_count:
            parts.append(f"{hash_count} hashes")
        if self.cves:
            parts.append(f"{len(self.cves)} CVEs")
        if self.emails:
            parts.append(f"{len(self.emails)} emails")
        if self.threat_actors:
            parts.append(f"{len(self.threat_actors)} threat actors")
        if self.malware_families:
            parts.append(f"{len(self.malware_families)} malware families")
        if self.mitre_techniques:
            parts.append(f"{len(self.mitre_techniques)} MITRE techniques")
        return ", ".join(parts) if parts else "No entities found"
