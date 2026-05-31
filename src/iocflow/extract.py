"""The :func:`extract` orchestrator — run every extractor over a piece of text."""
from __future__ import annotations

import logging
import re
from typing import Optional

from iocflow.extractors.actors import extract_malware_families, extract_threat_actors
from iocflow.extractors.contacts import extract_emails
from iocflow.extractors.files import extract_filenames, extract_hashes
from iocflow.extractors.network import extract_domains, extract_ips, extract_urls
from iocflow.extractors.vulns import extract_cves, extract_mitre_techniques
from iocflow.models import ExtractedEntities, ThreatActor
from iocflow.providers import ActorAliases, MalwareNames
from iocflow.refang import refang_text

logger = logging.getLogger(__name__)

_HTML_TAG = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s+")


def extract(
    text: str,
    *,
    actor_aliases: Optional[ActorAliases] = None,
    malware_names: Optional[MalwareNames] = None,
    refang: bool = True,
) -> ExtractedEntities:
    """Extract all entity types from ``text``.

    Args:
        text: The text to extract from.
        actor_aliases: Optional known-actor names + alias index. When given,
            actor names are also matched against this set and enriched with
            ``common_name`` / ``region`` / ``all_names``.
        malware_names: Optional malware/tool name set. Required for
            ``malware_families`` to be populated.
        refang: Whether to re-fang defanged IOCs (``[.]`` -> ``.`` etc.) first.

    Returns:
        An :class:`~iocflow.models.ExtractedEntities`.
    """
    if not text:
        return ExtractedEntities()

    # Strip HTML and collapse whitespace.
    clean = _HTML_TAG.sub(" ", text)
    clean = _WHITESPACE.sub(" ", clean)
    if refang:
        clean = refang_text(clean)

    raw_actors = extract_threat_actors(clean, actor_aliases)
    enriched = _enrich_actors(raw_actors, actor_aliases)

    urls = extract_urls(clean)
    entities = ExtractedEntities(
        ips=extract_ips(clean),
        domains=extract_domains(clean),
        urls=urls,
        filenames=extract_filenames(clean, urls=urls),
        hashes=extract_hashes(clean),
        cves=extract_cves(clean),
        emails=extract_emails(clean),
        threat_actors=raw_actors,
        threat_actors_enriched=enriched,
        malware_families=extract_malware_families(clean, malware_names),
        mitre_techniques=extract_mitre_techniques(clean),
    )

    if not entities.is_empty():
        logger.info("Extracted entities: %s", entities.summary())
    return entities


def _enrich_actors(
    raw_actors: list, actor_aliases: Optional[ActorAliases]
) -> list:
    """Map raw actor names to :class:`ThreatActor`, de-duplicating by common name."""
    enriched = []
    seen_common = set()
    for name in raw_actors:
        info = actor_aliases.lookup(name) if actor_aliases else None
        if info:
            common = info.get("common_name", name)
            if common.lower() in seen_common:
                continue
            seen_common.add(common.lower())
            enriched.append(
                ThreatActor(
                    name=name,
                    common_name=common,
                    region=info.get("region", ""),
                    all_names=info.get("all_names", []),
                )
            )
        else:
            enriched.append(ThreatActor(name=name, common_name=name))
    return enriched
