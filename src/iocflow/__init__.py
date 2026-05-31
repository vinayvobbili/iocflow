"""iocflow — an IOC-lifecycle toolkit.

Layer 1 is threat-entity extraction: pull IPs, domains, URLs, filenames,
hashes, CVEs, emails, MITRE technique IDs, threat actors, and malware families
out of unstructured text. The extracted :class:`ExtractedEntities` is the input
type that later layers (enrichment, AI commentary, hunt generation, blocking)
build on.

Quick start::

    from iocflow import extract

    entities = extract("APT28 used 185.220.101.5 and evil[.]example[.]com")
    print(entities.summary())
    for indicator in entities.iter_indicators():
        print(indicator.kind, indicator.value)
"""
from iocflow.extract import extract
from iocflow.extractors import (
    extract_cves,
    extract_domains,
    extract_emails,
    extract_filenames,
    extract_hashes,
    extract_ips,
    extract_malware_families,
    extract_mitre_procedures,
    extract_mitre_techniques,
    extract_threat_actors,
    extract_urls,
)
from iocflow.models import ExtractedEntities, Indicator, ThreatActor
from iocflow.providers import ActorAliases, MalwareNames
from iocflow.refang import refang_text

__version__ = "0.6.0"

__all__ = [
    # Orchestrator
    "extract",
    # Result types
    "ExtractedEntities",
    "Indicator",
    "ThreatActor",
    # Pluggable sources
    "ActorAliases",
    "MalwareNames",
    # Individual extractors
    "extract_ips",
    "extract_domains",
    "extract_urls",
    "extract_emails",
    "extract_filenames",
    "extract_hashes",
    "extract_cves",
    "extract_mitre_techniques",
    "extract_mitre_procedures",
    "extract_threat_actors",
    "extract_malware_families",
    # Utilities
    "refang_text",
    "__version__",
]
