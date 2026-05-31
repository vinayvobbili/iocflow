"""Individual, composable extraction functions.

Each function takes text and returns a list/dict of one entity type. They are
re-exported from the top-level :mod:`iocflow` package for convenience.
"""
from iocflow.extractors.actors import (
    extract_malware_families,
    extract_threat_actors,
)
from iocflow.extractors.contacts import extract_emails
from iocflow.extractors.files import extract_filenames, extract_hashes
from iocflow.extractors.network import (
    extract_domains,
    extract_ips,
    extract_urls,
)
from iocflow.extractors.vulns import (
    extract_cves,
    extract_mitre_procedures,
    extract_mitre_techniques,
)

__all__ = [
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
]
