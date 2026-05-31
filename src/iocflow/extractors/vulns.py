"""Vulnerability and MITRE ATT&CK indicators: CVEs and technique IDs."""
from __future__ import annotations

import re
from typing import Dict, List

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_TECHNIQUE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b", re.IGNORECASE)
# T1xxx[.xxx]: Technique Name - Procedure text (name may itself contain colons).
_PROCEDURE = re.compile(r"(T1\d{3}(?:\.\d{3})?)\s*:\s*(.+?)\s*-\s*(.+)")


def extract_cves(text: str) -> List[str]:
    """Extract CVE identifiers, normalized to uppercase."""
    return list(dict.fromkeys(cve.upper() for cve in _CVE.findall(text)))


def extract_mitre_techniques(text: str) -> List[str]:
    """Extract MITRE ATT&CK technique and sub-technique IDs (T1059, T1059.001)."""
    return list(dict.fromkeys(t.upper() for t in _TECHNIQUE.findall(text)))


def extract_mitre_procedures(text: str) -> Dict[str, str]:
    """Parse ``Txxxx: Name - Procedure`` lines into ``{id: "Name - Procedure"}``.

    Useful for reports that list techniques with a one-line procedure summary::

        T1005: Data from Local System - File-manager plugin enables browsing...
        T1552.003: Unsecured Credentials: Bash History - Env-var scanner...
    """
    procedures: Dict[str, str] = {}
    for line in text.split("\n"):
        m = _PROCEDURE.search(line.strip())
        if m:
            tech_id = m.group(1).upper()
            procedures[tech_id] = f"{m.group(2).strip()} - {m.group(3).strip()}"
    return procedures
