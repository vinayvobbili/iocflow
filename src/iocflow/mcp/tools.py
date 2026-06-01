"""The IOC lifecycle as plain MCP-tool functions — no MCP SDK import here.

Kept SDK-free on purpose: the tool *logic* is unit-testable without the ``mcp``
extra, and :mod:`iocflow.mcp.server` simply registers these functions on a
FastMCP instance. Each function's signature + docstring is what an MCP client
sees as the tool schema and description, so they're written for that audience.

All tools take text (or STIX) and return a JSON-serializable ``dict``. They
inherit the library's safety posture: nothing here changes external state — the
block tool is a DRY RUN that only reports what *would* be blocked.
"""
from __future__ import annotations

from typing import List, Optional


def extract_iocs(text: str) -> dict:
    """Extract indicators of compromise from unstructured text.

    Finds IPs, domains, URLs, file hashes (md5/sha1/sha256), filenames, CVEs,
    email addresses, MITRE ATT&CK techniques, threat actors, and malware
    families. Returns a dict of indicators grouped by kind.
    """
    from iocflow import extract

    return extract(text).to_dict()


def enrich_indicators(text: str) -> dict:
    """Extract IOCs from text, then look each up against configured threat-intel
    sources (VirusTotal / AbuseIPDB / abuse.ch) and return a verdict report.

    Sources are selected from environment API keys; with none configured the
    report is empty but the call still succeeds.
    """
    from iocflow import extract
    from iocflow.enrich import enrich

    return enrich(extract(text)).to_dict()


def assess_indicators(text: str) -> dict:
    """Extract and enrich IOCs, then produce an analyst-style assessment:
    a severity, a narrative, key findings, and recommendations.

    Uses the configured LLM when available, falling back to a deterministic
    report-derived assessment otherwise.
    """
    from iocflow import extract
    from iocflow.ai import comment
    from iocflow.enrich import enrich

    entities = extract(text)
    report = enrich(entities)
    return comment(report, entities=entities, text=text).to_dict()


def suggest_hunts(text: str, dialects: Optional[List[str]] = None) -> dict:
    """Extract and enrich IOCs, then suggest ready-to-run threat-hunt queries.

    Renders one IOC-sweep query per indicator kind in each requested dialect:
    ``crowdstrike`` (CQL), ``cortex`` (XQL), and ``sigma``. Pass ``dialects`` to
    restrict; omit for all three. Returns a hunt-plan dict.
    """
    from iocflow import extract
    from iocflow.enrich import enrich
    from iocflow.hunt import suggest

    entities = extract(text)
    return suggest(enrich(entities), entities=entities, dialects=dialects).to_dict()


def propose_blocks(text: str) -> dict:
    """Extract and enrich IOCs, then return a DRY-RUN block plan showing exactly
    what would be blocked at each configured control point, and why.

    This never changes anything: it is analysis only. Actually pushing blocks is
    deliberately not exposed as an MCP tool — that stays a human-gated action.
    """
    from iocflow import extract
    from iocflow.block import block
    from iocflow.enrich import enrich

    return block(enrich(extract(text))).to_dict()  # dry_run=True by default


def to_stix_bundle(text: str) -> dict:
    """Extract IOCs from text and emit a conformant STIX 2.1 bundle.

    Object ids are deterministic (UUIDv5 over the indicator), so the same input
    yields the same bundle. Returns the bundle as a dict.
    """
    from iocflow import extract
    from iocflow.stix import to_stix

    return to_stix(extract(text))


def from_stix_bundle(stix: str) -> dict:
    """Parse a STIX 2.1 bundle / object(s) / JSON string into extracted indicators.

    Walks both observable objects and indicator patterns; resilient to malformed
    objects. Returns a dict of indicators grouped by kind.
    """
    from iocflow.stix import from_stix

    return from_stix(stix).to_dict()


# The lifecycle as a ready-to-register tool list (order = lifecycle order).
MCP_TOOLS = [
    extract_iocs,
    enrich_indicators,
    assess_indicators,
    suggest_hunts,
    propose_blocks,
    to_stix_bundle,
    from_stix_bundle,
]
