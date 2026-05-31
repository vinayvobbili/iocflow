"""The IOC lifecycle exposed as LangChain tools.

Every deterministic capability (L1–L5) is wrapped as a ``@tool`` so it can be
handed to a tool-calling agent or invoked directly. The agent graph calls the
underlying layer functions; these wrappers are the public, composable tool
surface (and the showcase: "the IOC lifecycle as agent tools").
"""
from __future__ import annotations

from langchain_core.tools import tool


@tool
def extract_iocs(text: str) -> dict:
    """Extract indicators of compromise (IPs, domains, URLs, hashes, CVEs, MITRE
    techniques, threat actors, malware) from unstructured text. Returns a dict."""
    from iocflow import extract
    return extract(text).to_dict()


@tool
def enrich_indicators(text: str) -> dict:
    """Extract IOCs from text, then look each up against configured threat-intel
    sources (VirusTotal/AbuseIPDB/abuse.ch) and return a verdict report dict."""
    from iocflow import extract
    from iocflow.enrich import enrich
    return enrich(extract(text)).to_dict()


@tool
def suggest_hunts(text: str) -> dict:
    """Extract and enrich IOCs from text, then suggest ready-to-run hunt queries
    (CrowdStrike CQL / Cortex XQL / Sigma). Returns a hunt-plan dict."""
    from iocflow import extract
    from iocflow.enrich import enrich
    from iocflow.hunt import suggest
    entities = extract(text)
    return suggest(enrich(entities), entities=entities).to_dict()


@tool
def propose_blocks(text: str) -> dict:
    """Extract and enrich IOCs, then return a DRY-RUN block plan showing exactly
    what would be blocked at each control point. Never changes anything."""
    from iocflow import extract
    from iocflow.block import block
    from iocflow.enrich import enrich
    return block(enrich(extract(text))).to_dict()


# The L1–L5 capabilities as a ready-to-bind tool list.
IOCFLOW_TOOLS = [extract_iocs, enrich_indicators, suggest_hunts, propose_blocks]
