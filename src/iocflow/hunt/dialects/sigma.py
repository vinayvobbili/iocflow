"""Sigma — the vendor-neutral detection format.

Renders an indicator set into a complete, valid Sigma rule (YAML). Sigma
converts to many SIEM backends, so one rule reaches the broadest set of tools.
The rule id is derived deterministically from the indicators (stable output,
no randomness), and ``level`` reflects the hunt's severity.
"""
from __future__ import annotations

import hashlib
from typing import List, Optional, Tuple

from iocflow.hunt.dialects._common import basic_query_checks

# Indicator kind -> (logsource category, Sigma field, value prefix).
_FIELDS = {
    "ip": ("network_connection", "DestinationIp", ""),
    "domain": ("dns_query", "QueryName", ""),
    "url": ("proxy", "c-uri", ""),
    "filename": ("process_creation", "Image|endswith", "\\"),
    "md5": ("process_creation", "md5", ""),
    "sha1": ("process_creation", "sha1", ""),
    "sha256": ("process_creation", "sha256", ""),
}

_LEVELS = {"critical", "high", "medium", "low", "informational"}


def _yq(value: str) -> str:
    """Double-quote a value as a YAML scalar (escape ``\\`` and ``"``)."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _rule_id(kind: str, values: List[str]) -> str:
    """A deterministic UUID-shaped id derived from the indicator set."""
    digest = hashlib.sha1(f"iocflow:{kind}:{'|'.join(values)}".encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


class SigmaDialect:
    key = "sigma"
    label = "Sigma"

    behavioral_guide = (
        "Sigma rule (YAML) behavioral hunt structure — these keys are required:\n"
        "- title: <short name>\n"
        "- logsource: with a category (e.g. process_creation, dns_query)\n"
        "- detection: with one or more selections and a condition: line\n"
        "- level: one of critical/high/medium/low/informational\n"
        "Express the behavior in detection selections (field: value lists), not a "
        "single literal indicator. Return the rule as plain YAML text."
    )

    def supports(self, kind: str) -> bool:
        return kind in _FIELDS

    def validate_behavioral(self, query: str) -> Tuple[bool, str]:
        """Validate an LLM-authored Sigma rule's structure.

        Lightweight, stdlib-only (no YAML dependency): requires the mandatory
        Sigma keys — ``title:``, ``detection:`` and a ``condition``. Returns
        ``(ok, reason)``.
        """
        basic = basic_query_checks(query)
        if basic:
            return basic
        missing = [k for k in ("title:", "detection:", "condition") if k not in query]
        if missing:
            return False, f"missing Sigma key(s): {', '.join(missing)}"
        return True, ""

    def render(self, kind: str, values: List[str], *, level: Optional[str] = None) -> str:
        category, field, prefix = _FIELDS[kind]
        level = level if level in _LEVELS else "high"
        items = "\n".join(f"            - {_yq(prefix + v)}" for v in values)
        return (
            f"title: iocflow IOC sweep - {kind}\n"
            f"id: {_rule_id(kind, values)}\n"
            f"status: experimental\n"
            f"description: Matches the {kind} indicators extracted and enriched by iocflow.\n"
            f"logsource:\n"
            f"    category: {category}\n"
            f"detection:\n"
            f"    selection:\n"
            f"        {field}:\n"
            f"{items}\n"
            f"    condition: selection\n"
            f"level: {level}\n"
        )
