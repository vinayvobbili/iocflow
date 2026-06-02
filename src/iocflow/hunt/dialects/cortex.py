"""Cortex Query Language (XQL) — Palo Alto Cortex XSIAM / XDR.

Renders an indicator set into an ``xdr_data`` query with an ``in (...)`` filter
on the field that carries that indicator kind.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from iocflow.hunt.dialects._common import basic_query_checks

# Indicator kind -> the xdr_data field that carries it.
_FIELDS = {
    "ip": "action_remote_ip",
    "domain": "action_external_hostname",
    "filename": "action_file_name",
    "md5": "action_file_md5",
    "sha1": "action_file_sha1",
    "sha256": "action_file_sha256",
}

# Datasets a behavioral hunt may source. ``xdr_data`` is the canonical EDR
# telemetry dataset; anything else is rejected at validation time.
VALID_DATASETS = {"xdr_data"}

_DATASET_RE = re.compile(r"dataset\s*=\s*([A-Za-z0-9_\-]+)")


def _dq(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class CortexDialect:
    key = "cortex"
    label = "Cortex XQL"

    behavioral_guide = (
        "Palo Alto Cortex XSIAM — XQL behavioral hunt syntax:\n"
        "- Start from the dataset: dataset = xdr_data\n"
        "- Scope one event class: | filter event_type = ENUM.PROCESS\n"
        "  (valid: ENUM.PROCESS, ENUM.NETWORK, ENUM.FILE, ENUM.REGISTRY, ENUM.LOAD_IMAGE)\n"
        "- Pipe stages with |. String contains: field contains \"x\". Regex: field ~= \"(?i)pat\".\n"
        "- Combine with and / or / not and parentheses.\n"
        "- ALWAYS bound output with a final | limit 100.\n"
        "Fields: action_process_image_name, action_process_image_command_line, "
        "actor_process_image_name, action_remote_ip, action_file_name, agent_hostname."
    )

    def supports(self, kind: str) -> bool:
        return kind in _FIELDS

    def render(self, kind: str, values: List[str]) -> str:
        field = _FIELDS[kind]
        joined = ", ".join(_dq(v) for v in values)
        return f"dataset = xdr_data\n| filter {field} in ({joined})"

    def validate_behavioral(self, query: str) -> Tuple[bool, str]:
        """Validate an LLM-authored behavioral XQL hunt.

        Requires a ``dataset = <allowed>`` source clause and a ``| limit N``
        bound. (XQL has no clean event-name allow-list like CQL, so the dataset
        allow-list plus the repair loop are the guard rails.) Returns
        ``(ok, reason)``.
        """
        basic = basic_query_checks(query)
        if basic:
            return basic
        m = _DATASET_RE.search(query)
        if not m:
            return False, "no 'dataset = ...' source clause"
        if m.group(1) not in VALID_DATASETS:
            return False, f"disallowed dataset: {m.group(1)}"
        if not re.search(r"\|\s*limit\s+\d+", query, re.IGNORECASE):
            return False, "not output-bounded (needs | limit N)"
        return True, ""
