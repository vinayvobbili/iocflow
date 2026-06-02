"""CrowdStrike Query Language (CQL) — Falcon LogScale / Next-Gen SIEM.

Renders an indicator set into LogScale's ``in(field, values=[...])`` form, which
matches any event whose ``field`` is one of the given values.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from iocflow.hunt.dialects._common import basic_query_checks

# Indicator kind -> the LogScale event field that carries it.
_FIELDS = {
    "ip": "RemoteAddressIP4",
    "domain": "DomainName",
    "url": "HttpUrl",
    "filename": "FileName",
    "md5": "MD5HashData",
    "sha1": "SHA1HashData",
    "sha256": "SHA256HashData",
}

# CrowdStrike sensor ``event_simpleName`` values a behavioral hunt may scope to.
# An LLM hunt that references anything outside this set is rejected at validation
# time (catches hallucinated event names). These are CrowdStrike's documented
# Falcon telemetry events, not site-specific.
VALID_EVENTS = {
    "ProcessRollup2",
    "SyntheticProcessRollup2",
    "NetworkConnectIP4",
    "NetworkConnectIP6",
    "DnsRequest",
    "ImageHash",
    "UserLogon",
    "UserIdentity",
    "CreateRemoteThreadDetectInfo",
    "CommandHistory",
    "ServiceStartType",
    "DriverLoad",
    "ScheduledTaskRegistered",
    "WmiBindEventConsumerToFilter",
    "RegKeySecurityDecrease",
    "RawAccessRead",
    "IntegrityLevel",
    "UdpConnectionReceived",
    "CreateSocket",
    "AsepValueUpdate",
    "ProcessInjection",
}

_EVENT_RE = re.compile(r"#event_simpleName\s*=\s*\"?/?([A-Za-z0-9]+)")


def _dq(value: str) -> str:
    """Double-quote a value for a LogScale string list."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class CrowdStrikeDialect:
    key = "crowdstrike"
    label = "CrowdStrike CQL"

    # Cheat-sheet injected into the repair prompt when a behavioral hunt fails
    # validation, so the model has the syntax it needs to fix the query.
    behavioral_guide = (
        "CrowdStrike LogScale (Humio QL) behavioral hunt syntax:\n"
        "- Start by scoping an event: #event_simpleName=ProcessRollup2\n"
        "- Allowed event_simpleName values: " + ", ".join(sorted(VALID_EVENTS)) + "\n"
        "- Pipe stages with |. Case-insensitive regex match: FieldName=/pattern/i\n"
        "- Combine with and / or / not and parentheses.\n"
        "- ALWAYS bound output with a final | head(100) (or | tail(100)).\n"
        "Common fields: ImageFileName, ParentBaseFileName, CommandLine, "
        "ComputerName, UserName, RemoteAddressIP4, DomainName, aid."
    )

    def supports(self, kind: str) -> bool:
        return kind in _FIELDS

    def render(self, kind: str, values: List[str]) -> str:
        field = _FIELDS[kind]
        joined = ", ".join(_dq(v) for v in values)
        return f"in({field}, values=[{joined}])"

    def validate_behavioral(self, query: str) -> Tuple[bool, str]:
        """Validate an LLM-authored behavioral CQL hunt.

        Requires an ``#event_simpleName`` scope drawn only from
        :data:`VALID_EVENTS` and an output-bounding stage. Returns
        ``(ok, reason)`` — ``reason`` is empty when ``ok``.
        """
        basic = basic_query_checks(query)
        if basic:
            return basic
        events = _EVENT_RE.findall(query)
        if not events:
            return False, "no #event_simpleName scope"
        bad = sorted({e for e in events if e not in VALID_EVENTS})
        if bad:
            return False, f"disallowed event_simpleName: {', '.join(bad)}"
        if not re.search(r"\b(head|tail)\s*\(", query) and not re.search(r"\blimit\s*=", query):
            return False, "not output-bounded (needs head()/tail()/limit)"
        return True, ""
