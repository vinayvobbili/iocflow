"""The allowlist safety guard — the authoritative veto on what may be blocked.

This is deliberately deterministic and applied *before* any target call (and,
in the future agent, *after* the LLM proposes and before execution). The model
and the human can choose what to block; this guard decides what must never be
blocked — public resolvers, well-known infrastructure, private/internal IPs,
and benign domains — so a mislabeled indicator can't take down something safe.
"""
from __future__ import annotations

import ipaddress
from typing import List, Tuple

import tldextract

from iocflow.allowlists import BENIGN_DOMAINS, BENIGN_IPS
from iocflow.models import Indicator

# Use tldextract without network access (no live PSL fetch in a blocking path).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def is_allowlisted(kind: str, value: str) -> Tuple[bool, str]:
    """Return ``(blocked_from_blocking, reason)`` for one indicator.

    ``True`` means the guard forbids blocking this value. Hashes are never
    allowlisted (a hash names a specific file, not infrastructure).
    """
    if kind == "ip":
        return _ip_allowlisted(value)
    if kind in ("domain", "url"):
        return _domain_allowlisted(_host_of(value) if kind == "url" else value)
    if kind == "email":
        _, _, dom = value.partition("@")
        ok, reason = _domain_allowlisted(dom) if dom else (False, "")
        return ok, reason
    return False, ""


def guard(indicators: List[Indicator]) -> Tuple[List[Indicator], List[Tuple[Indicator, str]]]:
    """Partition indicators into ``(allowed, vetoed)``; vetoed carries a reason."""
    allowed: List[Indicator] = []
    vetoed: List[Tuple[Indicator, str]] = []
    for ind in indicators:
        blocked, reason = is_allowlisted(ind.kind, ind.value)
        if blocked:
            vetoed.append((ind, reason))
        else:
            allowed.append(ind)
    return allowed, vetoed


# -- helpers ---------------------------------------------------------------

def _ip_allowlisted(value: str) -> Tuple[bool, str]:
    if value in BENIGN_IPS:
        return True, "well-known benign IP"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False, ""
    # Never block non-global space at the perimeter — it's internal, not a threat.
    if ip.is_private:
        return True, "private/internal IP"
    if ip.is_loopback:
        return True, "loopback IP"
    if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True, "reserved/non-routable IP"
    return False, ""


def _domain_allowlisted(host: str) -> Tuple[bool, str]:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False, ""
    if host in BENIGN_DOMAINS:
        return True, "benign domain"
    ext = _EXTRACT(host)
    registered = ".".join(p for p in (ext.domain, ext.suffix) if p)
    if registered and registered in BENIGN_DOMAINS:
        return True, f"benign registered domain ({registered})"
    return False, ""


def _host_of(url: str) -> str:
    """Best-effort host extraction from a URL or bare host/path."""
    s = url.split("://", 1)[-1]
    s = s.split("/", 1)[0]
    s = s.split("@")[-1]  # strip userinfo
    return s.split(":", 1)[0]  # strip port
