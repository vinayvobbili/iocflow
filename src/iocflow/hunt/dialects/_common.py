"""Shared helpers for behavioral-hunt validation across dialects.

The deterministic renderers are always valid by construction; these checks only
guard *LLM-authored* behavioral hunts before they are surfaced (and drive the
optional repair loop in :mod:`iocflow.hunt.llm`). Stdlib-only — importing a
dialect must never pull in the LLM/ai layer.
"""
from __future__ import annotations

from typing import Optional, Tuple

# An LLM hunt query longer than this is almost certainly runaway prose, not a
# query; reject it rather than ship it.
MAX_QUERY_CHARS = 4000

# Lower-cased prefixes that mark a model refusal / prose instead of a query.
_REFUSAL_PREFIXES = ("i cannot", "i can't", "i'm sorry", "sorry", "as an ai", "i am unable")


def basic_query_checks(query: str) -> Optional[Tuple[bool, str]]:
    """Dialect-agnostic pre-checks.

    Returns ``(False, reason)`` on failure, or ``None`` when the query clears the
    basic bar (so a dialect can fall through to its own syntax checks).
    """
    if not query or not query.strip():
        return False, "empty query"
    if len(query) > MAX_QUERY_CHARS:
        return False, f"query too long ({len(query)} chars)"
    if query.strip().lower().startswith(_REFUSAL_PREFIXES):
        return False, "model returned prose, not a query"
    return None
