"""The structural ``Blocker`` protocol (no third-party imports).

A blocker enforces (or removes) a block for one indicator at one control point —
a firewall, a secure web gateway, an endpoint platform, an email gateway. Both
``block`` and ``unblock`` take ``dry_run`` and must never raise: failures are
reported via the result's ``status``/``error``. The flat ``(kind, value)``
signature is deliberate — it makes each blocker trivial to expose as an
LLM/agent tool later.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from iocflow.block.models import BlockResult


@runtime_checkable
class Blocker(Protocol):
    """Anything that can block (and optionally unblock) an indicator."""

    name: str

    def supports(self, kind: str) -> bool:
        """True if this target can act on ``kind`` (ip, domain, url, hash, email)."""
        ...

    def block(self, kind: str, value: str, *, action: str = "prevent",
              dry_run: bool = True) -> BlockResult:
        """Enforce a block. With ``dry_run`` (default) nothing is changed."""
        ...

    def unblock(self, kind: str, value: str, *, dry_run: bool = True) -> BlockResult:
        """Remove a block. With ``dry_run`` (default) nothing is changed."""
        ...
