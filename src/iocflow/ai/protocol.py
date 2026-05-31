"""The ``CommentaryModel`` protocol — any chat model that can complete a prompt."""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class CommentaryModel(Protocol):
    """A minimal chat-completion interface.

    Implementations need a ``name`` and a ``complete`` that returns the model's
    text response. When ``json`` is true the implementation should ask the model
    for a single JSON object (e.g. via OpenAI ``response_format``); callers still
    parse defensively, so best-effort is fine.
    """

    name: str

    def complete(self, system: str, user: str, *, json: bool = False) -> str: ...
