"""Build the agent's chat model from the environment.

The agent works with any LangChain ``BaseChatModel``. By default it builds a
``FailoverChatModel`` (from the ``langchain-failover`` package) wrapping a
primary and secondary OpenAI-compatible endpoint — so the agent inherits m1→s1
style failover. With only a primary configured it returns that single model;
with nothing configured it returns ``None`` and the graph runs deterministically.
"""
from __future__ import annotations

import os
from typing import Optional


def default_agent_model(env: Optional[dict] = None):
    """Construct the agent model from ``IOCFLOW_LLM_*`` (and optional secondary).

    Primary:   ``IOCFLOW_LLM_BASE_URL`` / ``IOCFLOW_LLM_API_KEY`` / ``IOCFLOW_LLM_MODEL``
    Secondary: ``IOCFLOW_LLM_SECONDARY_BASE_URL`` / ``_SECONDARY_API_KEY`` / ``_SECONDARY_MODEL``

    Returns a ``FailoverChatModel`` when a secondary is set, a single
    ``ChatOpenAI`` when only a primary is set, or ``None`` when neither is.
    """
    env = env if env is not None else os.environ
    primary = _chat_openai(
        env.get("IOCFLOW_LLM_BASE_URL"),
        env.get("IOCFLOW_LLM_API_KEY"),
        env.get("IOCFLOW_LLM_MODEL", "gpt-4o-mini"),
    )
    if primary is None:
        return None

    secondary = _chat_openai(
        env.get("IOCFLOW_LLM_SECONDARY_BASE_URL"),
        env.get("IOCFLOW_LLM_SECONDARY_API_KEY"),
        env.get("IOCFLOW_LLM_SECONDARY_MODEL", env.get("IOCFLOW_LLM_MODEL", "gpt-4o-mini")),
    )
    if secondary is None:
        return primary

    from langchain_failover import FailoverChatModel
    return FailoverChatModel(primary=primary, secondary=secondary)


def _chat_openai(base_url: Optional[str], api_key: Optional[str], model: str):
    """Build one ChatOpenAI, or None if neither base URL nor key is set."""
    if not base_url and not api_key:
        return None
    try:
        from langchain_openai import ChatOpenAI
    except ImportError:  # pragma: no cover - optional dependency
        return None
    kwargs = {"model": model, "temperature": 0.1}
    if base_url:
        kwargs["base_url"] = base_url
    # ChatOpenAI requires a non-empty key even for keyless local servers.
    kwargs["api_key"] = api_key or "EMPTY"
    return ChatOpenAI(**kwargs)
