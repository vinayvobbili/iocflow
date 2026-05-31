"""iocflow Layer 6 — the agentic capstone.

A small multi-agent team (LangGraph) that drives the whole IOC lifecycle: a
supervisor routes to specialist agents — extractor, enricher, hunter, responder
— that use Layers 1–5 as tools. The LLM applies judgment (routing, response
recommendations); the deterministic layers do the exact work and are the
fallback when no model is configured.

    from iocflow.agent import investigate

    case = investigate(report_text)          # safe: DenyAllGate approves nothing
    print(case.summary())
    print(case.commentary.severity.value, case.commentary.summary)
    for line in case.trace:
        print(" •", line)

Blocking is human-in-the-loop. The responder proposes blocks; an
:class:`ApprovalGate` authorizes them; the deterministic allowlist guard vetoes
benign/internal indicators underneath. Default is :class:`DenyAllGate` (nothing
is blocked). To act, pass an approving gate:

    from iocflow.agent import investigate, CLIApprovalGate
    case = investigate(report_text, gate=CLIApprovalGate())

The model is any LangChain chat model; :func:`default_agent_model` builds a
``FailoverChatModel`` (primary→secondary) from ``IOCFLOW_LLM_*``.

Needs the extra: ``pip install "iocflow[agent]"``.
"""
from iocflow.agent.chat_gate import (
    ChatApprovalGate,
    ChatTransport,
    SlackApprovalGate,
    SlackTransport,
)
from iocflow.agent.gate import (
    ApprovalDecision,
    ApprovalGate,
    AutoApproveGate,
    BlockProposal,
    CLIApprovalGate,
    DenyAllGate,
    ProposedAction,
)
from iocflow.agent.graph import build_graph, investigate
from iocflow.agent.model import default_agent_model
from iocflow.agent.state import Case, CaseFile
from iocflow.agent.tools import IOCFLOW_TOOLS

__all__ = [
    "investigate",
    "build_graph",
    "default_agent_model",
    "Case",
    "CaseFile",
    "IOCFLOW_TOOLS",
    # HITL
    "ApprovalGate",
    "ApprovalDecision",
    "BlockProposal",
    "ProposedAction",
    "DenyAllGate",
    "AutoApproveGate",
    "CLIApprovalGate",
    # chat-driven HITL (Slack reference adapter)
    "ChatApprovalGate",
    "ChatTransport",
    "SlackApprovalGate",
    "SlackTransport",
]
