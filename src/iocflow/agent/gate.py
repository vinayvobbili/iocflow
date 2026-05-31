"""The human-in-the-loop approval seam.

The responder agent never executes a block without passing the proposal through
an :class:`ApprovalGate`. The gate is where a human authorizes (or edits, or
rejects) the destructive step. The library ships three reference gates and the
protocol so you can wire your own to Slack/Teams/XSOAR/a web UI.

Three-layer authority: the LLM *proposes* (the agent), the human *authorizes*
(this gate), and the deterministic allowlist guard *vetoes* (Layer 5). The
default gate denies everything, so an unattended run changes nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Protocol, runtime_checkable

from iocflow.severity import Severity


@dataclass
class ProposedAction:
    """One indicator the agent proposes to block, and where/how."""

    kind: str
    value: str
    targets: List[str] = field(default_factory=list)  # control points that would act
    action: str = "prevent"
    rationale: str = ""
    severity: Severity = Severity.HIGH

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "value": self.value,
            "targets": self.targets,
            "action": self.action,
            "rationale": self.rationale,
            "severity": self.severity.value,
        }


@dataclass
class BlockProposal:
    """The full set of proposed actions an approver reviews."""

    actions: List[ProposedAction] = field(default_factory=list)
    dry_run_report: object = None  # the L5 BlockReport from the dry run

    def to_dict(self) -> dict:
        return {
            "actions": [a.to_dict() for a in self.actions],
            "dry_run_report": self.dry_run_report.to_dict()
            if hasattr(self.dry_run_report, "to_dict") else None,
        }


@dataclass
class ApprovalDecision:
    """What the gate authorized — a subset of the proposed actions."""

    approved: List[ProposedAction] = field(default_factory=list)
    note: str = ""


@runtime_checkable
class ApprovalGate(Protocol):
    """Reviews a block proposal and returns the approved actions."""

    def review(self, proposal: BlockProposal) -> ApprovalDecision: ...


class DenyAllGate:
    """Approves nothing — the safe default for an unattended run."""

    def review(self, proposal: BlockProposal) -> ApprovalDecision:
        return ApprovalDecision(approved=[], note="denied (DenyAllGate is the default)")


class AutoApproveGate:
    """Approves every proposed action. For dev/CI/demos ONLY — it blocks for real."""

    def review(self, proposal: BlockProposal) -> ApprovalDecision:
        return ApprovalDecision(approved=list(proposal.actions), note="auto-approved")


class CLIApprovalGate:
    """Prompts on the terminal — the whole plan at once, or one action at a time."""

    def __init__(self, *, per_action: bool = False, input_fn=input, print_fn=print) -> None:
        self.per_action = per_action
        self._input = input_fn
        self._print = print_fn

    def review(self, proposal: BlockProposal) -> ApprovalDecision:
        if not proposal.actions:
            return ApprovalDecision(approved=[], note="nothing to approve")
        self._print(f"\n{len(proposal.actions)} block action(s) proposed:")
        for i, a in enumerate(proposal.actions, 1):
            self._print(f"  {i}. [{a.severity.value}] {a.kind} {a.value} "
                        f"→ {', '.join(a.targets) or '(no target)'} ({a.action})"
                        + (f" — {a.rationale}" if a.rationale else ""))
        if self.per_action:
            approved = [a for a in proposal.actions
                        if self._yes(f"Block {a.kind} {a.value}? [y/N] ")]
            return ApprovalDecision(approved=approved, note="per-action CLI review")
        if self._yes("Approve ALL of the above? [y/N] "):
            return ApprovalDecision(approved=list(proposal.actions), note="plan approved via CLI")
        return ApprovalDecision(approved=[], note="plan rejected via CLI")

    def _yes(self, prompt: str) -> bool:
        return str(self._input(prompt)).strip().lower() in ("y", "yes")
