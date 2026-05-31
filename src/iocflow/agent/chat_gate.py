"""A chat-driven human-in-the-loop approval gate (Slack reference adapter).

This wires the :class:`~iocflow.agent.gate.ApprovalGate` seam to a chat channel
without standing up any inbound webhook server: the gate *posts* the proposed
blocks to a channel and then *polls* for an approval signal — a reaction from an
allowlisted approver — returning the authorized actions.

It keeps the same safe posture as the rest of Layer 6:

* approval is **plan-level** — one reaction approves (or denies) the whole plan;
* only reactions from ``approvers`` count (if an allowlist is given);
* a **timeout defaults to deny**, so an unattended proposal changes nothing;
* the Layer 5 allowlist guard still vetoes benign/internal indicators underneath,
  regardless of what a human approves.

The transport is a thin, easily-stubbed seam, so the polling/timeout/authority
logic lives here and is unit-tested without any network. The bundled
:class:`SlackTransport` talks to the Slack Web API; write your own ``post`` /
``reactions`` pair to target Webex, Teams, or anything else.

Needs the extra: ``pip install "iocflow[agent]"`` (the Slack transport uses
``requests``).
"""
from __future__ import annotations

import os
import time
from typing import Callable, List, Optional, Protocol, Sequence, Tuple, runtime_checkable

from iocflow.agent.gate import ApprovalDecision, BlockProposal


@runtime_checkable
class ChatTransport(Protocol):
    """Posts a message to a channel and reads reactions back.

    Two methods keep every platform pluggable:

    * ``post(text)`` publishes the proposal and returns an opaque handle.
    * ``reactions(handle)`` returns ``(emoji_name, user_id)`` pairs currently on
      that message.
    """

    def post(self, text: str) -> str: ...

    def reactions(self, handle: str) -> Sequence[Tuple[str, str]]: ...


def _format_proposal(proposal: BlockProposal, *, approve: str, deny: str) -> str:
    """A readable chat message describing exactly what would be blocked."""
    lines = [
        f"*iocflow — {len(proposal.actions)} block action(s) proposed for approval*",
        "",
    ]
    for i, a in enumerate(proposal.actions, 1):
        targets = ", ".join(a.targets) or "(no target)"
        line = (f"  {i}. [{a.severity.value}] `{a.kind} {a.value}` → {targets} "
                f"({a.action})")
        if a.rationale:
            line += f" — {a.rationale}"
        lines.append(line)
    report = proposal.dry_run_report
    if report is not None and hasattr(report, "summary"):
        lines += ["", f"_Dry run:_ {report.summary()}"]
    lines += [
        "",
        f":{approve}: to approve the whole plan · :{deny}: to deny "
        "(no response = denied).",
    ]
    return "\n".join(lines)


class ChatApprovalGate:
    """Posts a proposal to a chat channel and polls for an approver's reaction.

    Conforms to the :class:`~iocflow.agent.gate.ApprovalGate` protocol, so it
    drops straight into ``investigate(text, gate=...)``.

    Parameters
    ----------
    transport:
        A :class:`ChatTransport` (e.g. :class:`SlackTransport`).
    approvers:
        Optional allowlist of platform user IDs whose reactions count. ``None``
        accepts a reaction from anyone in the channel.
    approve_emoji / deny_emoji:
        Reaction names (without colons) that mean approve / deny.
    timeout:
        Seconds to wait for a decision before defaulting to **deny**.
    poll_interval:
        Seconds between reaction polls.
    """

    def __init__(
        self,
        transport: ChatTransport,
        *,
        approvers: Optional[Sequence[str]] = None,
        approve_emoji: str = "white_check_mark",
        deny_emoji: str = "x",
        timeout: float = 300.0,
        poll_interval: float = 5.0,
        sleep_fn: Callable[[float], None] = time.sleep,
        time_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self.transport = transport
        self.approvers = set(approvers) if approvers else None
        self.approve_emoji = approve_emoji.strip(":")
        self.deny_emoji = deny_emoji.strip(":")
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._sleep = sleep_fn
        self._now = time_fn

    def review(self, proposal: BlockProposal) -> ApprovalDecision:
        if not proposal.actions:
            return ApprovalDecision(approved=[], note="nothing to approve")

        handle = self.transport.post(
            _format_proposal(proposal, approve=self.approve_emoji, deny=self.deny_emoji)
        )

        deadline = self._now() + self.timeout
        while True:
            decision = self._scan(proposal, handle)
            if decision is not None:
                return decision
            if self._now() >= deadline:
                return ApprovalDecision(
                    approved=[], note="denied (approval timed out)"
                )
            self._sleep(self.poll_interval)

    def _scan(self, proposal: BlockProposal, handle: str) -> Optional[ApprovalDecision]:
        """One pass over current reactions. Deny wins over approve in a tie."""
        approved_by = None
        for emoji, user in self.transport.reactions(handle):
            name = str(emoji).strip(":")
            if self.approvers is not None and user not in self.approvers:
                continue
            if name == self.deny_emoji:
                return ApprovalDecision(approved=[], note=f"denied by {user}")
            if name == self.approve_emoji and approved_by is None:
                approved_by = user
        if approved_by is not None:
            return ApprovalDecision(
                approved=list(proposal.actions), note=f"approved by {approved_by}"
            )
        return None


class SlackTransport:
    """A :class:`ChatTransport` backed by the Slack Web API.

    Needs a bot token (``xoxb-…``) with ``chat:write`` and ``reactions:read``,
    and the bot invited to the channel. Reads ``SLACK_BOT_TOKEN`` and
    ``SLACK_APPROVAL_CHANNEL`` from the environment when not passed explicitly.
    """

    def __init__(
        self,
        *,
        token: Optional[str] = None,
        channel: Optional[str] = None,
        base_url: str = "https://slack.com/api",
        timeout: float = 15.0,
        session=None,
    ) -> None:
        self.token = token or os.environ.get("SLACK_BOT_TOKEN", "")
        self.channel = channel or os.environ.get("SLACK_APPROVAL_CHANNEL", "")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = session

    @property
    def is_configured(self) -> bool:
        return bool(self.token and self.channel)

    def _client(self):
        if self._session is None:
            import requests  # lazy: only the live path needs it

            self._session = requests.Session()
        return self._session

    def _call(self, method: str, payload: dict) -> dict:
        if not self.is_configured:
            raise RuntimeError(
                "SlackTransport needs SLACK_BOT_TOKEN and SLACK_APPROVAL_CHANNEL"
            )
        resp = self._client().post(
            f"{self.base_url}/{method}",
            json=payload,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=self.timeout,
        )
        data = resp.json()
        if not data.get("ok"):
            raise RuntimeError(f"Slack {method} failed: {data.get('error', 'unknown')}")
        return data

    def post(self, text: str) -> str:
        data = self._call("chat.postMessage", {"channel": self.channel, "text": text})
        return str(data["ts"])  # the message timestamp is its handle

    def reactions(self, handle: str) -> List[Tuple[str, str]]:
        data = self._call(
            "reactions.get", {"channel": self.channel, "timestamp": handle, "full": True}
        )
        out: List[Tuple[str, str]] = []
        for r in data.get("message", {}).get("reactions", []):
            name = r.get("name", "")
            for user in r.get("users", []):
                out.append((name, user))
        return out


class SlackApprovalGate(ChatApprovalGate):
    """A ready-to-use :class:`ChatApprovalGate` over Slack.

        from iocflow.agent import investigate
        from iocflow.agent.chat_gate import SlackApprovalGate

        gate = SlackApprovalGate(approvers=["U0123ANALYST"])  # token/channel from env
        case = investigate(report_text, gate=gate)

    The bot posts the proposed blocks to the channel; the first allowlisted
    approver to react :white_check_mark: authorizes the plan (:x: denies it). No
    response within ``timeout`` seconds = denied.
    """

    def __init__(
        self,
        *,
        token: Optional[str] = None,
        channel: Optional[str] = None,
        approvers: Optional[Sequence[str]] = None,
        base_url: str = "https://slack.com/api",
        request_timeout: float = 15.0,
        session=None,
        **gate_kwargs,
    ) -> None:
        transport = SlackTransport(
            token=token, channel=channel, base_url=base_url,
            timeout=request_timeout, session=session,
        )
        super().__init__(transport, approvers=approvers, **gate_kwargs)
