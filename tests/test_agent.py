"""Tests for iocflow Layer 6 agentic capstone (no network — models are stubbed)."""
import subprocess
import sys
from types import SimpleNamespace

import pytest

# The agent layer needs LangGraph/LangChain (Python >=3.10); skip the whole
# module where they are unavailable (e.g. the 3.9 CI leg).
pytest.importorskip("langgraph")

from iocflow.agent import (  # noqa: E402
    AutoApproveGate,
    BlockProposal,
    CLIApprovalGate,
    Case,
    DenyAllGate,
    ProposedAction,
    build_graph,
    default_agent_model,
    investigate,
)
from iocflow.agent.chat_gate import (  # noqa: E402
    ChatApprovalGate,
    SlackApprovalGate,
    SlackTransport,
    _format_proposal,
)
from iocflow.agent.nodes import (
    enricher_node,
    extractor_node,
    hunter_node,
    responder_node,
    supervisor_node,
)
from iocflow.agent.tools import IOCFLOW_TOOLS, extract_iocs
from iocflow.block import PanEdlFeed
from iocflow.block.models import BlockStatus
from iocflow.enrich.models import EnrichmentRecord, EnrichmentReport, Verdict

SAMPLE = ("APT28 used 185.220.101.5 and evil-domain.ru, dropping a.exe "
          "(sha256 " + "a" * 64 + "). Benign: 8.8.8.8.")


# ------------------------------ stubs -----------------------------

class StubModel:
    """Minimal chat model: invoke() returns an object with .content."""

    def __init__(self, content):
        self.content = content
        self.calls = []

    def invoke(self, messages):
        self.calls.append(messages)
        return SimpleNamespace(content=self.content)


def _mal_report(malicious=(), benign=()):
    recs = []
    for kind, value in malicious:
        recs.append(EnrichmentRecord("vt", kind, value, verdict=Verdict.MALICIOUS, score=90))
    for kind, value in benign:
        recs.append(EnrichmentRecord("vt", kind, value, verdict=Verdict.BENIGN))
    return EnrichmentReport(records=recs)


# ------------------------------ gates -----------------------------

def _proposal():
    return BlockProposal(actions=[ProposedAction("ip", "185.220.101.5", ["pan_edl"])])


def test_deny_all_gate_approves_nothing():
    assert DenyAllGate().review(_proposal()).approved == []


def test_auto_approve_gate_approves_all():
    d = AutoApproveGate().review(_proposal())
    assert len(d.approved) == 1


def test_cli_gate_plan_level_yes():
    gate = CLIApprovalGate(input_fn=lambda _: "y", print_fn=lambda *a: None)
    assert len(gate.review(_proposal()).approved) == 1


def test_cli_gate_plan_level_no():
    gate = CLIApprovalGate(input_fn=lambda _: "n", print_fn=lambda *a: None)
    assert gate.review(_proposal()).approved == []


def test_cli_gate_per_action():
    p = BlockProposal(actions=[ProposedAction("ip", "1.1.1.2", ["x"]),
                               ProposedAction("ip", "2.2.2.3", ["x"])])
    answers = iter(["y", "n"])
    gate = CLIApprovalGate(per_action=True, input_fn=lambda _: next(answers),
                           print_fn=lambda *a: None)
    approved = gate.review(p).approved
    assert [a.value for a in approved] == ["1.1.1.2"]


# ------------------------------ tools -----------------------------

def test_tools_are_invokable():
    out = extract_iocs.invoke({"text": SAMPLE})
    assert "185.220.101.5" in out["ips"]
    assert len(IOCFLOW_TOOLS) == 4


# ------------------------------ model -----------------------------

def test_default_agent_model_none_without_env():
    assert default_agent_model({}) is None


def test_default_agent_model_primary_only():
    m = default_agent_model({"IOCFLOW_LLM_BASE_URL": "http://localhost:8000/v1",
                             "IOCFLOW_LLM_API_KEY": "x", "IOCFLOW_LLM_MODEL": "m"})
    assert m is not None and hasattr(m, "bind_tools")


def test_default_agent_model_failover_with_secondary():
    from langchain_failover import FailoverChatModel
    m = default_agent_model({
        "IOCFLOW_LLM_BASE_URL": "http://m1/v1", "IOCFLOW_LLM_API_KEY": "x",
        "IOCFLOW_LLM_SECONDARY_BASE_URL": "http://s1/v1", "IOCFLOW_LLM_SECONDARY_API_KEY": "y",
    })
    assert isinstance(m, FailoverChatModel)


# --------------------------- supervisor ---------------------------

def test_supervisor_deterministic_order():
    assert supervisor_node({"visited": []})["next"] == "extractor"
    assert supervisor_node({"visited": ["extractor"]})["next"] == "enricher"


def test_supervisor_ends_when_all_visited():
    from langgraph.graph import END
    assert supervisor_node({"visited": ["extractor", "enricher", "hunter", "responder"]})["next"] is END


def test_supervisor_llm_routing_picks_remaining():
    out = supervisor_node({"visited": ["extractor"], "text": "x"}, model=StubModel("go to hunter next"))
    assert out["next"] == "hunter"


def test_supervisor_llm_bad_output_falls_back():
    out = supervisor_node({"visited": [], "text": "x"}, model=StubModel("gibberish"))
    assert out["next"] == "extractor"  # first remaining


# --------------------------- specialists --------------------------

def test_extractor_populates_entities():
    out = extractor_node({"text": SAMPLE})
    assert "185.220.101.5" in out["entities"].ips
    assert out["visited"] == ["extractor"]


def test_enricher_without_keys_is_empty_but_assesses():
    ents = extractor_node({"text": SAMPLE})["entities"]
    out = enricher_node({"text": SAMPLE, "entities": ents})
    assert out["enrichment"] is not None
    assert out["commentary"] is not None


def test_hunter_produces_plan():
    ents = extractor_node({"text": SAMPLE})["entities"]
    out = hunter_node({"entities": ents, "enrichment": EnrichmentReport()})
    assert out["hunts"].hunts


# --------------------------- responder + HITL ---------------------

def test_responder_denyall_does_not_block(tmp_path):
    rep = _mal_report(malicious=[("ip", "185.220.101.5")])
    out = responder_node({"enrichment": rep}, gate=DenyAllGate(), blockers=[PanEdlFeed(str(tmp_path))])
    assert out["proposal"].actions  # something was proposed
    assert all(r.status is BlockStatus.DRY_RUN for r in out["block_report"].results
               if r.target == "pan_edl")
    assert not (tmp_path / "ip.txt").exists()


def test_responder_autoapprove_blocks(tmp_path):
    rep = _mal_report(malicious=[("ip", "185.220.101.5")])
    out = responder_node({"enrichment": rep}, gate=AutoApproveGate(),
                         blockers=[PanEdlFeed(str(tmp_path))])
    assert out["block_report"].blocked
    assert (tmp_path / "ip.txt").read_text().strip() == "185.220.101.5"


def test_responder_guard_vetoes_benign_even_if_flagged(tmp_path):
    # 8.8.8.8 marked malicious must still never be proposed/blocked.
    rep = _mal_report(malicious=[("ip", "8.8.8.8"), ("ip", "185.220.101.5")])
    out = responder_node({"enrichment": rep}, gate=AutoApproveGate(),
                         blockers=[PanEdlFeed(str(tmp_path))])
    proposed = {a.value for a in out["proposal"].actions}
    assert proposed == {"185.220.101.5"}
    assert "8.8.8.8" not in (tmp_path / "ip.txt").read_text()


def test_responder_llm_refines_action_and_rationale(tmp_path):
    rep = _mal_report(malicious=[("ip", "185.220.101.5")])
    model = StubModel('{"actions":[{"value":"185.220.101.5","action":"detect",'
                      '"rationale":"low confidence, alert only"}]}')
    out = responder_node({"enrichment": rep, "commentary": None}, model=model,
                         gate=DenyAllGate(), blockers=[PanEdlFeed(str(tmp_path))])
    action = out["proposal"].actions[0]
    assert action.action == "detect"
    assert "alert only" in action.rationale


# --------------------------- end to end ---------------------------

def test_investigate_deterministic_runs_full_lifecycle():
    case = investigate(SAMPLE)  # no model, DenyAll
    assert isinstance(case, Case)
    assert "185.220.101.5" in case.entities.ips
    assert case.commentary is not None
    assert case.hunts.hunts
    assert case.block_report is not None
    stages = " ".join(case.trace)
    for agent in ("extractor", "enricher", "hunter", "responder"):
        assert agent in stages


def test_investigate_safe_by_default_blocks_nothing(tmp_path):
    # Even with a live blocker available, default DenyAll changes nothing.
    investigate(SAMPLE, blockers=[PanEdlFeed(str(tmp_path))])
    assert not (tmp_path / "ip.txt").exists()


def test_investigate_accepts_injected_enrichers(tmp_path):
    # An offline enricher flags every IP malicious; the guard still vetoes 8.8.8.8.
    class FlagIPs:
        name = "flag"

        def supports(self, kind):
            return kind == "ip"

        def enrich(self, kind, value):
            return EnrichmentRecord(self.name, kind, value,
                                    verdict=Verdict.MALICIOUS, score=99)

    case = investigate(SAMPLE, enrichers=[FlagIPs()], gate=AutoApproveGate(),
                       blockers=[PanEdlFeed(str(tmp_path))])
    assert case.block_report.blocked
    listed = (tmp_path / "ip.txt").read_text()
    assert "185.220.101.5" in listed and "8.8.8.8" not in listed


def test_case_to_dict_serializable():
    case = investigate(SAMPLE)
    d = case.to_dict()
    assert "entities" in d and "trace" in d
    import json
    json.dumps(d)  # must be JSON-serializable


def test_build_graph_compiles():
    g = build_graph()
    assert hasattr(g, "invoke")


# --------------------- chat-driven HITL gate ----------------------

class FakeTransport:
    """Stub ChatTransport: returns a scripted reaction list on each poll."""

    def __init__(self, script):
        # script: list of reaction lists [(emoji, user), ...] for successive polls
        self.script = [list(s) for s in script]
        self.posted = []
        self.i = 0

    def post(self, text):
        self.posted.append(text)
        return "ts.1"

    def reactions(self, handle):
        if self.i < len(self.script):
            r = self.script[self.i]
            self.i += 1
            return r
        return self.script[-1] if self.script else []


def _clock():
    """A controllable monotonic clock; sleep() just advances it (no real wait)."""
    t = {"v": 0.0}
    return (lambda: t["v"]), (lambda s: t.__setitem__("v", t["v"] + s))


def _chat_gate(transport, **kw):
    now, sleep = _clock()
    kw.setdefault("timeout", 30.0)
    kw.setdefault("poll_interval", 5.0)
    return ChatApprovalGate(transport, time_fn=now, sleep_fn=sleep, **kw)


def test_chat_gate_approve_reaction_authorizes_plan():
    t = FakeTransport([[("white_check_mark", "U1")]])
    d = _chat_gate(t).review(_proposal())
    assert len(d.approved) == 1 and "approved by U1" in d.note
    assert t.posted  # it announced the proposal


def test_chat_gate_deny_reaction_blocks_nothing():
    t = FakeTransport([[("x", "U1")]])
    d = _chat_gate(t).review(_proposal())
    assert d.approved == [] and "denied by U1" in d.note


def test_chat_gate_timeout_defaults_to_deny():
    t = FakeTransport([[]])  # never any reaction
    d = _chat_gate(t, timeout=12.0, poll_interval=5.0).review(_proposal())
    assert d.approved == [] and "timed out" in d.note


def test_chat_gate_only_allowlisted_approvers_count():
    # a stranger reacts ✅ first, then the real approver does
    t = FakeTransport([[("white_check_mark", "STRANGER")],
                       [("white_check_mark", "U_ANALYST")]])
    d = _chat_gate(t, approvers=["U_ANALYST"]).review(_proposal())
    assert len(d.approved) == 1 and "U_ANALYST" in d.note


def test_chat_gate_stranger_alone_times_out_denied():
    t = FakeTransport([[("white_check_mark", "STRANGER")]])
    d = _chat_gate(t, approvers=["U_ANALYST"], timeout=12.0).review(_proposal())
    assert d.approved == []


def test_chat_gate_deny_wins_over_approve_in_same_scan():
    t = FakeTransport([[("white_check_mark", "U1"), ("x", "U2")]])
    d = _chat_gate(t).review(_proposal())
    assert d.approved == [] and "denied" in d.note


def test_chat_gate_empty_proposal_does_not_post():
    t = FakeTransport([[]])
    d = _chat_gate(t).review(BlockProposal(actions=[]))
    assert d.approved == [] and not t.posted


def test_format_proposal_lists_indicator_and_emoji():
    msg = _format_proposal(_proposal(), approve="white_check_mark", deny="x")
    assert "185.220.101.5" in msg and "pan_edl" in msg
    assert ":white_check_mark:" in msg and ":x:" in msg


def test_slack_transport_unconfigured_raises_clearly():
    import pytest as _pytest
    tr = SlackTransport(token="", channel="")
    assert not tr.is_configured
    with _pytest.raises(RuntimeError, match="SLACK_BOT_TOKEN"):
        tr.post("hi")


def test_slack_transport_post_and_reactions_via_fake_session():
    # Drive the Slack adapter with a fake requests.Session — no network.
    class FakeResp:
        def __init__(self, payload):
            self._p = payload

        def json(self):
            return self._p

    class FakeSession:
        def __init__(self):
            self.calls = []

        def post(self, url, json, headers, timeout):
            self.calls.append((url, json))
            if url.endswith("chat.postMessage"):
                return FakeResp({"ok": True, "ts": "1700000000.0001"})
            if url.endswith("reactions.get"):
                return FakeResp({"ok": True, "message": {"reactions": [
                    {"name": "white_check_mark", "users": ["U_ANALYST"]}]}})
            return FakeResp({"ok": False, "error": "unexpected"})

    sess = FakeSession()
    tr = SlackTransport(token="xoxb-x", channel="C1", session=sess)
    handle = tr.post("hello")
    assert handle == "1700000000.0001"
    assert tr.reactions(handle) == [("white_check_mark", "U_ANALYST")]
    # end to end through the gate
    gate = SlackApprovalGate(token="xoxb-x", channel="C1", approvers=["U_ANALYST"],
                             session=sess, timeout=30.0)
    assert isinstance(gate, ChatApprovalGate)
    d = gate.review(_proposal())
    assert len(d.approved) == 1


def test_slack_transport_api_error_raises():
    import pytest as _pytest

    class FakeResp:
        def json(self):
            return {"ok": False, "error": "channel_not_found"}

    class FakeSession:
        def post(self, url, json, headers, timeout):
            return FakeResp()

    tr = SlackTransport(token="xoxb-x", channel="C_BAD", session=FakeSession())
    with _pytest.raises(RuntimeError, match="channel_not_found"):
        tr.post("hi")


# ------------------------- import isolation -----------------------

def test_importing_core_does_not_load_langchain():
    code = (
        "import sys, iocflow, iocflow.block, iocflow.hunt; "
        "assert 'langgraph' not in sys.modules, 'langgraph eagerly imported'; "
        "assert 'langchain_core' not in sys.modules, 'langchain eagerly imported'; "
        "print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "ok" in out.stdout
