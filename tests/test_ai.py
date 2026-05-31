"""Tests for iocflow Layer 3 AI commentary (no network — models are faked)."""
import json

from iocflow.ai import (
    Commentary,
    CommentaryModel,
    OpenAIChatModel,
    Severity,
    comment,
    default_model,
)
from iocflow.ai.prompt import build_user_prompt
from iocflow.enrich.models import EnrichmentRecord, EnrichmentReport, Verdict
from iocflow.models import ExtractedEntities


# ------------------------------ fakes -----------------------------

class FakeModel:
    """A CommentaryModel that returns a canned string and records the prompt."""

    name = "fake:test"

    def __init__(self, response, *, raise_exc=None):
        self._response = response
        self._raise = raise_exc
        self.calls = []

    def complete(self, system, user, *, json=False):
        self.calls.append({"system": system, "user": user, "json": json})
        if self._raise:
            raise self._raise
        return self._response


def _report(malicious_ips=(), suspicious_ips=(), benign_ips=()):
    records = []
    for ip in malicious_ips:
        records.append(EnrichmentRecord("virustotal", "ip", ip, verdict=Verdict.MALICIOUS, score=90.0))
    for ip in suspicious_ips:
        records.append(EnrichmentRecord("abuseipdb", "ip", ip, verdict=Verdict.SUSPICIOUS, score=40.0))
    for ip in benign_ips:
        records.append(EnrichmentRecord("virustotal", "ip", ip, verdict=Verdict.BENIGN))
    return EnrichmentReport(records=records)


# ----------------------------- protocol ---------------------------

def test_fakemodel_satisfies_protocol():
    assert isinstance(FakeModel("x"), CommentaryModel)
    assert isinstance(OpenAIChatModel(api_key="k"), CommentaryModel)


# --------------------------- happy path ---------------------------

def test_comment_parses_structured_json():
    payload = json.dumps({
        "severity": "high",
        "assessment": "Two malicious C2 IPs observed.",
        "key_findings": ["1.2.3.4 is a known C2", "5.6.7.8 flagged by VT"],
        "recommendations": ["Block both IPs", "Hunt for beacons"],
    })
    model = FakeModel(payload)
    note = comment(_report(malicious_ips=["1.2.3.4", "5.6.7.8"]), model=model)
    assert note.severity is Severity.HIGH
    assert note.summary == "Two malicious C2 IPs observed."
    assert len(note.key_findings) == 2
    assert note.recommendations == ["Block both IPs", "Hunt for beacons"]
    assert note.model == "fake:test"
    assert note.llm_generated
    assert note.error is None
    # model was asked for JSON
    assert model.calls[0]["json"] is True


def test_comment_strips_code_fences():
    payload = "```json\n" + json.dumps({"severity": "low", "assessment": "Quiet."}) + "\n```"
    note = comment(_report(benign_ips=["9.9.9.9"]), model=FakeModel(payload))
    assert note.severity is Severity.LOW
    assert note.assessment == "Quiet."


def test_comment_handles_prose_around_json():
    payload = 'Here is my analysis:\n{"severity":"medium","assessment":"Mixed signals."}\nThanks!'
    note = comment(_report(suspicious_ips=["1.1.1.2"]), model=FakeModel(payload))
    assert note.severity is Severity.MEDIUM
    assert note.assessment == "Mixed signals."


# --------------------------- fallbacks ----------------------------

def test_non_json_response_narrative_fallback():
    model = FakeModel("This looks like a phishing campaign with two bad IPs.")
    note = comment(_report(malicious_ips=["1.2.3.4"]), model=model)
    assert "phishing campaign" in note.summary
    assert note.error and "narrative fallback" in note.error
    assert not note.llm_generated
    # severity still derived from the report (>=1 malicious -> HIGH)
    assert note.severity is Severity.HIGH


def test_model_error_uses_deterministic_fallback():
    model = FakeModel("ignored", raise_exc=RuntimeError("timeout"))
    note = comment(_report(malicious_ips=["1.2.3.4", "5.6.7.8", "9.9.9.1"]), model=model)
    assert note.error and "model error" in note.error
    assert "RuntimeError" in note.error
    assert note.severity is Severity.CRITICAL  # >=3 malicious
    assert note.key_findings  # deterministic findings present
    assert any("1.2.3.4" in f for f in note.key_findings)


def test_no_model_deterministic_fallback():
    note = comment(_report(malicious_ips=["1.2.3.4"]), model=None)
    # No env model configured in the test environment
    assert note.error == "no commentary model configured"
    assert note.severity is Severity.HIGH
    assert "malicious" in note.summary.lower()


def test_deterministic_no_indicators_is_info():
    note = comment(EnrichmentReport(), model=None)
    assert note.severity is Severity.INFO
    assert note.recommendations == []


# --------------------------- severity logic -----------------------

def test_severity_scales_with_malicious_count():
    assert comment(_report(malicious_ips=["a"]), model=None).severity is Severity.HIGH
    assert comment(_report(malicious_ips=["a", "b", "c"]), model=None).severity is Severity.CRITICAL
    assert comment(_report(suspicious_ips=["a"]), model=None).severity is Severity.MEDIUM
    assert comment(_report(benign_ips=["a"]), model=None).severity is Severity.LOW


def test_severity_coerce_bad_value_falls_back():
    payload = json.dumps({"severity": "apocalyptic", "assessment": "x"})
    # bad severity string -> falls back to report-derived (HIGH for 1 malicious)
    note = comment(_report(malicious_ips=["1.2.3.4"]), model=FakeModel(payload))
    assert note.severity is Severity.HIGH


# ----------------------------- prompt -----------------------------

def test_prompt_includes_indicators_and_verdicts():
    user = build_user_prompt(_report(malicious_ips=["1.2.3.4"]))
    assert "1.2.3.4" in user
    assert "malicious" in user
    assert "virustotal" in user


def test_prompt_falls_back_to_entities_when_report_empty():
    entities = ExtractedEntities(ips=["8.8.4.4"], cves=["CVE-2021-44228"])
    user = build_user_prompt(EnrichmentReport(), entities=entities)
    assert "no enrichment available" in user.lower()
    assert "8.8.4.4" in user
    assert "CVE-2021-44228" in user


def test_prompt_includes_text_excerpt():
    user = build_user_prompt(EnrichmentReport(), text="Campaign uses spearphishing.")
    assert "spearphishing" in user


# ------------------------- default_model --------------------------

def test_default_model_from_env_key():
    m = default_model({"IOCFLOW_LLM_API_KEY": "sk-x", "IOCFLOW_LLM_MODEL": "gpt-4o"})
    assert isinstance(m, OpenAIChatModel)
    assert m.model == "gpt-4o"


def test_default_model_from_base_url_only():
    m = default_model({"IOCFLOW_LLM_BASE_URL": "http://localhost:11434/v1"})
    assert isinstance(m, OpenAIChatModel)
    assert m.base_url == "http://localhost:11434/v1"


def test_default_model_none_without_config():
    assert default_model({}) is None


# ----------------------- result serialization ---------------------

def test_commentary_to_dict():
    note = Commentary(summary="s", severity=Severity.HIGH, key_findings=["f"])
    d = note.to_dict()
    assert d["severity"] == "high"
    assert d["key_findings"] == ["f"]


# ----------------------- openai adapter (faked http) --------------

class FakeResp:
    def __init__(self, payload):
        self._p = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


class FakeSession:
    def __init__(self, payload):
        self._p = payload
        self.posted = []

    def post(self, url, **kw):
        self.posted.append((url, kw))
        return FakeResp(self._p)


def test_openai_adapter_builds_request_and_reads_content():
    payload = {"choices": [{"message": {"content": "hello"}}]}
    session = FakeSession(payload)
    model = OpenAIChatModel(api_key="sk-x", base_url="https://api.openai.com/v1/", session=session)
    out = model.complete("sys", "usr", json=True)
    assert out == "hello"
    url, kw = session.posted[0]
    assert url == "https://api.openai.com/v1/chat/completions"  # trailing slash trimmed
    assert kw["headers"]["Authorization"] == "Bearer sk-x"
    assert kw["json"]["response_format"] == {"type": "json_object"}
    assert kw["json"]["messages"][0]["role"] == "system"
