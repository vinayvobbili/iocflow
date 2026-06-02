"""Tests for iocflow Layer 4 suggested hunts (no network — models are faked)."""
import json
import subprocess
import sys

import pytest

from iocflow.enrich.models import EnrichmentRecord, EnrichmentReport, Verdict
from iocflow.hunt import (
    DEFAULT_DIALECTS,
    Dialect,
    Severity,
    all_dialects,
    get_dialect,
    suggest,
)
from iocflow.hunt.dialects import CortexDialect, CrowdStrikeDialect, SigmaDialect
from iocflow.hunt.prompt import build_user_prompt, system_prompt
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


def _report(malicious=(), suspicious=(), benign=()):
    """Build a report from (kind, value) tuples."""
    records = []
    for kind, value in malicious:
        records.append(EnrichmentRecord("virustotal", kind, value, verdict=Verdict.MALICIOUS, score=90.0))
    for kind, value in suspicious:
        records.append(EnrichmentRecord("abuseipdb", kind, value, verdict=Verdict.SUSPICIOUS, score=40.0))
    for kind, value in benign:
        records.append(EnrichmentRecord("virustotal", kind, value, verdict=Verdict.BENIGN))
    return EnrichmentReport(records=records)


# --------------------------- dialects -----------------------------

def test_dialects_satisfy_protocol():
    for d in all_dialects():
        assert isinstance(d, Dialect)


def test_crowdstrike_renders_in_function():
    q = CrowdStrikeDialect().render("ip", ["1.2.3.4", "5.6.7.8"])
    assert q == 'in(RemoteAddressIP4, values=["1.2.3.4", "5.6.7.8"])'


def test_crowdstrike_hash_fields():
    assert CrowdStrikeDialect().render("sha256", ["abc"]).startswith("in(SHA256HashData")
    assert "MD5HashData" in CrowdStrikeDialect().render("md5", ["abc"])


def test_cortex_renders_xdr_filter():
    q = CortexDialect().render("ip", ["1.2.3.4"])
    assert q == 'dataset = xdr_data\n| filter action_remote_ip in ("1.2.3.4")'


def test_cortex_does_not_support_url_or_email():
    d = CortexDialect()
    assert not d.supports("url")
    assert not d.supports("email")
    assert d.supports("domain")


def test_sigma_renders_valid_rule_structure():
    rule = SigmaDialect().render("domain", ["evil.example.com"], level="high")
    assert "title: iocflow IOC sweep - domain" in rule
    assert "logsource:" in rule
    assert "category: dns_query" in rule
    assert "QueryName:" in rule
    assert '- "evil.example.com"' in rule
    assert "condition: selection" in rule
    assert "level: high" in rule


def test_sigma_id_is_deterministic():
    a = SigmaDialect().render("ip", ["1.2.3.4"])
    b = SigmaDialect().render("ip", ["1.2.3.4"])
    assert a == b  # no randomness — stable output
    # id line is a uuid shape
    id_line = [ln for ln in a.splitlines() if ln.startswith("id: ")][0]
    uuid = id_line[len("id: "):]
    parts = uuid.split("-")
    assert [len(p) for p in parts] == [8, 4, 4, 4, 12]


def test_sigma_filename_endswith_prefix():
    rule = SigmaDialect().render("filename", ["evil.exe"])
    assert "Image|endswith:" in rule
    assert '- "\\\\evil.exe"' in rule  # backslash-prefixed, YAML-escaped


def test_sigma_bad_level_falls_back_to_high():
    rule = SigmaDialect().render("ip", ["1.2.3.4"], level="apocalyptic")
    assert "level: high" in rule


def test_quoting_escapes_embedded_quote():
    q = CrowdStrikeDialect().render("url", ['http://x/"a"'])
    assert '\\"a\\"' in q


# --------------------------- registry -----------------------------

def test_get_dialect_known_and_unknown():
    assert get_dialect("sigma").key == "sigma"
    with pytest.raises(ValueError, match="unknown dialect"):
        get_dialect("splunk")


def test_default_dialects_order():
    assert DEFAULT_DIALECTS == ("crowdstrike", "cortex", "sigma")


# --------------------------- suggest ------------------------------

def test_suggest_groups_by_kind_across_dialects():
    report = _report(malicious=[("ip", "1.2.3.4"), ("domain", "evil.com")])
    plan = suggest(report, model=None)
    # crowdstrike + cortex + sigma, each for ip and domain = 6 hunts
    assert len(plan.hunts) == 6
    assert set(plan.dialects) == {"crowdstrike", "cortex", "sigma"}
    ip_hunts = [h for h in plan.hunts if h.kinds == ["ip"]]
    assert len(ip_hunts) == 3
    assert all(h.source == "deterministic" for h in plan.hunts)


def test_suggest_skips_benign_by_default():
    report = _report(malicious=[("ip", "1.2.3.4")], benign=[("domain", "google.com")])
    plan = suggest(report, model=None)
    kinds = {k for h in plan.hunts for k in h.kinds}
    assert kinds == {"ip"}  # benign domain dropped


def test_suggest_include_benign():
    report = _report(benign=[("domain", "google.com")])
    plan = suggest(report, model=None, include_benign=True)
    assert any(h.kinds == ["domain"] for h in plan.hunts)


def test_suggest_severity_from_verdict():
    mal = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=None)
    assert all(h.severity is Severity.HIGH for h in mal.hunts)
    susp = suggest(_report(suspicious=[("ip", "1.2.3.4")]), model=None)
    assert all(h.severity is Severity.MEDIUM for h in susp.hunts)


def test_suggest_sigma_level_tracks_severity():
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), dialects=["sigma"], model=None)
    assert "level: high" in plan.hunts[0].query


def test_suggest_restrict_dialects():
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), dialects=["sigma"], model=None)
    assert plan.dialects == ["sigma"]


def test_suggest_unknown_dialect_raises():
    with pytest.raises(ValueError):
        suggest(_report(malicious=[("ip", "1.2.3.4")]), dialects=["nope"], model=None)


def test_suggest_from_entities_when_no_report():
    entities = ExtractedEntities(ips=["8.8.4.4"], domains=["evil.com"])
    plan = suggest(report=None, entities=entities, model=None)
    kinds = {k for h in plan.hunts for k in h.kinds}
    assert kinds == {"ip", "domain"}
    # unknown verdict -> LOW severity
    assert all(h.severity is Severity.LOW for h in plan.hunts)


def test_suggest_non_huntable_kinds_skipped():
    # CVEs / emails have no hunt field in any dialect
    report = _report(malicious=[("cve", "CVE-2021-44228"), ("email", "a@b.com")])
    plan = suggest(report, model=None)
    assert plan.hunts == []


def test_suggest_empty_is_valid_empty_plan():
    plan = suggest(EnrichmentReport(), model=None)
    assert plan.hunts == []
    assert plan.summary() == "No hunts suggested"
    assert plan.severity is Severity.INFO


# --------------------------- LLM path -----------------------------

def test_suggest_adds_llm_behavioral_hunts():
    payload = json.dumps({
        "hunts": [
            {"title": "Beacon cadence", "dialect": "sigma",
             "query": "title: beacon\ndetection:\n  selection:\n  condition: selection",
             "rationale": "fixed-interval callbacks", "severity": "high"},
        ]
    })
    model = FakeModel(payload)
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=model)
    llm = [h for h in plan.hunts if h.source == "llm"]
    assert len(llm) == 1
    assert llm[0].title == "Beacon cadence"
    assert llm[0].severity is Severity.HIGH
    assert plan.error is None
    # deterministic hunts still present
    assert any(h.source == "deterministic" for h in plan.hunts)
    assert model.calls[0]["json"] is True


def test_llm_filters_unknown_dialect_and_blanks():
    payload = json.dumps({
        "hunts": [
            {"title": "ok", "dialect": "sigma", "query": "q"},
            {"title": "bad dialect", "dialect": "splunk", "query": "q"},
            {"title": "", "dialect": "sigma", "query": "q"},
            {"dialect": "sigma", "query": "no title"},
        ]
    })
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=FakeModel(payload))
    llm = [h for h in plan.hunts if h.source == "llm"]
    assert len(llm) == 1
    assert llm[0].title == "ok"


def test_llm_error_leaves_deterministic_plan():
    model = FakeModel("x", raise_exc=RuntimeError("timeout"))
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=model)
    assert all(h.source == "deterministic" for h in plan.hunts)
    assert plan.hunts  # deterministic hunts intact
    assert plan.error and "model error" in plan.error


def test_llm_unparseable_output_is_non_fatal():
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=FakeModel("not json at all"))
    assert plan.error and "unparseable" in plan.error
    assert all(h.source == "deterministic" for h in plan.hunts)


def test_llm_strips_code_fences():
    payload = "```json\n" + json.dumps({"hunts": [
        {"title": "t", "dialect": "cortex", "query": "q"}]}) + "\n```"
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=FakeModel(payload))
    assert any(h.source == "llm" for h in plan.hunts)


# --------------------------- prompt -------------------------------

def test_prompt_includes_indicators_and_verdicts():
    user = build_user_prompt(_report(malicious=[("ip", "1.2.3.4")]))
    assert "1.2.3.4" in user
    assert "malicious" in user


def test_prompt_falls_back_to_entities():
    entities = ExtractedEntities(ips=["8.8.4.4"])
    user = build_user_prompt(EnrichmentReport(), entities=entities)
    assert "8.8.4.4" in user
    assert "no enrichment available" in user.lower()


def test_system_prompt_names_dialects():
    sp = system_prompt(all_dialects())
    assert "crowdstrike" in sp
    assert "cortex" in sp
    assert "sigma" in sp


# ----------------------- serialization ----------------------------

def test_hunt_and_plan_to_dict():
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), dialects=["crowdstrike"], model=None)
    d = plan.to_dict()
    assert d["severity"] == "high"
    h0 = d["hunts"][0]
    assert h0["dialect"] == "crowdstrike"
    assert h0["indicators"] == [{"kind": "ip", "value": "1.2.3.4"}]
    assert h0["source"] == "deterministic"


def test_plan_for_dialect_and_summary():
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=None)
    assert all(h.dialect == "sigma" for h in plan.for_dialect("sigma"))
    assert "hunts across" in plan.summary()


# ---------------------- robust JSON parsing -----------------------

def _llm_hunt(dialect, query, title="t"):
    return {"title": title, "dialect": dialect, "query": query}


def test_llm_parses_bare_array_without_hunts_wrapper():
    # Model returns a top-level array instead of {"hunts": [...]}.
    payload = json.dumps([_llm_hunt("sigma", "title: t\ndetection:\n  condition: x")])
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=FakeModel(payload))
    assert [h for h in plan.hunts if h.source == "llm"]


def test_llm_parses_multiple_top_level_objects():
    # Newline-separated objects (the classic "Extra data" failure of json.loads).
    a = json.dumps(_llm_hunt("sigma", "title: a\ndetection:\n  condition: x", "a"))
    b = json.dumps(_llm_hunt("cortex", "dataset = xdr_data\n| limit 100", "b"))
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=FakeModel(a + "\n" + b))
    titles = {h.title for h in plan.hunts if h.source == "llm"}
    assert {"a", "b"} <= titles


def test_llm_tolerates_trailing_prose_after_json():
    payload = json.dumps({"hunts": [_llm_hunt("cortex", "dataset = xdr_data\n| limit 100")]})
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=FakeModel(payload + "\n\nHope this helps!"))
    assert [h for h in plan.hunts if h.source == "llm"]


# ----------------- behavioral validate / repair -------------------

def test_dialect_behavioral_validators():
    cs, cx, sg = CrowdStrikeDialect(), CortexDialect(), SigmaDialect()
    assert cs.validate_behavioral("#event_simpleName=ProcessRollup2 CommandLine=/x/i | head(100)")[0]
    assert not cs.validate_behavioral("#event_simpleName=Bogus | head(100)")[0]  # bad event
    assert not cs.validate_behavioral("ImageFileName=/x/i")[0]  # no scope / no bound
    assert cx.validate_behavioral("dataset = xdr_data | filter event_type = ENUM.PROCESS | limit 100")[0]
    assert not cx.validate_behavioral("dataset = secret_db | limit 100")[0]  # bad dataset
    assert not cx.validate_behavioral("dataset = xdr_data | filter x")[0]  # unbounded
    assert sg.validate_behavioral("title: t\nlogsource:\ndetection:\n  condition: sel")[0]
    assert not sg.validate_behavioral("title: t\nlogsource: foo")[0]  # no detection/condition


def test_valid_llm_hunt_is_marked_validated():
    payload = json.dumps({"hunts": [
        {"title": "ok", "dialect": "cortex",
         "query": "dataset = xdr_data\n| filter event_type = ENUM.PROCESS\n| limit 100"}]})
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=FakeModel(payload))
    h = [h for h in plan.hunts if h.source == "llm"][0]
    assert h.validated and h.validation_error == ""


def test_unrepairable_hunt_is_kept_and_flagged():
    # FakeModel echoes the same payload on repair (no {"query": ...}), so repair
    # can't fix it; the hunt is surfaced anyway with validated=False.
    payload = json.dumps({"hunts": [{"title": "bad", "dialect": "cortex", "query": "garbage"}]})
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=FakeModel(payload))
    h = [h for h in plan.hunts if h.source == "llm"][0]
    assert not h.validated
    assert h.validation_error
    assert h.to_dict()["validated"] is False


class _RepairModel:
    """Returns a broken hunt first, then a corrected query on the repair call."""

    name = "fake:repair"

    def __init__(self, first, repaired):
        self._first, self._repaired = first, repaired
        self.calls = 0

    def complete(self, system, user, *, json=False):
        self.calls += 1
        return self._first if self.calls == 1 else self._repaired


def test_repair_loop_fixes_invalid_query():
    broken = json.dumps({"hunts": [{"title": "fix me", "dialect": "cortex", "query": "dataset = xdr_data"}]})
    fixed = json.dumps({"query": "dataset = xdr_data\n| filter event_type = ENUM.PROCESS\n| limit 100"})
    model = _RepairModel(broken, fixed)
    plan = suggest(_report(malicious=[("ip", "1.2.3.4")]), model=model)
    h = [h for h in plan.hunts if h.source == "llm"][0]
    assert h.validated
    assert "| limit 100" in h.query
    assert model.calls == 2  # one generate + one repair


# ------------------------- import isolation -----------------------

def test_importing_hunt_does_not_eagerly_load_ai_or_llm():
    # The deterministic core must not pull in the LLM/ai layer at import time.
    code = (
        "import sys; import iocflow.hunt; "
        "assert 'iocflow.ai' not in sys.modules, 'iocflow.ai eagerly imported'; "
        "assert 'iocflow.hunt.llm' not in sys.modules, 'llm path eagerly imported'; "
        "print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "ok" in out.stdout
