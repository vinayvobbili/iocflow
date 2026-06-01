"""Tests for the MISP interop layer (no network — the REST client is stubbed)."""
from iocflow.enrich.models import EnrichmentReport, EnrichmentRecord, Verdict
from iocflow.misp import (
    MISPEnricher,
    MISPEventSource,
    MISPPublisher,
    attribute_indicators,
)
from iocflow.models import ExtractedEntities


# ------------------------------ fake client -----------------------

class FakeResp:
    def __init__(self, payload):
        self._p = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


class FakeSession:
    """Records calls and returns a canned payload per path suffix."""

    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def post(self, url, json, headers, verify, timeout):
        self.calls.append(("POST", url, json, headers))
        return FakeResp(self.payload)

    def get(self, url, headers, verify, timeout):
        self.calls.append(("GET", url, None, headers))
        return FakeResp(self.payload)


# ------------------------------ mapping ---------------------------

def test_attribute_indicators_simple_and_composite():
    assert attribute_indicators("ip-dst", "1.2.3.4") == [("ip", "1.2.3.4")]
    assert attribute_indicators("vulnerability", "CVE-2021-44228") == [("cve", "CVE-2021-44228")]
    # composite splits into both halves
    assert attribute_indicators("domain|ip", "evil.test|1.2.3.4") == [
        ("domain", "evil.test"), ("ip", "1.2.3.4")]
    # the port half is dropped
    assert attribute_indicators("ip-dst|port", "1.2.3.4|443") == [("ip", "1.2.3.4")]
    # filename|sha256 keeps both
    assert attribute_indicators("filename|sha256", "x.exe|" + "a" * 64) == [
        ("filename", "x.exe"), ("sha256", "a" * 64)]
    # unknown type / empty value → nothing
    assert attribute_indicators("btc", "1abc") == []
    assert attribute_indicators("ip-dst", "") == []


# ------------------------------ enricher --------------------------

def _attr(value, to_ids=True, **kw):
    a = {"value": value, "type": "ip-dst", "category": "Network activity",
         "to_ids": to_ids, "Event": {"id": "42", "info": "Known APT infra"}}
    a.update(kw)
    return a


def test_enricher_to_ids_hit_is_malicious():
    sess = FakeSession({"response": {"Attribute": [_attr("1.2.3.4", to_ids="1")]}})
    en = MISPEnricher("https://misp.test", "key", session=sess)
    rec = en.enrich("ip", "1.2.3.4")
    assert rec.verdict is Verdict.MALICIOUS and rec.ok
    assert rec.score == 100.0
    assert rec.reference == "https://misp.test/events/view/42"
    assert rec.raw["to_ids"] is True and rec.raw["misp_matches"] == 1
    # auth header carries the raw key (not Bearer)
    assert sess.calls[0][3]["Authorization"] == "key"


def test_enricher_context_only_hit_is_suspicious():
    sess = FakeSession({"response": {"Attribute": [_attr("1.2.3.4", to_ids=False)]}})
    rec = MISPEnricher("https://misp.test", "key", session=sess).enrich("ip", "1.2.3.4")
    assert rec.verdict is Verdict.SUSPICIOUS and rec.score == 50.0


def test_enricher_no_match_is_unknown():
    sess = FakeSession({"response": {"Attribute": []}})
    rec = MISPEnricher("https://misp.test", "key", session=sess).enrich("ip", "9.9.9.9")
    assert rec.verdict is Verdict.UNKNOWN and rec.raw["misp_matches"] == 0


def test_enricher_unsupported_kind_and_unconfigured_are_error_records():
    sess = FakeSession({"response": {"Attribute": []}})
    en = MISPEnricher("https://misp.test", "key", session=sess)
    bad = en.enrich("cve", "CVE-2021-44228")          # cve not enriched via MISP attrs
    assert not bad.ok and "does not support" in bad.error
    nocfg = MISPEnricher(session=sess).enrich("ip", "1.2.3.4")  # no url/key
    assert not nocfg.ok and "no instance" in nocfg.error


def test_enricher_network_error_degrades_to_record():
    class Boom:
        def post(self, *a, **k):
            raise ConnectionError("down")

    en = MISPEnricher("https://misp.test", "key", session=Boom())
    rec = en.enrich("ip", "1.2.3.4")
    assert not rec.ok and "ConnectionError" in rec.error


def test_enricher_conforms_to_protocol():
    from iocflow.enrich.protocol import Enricher
    assert isinstance(MISPEnricher("u", "k"), Enricher)


def test_enricher_plugs_into_enrich_runner():
    from iocflow.enrich import enrich
    sess = FakeSession({"response": {"Attribute": [_attr("1.2.3.4", to_ids="1")]}})
    ents = ExtractedEntities(ips=["1.2.3.4"])
    report = enrich(ents, [MISPEnricher("https://misp.test", "key", session=sess)])
    assert report.verdict_for("ip", "1.2.3.4") is Verdict.MALICIOUS


# ------------------------------ source ----------------------------

EVENT_PAYLOAD = {"response": [{"Event": {
    "id": "7", "uuid": "ev-uuid-7", "info": "Emotet campaign May 2026",
    "date": "2026-05-31", "threat_level_id": "2",
    "Orgc": {"name": "CIRCL"},
    "Tag": [{"name": "tlp:white"}, {"name": "malware:emotet"}],
    "Attribute": [
        {"type": "ip-dst", "value": "185.220.101.5", "comment": "C2"},
        {"type": "domain|ip", "value": "evil.test|1.2.3.4"},
    ],
    "Object": [{"Attribute": [{"type": "sha256", "value": "b" * 64}]}],
}}]}


def test_source_builds_trigger_with_indicators_from_attrs_and_objects():
    sess = FakeSession(EVENT_PAYLOAD)
    src = MISPEventSource("https://misp.test", "key", session=sess)
    trigs = src.poll()
    assert len(trigs) == 1
    t = trigs[0]
    assert t.id == "ev-uuid-7" and t.source == "misp"
    assert ("ip", "185.220.101.5") in t.indicators
    assert ("domain", "evil.test") in t.indicators and ("ip", "1.2.3.4") in t.indicators
    assert ("sha256", "b" * 64) in t.indicators           # from a MISP object
    assert "Emotet" in t.text and "C2" in t.text          # info + comment
    assert t.url == "https://misp.test/events/view/7"
    assert t.meta["org"] == "CIRCL" and "tlp:white" in t.meta["tags"]


def test_source_unconfigured_returns_empty():
    assert MISPEventSource(session=FakeSession(EVENT_PAYLOAD)).poll() == []


def test_source_feeds_poller_and_dedupes():
    from iocflow.sources import Poller, MemorySeenStore
    sess = FakeSession(EVENT_PAYLOAD)
    poller = Poller([MISPEventSource("https://misp.test", "key", session=sess)],
                    store=MemorySeenStore())
    out = poller.run_once()
    assert len(out) == 1
    res = out[0].output
    assert "185.220.101.5" in res.entities.ips
    assert "b" * 64 in res.entities.hashes["sha256"]      # structured indicator merged
    assert poller.run_once() == []                        # same event uuid → seen


# ------------------------------ publisher -------------------------

def test_publisher_dry_run_builds_event_without_network():
    sess = FakeSession({})
    pub = MISPPublisher("https://misp.test", "key", session=sess)   # dry_run default
    ents = ExtractedEntities(ips=["1.2.3.4"], domains=["evil.test"])
    out = pub.publish(ents, info="from a report")
    assert out["ok"] and out["dry_run"] is True
    ev = out["event"]["Event"]
    assert ev["info"] == "from a report" and ev["published"] is False
    assert ev["distribution"] == 0
    types = {a["type"] for a in ev["Attribute"]}
    assert types == {"ip-dst", "domain"}
    assert all(a["to_ids"] is False for a in ev["Attribute"])       # no verdicts → not actionable
    assert sess.calls == []                                         # never contacted server


def test_publisher_sets_to_ids_from_enrichment_verdicts():
    report = EnrichmentReport(records=[
        EnrichmentRecord(source="x", kind="ip", value="1.2.3.4", verdict=Verdict.MALICIOUS),
        EnrichmentRecord(source="x", kind="domain", value="ok.test", verdict=Verdict.BENIGN),
    ])
    pub = MISPPublisher("https://misp.test", "key", session=FakeSession({}))
    ev = pub.build_event(report)["Event"]
    by_val = {a["value"]: a for a in ev["Attribute"]}
    assert by_val["1.2.3.4"]["to_ids"] is True             # malicious → actionable
    assert by_val["ok.test"]["to_ids"] is False            # benign → context only


def test_publisher_live_call_posts_event():
    sess = FakeSession({"Event": {"id": "100", "uuid": "new-uuid"}})
    pub = MISPPublisher("https://misp.test", "key", session=sess, dry_run=False)
    out = pub.publish(ExtractedEntities(ips=["1.2.3.4"]))
    assert out["ok"] and out["dry_run"] is False
    assert out["event_id"] == "100" and out["uuid"] == "new-uuid"
    assert sess.calls[0][1].endswith("/events/add")


def test_publisher_no_indicators_is_a_result_not_a_crash():
    out = MISPPublisher("https://misp.test", "key").publish(ExtractedEntities())
    assert not out["ok"] and "no shareable indicators" in out["error"]


def test_publisher_force_to_ids_overrides():
    pub = MISPPublisher("https://misp.test", "key")
    ev = pub.build_event(ExtractedEntities(ips=["1.2.3.4"]), force_to_ids=True)["Event"]
    assert ev["Attribute"][0]["to_ids"] is True


# ------------------------- registry wiring ------------------------

def test_default_enrichers_wires_misp_from_env():
    from iocflow.enrich import default_enrichers
    env = {"IOCFLOW_MISP_URL": "https://misp.test", "IOCFLOW_MISP_KEY": "k"}
    names = [e.name for e in default_enrichers(env)]
    assert "misp" in names


def test_default_sources_wires_misp_when_enabled():
    from iocflow.sources import default_sources
    env = {"IOCFLOW_MISP_SOURCE": "true", "IOCFLOW_MISP_URL": "https://misp.test",
           "IOCFLOW_MISP_KEY": "k", "IOCFLOW_MISP_TAGS": "tlp:white,apt"}
    srcs = default_sources(env)
    assert any(getattr(s, "name", "") == "misp" for s in srcs)
    # not enabled without the IOCFLOW_MISP_SOURCE flag
    env2 = dict(env)
    del env2["IOCFLOW_MISP_SOURCE"]
    assert not any(getattr(s, "name", "") == "misp" for s in default_sources(env2))


# ------------------------- import isolation -----------------------

def test_importing_core_does_not_load_misp():
    import subprocess
    import sys
    code = ("import sys, iocflow; "
            "assert 'iocflow.misp' not in sys.modules; print('ok')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0 and "ok" in out.stdout, out.stderr


def test_importing_misp_does_not_load_heavy_optional_deps():
    import subprocess
    import sys
    code = ("import iocflow.misp; import sys; "
            "assert 'feedparser' not in sys.modules; "
            "assert 'langgraph' not in sys.modules; print('ok')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0 and "ok" in out.stdout, out.stderr
