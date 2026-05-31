"""Tests for iocflow Layer 2 enrichment (no network — sessions are faked)."""
import pytest

from iocflow import extract
from iocflow.enrich import (
    AbuseChEnricher,
    AbuseIPDBEnricher,
    EnrichmentRecord,
    EnrichmentReport,
    MemoryCache,
    Verdict,
    VirusTotalEnricher,
    aggregate_verdict,
    default_enrichers,
    enrich,
)
from iocflow.enrich.protocol import Enricher
from iocflow.models import ExtractedEntities


# ------------------------------ fakes -----------------------------

class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class FakeSession:
    """Records calls and returns queued responses by method."""

    def __init__(self, get=None, post=None):
        self._get = get
        self._post = post
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return self._get(url, kw) if callable(self._get) else self._get

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return self._post(url, kw) if callable(self._post) else self._post


# --------------------------- verdict model ------------------------

def test_verdict_rank_and_aggregate():
    assert Verdict.MALICIOUS.rank > Verdict.SUSPICIOUS.rank > Verdict.BENIGN.rank
    assert Verdict.BENIGN.rank > Verdict.UNKNOWN.rank
    assert aggregate_verdict([Verdict.BENIGN, Verdict.MALICIOUS]) is Verdict.MALICIOUS
    assert aggregate_verdict([Verdict.UNKNOWN, Verdict.BENIGN]) is Verdict.BENIGN
    assert aggregate_verdict([]) is Verdict.UNKNOWN


def test_report_helpers():
    report = EnrichmentReport(records=[
        EnrichmentRecord("a", "ip", "1.2.3.4", verdict=Verdict.MALICIOUS),
        EnrichmentRecord("b", "ip", "1.2.3.4", verdict=Verdict.BENIGN),
        EnrichmentRecord("a", "domain", "ok.test", verdict=Verdict.BENIGN),
        EnrichmentRecord("b", "domain", "ok.test", verdict=Verdict.UNKNOWN, error="boom"),
    ])
    assert report.verdict_for("ip", "1.2.3.4") is Verdict.MALICIOUS
    assert report.verdict_for("domain", "ok.test") is Verdict.BENIGN  # error record ignored
    assert [i.value for i in report.malicious] == ["1.2.3.4"]
    assert len(report.errors) == 1
    assert "verdicts" in report.to_dict()


# ----------------------------- VirusTotal -------------------------

def test_virustotal_malicious():
    vt_payload = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 8, "suspicious": 1, "harmless": 80, "undetected": 11},
        "reputation": -20,
    }}}
    en = VirusTotalEnricher("key", session=FakeSession(get=FakeResponse(vt_payload)))
    rec = en.enrich("ip", "185.220.101.5")
    assert rec.verdict is Verdict.MALICIOUS
    assert rec.score == 8.0  # 8/100
    assert rec.reference.endswith("/ip-address/185.220.101.5")
    assert rec.ok


def test_virustotal_harmless_is_benign():
    payload = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 10}}}}
    en = VirusTotalEnricher("key", session=FakeSession(get=FakeResponse(payload)))
    assert en.enrich("domain", "ok.test").verdict is Verdict.BENIGN


def test_virustotal_url_uses_b64_id():
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 1}}}}
    session = FakeSession(get=FakeResponse(payload))
    en = VirusTotalEnricher("key", session=session)
    en.enrich("url", "https://bad.test/x")
    # URL id must be unpadded base64url, never the raw URL
    called_url = session.calls[0][1]
    assert "/urls/" in called_url
    assert "https://bad.test" not in called_url


def test_virustotal_supports_only_known_kinds():
    en = VirusTotalEnricher("key")
    assert en.supports("ip") and en.supports("sha256")
    assert not en.supports("email")
    # Unsupported kind degrades to an error record, not an exception
    rec = en.enrich("email", "a@b.test")
    assert not rec.ok


# ------------------------------ AbuseIPDB -------------------------

@pytest.mark.parametrize("score,expected", [
    (95, Verdict.MALICIOUS),
    (30, Verdict.SUSPICIOUS),
    (0, Verdict.BENIGN),
])
def test_abuseipdb_verdicts(score, expected):
    payload = {"data": {"abuseConfidenceScore": score, "totalReports": 3, "isp": "X"}}
    en = AbuseIPDBEnricher("key", session=FakeSession(get=FakeResponse(payload)))
    rec = en.enrich("ip", "9.9.9.9")
    assert rec.verdict is expected
    assert rec.score == float(score)


def test_abuseipdb_ip_only():
    assert AbuseIPDBEnricher("key").supports("ip")
    assert not AbuseIPDBEnricher("key").supports("domain")


# ------------------------------ abuse.ch --------------------------

def test_abusech_threatfox_hit_for_ip():
    payload = {"query_status": "ok", "data": [
        {"id": "42", "malware_printable": "Cobalt Strike",
         "threat_type": "botnet_cc", "confidence_level": 75}]}
    en = AbuseChEnricher("key", session=FakeSession(post=FakeResponse(payload)))
    rec = en.enrich("ip", "1.2.3.4")
    assert rec.verdict is Verdict.MALICIOUS
    assert rec.score == 75.0
    assert rec.reference == "https://threatfox.abuse.ch/ioc/42/"
    assert rec.raw["malware"] == "Cobalt Strike"


def test_abusech_no_result_is_unknown():
    payload = {"query_status": "no_result", "data": []}
    en = AbuseChEnricher("key", session=FakeSession(post=FakeResponse(payload)))
    assert en.enrich("domain", "clean.test").verdict is Verdict.UNKNOWN


def test_abusech_malwarebazaar_for_hash():
    payload = {"query_status": "ok", "data": [
        {"sha256_hash": "abc", "signature": "Emotet", "file_type": "exe"}]}
    session = FakeSession(post=FakeResponse(payload))
    en = AbuseChEnricher("key", session=session)
    rec = en.enrich("sha256", "abc")
    assert rec.verdict is Verdict.MALICIOUS
    assert "bazaar.abuse.ch/sample/abc" in rec.reference
    assert "mb-api.abuse.ch" in session.calls[0][1]


def test_abusech_urlhaus_for_url():
    payload = {"query_status": "ok", "threat": "malware_download",
               "url_status": "online", "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}
    session = FakeSession(post=FakeResponse(payload))
    en = AbuseChEnricher("key", session=session)
    rec = en.enrich("url", "https://bad.test/x")
    assert rec.verdict is Verdict.MALICIOUS
    assert "urlhaus-api.abuse.ch" in session.calls[0][1]


# --------------------------- error handling -----------------------

def test_lookup_http_error_becomes_error_record():
    en = VirusTotalEnricher("key", session=FakeSession(get=FakeResponse({}, status=500)))
    rec = en.enrich("ip", "1.2.3.4")
    assert not rec.ok
    assert rec.verdict is Verdict.UNKNOWN
    assert "500" in rec.error


# ----------------------------- orchestrator -----------------------

class StubEnricher:
    """A protocol-conforming enricher with no network."""

    def __init__(self, name, kinds, verdict=Verdict.MALICIOUS):
        self.name = name
        self._kinds = set(kinds)
        self._verdict = verdict
        self.seen = []

    def supports(self, kind):
        return kind in self._kinds

    def enrich(self, kind, value):
        self.seen.append((kind, value))
        return EnrichmentRecord(self.name, kind, value, verdict=self._verdict)


def test_stub_satisfies_protocol():
    assert isinstance(StubEnricher("s", ["ip"]), Enricher)


def test_enrich_routes_by_kind():
    entities = extract("c2 at 185.220.101.5 and evil-domain.ru")
    ip_only = StubEnricher("ipsrc", ["ip"])
    dom_only = StubEnricher("domsrc", ["domain"])
    report = enrich(entities, [ip_only, dom_only], max_workers=4)
    assert ("ip", "185.220.101.5") in ip_only.seen
    assert ("ip", "185.220.101.5") not in dom_only.seen
    assert report.verdict_for("ip", "185.220.101.5") is Verdict.MALICIOUS
    assert len(report.records) == 2  # one per supported (enricher, indicator)


def test_enrich_kinds_filter():
    entities = extract("c2 at 185.220.101.5 and evil-domain.ru")
    src = StubEnricher("s", ["ip", "domain"])
    enrich(entities, [src], kinds={"ip"})
    assert all(k == "ip" for k, _ in src.seen)


def test_enrich_empty_when_no_enrichers():
    report = enrich(ExtractedEntities(ips=["1.2.3.4"]), [])
    assert report.records == []


def test_enrich_uses_cache():
    entities = ExtractedEntities(ips=["1.2.3.4"])
    src = StubEnricher("s", ["ip"])
    cache = MemoryCache()
    enrich(entities, [src], cache=cache)
    enrich(entities, [src], cache=cache)  # second run should hit cache
    assert len(src.seen) == 1  # enricher called only once


def test_default_enrichers_from_env():
    env = {"IOCFLOW_VT_API_KEY": "v", "IOCFLOW_ABUSEIPDB_API_KEY": "a"}
    names = {e.name for e in default_enrichers(env)}
    assert names == {"virustotal", "abuseipdb"}
    assert default_enrichers({}) == []
