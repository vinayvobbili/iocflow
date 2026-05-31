"""Tests for iocflow STIX interop (stdlib parse/build; TaxiiSource stubbed)."""
import json

from iocflow import extract
from iocflow.enrich.models import EnrichmentRecord, EnrichmentReport, Verdict
from iocflow.sources import MemorySeenStore, Poller
from iocflow.stix import TaxiiSource, from_stix, to_stix

FIXED = "2026-05-31T00:00:00.000Z"


# ------------------------------ from_stix -------------------------

BUNDLE = {
    "type": "bundle",
    "id": "bundle--11111111-1111-1111-1111-111111111111",
    "objects": [
        {"type": "ipv4-addr", "id": "ipv4-addr--a", "value": "185.220.101.5"},
        {"type": "domain-name", "id": "domain-name--b", "value": "evil-domain.ru"},
        {"type": "url", "id": "url--c", "value": "http://evil-domain.ru/x"},
        {"type": "email-addr", "id": "email-addr--d", "value": "ops@evil-domain.ru"},
        {"type": "file", "id": "file--e", "name": "install.ps1",
         "hashes": {"SHA-256": "a" * 64, "MD5": "b" * 32}},
        {"type": "vulnerability", "id": "vulnerability--f", "name": "Log4Shell",
         "external_references": [{"source_name": "cve", "external_id": "CVE-2021-44228"}]},
        {"type": "malware", "id": "malware--g", "name": "Cobalt Strike", "is_family": True},
        {"type": "threat-actor", "id": "threat-actor--h", "name": "APT28"},
        {"type": "attack-pattern", "id": "attack-pattern--i", "name": "Exploit Public-Facing App",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}]},
    ],
}


def test_from_stix_parses_scos_and_sdos():
    ents = from_stix(BUNDLE)
    assert ents.ips == ["185.220.101.5"]
    assert ents.domains == ["evil-domain.ru"]
    assert ents.urls == ["http://evil-domain.ru/x"]
    assert ents.emails == ["ops@evil-domain.ru"]
    assert ents.filenames == ["install.ps1"]
    assert ents.hashes["sha256"] == ["a" * 64] and ents.hashes["md5"] == ["b" * 32]
    assert ents.cves == ["CVE-2021-44228"]
    assert ents.malware_families == ["Cobalt Strike"]
    assert ents.threat_actors == ["APT28"]
    assert ents.mitre_techniques == ["T1190"]


def test_from_stix_indicator_patterns():
    objs = [
        {"type": "indicator", "pattern_type": "stix",
         "pattern": "[ipv4-addr:value = '9.9.9.9']"},
        {"type": "indicator", "pattern_type": "stix",
         "pattern": "[file:hashes.'SHA-256' = '" + "c" * 64 + "']"},
        {"type": "indicator", "pattern_type": "stix",
         "pattern": "[domain-name:value = 'a.test'] OR [url:value = 'http://b.test']"},
    ]
    ents = from_stix(objs)
    assert ents.ips == ["9.9.9.9"]
    assert ents.hashes["sha256"] == ["c" * 64]
    assert ents.domains == ["a.test"] and ents.urls == ["http://b.test"]


def test_from_stix_accepts_json_string_and_single_object():
    assert from_stix(json.dumps(BUNDLE)).ips == ["185.220.101.5"]
    assert from_stix({"type": "ipv4-addr", "value": "1.2.3.4"}).ips == ["1.2.3.4"]


def test_from_stix_is_resilient_to_garbage():
    assert from_stix("not json").is_empty()
    assert from_stix(42).is_empty()
    mixed = [{"type": "ipv4-addr", "value": "1.1.1.1"}, "junk", {"no_type": True},
             {"type": "file"}]  # file with no name/hashes
    ents = from_stix(mixed)
    assert ents.ips == ["1.1.1.1"]


def test_from_stix_dedups():
    objs = [{"type": "ipv4-addr", "value": "5.5.5.5"},
            {"type": "ipv4-addr", "value": "5.5.5.5"}]
    assert from_stix(objs).ips == ["5.5.5.5"]


# ------------------------------ to_stix ---------------------------

def test_to_stix_from_entities_builds_conformant_bundle():
    ents = extract("APT28 used 185.220.101.5 and evil-domain.ru via T1190. "
                   "sha256 " + "a" * 64 + ". CVE-2021-44228.")
    bundle = to_stix(ents, created=FIXED)
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    by_type = {}
    for o in bundle["objects"]:
        assert o["spec_version"] == "2.1"
        by_type.setdefault(o["type"], []).append(o)
    ind = by_type["indicator"]
    patterns = [o["pattern"] for o in ind]
    assert "[ipv4-addr:value = '185.220.101.5']" in patterns
    assert "[domain-name:value = 'evil-domain.ru']" in patterns
    assert any(p == "[file:hashes.'SHA-256' = '" + "a" * 64 + "']" for p in patterns)
    for o in ind:
        assert o["pattern_type"] == "stix" and o["valid_from"] == FIXED
        assert o["id"].startswith("indicator--")
    assert by_type["vulnerability"][0]["name"] == "CVE-2021-44228"
    assert by_type["attack-pattern"][0]["external_references"][0]["external_id"] == "T1190"


def test_to_stix_ids_are_deterministic():
    ents = extract("185.220.101.5 evil.test")
    b1 = to_stix(ents, created=FIXED)
    b2 = to_stix(ents, created=FIXED)
    assert [o["id"] for o in b1["objects"]] == [o["id"] for o in b2["objects"]]
    assert b1["id"] == b2["id"]


def test_to_stix_escapes_quotes_in_values():
    bundle = to_stix([("filename", "o'brien.exe")], created=FIXED)
    assert bundle["objects"][0]["pattern"] == "[file:name = 'o\\'brien.exe']"


def test_to_stix_ipv6_uses_ipv6_addr():
    bundle = to_stix([("ip", "2001:db8::1")], created=FIXED)
    assert bundle["objects"][0]["pattern"] == "[ipv6-addr:value = '2001:db8::1']"


def test_to_stix_from_enrichment_report_sets_verdict_types():
    rep = EnrichmentReport(records=[
        EnrichmentRecord("vt", "ip", "185.220.101.5", verdict=Verdict.MALICIOUS, score=90),
        EnrichmentRecord("vt", "domain", "ok.test", verdict=Verdict.BENIGN),
    ])
    objs = {o["pattern"]: o for o in to_stix(rep, created=FIXED)["objects"]}
    mal = objs["[ipv4-addr:value = '185.220.101.5']"]
    ben = objs["[domain-name:value = 'ok.test']"]
    assert mal["indicator_types"] == ["malicious-activity"] and mal["confidence"] == 90
    assert ben["indicator_types"] == ["benign"]


def test_to_stix_from_empty_is_valid_empty_bundle():
    bundle = to_stix([], created=FIXED)
    assert bundle["type"] == "bundle" and bundle["objects"] == []


# ----------------------------- round trip -------------------------

def test_roundtrip_entities_to_stix_and_back():
    ents = extract("185.220.101.5 evil-domain.ru ops@evil-domain.ru "
                   "install.ps1 sha256 " + "a" * 64)
    back = from_stix(to_stix(ents, created=FIXED))
    assert set(back.ips) == set(ents.ips)
    assert set(back.domains) == set(ents.domains)
    assert set(back.emails) == set(ents.emails)
    assert back.hashes["sha256"] == ents.hashes["sha256"]
    json.dumps(to_stix(ents, created=FIXED))  # serializable


# ------------------------------ TaxiiSource -----------------------

class FakeResp:
    def __init__(self, payload):
        self._p = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


class FakeTaxiiSession:
    def __init__(self, payload):
        self.payload = payload
        self.last = None

    def get(self, url, headers, params, auth, timeout):
        self.last = {"url": url, "headers": headers, "params": params, "auth": auth}
        return FakeResp(self.payload)


def test_taxii_source_builds_triggers_with_indicators():
    payload = {"objects": [
        {"type": "indicator", "id": "indicator--1", "name": "bad ip",
         "pattern": "[ipv4-addr:value = '185.220.101.5']", "modified": "2026-05-31T00:00:00Z"},
        {"type": "ipv4-addr", "id": "ipv4-addr--2", "value": "9.9.9.9"},
        {"weird": "no id or type"},
    ]}
    sess = FakeTaxiiSession(payload)
    src = TaxiiSource("https://taxii.test/api1/", "coll-1", token="t", session=sess)
    trigs = src.poll()
    assert [t.id for t in trigs] == ["indicator--1", "ipv4-addr--2"]
    assert ("ip", "185.220.101.5") in trigs[0].indicators
    assert sess.last["headers"]["Authorization"] == "Bearer t"
    assert sess.last["url"].endswith("/collections/coll-1/objects/")


def test_taxii_source_basic_auth_when_no_token():
    sess = FakeTaxiiSession({"objects": []})
    TaxiiSource("https://t/api", "c", username="u", password="p", session=sess).poll()
    assert sess.last["auth"] == ("u", "p")


def test_taxii_source_feeds_poller_and_dedupes():
    payload = {"objects": [
        {"type": "indicator", "id": "indicator--xyz",
         "pattern": "[domain-name:value = 'evil.test']"}]}
    src = TaxiiSource("https://t/api", "c", session=FakeTaxiiSession(payload))
    poller = Poller([src], store=MemorySeenStore())
    out = poller.run_once()
    assert len(out) == 1 and "evil.test" in out[0].output.entities.domains
    assert poller.run_once() == []  # same STIX id → seen
