"""Property-based (Hypothesis) fuzzing of Layer 1 extraction.

Extraction runs over attacker-controlled text (report bodies, feed entries,
pasted alerts), so its one hard contract is: *never crash, whatever the input*.
These properties hammer ``extract`` and every individual extractor with random
text — arbitrary Unicode, defang noise, and IOC-shaped tokens — and assert the
structural invariants the rest of the pipeline relies on.
"""
import ipaddress
import re
import string

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from iocflow import (
    ExtractedEntities,
    extract,
    extract_cves,
    extract_domains,
    extract_emails,
    extract_filenames,
    extract_hashes,
    extract_ips,
    extract_malware_families,
    extract_mitre_techniques,
    extract_threat_actors,
    extract_urls,
    refang_text,
)

# Known indicator kinds emitted by ExtractedEntities.iter_indicators().
_KINDS = {
    "ip", "domain", "url", "email", "filename", "md5", "sha1", "sha256",
    "cve", "mitre_technique", "threat_actor", "malware_family",
}

# A strategy that mixes free Unicode text with IOC-shaped fragments, so the
# fuzzer spends time near the grammar the extractors actually parse rather than
# only on random noise that never matches anything.
_IOC_FRAGMENTS = st.sampled_from([
    "185.220.101.5", "8.8.8.8", "999.999.999.999", "1.2.3", "0.0.0.0",
    "evil[.]example[.]com", "good.example.org", "sub.domain.co.uk",
    "hxxps://bad.test/path?q=1", "http://a.b/", "https://",
    "user[at]evil[.]com", "a@b", "name@sub.domain.io",
    "CVE-2021-44228", "cve-1999-0001", "CVE-0000-0",
    "T1059", "T1059.003", "TA0001", "G0007", "S0154",
    "d41d8cd98f00b204e9800998ecf8427e",  # md5
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # sha1
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256
    "invoice.docx", "evil.exe", "payload.dll", "a.sh", "..", "....",
    "APT28", "Lazarus Group", "Emotet", "the the", "  ", "[.]", "[dot]",
    "<script>", "</b>", "&amp;", "\x00\x01", "🦠 malware 🛡️",
])

_text = st.one_of(
    st.text(),
    st.text(alphabet=string.printable),
    st.lists(st.one_of(_IOC_FRAGMENTS, st.text(max_size=12)), max_size=20).map(" ".join),
)

_SETTINGS = settings(
    max_examples=400,
    deadline=None,  # tldextract's suffix lookup makes per-call timing noisy
    suppress_health_check=[HealthCheck.too_slow],
)

_ALL_EXTRACTORS = [
    extract_ips, extract_domains, extract_urls, extract_emails,
    extract_filenames, extract_cves, extract_mitre_techniques,
    extract_threat_actors, extract_malware_families,
]


# ----------------------------- never crashes -----------------------------

@_SETTINGS
@given(_text)
def test_extract_never_raises(text):
    result = extract(text)
    assert isinstance(result, ExtractedEntities)


@_SETTINGS
@given(_text)
def test_extract_without_refang_never_raises(text):
    assert isinstance(extract(text, refang=False), ExtractedEntities)


@_SETTINGS
@given(_text)
def test_refang_never_raises_and_returns_str(text):
    out = refang_text(text)
    assert isinstance(out, str)


@_SETTINGS
@given(_text)
def test_individual_extractors_never_raise(text):
    for fn in _ALL_EXTRACTORS:
        out = fn(text)
        assert isinstance(out, list)
    digests = extract_hashes(text)
    assert set(digests) >= {"md5", "sha1", "sha256"}


# ----------------------------- structural invariants -----------------------------

@_SETTINGS
@given(_text)
def test_indicators_are_well_formed(text):
    for ind in extract(text).iter_indicators():
        assert ind.kind in _KINDS
        assert isinstance(ind.value, str) and ind.value != ""
        # No interior whitespace leaks into a single indicator value.
        assert not re.search(r"\s", ind.value) or ind.kind in {"threat_actor", "malware_family"}


@_SETTINGS
@given(_text)
def test_extraction_is_deterministic(text):
    assert extract(text).to_dict() == extract(text).to_dict()


@_SETTINGS
@given(_text)
def test_is_empty_agrees_with_iter_indicators(text):
    result = extract(text)
    assert result.is_empty() == (next(result.iter_indicators(), None) is None)


# ----------------------------- semantic invariants -----------------------------

@_SETTINGS
@given(_text)
def test_every_emitted_ip_is_a_valid_address(text):
    for ip in extract_ips(text):
        ipaddress.ip_address(ip)  # raises ValueError if malformed


_HEX_LEN = {"md5": 32, "sha1": 40, "sha256": 64}


@_SETTINGS
@given(_text)
def test_hashes_have_correct_length_and_alphabet(text):
    digests = extract_hashes(text)
    for algo, length in _HEX_LEN.items():
        for digest in digests[algo]:
            assert len(digest) == length
            assert all(c in string.hexdigits for c in digest)


_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@_SETTINGS
@given(_text)
def test_cves_match_canonical_form(text):
    for cve in extract_cves(text):
        assert _CVE.match(cve), cve


# ----------------------------- round-trip / idempotence -----------------------------

# A known IOC, when extracted and re-fed, is found again (extraction is stable
# on its own canonical output — no octet-mangling, no progressive trimming).
# Values are public, non-allowlisted addresses the extractor actually emits
# (8.8.8.8 / 192.168.x are deliberately filtered as benign/private noise).
@_SETTINGS
@given(st.sampled_from(["185.220.101.5", "45.83.122.10", "1.2.3.4"]))
def test_extracted_ip_round_trips(ip):
    once = extract_ips(ip)
    assert ip in once
    assert extract_ips(" ".join(once)) == once


@pytest.mark.parametrize("digest", [
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
])
def test_known_hash_round_trips(digest):
    found = [d for kind in ("md5", "sha1", "sha256") for d in extract_hashes(digest)[kind]]
    assert digest in found
