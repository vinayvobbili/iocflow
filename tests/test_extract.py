"""Tests for iocflow Layer 1 extraction."""
from iocflow import (
    ActorAliases,
    ExtractedEntities,
    Indicator,
    MalwareNames,
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
from iocflow.extractors.vulns import extract_mitre_procedures


# ----------------------------- refang -----------------------------

def test_refang_dot_and_at_and_hxxp():
    assert refang_text("evil[.]com") == "evil.com"
    assert refang_text("a[dot]b[DOT]c") == "a.b.c"
    assert refang_text("user[at]evil[.]com") == "user@evil.com"
    assert refang_text("hxxps://bad.test") == "https://bad.test"
    assert refang_text("hxxp[://]bad") == "http://bad"


# ----------------------------- IPs --------------------------------

def test_extract_ips_public_only():
    assert extract_ips("c2 at 185.220.101.5") == ["185.220.101.5"]


def test_extract_ips_skips_private_and_benign():
    text = "10.0.0.1 192.168.1.1 172.16.0.1 127.0.0.1 8.8.8.8 1.1.1.1"
    assert extract_ips(text) == []


def test_extract_ips_skips_version_numbers():
    # Chrome/122.0.0.0 user-agent style
    assert extract_ips("Chrome/122.0.0.0") == []


def test_extract_ips_dedupes():
    assert extract_ips("9.9.9.9 then 9.9.9.9 again") == ["9.9.9.9"]


# --------------------------- domains ------------------------------

def test_extract_domains_basic():
    assert "evil-domain.ru" in extract_domains("see evil-domain.ru now")


def test_extract_domains_skips_benign_and_subdomains():
    out = extract_domains("github.com and api.github.com and microsoft.com")
    assert out == []


def test_extract_domains_skips_filename_lookalikes():
    # install.sh should not be read as a domain (sh is a TLD)
    assert "install.sh" not in extract_domains("run install.sh to begin")


def test_extract_domains_keeps_brandable_dot_ai():
    assert "openclaw.ai" in extract_domains("the openclaw.ai package")


# ----------------------------- URLs -------------------------------

def test_extract_urls_full_and_bare_path():
    text = "fetch https://bad.test/payload and registry.npmjs.org/evilpkg/x"
    urls = extract_urls(text)
    assert "https://bad.test/payload" in urls
    # benign host but malicious path is kept and prefixed
    assert any("registry.npmjs.org/evilpkg" in u for u in urls)


def test_extract_urls_drops_benign_full_url():
    assert extract_urls("see https://github.com/foo/bar") == []


# --------------------------- filenames ----------------------------

def test_extract_filenames():
    out = extract_filenames("drops install.ps1 and evil.exe and macro.docm")
    assert "install.ps1" in out
    assert "evil.exe" in out
    assert "macro.docm" in out


def test_extract_filenames_from_urls():
    out = extract_filenames("", urls=["https://bad.test/a/dropper.scr"])
    assert "dropper.scr" in out


# ----------------------------- hashes -----------------------------

def test_extract_hashes_classifies_by_length():
    md5 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    h = extract_hashes(f"{md5} {sha1} {sha256}")
    assert h["md5"] == [md5]
    assert h["sha1"] == [sha1]
    assert h["sha256"] == [sha256]


# ----------------------------- CVEs -------------------------------

def test_extract_cves_uppercased_deduped():
    assert extract_cves("cve-2021-44228 and CVE-2021-44228") == ["CVE-2021-44228"]


# --------------------------- MITRE --------------------------------

def test_extract_mitre_techniques():
    assert extract_mitre_techniques("uses T1059 and t1059.001") == ["T1059", "T1059.001"]


def test_extract_mitre_procedures():
    line = "T1552.003: Unsecured Credentials: Bash History - scans env vars"
    procs = extract_mitre_procedures(line)
    assert procs["T1552.003"] == "Unsecured Credentials: Bash History - scans env vars"


# ----------------------------- emails -----------------------------

def test_extract_emails_lowercased():
    assert extract_emails("Ops@Evil.test") == ["ops@evil.test"]


# -------------------------- threat actors -------------------------

def test_extract_threat_actors_patterns():
    out = extract_threat_actors("APT28 UNC2452 FIN7 TA505 DEV-0537 STORM-0558")
    assert {"APT28", "UNC2452", "FIN7", "TA505", "DEV-0537", "STORM-0558"} <= set(out)


def test_extract_threat_actors_well_known():
    assert "LockBit" in extract_threat_actors("the LockBit affiliate")


def test_extract_threat_actors_ransomware_pattern():
    assert "CrazyHunter" in extract_threat_actors("CrazyHunter ransomware hit them")


def test_extract_threat_actors_ransomware_false_positive():
    assert "The" not in extract_threat_actors("The ransomware spread")


def test_extract_threat_actors_with_alias_provider():
    aliases = ActorAliases.from_index(
        {"evilbear": {"common_name": "EvilBear", "region": "Nowhere", "all_names": ["EvilBear"]}}
    )
    assert "EvilBear" in extract_threat_actors("the EvilBear crew", aliases)


# -------------------------- malware families ----------------------

def test_extract_malware_families_requires_provider():
    assert extract_malware_families("Emotet seen") == []


def test_extract_malware_families_matches_and_canonicalizes():
    names = MalwareNames.from_entries(
        [{"name": "Emotet", "aliases": ["Emotet", "Geodo"]}]
    )
    assert extract_malware_families("infected with Geodo", names) == ["Emotet"]


def test_extract_malware_families_blocklist():
    # "net" is a real MITRE tool name but blocklisted as a LOLBin/common word
    names = MalwareNames.from_names(["net"])
    assert extract_malware_families("use the net command", names) == []


def test_extract_malware_families_skips_short_names():
    names = MalwareNames.from_names(["AB"])
    assert extract_malware_families("AB everywhere", names) == []


# --------------------------- orchestrator -------------------------

def test_extract_full_pipeline_with_refang():
    text = (
        "APT28 staged from evil-domain[.]ru and 185.220.101.5, dropping "
        "install.ps1 (MD5 a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4). Exploited "
        "CVE-2021-44228 via T1190. Contact ops@evil-domain[.]ru."
    )
    e = extract(text)
    assert "185.220.101.5" in e.ips
    assert "evil-domain.ru" in e.domains
    assert "install.ps1" in e.filenames
    assert "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" in e.hashes["md5"]
    assert "CVE-2021-44228" in e.cves
    assert "T1190" in e.mitre_techniques
    assert "ops@evil-domain.ru" in e.emails
    assert "APT28" in e.threat_actors
    assert not e.is_empty()


def test_extract_empty_text():
    assert extract("").is_empty()


def test_extract_strips_html():
    e = extract("<p>c2 at 185.220.101.5</p>")
    assert e.ips == ["185.220.101.5"]


def test_extract_no_refang_when_disabled():
    e = extract("evil[.]com", refang=False)
    assert "evil.com" not in e.domains


# -------------------------- result helpers ------------------------

def test_iter_indicators():
    e = ExtractedEntities(ips=["1.2.3.4"], cves=["CVE-2021-44228"])
    inds = list(e.iter_indicators())
    assert Indicator("ip", "1.2.3.4") in inds
    assert Indicator("cve", "CVE-2021-44228") in inds


def test_to_dict_roundtrip_keys():
    e = extract("c2 at 185.220.101.5")
    d = e.to_dict()
    assert d["ips"] == ["185.220.101.5"]
    assert set(d) >= {"ips", "domains", "urls", "hashes", "cves", "threat_actors_enriched"}


def test_summary_no_entities():
    assert ExtractedEntities().summary() == "No entities found"
