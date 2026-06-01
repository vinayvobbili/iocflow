"""A hand-labeled corpus for measuring extraction accuracy.

Each :class:`Sample` pairs a realistic threat-report snippet with the indicators
a correct extractor should return. ``domains`` intentionally includes the hosts
of any labeled URLs and email addresses — iocflow surfaces those as domains too,
and that is the desired behavior.

The corpus is deliberately adversarial in two directions:
  * **positives** carry defanged IOCs, mixed casing, and prose noise;
  * **negatives** are vendor write-ups full of benign domains, private IPs,
    resolver IPs, and version numbers that *look* like indicators but must not be
    extracted — these measure precision, not just recall.

Threat actors are limited to clean ``APT##``-style names; multi-word group names
are matched by a heuristic that emits overlapping spans, which would measure the
heuristic's quirks rather than extraction accuracy.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass(frozen=True)
class Sample:
    name: str
    text: str
    expected: Dict[str, Set[str]] = field(default_factory=dict)


def _s(name: str, text: str, **expected: Set[str]) -> Sample:
    return Sample(name=name, text=text, expected={k: set(v) for k, v in expected.items()})


CORPUS: List[Sample] = [
    # ----------------------------- positives -----------------------------
    _s(
        "apt29-c2",
        "APT29 staged 185.220.101.5 and the C2 evil-corp[.]biz; operators dropped "
        "invoice.scr (md5 44d88612fea8a8f36de82e1278abb02f). Exploitation used "
        "CVE-2021-44228 via technique T1059.003.",
        ips={"185.220.101.5"},
        domains={"evil-corp.biz"},
        filenames={"invoice.scr"},
        hashes={"44d88612fea8a8f36de82e1278abb02f"},
        cves={"CVE-2021-44228"},
        mitre_techniques={"T1059.003"},
        threat_actors={"APT29"},
    ),
    _s(
        "phish-credential",
        "Phishing originated from admin@malicious-domain.ru and linked to "
        "hxxps://bad-actor.tk/login.php. The sender host 45.83.122.10 was already "
        "flagged in prior campaigns.",
        ips={"45.83.122.10"},
        domains={"malicious-domain.ru", "bad-actor.tk"},
        urls={"https://bad-actor.tk/login.php"},
        emails={"admin@malicious-domain.ru"},
    ),
    _s(
        "apt38-dropper",
        "APT38 leveraged T1566.001 to deliver a.dll, whose sha256 is "
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.",
        filenames={"a.dll"},
        hashes={"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        mitre_techniques={"T1566.001"},
        threat_actors={"APT38"},
    ),
    _s(
        "multi-ioc",
        "Indicators: 91.219.236.18, 193.142.146.77, and the staging domain "
        "exfil-node[.]xyz. Beaconing matched CVE-2023-23397 and CVE-2022-30190.",
        ips={"91.219.236.18", "193.142.146.77"},
        domains={"exfil-node.xyz"},
        cves={"CVE-2023-23397", "CVE-2022-30190"},
    ),
    _s(
        "hashes-three",
        "Three samples were recovered: "
        "5d41402abc4b2a76b9719d911017c592 (md5), "
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d (sha1), and "
        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae (sha256).",
        hashes={
            "5d41402abc4b2a76b9719d911017c592",
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        },
    ),
    _s(
        "defanged-urls",
        "Two payload URLs were observed: hxxp://203.0.113.55/gate.php and "
        "hxxps://malware-host[.]top/wp-content/x.bin serving update.exe.",
        ips={"203.0.113.55"},
        domains={"malware-host.top"},
        urls={"http://203.0.113.55/gate.php", "https://malware-host.top/wp-content/x.bin"},
        # x.bin lives inside a labeled URL path; iocflow surfaces it as part of the
        # URL, not as a separate filename, so only the standalone name is expected.
        filenames={"update.exe"},
    ),
    _s(
        "technique-heavy",
        "The intrusion chained T1190, T1059.001, and T1486 before contacting "
        "ransom-portal[.]onion-relay.net at 5.255.99.12.",
        ips={"5.255.99.12"},
        domains={"ransom-portal.onion-relay.net"},
        mitre_techniques={"T1190", "T1059.001", "T1486"},
    ),
    _s(
        "email-and-attachment",
        "Lure was sent by hr@payroll-update.cc carrying salary_review.docm; the "
        "macro pulled config.exe from 84.32.188.9.",
        ips={"84.32.188.9"},
        domains={"payroll-update.cc"},
        emails={"hr@payroll-update.cc"},
        filenames={"salary_review.docm", "config.exe"},
    ),
    _s(
        "apt28-cve",
        "APT28 exploited CVE-2020-0688 on the perimeter and pivoted to "
        "10-13-37-200.bad-cdn[.]ru, exfiltrating via 176.119.147.4.",
        ips={"176.119.147.4"},
        domains={"10-13-37-200.bad-cdn.ru"},
        cves={"CVE-2020-0688"},
        threat_actors={"APT28"},
    ),
    _s(
        "mixed-case-defang",
        "Beacon to EVIL-Beacon[.]NET over 45.143.220.59; sample HtmlDropper.HTA "
        "hashed to 9e107d9d372bb6826bd81d3542a419d6.",
        ips={"45.143.220.59"},
        domains={"evil-beacon.net"},
        filenames={"HtmlDropper.HTA"},
        hashes={"9e107d9d372bb6826bd81d3542a419d6"},
    ),
    # ----------------------------- negatives (precision) -----------------------------
    _s(
        "vendor-writeup",
        "For details see microsoft.com and the CrowdStrike blog at "
        "falcon.crowdstrike.com. Mitigations are documented on github.com.",
        # all-benign: nothing should be extracted
    ),
    _s(
        "internal-network",
        "Internal scan covered 10.0.0.5, 192.168.1.20, and 172.16.4.9; DNS was "
        "resolved by 8.8.8.8 and 1.1.1.1. No external indicators were found.",
        # private + resolver IPs are filtered as noise
    ),
    _s(
        "version-noise",
        "Upgrade to version 1.2.3 or 10.0.0; the agent build 4.5.6.7 is unaffected. "
        "Contact us at support.example.com for help.",
        # version strings are not IPs; example.com is benign
    ),
    _s(
        "benign-mixed",
        "Researchers at talosintelligence.com cross-referenced pypi.org and "
        "registry.npmjs.org. The report PDF lives on docs.google.com.",
    ),
]
