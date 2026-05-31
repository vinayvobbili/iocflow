# iocflow

[![CI](https://github.com/vinayvobbili/iocflow/actions/workflows/ci.yml/badge.svg)](https://github.com/vinayvobbili/iocflow/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/iocflow)](https://pypi.org/project/iocflow/)
[![Python](https://img.shields.io/pypi/pyversions/iocflow)](https://pypi.org/project/iocflow/)
[![License](https://img.shields.io/pypi/l/iocflow)](https://github.com/vinayvobbili/iocflow/blob/main/LICENSE)

Pull **indicators of compromise** out of unstructured text — threat-intel
reports, advisories, emails, tickets — in one call. iocflow extracts IPs,
domains, URLs, filenames, file hashes, CVEs, MITRE ATT&CK technique IDs, threat
actors, and malware families, with the false-positive defenses you'd otherwise
write by hand: a Public Suffix List domain validator, benign-domain/IP
allowlists, hash de-duplication across MD5/SHA1/SHA256, and re-fanging of
defanged IOCs.

```python
from iocflow import extract

text = """
APT28 (a.k.a. Fancy Bear) staged Cobalt Strike from evil-domain[.]ru and
185.220.101.5, dropping install.ps1 (MD5 a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4).
Exploited CVE-2021-44228 via T1190. Contact: ops@evil-domain[.]ru.
"""

entities = extract(text)
print(entities.summary())
# 1 IPs, 1 domains, 1 filenames, 1 hashes, 1 CVEs, 1 emails, 1 threat actors, 1 MITRE techniques

for ind in entities.iter_indicators():
    print(ind.kind, ind.value)
# ip 185.220.101.5
# domain evil-domain.ru
# ...
```

The defanged `evil-domain[.]ru` and `ops@evil-domain[.]ru` are re-fanged
automatically; `185.220.101.5` is kept while private/benign IPs are dropped.

## Install

```bash
pip install iocflow              # core — one dependency (tldextract)
pip install "iocflow[mitre]"     # + a ready-made MITRE ATT&CK malware-name source
```

## What it extracts

`extract(text)` returns an `ExtractedEntities` with:

- `ips` — public IPv4, excluding private ranges, benign IPs, and version-number-like values
- `domains` — validated against the Mozilla Public Suffix List via `tldextract`
- `urls` — both `https://…` and bare `host/path` forms (so package-registry paths survive)
- `filenames` — suspicious script/executable/macro/archive filenames
- `hashes` — `{"md5": [...], "sha1": [...], "sha256": [...]}`, de-duplicated across lengths
- `cves` — `CVE-YYYY-NNNN+`, normalized to uppercase
- `emails`
- `mitre_techniques` — `T1059`, `T1059.001`, …
- `threat_actors` (+ `threat_actors_enriched`) — APT/UNC/FIN/TA/DEV/STORM designators,
  a curated well-known list, and the `"<Name> ransomware"` pattern
- `malware_families` — populated when you supply a malware-name source (see below)

Each individual extractor is also importable and composable:

```python
from iocflow import extract_ips, extract_hashes, refang_text
extract_ips(refang_text("c2 at 185[.]220[.]101[.]5"))   # ['185.220.101.5']
```

## Pluggable name sources

The core has **no external-data dependency**. Two enrichment sources are
optional and supplied by you, so iocflow drops cleanly into any environment —
plug in your own feeds, or use the bundled MITRE extra.

**Malware families.** Give `extract` a `MalwareNames` and it matches families
(with alias-to-canonical normalization) behind a three-layer false-positive
defense. Build one from your own list, from MITRE-shaped records, or from the
optional extra:

```python
from iocflow import extract, MalwareNames

# Your own list:
names = MalwareNames.from_names(["Cobalt Strike", "Emotet", "Qakbot"])
entities = extract(report_text, malware_names=names)

# Or the bundled MITRE ATT&CK source (needs: pip install "iocflow[mitre]"):
from iocflow.mitre import mitre_malware_names
entities = extract(report_text, malware_names=mitre_malware_names())
```

**Threat-actor aliases.** Give `extract` an `ActorAliases` to match a custom
name set and enrich actors with `common_name` / `region` / `all_names`. Without
it, actors are still found by pattern and curated list:

```python
from iocflow import extract, ActorAliases

aliases = ActorAliases.from_index({
    "apt28": {"common_name": "APT28", "region": "Russia",
              "all_names": ["Fancy Bear", "Sofacy", "Sednit"]},
})
entities = extract(report_text, actor_aliases=aliases)
entities.threat_actors_enriched[0].region        # "Russia"
entities.threat_actors_enriched[0].aliases_display()  # "Fancy Bear, Sofacy, Sednit"
```

## Command line

```bash
iocflow "APT28 used 185.220.101.5 and evil[.]example[.]com"
echo "report text…" | iocflow --json
iocflow --mitre "Emotet dropped Cobalt Strike"     # needs iocflow[mitre]
```

## Layer 2 — enrichment

Take the extracted entities and look every indicator up against threat-intel
sources, getting back a normalized verdict per indicator. Install the extra and
set the API keys you have:

```bash
pip install "iocflow[enrich]"
export IOCFLOW_VT_API_KEY=...          # VirusTotal      (free key)
export IOCFLOW_ABUSEIPDB_API_KEY=...   # AbuseIPDB       (free key)
export IOCFLOW_ABUSECH_API_KEY=...     # abuse.ch        (free Auth-Key)
```

```python
from iocflow import extract
from iocflow.enrich import enrich

entities = extract(report_text)
report = enrich(entities)              # uses every source whose key is set

print(report.summary())
# 5 indicators across 3 sources, 2 malicious, 1 suspicious

for ind in report.malicious:
    print("malicious:", ind.kind, ind.value, "→", report.verdict_for(ind.kind, ind.value).value)
```

Each indicator is routed only to the sources that handle its kind (VirusTotal:
IPs/domains/URLs/hashes; AbuseIPDB: IPs; abuse.ch: IPs/domains/URLs/hashes via
ThreatFox/URLhaus/MalwareBazaar). Lookups fan out over a thread pool. A source
with no key is skipped, and a failing lookup becomes an error record rather than
crashing the batch — so partial coverage still produces a report.

Verdicts are normalized to `MALICIOUS / SUSPICIOUS / BENIGN / UNKNOWN` and
aggregated worst-wins across sources. You can also pass enrichers explicitly,
restrict to certain `kinds`, or supply a cache:

```python
from iocflow.enrich import enrich, VirusTotalEnricher, MemoryCache

report = enrich(
    entities,
    [VirusTotalEnricher("my-key")],
    kinds={"ip", "domain"},
    cache=MemoryCache(),
)
```

Bring your own source by implementing the `Enricher` protocol (`name`,
`supports(kind)`, `enrich(kind, value) -> EnrichmentRecord`) — or subclass
`HTTPEnricher` to get session handling, rate-limiting, and error-wrapping for
free.

## Where this is going

iocflow grows in independently-useful layers, each behind its own pip extra.
**Layer 1** (extraction) and **Layer 2** (enrichment) ship today; next are AI
commentary, suggested hunts, and optional perimeter blocking. The pipeline is a
clean hand-off chain of stable types: `ExtractedEntities` (L1) feeds `enrich()`,
which returns an `EnrichmentReport` (L2) that later layers consume.

## License

MIT
