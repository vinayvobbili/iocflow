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

> **Background:** [iocflow: Turning a Production AI SOC into a Shippable OSS Library](https://vinayvobbili.github.io/posts/iocflow-agentic-ioc-lifecycle/) — the production AI SOC this library was distilled from, and the design rationale behind it.

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
pip install "iocflow[misp]"      # + MISP interop: enrich / ingest / share back
pip install "iocflow[mcp]"       # + an MCP server (drive the lifecycle from any MCP client)
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

The whole lifecycle is a CLI. A bare invocation extracts (the common case); every
layer is a subcommand, takes text from arguments or stdin, and speaks `--json`.

```bash
iocflow "APT28 used 185.220.101.5 and evil[.]example[.]com"   # extract (default)
echo "report text…" | iocflow --json                          # stdin + JSON

iocflow enrich      "c2 at 185.220.101.5"      # L1→L2 (uses env API keys)
iocflow comment     "…report…"                 # +L3 AI assessment
iocflow hunt --dialect sigma "…report…"        # +L4 hunt queries
iocflow coverage    "…report…" -c catalog.json # L4 — covered/partial/gap vs your rules
iocflow block       "…report…"                 # L5 — DRY RUN; add --commit to push
iocflow investigate "…report…"                 # L6 agentic capstone (--gate auto for dev)
iocflow poll                                   # ingestion: run env-configured sources once
iocflow stix --to   "1.2.3.4"                  # emit a STIX 2.1 bundle
iocflow stix --from < bundle.json              # parse STIX into indicators
```

Each subcommand imports only its own layer, so it just needs that extra (e.g.
`pip install "iocflow[hunt]"`). With no API keys the deterministic layers still
run — `enrich` returns an empty report, `hunt`/`comment` produce their
deterministic output — so the CLI is useful offline. `python -m iocflow …` works
too.

### Docker

The image bundles every extra, so any subcommand works out of the box; the
entrypoint *is* `iocflow`, and it runs as a non-root user.

```bash
docker build -t iocflow .
echo "c2 at 185.220.101.5" | docker run -i --rm iocflow extract --json
docker run --rm -e IOCFLOW_ABUSEIPDB_API_KEY=… iocflow enrich "185.220.101.5"
```

### GitHub Action

Scan text or a file for IOCs in CI — and optionally fail the job when any are
found (a content gate). Outputs the JSON result and an indicator `count`.

```yaml
- uses: vinayvobbili/iocflow@v1
  id: ioc
  with:
    command: extract
    file: docs/CHANGES.md
    fail-on-findings: "true"     # gate: non-zero exit if any IOC appears
- run: echo "found ${{ steps.ioc.outputs.count }} indicators"
```

See [`examples/github-action-usage.yml`](examples/github-action-usage.yml).

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

## Layer 3 — AI commentary

Turn the enrichment report into an analyst-style assessment with an LLM. Install
the extra and point it at any OpenAI-compatible endpoint (OpenAI, Azure, or a
local server like vLLM / Ollama / LM Studio):

```bash
pip install "iocflow[ai]"
export IOCFLOW_LLM_API_KEY=...                       # omit for keyless local servers
export IOCFLOW_LLM_BASE_URL=http://localhost:11434/v1   # default: OpenAI
export IOCFLOW_LLM_MODEL=gpt-4o-mini
```

```python
from iocflow import extract
from iocflow.enrich import enrich
from iocflow.ai import comment

entities = extract(report_text)
report = enrich(entities)
note = comment(report, entities=entities, text=report_text)

print(note.severity.value, "—", note.summary)
for finding in note.key_findings:
    print(" •", finding)
for action in note.recommendations:
    print(" →", action)
```

`comment()` returns a structured `Commentary` (`severity`, `assessment`,
`key_findings`, `recommendations`) and is hardened against flaky model output:

- The model is asked for JSON; if it answers with prose or fenced JSON, the text
  is parsed best-effort, falling back to using it as the narrative.
- If no model is configured, or a call fails, `comment()` returns a
  **deterministic assessment built straight from the report** — so it always
  returns a usable result and never raises. The LLM is the primary path; the
  fallback guarantees the pipeline keeps working without one.

Bring any model by implementing the `CommentaryModel` protocol (`name` +
`complete(system, user, *, json=False) -> str`).

## Layer 4 — suggested hunts

Turn the indicators into ready-to-run hunt queries for the platforms a SOC
actually uses. The deterministic core runs offline — no network, no API keys:

```bash
pip install "iocflow[hunt]"   # only the optional LLM path needs the extra
```

```python
from iocflow import extract
from iocflow.enrich import enrich
from iocflow.hunt import suggest

entities = extract(report_text)
report = enrich(entities)
plan = suggest(report)                 # CrowdStrike CQL, Cortex XQL, Sigma

print(plan.summary())
# 9 hunts across 3 dialects

for hunt in plan.for_dialect("sigma"):
    print(f"# {hunt.title}  [{hunt.severity.value}]")
    print(hunt.query)
```

For each indicator kind it renders one sweep query per dialect — CrowdStrike
**CQL** (`in(RemoteAddressIP4, values=[...])`), Cortex **XQL**
(`dataset = xdr_data | filter ...`), and a complete **Sigma** rule (with a
stable, content-derived id). Values are escaped and de-duplicated; each dialect
renders only the indicator kinds it has a real field for, and benign-verdict
indicators are skipped by default (`include_benign=True` to keep them). Restrict
output with `dialects=["sigma"]`.

With a model configured (the same `IOCFLOW_LLM_*` env as Layer 3), `suggest()`
also proposes **behavioral hunts** — TTP- and anomaly-based ideas that go beyond
literal IOC matching:

```python
plan = suggest(report, entities=entities, commentary=note)
behavioral = [h for h in plan.hunts if h.source == "llm"]
```

Behavioral hunts are **validated against their dialect and repaired** before you
see them. Each authored query is checked (CQL must scope a real
`#event_simpleName` and bound its output; XQL must source an allowed `dataset`
and `| limit`; Sigma must carry the mandatory `title`/`detection`/`condition`
keys); a broken query is fed back to the model once with the failure reason to
fix. A hunt that still doesn't validate is **kept** with `validated=False` and a
`validation_error` — surfaced for a human to review, never silently dropped or
shipped as plausible-looking garbage. Model output is also parsed defensively
(code fences, trailing prose, and multiple top-level objects are all tolerated).

The LLM is strictly additive: with no model, or on any model error, you still
get the full deterministic plan — `suggest()` never raises. Add a query language
by implementing the `Dialect` protocol (`key`, `label`, `supports`, `render`,
and optionally `validate_behavioral` + `behavioral_guide` to opt into the
validate→repair loop).

### Coverage gaps — "can we already detect this?"

`suggest()` says *how to hunt*; its companion `assess_coverage()` says *where
you're blind*. Given the ATT&CK techniques in a CTI report and the detection
rules you already run, it returns a per-technique verdict — `covered`, `partial`,
or `gap`:

```python
from iocflow import extract
from iocflow.hunt import assess_coverage

entities = extract(cti_report_text)

# Bring your own rule inventory — a list of plain dicts, exported from whatever
# platforms you run. Each rule declares the ATT&CK techniques it covers.
catalog = [
    {"name": "Encoded PowerShell", "source": "crowdstrike", "techniques": ["T1059.001"]},
    {"name": "WMI Process Create",  "source": "sigma",       "techniques": ["T1047"]},
]

report = assess_coverage(entities, catalog)   # deterministic, offline, never raises
print(report.summary())                       # "1/3 techniques covered, 2 gaps"
for gap in report.gaps:
    print("BLIND:", gap.technique)
```

The deterministic core needs no network and no keys: it indexes the catalog by
technique and classifies each of the report's techniques as `covered` or `gap`.
By default a sub-technique is covered by a rule on its parent (`T1059.001`
satisfied by a `T1059` rule); pass `strict=True` to require exact matches. Pass
`techniques=[...]` to skip extraction when you already have the IDs.

With a model configured (the same `IOCFLOW_LLM_*` env), an optional pass
sharpens the verdict — a rule *tagged* for a technique doesn't always catch every
procedure under it, so the model can downgrade `covered → partial` with a
one-line rationale. Any model error leaves the deterministic verdicts intact;
`assess_coverage()` never raises. Together, `coverage` (where you're blind) and
`suggest` (how to look) are the "can we detect this?" answer for incoming CTI:

```python
coverage = assess_coverage(entities, catalog)
hunts    = suggest(report, entities=entities)
gap_techniques = {g.technique for g in coverage.gaps}   # drive manual hunting at the holes
```

## Layer 5 — response / blocking

Take the indicators the report flagged malicious and block them at the control
points you operate. **Blocking is dry-run by default** — you must explicitly opt
into live changes:

```bash
pip install "iocflow[block]"
```

```python
from iocflow import extract
from iocflow.enrich import enrich
from iocflow.block import block, unblock

entities = extract(report_text)
report = enrich(entities)

plan = block(report)                 # DRY RUN — shows exactly what would be blocked
print(plan.summary())
# DRY RUN: 1 skipped, 6 dry_run

result = block(report, dry_run=False)   # actually push the blocks
unblock(report, dry_run=False)          # reverse them
```

Targets, each acting only on the kinds it can enforce:

- **Palo Alto** — `PanEdlFeed` maintains typed `ip`/`domain`/`url` External
  Dynamic List files your firewall pulls (decoupled, non-destructive), and
  `PanOsBlocker` registers IP tags live via the User-ID API for a Dynamic
  Address Group deny policy.
- **Zscaler ZIA** — `ZscalerBlocker` adds URLs/domains to the denylist and
  activates the change.
- **CrowdStrike Falcon** — `CrowdStrikeBlocker` creates custom IOCs
  (`md5`/`sha256`/`domain`/`ip`) with a `prevent` action via the IOC Management API.
- **Abnormal Security** — `AbnormalBlocker` blocks email senders (experimental).

Safety is the point of this layer and it's authoritative:

- **Dry-run by default.** Nothing changes unless you pass `dry_run=False`.
- **An allowlist guard vetoes benign and internal indicators** — public
  resolvers, private/internal IPs, well-known domains — *before any target is
  called*, even if a report mislabeled one as malicious. You cannot accidentally
  block `8.8.8.8`.
- **Malicious-only by default** (`min_verdict="suspicious"` to widen), keyless
  targets are skipped, and a failing target becomes a `FAILED` result rather than
  crashing the batch. Every result carries the exact payload sent, so a dry run
  is a full audit.

Set credentials via the environment (`IOCFLOW_PANOS_*`, `IOCFLOW_ZSCALER_*`,
`IOCFLOW_FALCON_*`, `IOCFLOW_PAN_EDL_PATH`, `IOCFLOW_ABNORMAL_API_TOKEN`) and
`default_blockers()` builds every configured target, or pass blockers explicitly.
Bring your own control point by implementing the `Blocker` protocol
(`name`, `supports`, `block`, `unblock`).

## Layer 6 — the agentic capstone

Hand a report to a small multi-agent team and let it run the whole lifecycle: a
supervisor routes to specialist agents (extractor → enricher → hunter →
responder) that use Layers 1–5 as tools. The LLM applies judgment; the
deterministic layers do the exact work and are the fallback.

![iocflow investigate() running the full lifecycle with a human-in-the-loop approval gate](docs/demo.gif)

*(Run it yourself: [`examples/demo_investigate.py`](examples/demo_investigate.py).)*

```bash
pip install "iocflow[agent]"      # Python 3.10+ (LangGraph / LangChain)
```

```python
from iocflow.agent import investigate

case = investigate(report_text)        # safe: nothing is blocked by default
print(case.summary())
print(case.commentary.severity.value, "—", case.commentary.summary)
for line in case.trace:                # the agents' reasoning trace
    print(" •", line)
```

The model is any LangChain chat model; `default_agent_model()` builds a
`FailoverChatModel` (primary→secondary, via
[`langchain-failover`](https://pypi.org/project/langchain-failover/)) from the
same `IOCFLOW_LLM_*` env. With no model configured, the graph runs the layers in
a fixed deterministic order — so it always produces a `Case`.

**Blocking is human-in-the-loop, with three-layer authority.** The responder
agent *proposes* blocks, an `ApprovalGate` lets a human *authorize* them, and the
Layer 5 allowlist guard *vetoes* benign/internal indicators underneath — the LLM
is never the sole authority for a destructive action. The default is
`DenyAllGate` (an unattended run blocks nothing); pass an approving gate to act:

```python
from iocflow.agent import investigate, CLIApprovalGate
case = investigate(report_text, gate=CLIApprovalGate())   # prompts before blocking
```

`AutoApproveGate` (dev/CI) and `CLIApprovalGate` (plan-level or per-action) ship
in the box, and so does a real chat gate — **`SlackApprovalGate`** posts the
proposed blocks to a channel and waits for an allowlisted approver to react,
defaulting to *deny* on timeout (no inbound webhook server required):

```python
from iocflow.agent import investigate
from iocflow.agent.chat_gate import SlackApprovalGate

# SLACK_BOT_TOKEN + SLACK_APPROVAL_CHANNEL from the env; only these users count
gate = SlackApprovalGate(approvers=["U_ANALYST"], timeout=600)
case = investigate(report_text, gate=gate)   # ✅ to authorize, ❌ or no reply = denied
```

`ChatApprovalGate` + a two-method `ChatTransport` (`post`, `reactions`) make the
same flow portable to Webex, Teams, or anything else — implement the
`ApprovalGate` protocol to wire any channel you like. The threat-intel sources
(`enrichers=`) and block targets (`blockers=`) are equally pluggable, so the
agent runs fully offline in tests. The lifecycle is also exposed as LangChain
tools (`IOCFLOW_TOOLS`) for your own agents.

## Sources — trigger the lifecycle automatically

Everything above starts from text you hand in. Sources answer the other half:
*where does that text come from?* A `Source` polls a feed and yields `Trigger`
work items; a `Poller` de-duplicates them against a `SeenStore` and runs a
handler — by default the deterministic extract → enrich → comment → suggest
lifecycle. It's the same shape as a real critical-advisory poller, as a library.

```bash
pip install "iocflow[sources]"
```

```python
from iocflow.sources import Poller, SqliteSeenStore, GitHubAdvisorySource

poller = Poller(
    [GitHubAdvisorySource(severities=["critical"])],
    store=SqliteSeenStore("advisories.sqlite"),   # durable: survives restarts
)
for result in poller.run_once():                  # call from cron / a systemd timer
    print(result.output.summary())
```

Reference sources ship for **GitHub Security Advisories**, any **RSS/Atom** feed
(vendor advisories, threat blogs), and a **watched directory** of files;
`default_sources()` builds them from the environment. Scheduling stays yours —
the library offers `run_once()` and a simple `run_forever(interval)`, so it drops
behind your own cron or systemd timer.

Crucially, **a poller never blocks anything**: the default handler only analyzes
and (with the agent layer) *proposes*. To close the loop, hand the trigger to
`investigate()` with an approval gate — feed → investigate → propose → a human
approves in Slack — so automation does the toil and a person still holds the
trigger on anything destructive. See
[`examples/poller_advisories.py`](examples/poller_advisories.py).

## STIX interop — the threat-intel lingua franca

iocflow speaks STIX 2.1 both ways, so it drops into an existing TIP / TAXII
pipeline rather than living on an island.

```bash
pip install "iocflow[stix]"
```

```python
from iocflow.stix import from_stix, to_stix

entities = from_stix(bundle)          # STIX bundle/objects/JSON → extracted indicators
out = to_stix(enrichment_report)      # any iocflow result → a conformant STIX 2.1 bundle
```

`from_stix` walks observable objects *and* indicator patterns and is resilient to
the messy bundles real feeds emit (a bad object is skipped, never fatal).
`to_stix` accepts entities, an `EnrichmentReport` (verdicts become
`indicator_types` / `confidence`), a `Case`, or plain `(kind, value)` pairs, and
gives every object a **deterministic id** (UUIDv5 over the indicator) so bundles
are reproducible and idempotent to re-ingest. Both are stdlib-only.

A **TAXII 2.1** collection is also an ingestion source — it plugs straight into
the poller from the previous section:

```python
from iocflow.stix import TaxiiSource
from iocflow.sources import Poller, SqliteSeenStore

poller = Poller(
    [TaxiiSource(api_root, collection_id, token="…")],
    store=SqliteSeenStore("taxii.sqlite"),
)
```

See [`examples/stix_interop.py`](examples/stix_interop.py).

## MISP interop

MISP is where many teams already keep their shared threat intel. iocflow connects
to it three ways, each conforming to a seam you've already seen — so MISP is just
another enricher, another source, and a place to publish results.

```bash
pip install "iocflow[misp]"
```

```python
from iocflow import extract
from iocflow.enrich import enrich
from iocflow.misp import MISPEnricher, MISPEventSource, MISPPublisher

entities = extract(report_text)

# 1) Enrich: an Enricher like any other — a to_ids hit is malicious, a context
#    hit is suspicious, no hit is unknown.
report = enrich(entities, [MISPEnricher("https://misp.example.org", key)])

# 2) Ingest: a MISP instance as a Source — poll events and drive the lifecycle.
from iocflow.sources import Poller
Poller([MISPEventSource("https://misp.example.org", key, tags=["tlp:white"])]).run_once()

# 3) Share back: push the triage out as a MISP event. Safe by default —
#    dry_run=True builds the event without contacting the server; org-only
#    distribution and published=False keep it from going wider until you say so.
MISPPublisher("https://misp.example.org", key).publish(report)
```

Verdicts shape what gets shared: an attribute is marked `to_ids` (actionable) only
when its enrichment verdict is malicious. Configure via `IOCFLOW_MISP_URL` +
`IOCFLOW_MISP_KEY` (and `IOCFLOW_MISP_SOURCE=true` to auto-wire the event source).
A thin REST client — stdlib + `requests`, no `pymisp`. See
[`examples/misp_interop.py`](examples/misp_interop.py).

## MCP server

iocflow speaks the **Model Context Protocol**, so any MCP client — Claude
Desktop, an IDE assistant, your own agent — can drive the lifecycle as tools.

```bash
pip install "iocflow[mcp]"      # Python 3.10+
iocflow-mcp                     # serve over stdio (also: python -m iocflow.mcp)
```

Wire it into Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "iocflow": { "command": "iocflow-mcp" }
  }
}
```

Seven tools are exposed: `extract_iocs`, `enrich_indicators`, `assess_indicators`,
`suggest_hunts`, `propose_blocks` (always a **dry run** — pushing real blocks is
deliberately not an MCP tool), and `to_stix_bundle` / `from_stix_bundle`. The tool
functions are plain and SDK-free (in `iocflow.mcp.tools`), so importing the
package doesn't require the MCP SDK — only running the server does. See
[`examples/mcp_server.py`](examples/mcp_server.py).

## Where this is going

iocflow grows in independently-useful layers, each behind its own pip extra.
**Layers 1–6** all ship today — extraction, enrichment, AI commentary, suggested
hunts, response/blocking, and the agentic capstone. The pipeline is a clean
hand-off chain of stable types: `ExtractedEntities` (L1) → `enrich()` →
`EnrichmentReport` (L2) → `comment()` → `Commentary` (L3) → `suggest()` →
`HuntPlan` (L4) → `block()` → `BlockReport` (L5) — and `investigate()` (L6)
orchestrates the whole chain as a multi-agent team with a human-in-the-loop gate.
Everything but the agent capstone runs on Python 3.9+; `import iocflow` stays
dependency-light (one dependency) and pulls in no layer you don't ask for.

## Quality & trust

iocflow is built to be depended on:

- **Typed.** The package ships a `py.typed` marker (PEP 561), so your type
  checker sees iocflow's real signatures. The whole codebase type-checks clean
  under `mypy` in CI.
- **Fuzzed.** A [Hypothesis](https://hypothesis.readthedocs.io/) property suite
  throws arbitrary Unicode, defang noise, and IOC-shaped tokens at the
  extractor. Layer 1's contract is simple — it parses untrusted text and **never
  crashes**, never executes input — and the suite holds it to that, plus
  invariants like "every emitted IP is a valid address" and "extraction is
  deterministic".
- **Benchmarked.** Accuracy is measured, not asserted. Run the scorecard against
  the labeled corpus:

  ```bash
  python -m benchmarks
  # OVERALL  precision 0.979  recall 1.000  f1 0.989
  ```

  A regression test guards the headline precision/recall so accuracy can't
  silently drift.
- **Secure by design.** Blocking is dry-run by default behind an authoritative
  allowlist guard, the agent gate denies by default, and the MCP server never
  exposes a tool that pushes real blocks. See
  [`SECURITY.md`](SECURITY.md) for the full posture and how to report a
  vulnerability.

## License

MIT
