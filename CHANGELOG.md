# Changelog

## Unreleased

## 0.14.0 (2026-06-06)
- **ATT&CK coverage-gap analysis — "can we already detect this?".** New
  `iocflow.hunt.assess_coverage(entities, catalog)`, the companion to
  `suggest()`. `suggest` says *how to hunt*; `coverage` says *where you're
  blind*. Given the ATT&CK techniques in a CTI report and the detection rules you
  already run (a list of `{name, source, techniques}` dicts — the same loose
  shape detflow's overlap input uses), it returns a per-technique verdict:
  `covered`, `partial`, or `gap`.
  - **Deterministic core, no network, no keys.** Indexes the catalog by technique
    and classifies each report technique. Lenient by default — a sub-technique is
    covered by a rule on its parent (`T1059.001` satisfied by a `T1059` rule);
    `strict=True` requires exact matches. Pass `techniques=[...]` to skip
    extraction. Robust to garbage catalog rows (non-dicts, missing fields).
  - **Optional LLM refinement.** With a model configured (the same
    `IOCFLOW_LLM_*` env as Layers 3/4), a single pass can downgrade
    `covered → partial` when a tagged rule looks unlikely to catch *this* CTI's
    procedure, with a one-line rationale. Strictly additive: any model/parse
    failure leaves the deterministic verdicts intact and records a non-fatal
    `report.error`. `assess_coverage()` never raises and never consults the model
    when there's nothing covered to refine.
  - New result types `CoverageReport` / `CoverageItem` / `CoverageRule` /
    `CoverageStatus` (re-exported from `iocflow.hunt`), with `.gaps`, `.covered`,
    `.partial`, `.summary()`, and `.to_dict()`.
  - New CLI: `iocflow coverage "…report…" -c catalog.json [--strict] [--json]`.

## 0.13.0 (2026-06-02)
- **Behavioral hunts are now validated and repaired.** The optional LLM hunt
  path (`iocflow[hunt]`) no longer ships whatever the model emits. Each authored
  behavioral hunt is checked against its dialect — CrowdStrike CQL must scope a
  real `#event_simpleName` (from an allow-list of Falcon sensor events) and bound
  its output; Cortex XQL must source an allowed `dataset` and `| limit`; Sigma
  must carry the mandatory `title`/`detection`/`condition` keys. A query that
  fails is fed back to the model **once** with the failure reason (and the
  dialect's syntax guide) to repair it. A hunt that still doesn't validate is
  **kept** with `validated=False` and a `validation_error` — surfaced for a human
  to review, never silently dropped or shipped as plausible-looking garbage.
  - New `Hunt.validated` / `Hunt.validation_error` fields (in `to_dict()`).
    Deterministic hunts are valid by construction (`validated=True`).
  - Dialects opt in by implementing `validate_behavioral(query) -> (ok, reason)`
    and a `behavioral_guide` string; the loop no-ops for dialects without them.
- **Tolerant LLM JSON parsing.** The hunt parser previously sliced first-`{` to
  last-`}`, which dropped the brackets of a JSON *array* (collapsing a list of
  hunts to one object) and choked on "Extra data". It now scans with
  `raw_decode`, recovering the payload from code fences, leading/trailing prose,
  a bare top-level array, or several top-level objects emitted back-to-back.

## 0.12.0 (2026-06-01)
- **Trust hardening.** iocflow now ships type information and is verified by a
  stronger CI gate.
  - **Typed (`py.typed`).** The package is marked typed (PEP 561), so downstream
    users get full type-checking against iocflow's public API. The whole package
    type-checks clean under `mypy` (now a CI job), with sound types threaded
    through the agent state and the env/config seams along the way.
  - **Fuzzed extractor.** A Hypothesis property suite hammers `extract` and every
    individual extractor with arbitrary Unicode, defang noise, and IOC-shaped
    tokens, asserting the hard contract — *never crash on untrusted input* — plus
    structural and semantic invariants (valid IPs, correct hash lengths,
    canonical CVE form, determinism). Fixed a latent `None`-crash in the hunt
    LLM prompt path found while typing.
  - **Accuracy benchmark.** A hand-labeled corpus of report snippets (positives
    and benign-distractor negatives) with a precision/recall evaluator:
    `python -m benchmarks` prints a scorecard, and `tests/test_benchmark.py`
    guards the headline metrics (currently ~0.98 precision, 1.0 recall) against
    silent regression.
  - **`SECURITY.md`.** A private vulnerability-disclosure policy plus the
    library's safety guarantees (dry-run blocking, allowlist guard, deny-by-default
    gate, MCP never pushes blocks).

## 0.11.0 (2026-05-31)
- **MCP server** (`iocflow[mcp]`). iocflow now speaks the Model Context Protocol,
  so any MCP client (Claude Desktop, an IDE assistant, your own agent) can drive
  the lifecycle as tools. Run it with the `iocflow-mcp` console script or
  `python -m iocflow.mcp` (stdio transport). Seven tools: `extract_iocs`,
  `enrich_indicators`, `assess_indicators`, `suggest_hunts`, `propose_blocks`
  (always a dry run — pushing real blocks is deliberately not exposed as a tool),
  and `to_stix_bundle` / `from_stix_bundle`.
- The tool functions live in `iocflow.mcp.tools` and are SDK-free: importing the
  package (and unit-testing the tools) needs no MCP SDK — only running the server
  does (`build_server()`). The MCP SDK requires Python 3.10+; the rest of iocflow
  still runs on 3.9. New `examples/mcp_server.py`.

## 0.10.0 (2026-05-31)
- **Full lifecycle CLI.** The `iocflow` command grew from extract-only to the
  whole lifecycle as subcommands: `extract` (still the default — `iocflow "…"`
  works unchanged), `enrich`, `comment`, `hunt`, `block` (dry-run unless
  `--commit`), `investigate`, `poll` (run env-configured ingestion sources once),
  and `stix --to`/`--from`. Each reads text from args or stdin, speaks `--json`,
  imports only its own layer (so it needs just that extra), and still runs with
  no API keys (the deterministic layers produce output). `python -m iocflow`
  works via a new `__main__`.
- **Docker image.** A multi-stage `Dockerfile` builds a slim image with every
  extra installed; the entrypoint is `iocflow` and it runs as a non-root user.
- **GitHub Action.** A composite `action.yml` (`uses: vinayvobbili/iocflow@v1`)
  scans inline text or a file for IOCs in CI, exposes the JSON result and an
  indicator `count`, and can fail the job on findings (`fail-on-findings`) as a
  content gate. Example workflow in `examples/github-action-usage.yml`.
- Pin the build backend below `hatchling` 1.30, which emits Metadata-Version 2.5
  — rejected by current `packaging`/`twine` and PyPI's validator; 2.4 is the
  accepted version.

## 0.9.0 (2026-05-31)
- **MISP interop** (`iocflow[misp]`). Connects iocflow to a MISP instance three
  ways, each conforming to an existing seam: `MISPEnricher` is an `Enricher`
  (a `to_ids` hit → malicious, a context-only hit → suspicious, no hit →
  unknown); `MISPEventSource` is a `Source` that polls events (filtered by tag /
  published state / recency) and folds every attribute — including those nested
  in MISP objects, and composite types like `domain|ip` — into a `Trigger`;
  `MISPPublisher` is a share-back sink that pushes a triage result *out* as a
  MISP event.
- `MISPPublisher` is safe by default like Layer 5 blocking: `dry_run=True` builds
  the event payload without contacting the server, `distribution=0` (org-only)
  and `published=False` keep it from going wider until you opt in. Enrichment
  verdicts drive `to_ids` — only malicious indicators are marked actionable.
- A thin REST client (stdlib + `requests`, no `pymisp`), so the extra is just
  `requests`. Auto-wires from `IOCFLOW_MISP_URL` + `IOCFLOW_MISP_KEY` (the
  enricher) and `IOCFLOW_MISP_SOURCE=true` (the event source). New
  `examples/misp_interop.py`.

## 0.8.0 (2026-05-31)
- **STIX 2.1 interop** (`iocflow[stix]`). `from_stix(bundle)` parses a STIX
  bundle / object(s) / JSON string into `ExtractedEntities` — walking both
  observable objects (SCOs) and indicator patterns, and resilient to the messy
  bundles real feeds emit (a malformed object is skipped, never fatal).
  `to_stix(source)` emits a conformant STIX 2.1 `bundle` from any iocflow result
  (`ExtractedEntities`, an `EnrichmentReport` whose verdicts become
  `indicator_types` / `confidence`, a `Case`, or plain `(kind, value)` pairs).
- Object ids are **deterministic** (UUIDv5 over the indicator), so re-emitting an
  indicator yields the same id — bundles are reproducible and idempotent to
  ingest. `from_stix`/`to_stix` are stdlib-only.
- **`TaxiiSource`** makes a TAXII 2.1 collection an ingestion source that plugs
  straight into the `Poller` (de-dup keyed on STIX object id). Its pre-parsed
  indicators flow through the lifecycle even when the trigger text is only a
  pattern — the default handler now merges a trigger's structured indicators with
  what it extracts from text. New `examples/stix_interop.py`.

## 0.7.0 (2026-05-31)
- **Ingestion / triggers** (`iocflow[sources]`). A `Source` polls a feed and
  yields `Trigger` work items; a `Poller` de-duplicates them against a
  `SeenStore` and runs a handler — by default the deterministic extract → enrich
  → comment → suggest lifecycle, returning a `TriageResult`. It turns iocflow
  from "paste text + click" into something a feed can drive, the same shape as a
  critical-advisory poller.
- Reference sources: `GitHubAdvisorySource` (GitHub Security Advisories, severity
  / ecosystem filters), `RssSource` (any RSS/Atom feed; accepts a raw string for
  offline use), and `FileSource` (a watched directory). `default_sources()`
  builds them from the environment (`IOCFLOW_GITHUB_ADVISORIES`,
  `IOCFLOW_RSS_FEEDS`, `IOCFLOW_FILE_SOURCE_DIR`).
- `SeenStore` de-dup with a stdlib `SqliteSeenStore` (durable across restarts)
  and a `MemorySeenStore`. The `Poller` is resilient — one failing source or
  handler never sinks the batch, and a failed handler leaves its trigger unmarked
  so the next poll retries it (`mark_on_error=` to opt out).
- Scheduling stays out of the library: `run_once()` for cron / a systemd timer,
  or `run_forever(interval)`. A poller **never blocks** — analysis and proposals
  only; destructive action still goes through the Layer 6 approval gate. Wire the
  full loop with `handler=lambda t: investigate(t.text, gate=...)`.
- Lazy and isolated: `import iocflow` doesn't load `sources`, and importing
  `iocflow.sources` doesn't pull `feedparser` until `RssSource.poll()`. New
  `examples/poller_advisories.py`.

## 0.6.1 (2026-05-31)
- **A real chat approval gate.** `SlackApprovalGate` wires the Layer 6
  human-in-the-loop seam to Slack: it posts the proposed blocks to a channel and
  polls for a reaction from an allowlisted approver (✅ approves the plan, ❌ or no
  reply within the timeout denies it) — no inbound webhook server needed. The
  underlying `ChatApprovalGate` + two-method `ChatTransport` (`post`,
  `reactions`) make the same flow portable to Webex/Teams/etc. A timeout defaults
  to deny, and the Layer 5 allowlist guard still vetoes underneath.
- **Pluggable enrichers in the agent.** `investigate(...)` / `build_graph(...)`
  now take `enrichers=` alongside `blockers=`, so the threat-intel sources are
  injectable (and the whole agent runs offline in tests/demos).
- **Demo.** `examples/demo_investigate.py` runs the full lifecycle with the CLI
  approval gate against a sample report (nothing real is touched); `docs/demo.gif`
  records it for the README.

## 0.6.0 (2026-05-31)
- **Layer 6: the agentic capstone** (`iocflow[agent]`). `iocflow.agent.investigate(text)`
  drives the whole IOC lifecycle as a small multi-agent team (LangGraph): a
  supervisor routes to specialist agents — extractor, enricher, hunter,
  responder — that use Layers 1–5 as tools, returning a `Case` (every layer's
  output plus a human-readable reasoning `trace`).
- The LLM applies judgment (supervisor routing, per-indicator response
  recommendations) while the deterministic layers do the exact work — and are
  the fallback: with no model configured, the graph runs the layers in a fixed
  deterministic order. The agent's model is any LangChain chat model;
  `default_agent_model()` builds a `FailoverChatModel` (primary→secondary, via
  `langchain-failover`) from `IOCFLOW_LLM_*`.
- Blocking is human-in-the-loop with three-layer authority: the agent
  **proposes**, an `ApprovalGate` lets a human **authorize**, and the Layer 5
  allowlist guard **vetoes** benign/internal indicators — the LLM is never the
  sole authority for a destructive action. Ships `DenyAllGate` (the safe
  default — an unattended run blocks nothing), `AutoApproveGate` (dev/CI), and
  `CLIApprovalGate` (plan-level or per-action); the `ApprovalGate` protocol lets
  you wire your own approval channel.
- The IOC lifecycle is also exposed as LangChain tools (`IOCFLOW_TOOLS`) for use
  in your own agents.
- Opt-in and isolated: `import iocflow` (and L1–L5) imports no LangChain. The
  agent extra requires Python 3.10+ (LangGraph/LangChain); the rest of iocflow
  still runs on 3.9.

## 0.5.0 (2026-05-31)
- **Layer 5: response / blocking** (`iocflow[block]`). `iocflow.block.block(report)`
  takes the indicators an enrichment report flagged malicious and blocks them at
  the control points you operate, returning a `BlockReport` of per-target
  `BlockResult`s. `unblock(...)` reverses them where the target supports it.
- Targets: **Palo Alto** — `PanEdlFeed` (maintains typed ip/domain/url External
  Dynamic List files the firewall pulls; stdlib-only, non-destructive) and
  `PanOsBlocker` (live User-ID registered-IP/DAG tagging); **Zscaler ZIA**
  (`ZscalerBlocker`, denylist + activation, url/domain); **CrowdStrike Falcon**
  (`CrowdStrikeBlocker`, IOC Management API, md5/sha256/domain/ip, OAuth2); and
  **Abnormal Security** (`AbnormalBlocker`, email sender, experimental).
- Safety is built in and authoritative: `dry_run=True` is the default everywhere
  (you must pass `dry_run=False` to change anything); an allowlist guard vetoes
  benign/internal indicators (public resolvers, private IPs, well-known domains)
  *before any target is called*, even if a report mislabeled them malicious; only
  malicious indicators are selected by default (`min_verdict=`); targets with no
  credentials are skipped; and nothing raises — failures become `FAILED` results.
- Every `BlockResult` carries the exact payload that was (or would be) sent, so a
  dry run is a full audit of the intended change.
- `Blocker` protocol (flat `block`/`unblock(kind, value, ...)` signatures, chosen
  so each target drops in cleanly as an agent tool later); `default_blockers()`
  builds every target whose credentials are present in the environment.
- Core install stays dependency-light: `import iocflow` loads none of
  `block`/`hunt`/`ai`/`enrich`.

## 0.4.0 (2026-05-30)
- **Layer 4: suggested hunts** (`iocflow[hunt]`). `iocflow.hunt.suggest(report)`
  turns an enrichment report (or extracted entities) into ready-to-run hunt
  queries — a `HuntPlan` of `Hunt`s, each with a `query`, `severity`, and
  `rationale`.
- Deterministic, offline core (no network, no keys): renders one IOC-sweep query
  per indicator kind in three dialects — **CrowdStrike CQL**, **Cortex XQL**, and
  **Sigma** (a complete rule with a content-derived, stable id). Values are
  escaped and de-duplicated; benign-verdict indicators are skipped by default.
  Each dialect renders only the kinds it has a real field for.
- Optional LLM behavioral hunts: with a model configured (`IOCFLOW_LLM_*`, the
  same config as Layer 3) `suggest()` additionally proposes TTP/anomaly-based
  hunts. The LLM path is strictly additive — any model failure leaves the
  deterministic plan intact, and `suggest()` never raises.
- `Dialect` protocol + registry (`get_dialect`, `all_dialects`,
  `DEFAULT_DIALECTS`) so new query languages drop in.
- `Severity` now lives in the dependency-light core (`iocflow.severity`) and is
  shared by Layers 3 and 4; `from iocflow.ai.models import Severity` is
  unchanged. The deterministic hunt renderers are stdlib-only — `import
  iocflow.hunt` pulls in neither `iocflow.ai` nor the LLM path.
- `HuntPlan` is the serializable seam for Layer 5 (optional perimeter blocking).

## 0.3.0 (2026-05-30)
- **Layer 3: AI commentary** (`iocflow[ai]`). `iocflow.ai.comment(report)` turns
  an enrichment report into a structured `Commentary` (`severity`, `assessment`,
  `key_findings`, `recommendations`).
- Bundled `OpenAIChatModel` adapter (`requests`-only) works with any
  OpenAI-compatible endpoint — OpenAI, Azure, vLLM, Ollama, LM Studio, gateways.
  Configured via `IOCFLOW_LLM_API_KEY` / `IOCFLOW_LLM_BASE_URL` /
  `IOCFLOW_LLM_MODEL`; `CommentaryModel` protocol lets any other model plug in.
- Robust output handling: the model is asked for JSON, with best-effort parsing
  (strips code fences / surrounding prose) and a narrative fallback. With no
  model configured or on a model error, `comment()` returns a deterministic
  assessment built from the report — it always returns a `Commentary` and never
  raises.
- Core install stays dependency-light: `import iocflow` does not import
  `iocflow.ai` (or `iocflow.enrich`). `Commentary` is the seam for Layer 4.

## 0.2.1 (2026-05-30)
- Enrichers with no API key now fail gracefully: an explicitly-constructed
  source whose key is missing/empty short-circuits to a clear "no API key
  configured" error record *before* any network call, instead of making a
  doomed request. The batch still completes and other sources' verdicts land.
  (`default_enrichers()` already skipped keyless sources; this covers manual
  construction too.)
- Update the package description to reflect extraction **and** enrichment.

## 0.2.0 (2026-05-30)
- **Layer 2: enrichment** (`iocflow[enrich]`). `enrich(entities)` looks every
  extracted indicator up against threat-intel sources and returns a normalized
  `EnrichmentReport` (worst-wins `MALICIOUS / SUSPICIOUS / BENIGN / UNKNOWN`
  verdict per indicator).
- Free-tier sources: `VirusTotalEnricher` (IPs/domains/URLs/hashes),
  `AbuseIPDBEnricher` (IPs), `AbuseChEnricher` (ThreatFox/URLhaus/MalwareBazaar).
- `default_enrichers()` builds every source whose API key is present in the
  environment (`IOCFLOW_VT_API_KEY`, `IOCFLOW_ABUSEIPDB_API_KEY`,
  `IOCFLOW_ABUSECH_API_KEY`); missing keys are skipped, not errors.
- Sync thread-pool fan-out; indicators routed to sources by kind. Failing
  lookups become error records instead of crashing the batch.
- `Enricher` protocol + `HTTPEnricher` base (session, per-source rate-limiting,
  error-wrapping) for custom sources; optional `Cache` seam with `MemoryCache`.
- Core install stays dependency-light: enrichment is not imported unless you
  `import iocflow.enrich`.

## 0.1.0 (2026-05-30)

- Initial release — Layer 1: threat-entity extraction.
- `extract(text)` pulls IPs, domains, URLs, filenames, hashes (MD5/SHA1/SHA256),
  CVEs, emails, MITRE technique IDs, threat actors, and malware families from
  unstructured text.
- `refang_text` re-fangs defanged IOCs (`[.]`, `[at]`, `hxxp`, …) before extraction.
- Domain validation via `tldextract` (Mozilla Public Suffix List); broad
  benign-domain / benign-IP allowlists; three-layer malware false-positive defense.
- Pluggable enrichment sources: `MalwareNames` and `ActorAliases` — supply your
  own name sets; the core has no external-data dependency and works fully without them.
- Optional `iocflow[mitre]` extra: `mitre.mitre_malware_names()` fetches the public
  MITRE ATT&CK STIX bundle and returns a ready-made `MalwareNames` (7-day disk cache).
- `ExtractedEntities.iter_indicators()` yields flat `(kind, value)` indicators —
  the input surface for future enrichment layers.
- `iocflow` CLI / `python -m iocflow` with `--json`, `--no-refang`, `--mitre`.
