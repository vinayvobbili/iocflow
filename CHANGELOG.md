# Changelog

## Unreleased

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
