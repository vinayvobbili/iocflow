# Changelog

## Unreleased

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
