# Design sketch: ATT&CK coverage-gap analysis (`iocflow.hunt.coverage`)

> Status: **IMPLEMENTED** in v0.14.0 (`iocflow.hunt.assess_coverage`,
> `iocflow.hunt.coverage` / `coverage_models`, `iocflow coverage` CLI). This
> document is kept as the original design rationale; the shipped API matches it,
> with `name`-resolution and the malware/actor→technique mapping (steps 1 and 4
> below) deferred — the v1 technique set comes from `entities.mitre_techniques`
> (or the explicit `techniques=` arg), and the MCP tool remains a follow-on.

## The gap

Layer 4 (`iocflow.hunt.suggest`) answers **"how do I hunt for this?"** — it turns
extracted/enriched indicators into ready-to-run queries (CrowdStrike CQL, Cortex
XQL, Sigma) plus optional LLM behavioral hunts.

It does **not** answer the other question a responder asks when CTI lands:

> **"Can we already detect this — and where are the gaps?"**

Given a piece of threat intel and the detection rules you already run, you want a
per-technique verdict: *covered*, *partial*, or *gap* — so you know what to hunt
manually (because you're blind to it) versus what should already be alerting.

This is the natural companion to `suggest()`: `suggest` produces hunts; `coverage`
tells you which of the CTI's techniques your rule inventory already covers and
which are holes. Together they're the "were we touched / can we detect this"
workbench, as a library.

## Why it belongs in iocflow (not a new package)

- The input is **ATT&CK techniques extracted from CTI** — already Layer 1
  (`extract` → `extract_mitre_techniques`, malware/actor → technique mapping via
  `iocflow.mitre`).
- It's the same shape as the existing hunt layer (deterministic core, optional
  LLM refinement, never raises) and reuses the same `CommentaryModel` protocol.
- Splitting it into a separate library would fork the IOC/CTI lifecycle across
  two packages. Keep the lifecycle in one place; add a capability.

## Public API

New module `src/iocflow/hunt/coverage.py`, re-exported from `iocflow.hunt`.

```python
from iocflow import extract
from iocflow.hunt import assess_coverage         # new

entities = extract(cti_report_text)

# Bring your own rule inventory — a list of plain dicts, exported from whatever
# platforms you run. Each rule declares the ATT&CK techniques it covers.
catalog = [
    {"name": "Encoded PowerShell", "source": "crowdstrike", "techniques": ["T1059.001"]},
    {"name": "WMI Process Create",  "source": "sigma",       "techniques": ["T1047"]},
]

report = assess_coverage(entities, catalog)       # deterministic, offline, never raises

print(report.summary())          # "3/5 techniques covered, 2 gaps"
for item in report.items:
    print(item.technique, item.status, "->", [r.name for r in item.rules])
for gap in report.gaps:          # convenience: items with status == GAP
    print("BLIND:", gap.technique, gap.name)
```

Optional LLM pass — distinguishes *real* coverage from a shared technique ID
(a rule tagged `T1059.001` for a different PowerShell procedure may not catch
*this* CTI's procedure):

```python
from iocflow.hunt import assess_coverage, default_model   # default_model already exists in hunt

report = assess_coverage(entities, catalog, model=default_model())
# items can now be downgraded covered -> partial with item.rationale set
```

Explicit techniques (skip extraction) for callers that already have them:

```python
assess_coverage(techniques=["T1059.001", "T1047", "T1218.011"], catalog=catalog)
```

## Data model (`src/iocflow/hunt/coverage_models.py`)

```python
class CoverageStatus(str, Enum):
    COVERED = "covered"     # >=1 catalog rule maps to this technique
    PARTIAL = "partial"     # mapped, but LLM judged it may miss this procedure
    GAP     = "gap"         # no catalog rule maps to this technique

@dataclass
class CoverageItem:
    technique: str               # "T1059.001"
    name: str                    # ATT&CK technique name (via iocflow.mitre, best-effort)
    status: CoverageStatus
    rules: list[CoverageRule]    # catalog rules that map (name, source)
    rationale: str = ""          # set only by the optional LLM pass

@dataclass
class CoverageReport:
    items: list[CoverageItem]
    @property
    def gaps(self) -> list[CoverageItem]: ...
    @property
    def covered(self) -> list[CoverageItem]: ...
    def summary(self) -> str: ...
    def to_dict(self) -> dict: ...
```

## Algorithm

**Deterministic core (no network, no keys):**

1. Resolve the technique set:
   - from `entities` — union of `extract_mitre_techniques` output and techniques
     implied by extracted malware/actors (reuse `iocflow.mitre` mappings), or
   - from the explicit `techniques=` argument.
   - Normalize to canonical IDs; fold sub-techniques' parents in as needed
     (`T1059.001` also satisfies a rule tagged `T1059`, configurable).
2. Index the catalog by technique (`dict[str, list[CoverageRule]]`).
3. For each technique: `COVERED` if the index has a rule, else `GAP`.
4. Best-effort enrich each technique with its ATT&CK name via `iocflow.mitre`
   (already a bundled provider; falls back to the bare ID if unavailable).

**Optional LLM pass (only when a `model` is given):**

5. For `COVERED` techniques where the CTI carries a specific procedure, ask the
   model whether the matched rule(s) plausibly catch *that* procedure. Downgrade
   `COVERED → PARTIAL` with a one-line `rationale` when the model is doubtful.
   Any model error leaves the deterministic result intact. Never raises.

No LLM is ever required; the LLM only *refines* `covered → partial`. Gaps and
plain coverage are fully deterministic.

## Dependencies

**None new.** Core is stdlib. The optional pass reuses the existing
`CommentaryModel` protocol + `default_model()` already used by Layer 3/4 and the
`[hunt]` extra (`requests`). `iocflow.mitre` (the `[mitre]` extra) is used
best-effort for technique names and falls back gracefully.

## How it composes

```python
entities = extract(cti_text)
report   = enrich(entities)            # L2 (optional)
note     = comment(report)             # L3 (optional)

coverage = assess_coverage(entities, catalog)     # NEW: what can we already see?
hunts    = suggest(report, entities=entities)     # L4: how to hunt the rest

# Drive manual hunting at the gaps specifically:
gap_techniques = {g.technique for g in coverage.gaps}
priority_hunts = [h for h in hunts.hunts if gap_techniques & set(h.kinds_or_techniques())]
```

`suggest` says *how to look*; `coverage` says *where you're blind*. The union is
the "can we detect this?" answer for an incoming CTI report — offline by default,
LLM-sharpened when a model is present.

## Testing

- Deterministic: covered/gap classification, parent/sub-technique folding,
  empty-catalog → all gaps, explicit-techniques path, malware→technique
  resolution via a faked `iocflow.mitre`.
- LLM pass: a `FakeModel` (same fixture style as `tests/test_hunt.py`) that
  downgrades one item to `partial`; a model that raises → report unchanged.
- `assess_coverage` never raises on any input (mirror the hunt-layer contract).

## CLI / MCP (follow-on, out of scope for v1)

- `iocflow coverage --catalog catalog.json report.txt`
- An MCP tool `coverage_gap(text, catalog)` alongside the existing hunt tool.

## Open questions

1. Parent/sub-technique folding default — strict (exact match) or lenient
   (`T1059.001` satisfied by a `T1059` rule)? Propose: lenient by default,
   `strict=True` to opt out.
2. Catalog schema — reuse the loose `{"name","source","techniques"}` dict (same
   as detflow's overlap input) so a single exported inventory feeds both.
3. Should `suggest()` optionally take a `catalog=` and auto-prioritize hunts at
   the gaps, or keep that composition in the caller's hands (as above)? Propose:
   keep it explicit for v1; revisit once `coverage` lands.
```
