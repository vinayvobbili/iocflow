# Security Policy

`iocflow` parses untrusted text and can talk to security-control planes
(firewalls, EDR, mail security), so we take its security posture seriously. This
document covers how to report a vulnerability and the safety guarantees the
library is designed around.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for a
suspected vulnerability.

- Preferred: open a [GitHub private security advisory](https://github.com/vinayvobbili/iocflow/security/advisories/new).
- Alternatively, email **vinayvobbilichetty11@gmail.com** with `iocflow security`
  in the subject.

Please include:

- the affected version (`iocflow --version` or `iocflow.__version__`),
- a description of the issue and its impact,
- the smallest input or steps that reproduce it.

What to expect:

- acknowledgement within **3 business days**,
- an initial assessment within **10 business days**,
- coordinated disclosure once a fix is available; we're happy to credit you.

## Supported versions

`iocflow` is pre-1.0 and ships from `main`. Security fixes land in a new patch
release on the latest minor version; please upgrade to the most recent release
before reporting. Older versions are not separately patched.

## Design guarantees (and their limits)

Several behaviors are load-bearing for safety. Treat a regression in any of them
as a security issue:

- **Extraction never executes input.** Layer 1 is pure parsing — regexes and
  string handling. It does not deserialize, `eval`, or run extracted content. It
  is fuzz-tested to never raise on arbitrary input (`tests/test_fuzz.py`).
- **Blocking is dry-run by default.** Every Layer 5 blocker defaults to
  `dry_run=True`. Pushing a real block requires an explicit opt-in, and an
  authoritative allowlist guard rejects attempts to block allowlisted
  indicators *before* any control-plane call.
- **The agent gate denies by default.** The Layer 6 supervisor's human-in-the-loop
  gate is `DenyAll` unless a caller deliberately supplies an approving gate.
- **The MCP server never pushes blocks.** The `propose_blocks` MCP tool is
  dry-run only; executing a block is intentionally not exposed as a tool, so an
  LLM client cannot trigger destructive action with a single call.
- **Network calls require explicit credentials.** Enrichment, blocking, and
  feed sources are inert until you configure the relevant API keys/URLs;
  nothing reaches out by default.

### Your responsibilities

- Keep API keys and control-plane credentials in the environment, not in code.
- Review proposed blocks before committing them; the dry-run default exists for
  this. Maintain your allowlists.
- Indicator *verdicts* come from third-party intel and an optional LLM — treat
  them as advisory, not ground truth, especially before automated blocking.

## Scope

In scope: the `iocflow` package and its console scripts. Out of scope: issues in
third-party dependencies (report those upstream), and the security of remote
services you point iocflow at (your MISP, TAXII, EDR, etc.).
