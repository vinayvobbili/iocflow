"""The ``iocflow`` command line — the whole lifecycle from a terminal.

Subcommands mirror the library layers:

    iocflow extract   "…text…"     # L1  (also the default: `iocflow "…"`)
    iocflow enrich    "…text…"     # L1→L2
    iocflow comment   "…text…"     # +L3 AI assessment
    iocflow hunt      "…text…"     # +L4 suggested hunts
    iocflow block     "…text…"     # L5  (DRY RUN unless --commit)
    iocflow investigate "…text…"   # L6  agentic capstone
    iocflow poll                   # ingestion: run env-configured sources once
    iocflow stix --to|--from       # STIX 2.1 conversion
    iocflow version

Every command reads text from arguments or stdin, takes ``--json`` for machine
output, and degrades gracefully with no API keys (the deterministic layers still
run). Each layer is imported lazily, so a command only needs its own extra.
"""
from __future__ import annotations

import argparse
import json
import sys

from iocflow.extract import extract

_LAYER_SUBCOMMANDS = (
    "extract", "enrich", "comment", "hunt", "block", "investigate",
    "poll", "stix", "version",
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _read_text(args) -> str:
    return " ".join(args.text) if args.text else sys.stdin.read()


def _emit_json(obj) -> None:
    json.dump(obj, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def _need(extra: str, exc: Exception) -> int:
    sys.stderr.write(f"iocflow: this command needs an extra — pip install 'iocflow[{extra}]'\n"
                     f"  ({exc})\n")
    return 2


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #

def _cmd_extract(args) -> int:
    malware_names = None
    if args.mitre:
        try:
            from iocflow.mitre import mitre_malware_names

            malware_names = mitre_malware_names()
        except ImportError as exc:
            return _need("mitre", exc)
    entities = extract(_read_text(args), malware_names=malware_names, refang=not args.no_refang)
    if args.json:
        _emit_json(entities.to_dict())
    else:
        print(entities.summary())
        for ind in entities.iter_indicators():
            print(f"  {ind.kind:16} {ind.value}")
    return 0


def _cmd_enrich(args) -> int:
    try:
        from iocflow.enrich import enrich
    except ImportError as exc:
        return _need("enrich", exc)
    entities = extract(_read_text(args))
    report = enrich(entities)
    if args.json:
        _emit_json(report.to_dict())
    else:
        print(report.summary())
        for ind in report.indicators():
            print(f"  {report.verdict_for(ind.kind, ind.value).value:10} {ind.kind:8} {ind.value}")
    return 0


def _cmd_comment(args) -> int:
    try:
        from iocflow.ai import comment
        from iocflow.enrich import enrich
    except ImportError as exc:
        return _need("ai", exc)
    text = _read_text(args)
    entities = extract(text)
    report = enrich(entities)
    c = comment(report, entities=entities, text=text)
    if args.json:
        _emit_json(c.to_dict())
    else:
        print(f"severity: {c.severity.value}")
        print(c.assessment)
        for f in c.key_findings:
            print(f"  - {f}")
        if c.recommendations:
            print("recommendations:")
            for r in c.recommendations:
                print(f"  - {r}")
    return 0


def _cmd_hunt(args) -> int:
    try:
        from iocflow.enrich import enrich
        from iocflow.hunt import suggest
    except ImportError as exc:
        return _need("hunt", exc)
    entities = extract(_read_text(args))
    report = enrich(entities)
    plan = suggest(report, entities=entities, dialects=args.dialect or None)
    if args.json:
        _emit_json(plan.to_dict())
    else:
        print(plan.summary())
        for h in plan.hunts:
            print(f"\n# [{h.source}/{h.severity.value}] {h.rationale}")
            print(h.query)
    return 0


def _cmd_block(args) -> int:
    try:
        from iocflow.block import block
        from iocflow.enrich import enrich
    except ImportError as exc:
        return _need("block", exc)
    entities = extract(_read_text(args))
    report = enrich(entities)
    result = block(report, dry_run=not args.commit)
    if args.json:
        _emit_json(result.to_dict())
    else:
        mode = "COMMIT" if args.commit else "dry-run"
        print(f"[{mode}] {result.summary()}")
        for r in result.results:
            print(f"  {r.status:9} {r.target:14} {r.kind:7} {r.value}")
    return 0


def _cmd_investigate(args) -> int:
    try:
        from iocflow.agent import investigate
        from iocflow.agent.gate import AutoApproveGate, DenyAllGate
    except ImportError as exc:
        return _need("agent", exc)
    gate = AutoApproveGate() if args.gate == "auto" else DenyAllGate()
    case = investigate(_read_text(args), gate=gate)
    if args.json:
        _emit_json(case.to_dict())
    else:
        print(case.summary())
        for line in case.trace or []:
            print(f"  · {line}")
    return 0


def _cmd_poll(args) -> int:
    try:
        from iocflow.sources import Poller, default_sources
    except ImportError as exc:
        return _need("sources", exc)
    sources = default_sources()
    if not sources:
        sys.stderr.write(
            "iocflow: no sources configured. Set e.g. IOCFLOW_GITHUB_ADVISORIES=true, "
            "IOCFLOW_RSS_FEEDS=…, IOCFLOW_FILE_SOURCE_DIR=…, or IOCFLOW_MISP_SOURCE=true.\n"
        )
        return 1
    results = Poller(sources).run_once()
    if args.json:
        _emit_json([r.to_dict() for r in results])
    else:
        print(f"{len(results)} new trigger(s) from {len(sources)} source(s)")
        for r in results:
            tag = "ok" if r.ok else f"ERROR: {r.error}"
            # output is duck-typed (a TriageResult by default); read defensively.
            ents = getattr(r.output, "entities", None) if r.ok else None
            summary = ents.summary() if ents is not None else ""
            print(f"  [{tag}] {r.trigger.source}:{r.trigger.id} {r.trigger.title or ''} {summary}")
    return 0


def _cmd_stix(args) -> int:
    try:
        from iocflow.stix import from_stix, to_stix
    except ImportError as exc:
        return _need("stix", exc)
    if args.to:
        entities = extract(_read_text(args))
        _emit_json(to_stix(entities))
    else:  # --from (the default direction for the stix command)
        raw = " ".join(args.text) if args.text else sys.stdin.read()
        entities = from_stix(raw)
        if args.json:
            _emit_json(entities.to_dict())
        else:
            print(entities.summary())
            for ind in entities.iter_indicators():
                print(f"  {ind.kind:16} {ind.value}")
    return 0


def _cmd_version(args) -> int:
    from iocflow import __version__

    print(__version__)
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #

def _add_text_arg(p) -> None:
    p.add_argument("text", nargs="*", help="Input text; if omitted, read from stdin.")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of a human summary.")


def _build_parser() -> argparse.ArgumentParser:
    from iocflow import __version__

    parser = argparse.ArgumentParser(
        prog="iocflow",
        description="Extract, enrich, assess, hunt, block, and investigate IOCs.",
    )
    parser.add_argument("--version", action="version", version=f"iocflow {__version__}")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("extract", help="Extract indicators from text (Layer 1).")
    _add_text_arg(p)
    p.add_argument("--no-refang", action="store_true", help="Do not re-fang defanged IOCs.")
    p.add_argument("--mitre", action="store_true", help="Load MITRE malware names (iocflow[mitre]).")
    p.set_defaults(func=_cmd_extract)

    p = sub.add_parser("enrich", help="Extract then enrich against threat-intel (L1→L2).")
    _add_text_arg(p)
    p.set_defaults(func=_cmd_enrich)

    p = sub.add_parser("comment", help="Add an AI analyst assessment (L3).")
    _add_text_arg(p)
    p.set_defaults(func=_cmd_comment)

    p = sub.add_parser("hunt", help="Suggest hunt queries (L4).")
    _add_text_arg(p)
    p.add_argument("--dialect", action="append",
                   help="Hunt dialect(s): crowdstrike, cortex, sigma (repeatable).")
    p.set_defaults(func=_cmd_hunt)

    p = sub.add_parser("block", help="Block malicious indicators (L5; DRY RUN by default).")
    _add_text_arg(p)
    p.add_argument("--commit", action="store_true",
                   help="Actually push blocks (default is a dry run that changes nothing).")
    p.set_defaults(func=_cmd_block)

    p = sub.add_parser("investigate", help="Run the agentic multi-agent lifecycle (L6).")
    _add_text_arg(p)
    p.add_argument("--gate", choices=("deny", "auto"), default="deny",
                   help="Approval gate: 'deny' (default, safe) or 'auto' (dev — approves blocks).")
    p.set_defaults(func=_cmd_investigate)

    p = sub.add_parser("poll", help="Run env-configured ingestion sources once.")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of a human summary.")
    p.set_defaults(func=_cmd_poll, text=None)

    p = sub.add_parser("stix", help="Convert STIX 2.1 ↔ indicators.")
    _add_text_arg(p)
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--from", dest="from_", action="store_true",
                     help="Parse STIX input into indicators (default).")
    grp.add_argument("--to", action="store_true", help="Emit a STIX 2.1 bundle from text.")
    p.set_defaults(func=_cmd_stix)

    p = sub.add_parser("version", help="Print the iocflow version.")
    p.set_defaults(func=_cmd_version, text=None)

    return parser


def _inject_default(argv):
    """Default to ``extract`` when no subcommand is given (``iocflow "…text…"``)."""
    for tok in argv:
        if tok in ("-h", "--help", "--version"):
            return argv
        if not tok.startswith("-"):
            return argv if tok in _LAYER_SUBCOMMANDS else ["extract", *argv]
    return ["extract", *argv]  # only flags, or empty → extract (from stdin)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    args = parser.parse_args(_inject_default(argv))
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
