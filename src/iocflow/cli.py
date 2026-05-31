"""Command-line entry point: ``python -m iocflow`` (or the ``iocflow`` script)."""
from __future__ import annotations

import argparse
import json
import sys

from iocflow.extract import extract


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="iocflow",
        description="Extract threat indicators (IOCs) from text.",
    )
    parser.add_argument(
        "text",
        nargs="*",
        help="Text to extract from. If omitted, reads from stdin.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full result as JSON instead of a human summary.",
    )
    parser.add_argument(
        "--no-refang",
        action="store_true",
        help="Do not re-fang defanged IOCs before extracting.",
    )
    parser.add_argument(
        "--mitre",
        action="store_true",
        help="Load MITRE malware names for family extraction (needs iocflow[mitre]).",
    )
    args = parser.parse_args(argv)

    text = " ".join(args.text) if args.text else sys.stdin.read()

    malware_names = None
    if args.mitre:
        try:
            from iocflow.mitre import mitre_malware_names

            malware_names = mitre_malware_names()
        except ImportError:
            parser.error("--mitre requires the extra: pip install 'iocflow[mitre]'")

    entities = extract(text, malware_names=malware_names, refang=not args.no_refang)

    if args.json:
        json.dump(entities.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(entities.summary())
        for indicator in entities.iter_indicators():
            print(f"  {indicator.kind:16} {indicator.value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
