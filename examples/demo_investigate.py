#!/usr/bin/env python3
"""A short, self-contained demo of iocflow's agentic capstone (Layer 6).

Runs the full IOC lifecycle on a sample report as a small multi-agent team —
extractor → enricher → hunter → responder — and stops at a human-in-the-loop
gate before any block. Nothing real is touched: blocks are written to a
throwaway Palo Alto EDL file in a temp dir.

    python examples/demo_investigate.py

The approval keystroke is simulated here so the demo is deterministic and
recordable; in real use you'd pass a plain ``CLIApprovalGate()`` (or the Slack
gate) and a human would answer.
"""
import tempfile
import time
from pathlib import Path

from iocflow.agent import CLIApprovalGate, investigate
from iocflow.block import PanEdlFeed
from iocflow.enrich.models import EnrichmentRecord, Verdict


class DemoEnricher:
    """An offline stand-in for a real threat-intel source (no API keys/network).

    Flags a small set of known-bad indicators MALICIOUS so the demo has
    something to act on. In real use you'd pass VirusTotal/AbuseIPDB/abuse.ch
    via ``default_enrichers()`` instead — the agent takes any ``enrichers=``.
    """

    name = "demo-intel"
    _BAD = {"185.220.101.5", "evil-domain.ru", "ops@evil-domain.ru",
            "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44"}

    def supports(self, kind):
        return kind in ("ip", "domain", "url", "hash", "email")

    def enrich(self, kind, value):
        if value in self._BAD:
            return EnrichmentRecord(self.name, kind, value,
                                    verdict=Verdict.MALICIOUS, score=95,
                                    reference="demo: known-bad fixture")
        return EnrichmentRecord(self.name, kind, value, verdict=Verdict.UNKNOWN)

REPORT = """
Threat advisory — APT28 (Fancy Bear) infrastructure update.

The actor staged Cobalt Strike from evil-domain[.]ru and 185.220.101.5,
dropping install.ps1 (sha256
aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44).
Exploited CVE-2021-44228 via T1190. Sender: ops@evil-domain[.]ru.
Note: 8.8.8.8 appears in logs but is a benign public resolver.
"""


def typed(answer, delay=0.9):
    """Simulate a human reading the prompt, then typing an answer."""
    def _input(prompt):
        print(prompt, end="", flush=True)
        time.sleep(delay)
        print(answer)
        return answer
    return _input


def slow_print(lines, delay=0.25):
    for line in lines:
        print(line)
        time.sleep(delay)


def main():
    print("=" * 64)
    print("  iocflow — agentic IOC investigation (extract → … → respond)")
    print("=" * 64)
    print(REPORT.strip())
    print("\nInvestigating...\n")
    time.sleep(0.6)

    with tempfile.TemporaryDirectory() as tmp:
        # Human-in-the-loop: approve the whole plan. (Keystroke simulated here.)
        gate = CLIApprovalGate(input_fn=typed("y"))
        case = investigate(REPORT, gate=gate, blockers=[PanEdlFeed(tmp)],
                           enrichers=[DemoEnricher()])

        print("\nAgent reasoning trace:")
        slow_print(f"  • {line}" for line in case.trace)

        print(f"\n{case.summary()}")
        if case.commentary is not None:
            print(f"Assessment [{case.commentary.severity.value}]: "
                  f"{case.commentary.summary}")

        if case.hunts is not None and case.hunts.hunts:
            print(f"\nSuggested hunts: {len(case.hunts.hunts)} "
                  f"({', '.join(sorted(case.hunts.dialects))})")

        report = case.block_report
        if report is not None:
            print(f"\nBlocking: {report.summary()}")
            edl = Path(tmp) / "ip.txt"
            if edl.exists():
                print(f"  Palo Alto EDL now lists: {edl.read_text().strip()}")
        print("\nBenign 8.8.8.8 was never proposed — the allowlist guard "
              "vetoes it underneath, even if flagged.")


if __name__ == "__main__":
    main()
