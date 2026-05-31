#!/usr/bin/env python3
"""Trigger the IOC lifecycle from a feed instead of a human paste.

Polls GitHub's critical Security Advisories, de-duplicates against a SQLite
store (so a restart doesn't re-process), and runs the deterministic lifecycle
(extract → enrich → comment → suggest) over each *new* advisory. Nothing is
blocked — that stays behind the Layer 6 approval gate.

    pip install "iocflow[sources,enrich,hunt,ai]"
    python examples/poller_advisories.py

Run it from cron or a systemd timer (the library doesn't own the clock):
    */15 * * * *  python /path/to/poller_advisories.py

To close the loop with the full multi-agent path + a human Slack approval on
proposed blocks, swap the handler (needs iocflow[agent]):

    from iocflow.agent import investigate
    from iocflow.agent.chat_gate import SlackApprovalGate
    gate = SlackApprovalGate(approvers=["U_ANALYST"])
    poller = Poller(sources, store=store, handler=lambda t: investigate(t.text, gate=gate))
"""
from iocflow.sources import GitHubAdvisorySource, Poller, SqliteSeenStore


def main():
    sources = [GitHubAdvisorySource(severities=["critical"])]
    store = SqliteSeenStore("advisories_seen.sqlite")
    poller = Poller(sources, store=store)

    print("Polling GitHub critical advisories...\n")
    results = poller.run_once()

    if not results:
        print("No new advisories since last run.")
        return

    for r in results:
        if not r.ok:
            print(f"  ! {r.trigger.title}: {r.error}")
            continue
        triage = r.output
        ents = triage.entities
        sev = triage.commentary.severity.value if triage.commentary else "n/a"
        print(f"  • {r.trigger.title}")
        print(f"    {r.trigger.url}")
        print(f"    extracted: {ents.summary()}")
        print(f"    assessment: [{sev}] {getattr(triage.commentary, 'summary', '')}")
        if triage.hunts and triage.hunts.hunts:
            print(f"    hunts: {len(triage.hunts.hunts)} ready-to-run queries")
        print()


if __name__ == "__main__":
    main()
