"""iocflow ingestion — feed the lifecycle automatically.

The other layers answer "what do I do with this report?". This one answers
"where do reports come from?". A :class:`Source` polls a feed (GitHub Security
Advisories, an RSS/Atom feed, a watched directory) and yields :class:`Trigger`
work items; a :class:`Poller` de-duplicates them against a :class:`SeenStore`
and runs a handler — by default the deterministic L1–L4 lifecycle.

    from iocflow.sources import Poller, SqliteSeenStore, GitHubAdvisorySource

    poller = Poller(
        [GitHubAdvisorySource(severities=["critical"])],
        store=SqliteSeenStore("advisories.sqlite"),   # survives restarts
    )
    for result in poller.run_once():                  # call from cron/systemd
        print(result.output.summary())

Scheduling stays yours (cron / a systemd timer), as with any real advisory
poller — the library only provides ``run_once`` and a simple ``run_forever``.

Blocking is never automatic here: the default handler proposes nothing
destructive. To close the loop with the full multi-agent path and a human gate,
pass ``handler=lambda t: investigate(t.text, gate=SlackApprovalGate(...))``
(needs ``iocflow[agent]``).

Needs the extra: ``pip install "iocflow[sources]"``.
"""
from iocflow.sources.feeds import FileSource, GitHubAdvisorySource, RssSource
from iocflow.sources.models import PollResult, Trigger, TriageResult
from iocflow.sources.poller import Poller, default_handler
from iocflow.sources.protocol import SeenStore, Source
from iocflow.sources.registry import default_sources
from iocflow.sources.store import MemorySeenStore, SqliteSeenStore

__all__ = [
    # Orchestration
    "Poller",
    "default_handler",
    "default_sources",
    # Result/work types
    "Trigger",
    "TriageResult",
    "PollResult",
    # Protocols
    "Source",
    "SeenStore",
    # Stores
    "MemorySeenStore",
    "SqliteSeenStore",
    # Reference sources
    "GitHubAdvisorySource",
    "RssSource",
    "FileSource",
]
