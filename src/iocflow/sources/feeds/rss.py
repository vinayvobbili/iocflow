"""A :class:`Source` over any RSS/Atom feed (vendor advisories, threat blogs).

Each feed entry becomes a trigger whose text is the title + summary, so the
lifecycle can pull IOCs straight out of the post. Uses ``feedparser`` (the
``iocflow[sources]`` extra), which also accepts a raw feed string — handy for
tests and offline use.
"""
from __future__ import annotations

import html
import re
from typing import List, Optional

from iocflow.sources.models import Trigger

_TAG = re.compile(r"<[^>]+>")


def _text(s: str) -> str:
    """Strip HTML tags and unescape entities from a feed field."""
    return html.unescape(_TAG.sub(" ", s or "")).strip()


class RssSource:
    """Polls an RSS/Atom feed URL (or a raw feed string) and emits a trigger per entry.

    Args:
        url: the feed URL, or a raw RSS/Atom document (feedparser accepts both).
        name: source name; defaults to the feed title or the URL host.
        limit: cap the number of entries returned per poll.
    """

    def __init__(self, url: str, *, name: Optional[str] = None, limit: int = 50) -> None:
        self.url = url
        self.name = name or "rss"
        self.limit = limit

    def poll(self) -> List[Trigger]:
        import feedparser  # lazy: part of the [sources] extra

        parsed = feedparser.parse(self.url)
        feed_title = (parsed.feed or {}).get("title") if hasattr(parsed, "feed") else None
        source_name = self.name if self.name != "rss" else (feed_title or "rss")

        triggers: List[Trigger] = []
        for entry in (parsed.entries or [])[: self.limit]:
            ident = entry.get("id") or entry.get("link") or entry.get("title", "")
            title = _text(entry.get("title", ""))
            summary = _text(entry.get("summary", "") or entry.get("description", ""))
            triggers.append(Trigger(
                source=source_name,
                id=str(ident),
                text=f"{title}\n\n{summary}".strip(),
                title=title,
                url=entry.get("link", ""),
                ts=entry.get("published", "") or entry.get("updated", ""),
            ))
        return triggers
