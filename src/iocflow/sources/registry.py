"""Build sources from the environment, like ``default_enrichers``/``default_blockers``.

Reads:
  * ``IOCFLOW_GITHUB_ADVISORIES`` — truthy enables ``GitHubAdvisorySource``;
    ``IOCFLOW_GITHUB_ADVISORY_SEVERITIES`` (comma list) sets the filter.
  * ``IOCFLOW_RSS_FEEDS`` — comma-separated feed URLs → one ``RssSource`` each.
  * ``IOCFLOW_FILE_SOURCE_DIR`` — a directory → ``FileSource``.

Anything not configured is simply omitted (no error), so a deployment turns
sources on by setting env, exactly like the enrichers and blockers.
"""
from __future__ import annotations

import os
from typing import List, Optional

from iocflow.sources.protocol import Source


def _truthy(v: str) -> bool:
    return v.strip().lower() in ("1", "true", "yes", "on")


def default_sources(env: Optional[dict] = None) -> List[Source]:
    env = os.environ if env is None else env
    sources: List[Source] = []

    if _truthy(env.get("IOCFLOW_GITHUB_ADVISORIES", "")):
        from iocflow.sources.feeds.github_advisory import GitHubAdvisorySource

        sevs = env.get("IOCFLOW_GITHUB_ADVISORY_SEVERITIES", "critical")
        severities = [s.strip() for s in sevs.split(",") if s.strip()] or None
        sources.append(GitHubAdvisorySource(severities=severities))

    feeds = env.get("IOCFLOW_RSS_FEEDS", "")
    if feeds.strip():
        from iocflow.sources.feeds.rss import RssSource

        for url in (u.strip() for u in feeds.split(",")):
            if url:
                sources.append(RssSource(url))

    file_dir = env.get("IOCFLOW_FILE_SOURCE_DIR", "")
    if file_dir.strip():
        from iocflow.sources.feeds.file import FileSource

        sources.append(FileSource(file_dir.strip()))

    # MISP event source (its own [misp] extra): enabled by IOCFLOW_MISP_SOURCE
    # when an instance URL + key are configured.
    misp_url = env.get("IOCFLOW_MISP_URL")
    misp_key = env.get("IOCFLOW_MISP_KEY") or env.get("IOCFLOW_MISP_API_KEY")
    if _truthy(env.get("IOCFLOW_MISP_SOURCE", "")) and misp_url and misp_key:
        try:
            from iocflow.misp import MISPEventSource

            tag_csv = env.get("IOCFLOW_MISP_TAGS", "")
            tags = [t.strip() for t in tag_csv.split(",") if t.strip()] or None
            sources.append(MISPEventSource(misp_url, misp_key, tags=tags))
        except ImportError:  # pragma: no cover - extra not installed
            pass

    return sources
