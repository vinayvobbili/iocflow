"""A :class:`Source` over GitHub's global Security Advisories.

Mirrors the shape of a critical-advisory poller: pull recently-published reviewed
advisories (optionally filtered by severity / ecosystem), and emit one trigger
each. The advisory's summary + description is the text the lifecycle extracts
from; CVE identifiers are seeded as indicators directly.
"""
from __future__ import annotations

import os
from typing import List, Optional, Sequence

from iocflow.sources.models import Trigger

_API = "https://api.github.com/advisories"


class GitHubAdvisorySource:
    """Polls https://api.github.com/advisories (no auth needed, but rate-limited).

    Args:
        severities: keep only these severities (e.g. ``("critical", "high")``);
            ``None`` keeps all.
        ecosystems: filter to these package ecosystems (``"pip"``, ``"npm"``…);
            ``None`` keeps all.
        per_page: page size (max 100).
        token: a GitHub token to raise the rate limit; falls back to
            ``GITHUB_TOKEN`` in the environment.
    """

    def __init__(
        self,
        *,
        severities: Optional[Sequence[str]] = ("critical",),
        ecosystems: Optional[Sequence[str]] = None,
        per_page: int = 50,
        token: Optional[str] = None,
        timeout: float = 20.0,
        session=None,
        name: str = "github-advisory",
    ) -> None:
        self.name = name
        self.severities = [s.lower() for s in severities] if severities else None
        self.ecosystems = list(ecosystems) if ecosystems else None
        self.per_page = min(per_page, 100)
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.timeout = timeout
        self._session = session

    def _client(self):
        if self._session is None:
            import requests  # lazy: only the live path needs it

            self._session = requests.Session()
        return self._session

    def _fetch(self) -> list:
        params = {"type": "reviewed", "per_page": self.per_page, "sort": "published"}
        if self.severities and len(self.severities) == 1:
            params["severity"] = self.severities[0]  # API takes a single severity
        if self.ecosystems and len(self.ecosystems) == 1:
            params["ecosystem"] = self.ecosystems[0]
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        resp = self._client().get(_API, params=params, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else []

    def poll(self) -> List[Trigger]:
        triggers: List[Trigger] = []
        for adv in self._fetch():
            severity = (adv.get("severity") or "").lower()
            if self.severities and severity not in self.severities:
                continue
            if self.ecosystems:
                ecos = {(v.get("package") or {}).get("ecosystem") for v in adv.get("vulnerabilities") or []}
                if not (ecos & set(self.ecosystems)):
                    continue
            ghsa = adv.get("ghsa_id") or adv.get("cve_id") or adv.get("url", "")
            summary = adv.get("summary") or ""
            description = adv.get("description") or ""
            cves = [adv["cve_id"]] if adv.get("cve_id") else []
            indicators = [("cve", c) for c in cves]
            triggers.append(Trigger(
                source=self.name,
                id=str(ghsa),
                text=f"{summary}\n\n{description}".strip(),
                indicators=indicators,
                title=summary,
                url=adv.get("html_url", ""),
                ts=adv.get("published_at", ""),
                meta={"severity": severity, "cve_id": adv.get("cve_id")},
            ))
        return triggers
