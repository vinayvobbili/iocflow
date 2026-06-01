"""``TaxiiSource`` — a TAXII 2.1 collection as an ingestion :class:`Source`.

Polls a collection's objects endpoint, turns each STIX object into a
:class:`~iocflow.sources.models.Trigger` (with its indicators parsed via
:func:`~iocflow.stix.parse.from_stix`), and hands it to a ``Poller``. De-dup is
the poller's job, keyed on the STIX object id.
"""
from __future__ import annotations

from typing import List, Optional

from iocflow.sources.models import Trigger
from iocflow.stix.parse import from_stix

_ACCEPT = "application/taxii+json;version=2.1"


class TaxiiSource:
    """Polls one TAXII 2.1 collection.

    Args:
        api_root: the API root URL, e.g. ``https://taxii.example.com/api1``.
        collection_id: the collection UUID.
        username/password: HTTP basic auth, or
        token: a bearer token (takes precedence over basic auth).
        added_after: only fetch objects added after this ISO8601 timestamp.
        limit: page size hint sent to the server.
    """

    def __init__(
        self,
        api_root: str,
        collection_id: str,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        added_after: Optional[str] = None,
        limit: int = 100,
        timeout: float = 30.0,
        session=None,
        name: str = "taxii",
    ) -> None:
        self.api_root = api_root.rstrip("/")
        self.collection_id = collection_id
        self.username = username
        self.password = password
        self.token = token
        self.added_after = added_after
        self.limit = limit
        self.timeout = timeout
        self._session = session
        self.name = name

    def _client(self):
        if self._session is None:
            import requests  # lazy: only the live path needs it

            self._session = requests.Session()
        return self._session

    def _fetch(self) -> list:
        url = f"{self.api_root}/collections/{self.collection_id}/objects/"
        headers = {"Accept": _ACCEPT}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        params: dict = {"limit": self.limit}
        if self.added_after:
            params["added_after"] = self.added_after
        auth = (self.username, self.password) if (self.username and not self.token) else None
        resp = self._client().get(url, headers=headers, params=params,
                                  auth=auth, timeout=self.timeout)
        resp.raise_for_status()
        envelope = resp.json()
        return envelope.get("objects", []) if isinstance(envelope, dict) else []

    def poll(self) -> List[Trigger]:
        triggers: List[Trigger] = []
        for obj in self._fetch():
            if not isinstance(obj, dict) or not obj.get("id"):
                continue
            ents = from_stix(obj)
            indicators = [(i.kind, i.value) for i in ents.iter_indicators()]
            text = obj.get("description", "") or obj.get("pattern", "") or ""
            triggers.append(Trigger(
                source=self.name,
                id=str(obj["id"]),
                text=text,
                indicators=indicators,
                stix=obj,
                title=obj.get("name", "") or obj.get("type", ""),
                ts=obj.get("modified", "") or obj.get("created", ""),
                meta={"stix_type": obj.get("type", "")},
            ))
        return triggers
