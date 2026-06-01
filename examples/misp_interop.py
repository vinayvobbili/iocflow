"""MISP interop, offline — enrich against, ingest from, and share back to MISP.

Runs with no MISP instance and no network: every REST call is served by a small
in-memory fake so you can see the shapes. Swap ``session=_FAKE`` for real
``url=`` / ``api_key=`` (or set ``IOCFLOW_MISP_URL`` + ``IOCFLOW_MISP_KEY``) to
point at a live instance.

    pip install "iocflow[misp,enrich]"
    python examples/misp_interop.py
"""
from iocflow import extract
from iocflow.enrich import enrich
from iocflow.misp import MISPEnricher, MISPEventSource, MISPPublisher


# --- a fake MISP REST session (stands in for a live instance) ---------------
class _FakeResp:
    def __init__(self, p):
        self._p = p

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


class _FakeMisp:
    """Answers /attributes/restSearch, /events/restSearch, /events/add."""

    def post(self, url, json, headers, verify, timeout):
        if url.endswith("/attributes/restSearch"):
            hit = json["value"] == "185.220.101.5"
            attrs = ([{"value": "185.220.101.5", "type": "ip-dst", "to_ids": "1",
                       "category": "Network activity",
                       "Event": {"id": "42", "info": "Known C2 infrastructure"}}]
                     if hit else [])
            return _FakeResp({"response": {"Attribute": attrs}})
        if url.endswith("/events/restSearch"):
            return _FakeResp({"response": [{"Event": {
                "id": "7", "uuid": "ev-7", "info": "Emotet campaign",
                "date": "2026-05-31", "Tag": [{"name": "malware:emotet"}],
                "Attribute": [{"type": "domain|ip", "value": "evil.test|9.9.9.9"}],
            }}]})
        if url.endswith("/events/add"):
            return _FakeResp({"Event": {"id": "100", "uuid": "shared-100"}})
        return _FakeResp({})

    def get(self, *a, **k):
        return _FakeResp({})


FAKE = _FakeMisp()
URL, KEY = "https://misp.example.org", "demo-key"


def main() -> None:
    # 1) Enrich extracted indicators against MISP --------------------------
    entities = extract("Traffic to 185.220.101.5 and benign 8.8.8.8 was observed.")
    report = enrich(entities, [MISPEnricher(URL, KEY, session=FAKE)])
    print("== enrich ==")
    for ind in entities.iter_indicators():
        v = report.verdict_for(ind.kind, ind.value)
        print(f"  {ind.kind:7} {ind.value:16} -> {v.value}")

    # 2) Ingest a MISP event as a trigger ---------------------------------
    print("\n== source ==")
    for trig in MISPEventSource(URL, KEY, session=FAKE).poll():
        print(f"  {trig.title!r}  indicators={trig.indicators}")

    # 3) Share the triage back to MISP (dry-run: builds, does not POST) ----
    print("\n== publish (dry-run) ==")
    out = MISPPublisher(URL, KEY, session=FAKE).publish(report, info="iocflow demo share")
    ev = out["event"]["Event"]
    print(f"  ok={out['ok']} dry_run={out['dry_run']} attributes={len(ev['Attribute'])}")
    for a in ev["Attribute"]:
        print(f"    {a['type']:8} {a['value']:16} to_ids={a['to_ids']}")


if __name__ == "__main__":
    main()
