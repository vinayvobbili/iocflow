#!/usr/bin/env python3
"""STIX 2.1 interop: parse a bundle in, emit a verdict-aware bundle out.

    pip install "iocflow[stix]"
    python examples/stix_interop.py

A TAXII 2.1 collection is also an ingestion source (needs a live server):

    from iocflow.stix import TaxiiSource
    from iocflow.sources import Poller, SqliteSeenStore
    poller = Poller([TaxiiSource(api_root, collection_id, token="…")],
                    store=SqliteSeenStore("taxii.sqlite"))
    for r in poller.run_once():
        print(r.output.summary())
"""
import json

from iocflow.stix import from_stix, to_stix

INCOMING = {
    "type": "bundle",
    "id": "bundle--11111111-1111-1111-1111-111111111111",
    "objects": [
        {"type": "indicator", "spec_version": "2.1", "pattern_type": "stix",
         "pattern": "[ipv4-addr:value = '185.220.101.5']"},
        {"type": "domain-name", "value": "evil-domain.ru"},
        {"type": "vulnerability", "name": "Log4Shell",
         "external_references": [{"source_name": "cve", "external_id": "CVE-2021-44228"}]},
    ],
}


def main():
    print("== STIX in ==")
    entities = from_stix(INCOMING)
    print(" ", entities.summary())

    print("\n== STIX out (deterministic ids) ==")
    bundle = to_stix(entities)
    for obj in bundle["objects"]:
        label = obj.get("pattern") or obj.get("name")
        print(f"  {obj['type']:<14} {label}")

    print("\n== round-trips cleanly ==")
    again = from_stix(bundle)
    print("  ips match:", set(again.ips) == set(entities.ips))
    print("  cves match:", set(again.cves) == set(entities.cves))
    json.dumps(bundle)  # fully serializable


if __name__ == "__main__":
    main()
