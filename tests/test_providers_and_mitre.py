"""Tests for the pluggable providers and the MITRE extra (no network)."""
from iocflow.mitre import _extract_malware
from iocflow.providers import ActorAliases, MalwareNames


def test_malware_names_from_entries():
    mn = MalwareNames.from_entries(
        [{"name": "Emotet", "aliases": ["Emotet", "Geodo"]}]
    )
    assert "Geodo" in mn.names
    assert mn.alias_map["geodo"] == "Emotet"


def test_malware_names_from_entries_defaults_alias_to_name():
    mn = MalwareNames.from_entries([{"name": "Solo"}])
    assert "Solo" in mn.names
    assert mn.alias_map["solo"] == "Solo"


def test_malware_names_from_names():
    mn = MalwareNames.from_names(["Qakbot"])
    assert mn.alias_map["qakbot"] == "Qakbot"


def test_actor_aliases_lookup_and_known_names():
    aa = ActorAliases.from_index(
        {"apt28": {"common_name": "APT28", "region": "Russia",
                   "all_names": ["Fancy Bear", "Sofacy"]}}
    )
    assert aa.lookup("APT28")["region"] == "Russia"
    # aliases from all_names become matchable known names
    assert "Fancy Bear" in aa.known_names
    assert aa.lookup("fancy bear")["common_name"] == "APT28"


def test_mitre_extract_malware_from_stix_bundle_shape():
    bundle = {
        "objects": [
            {
                "type": "malware",
                "name": "Emotet",
                "x_mitre_aliases": ["Emotet", "Geodo"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "S0367"}
                ],
            },
            {  # deprecated — must be skipped
                "type": "tool",
                "name": "OldTool",
                "x_mitre_deprecated": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "S9999"}
                ],
            },
            {  # not a malware/tool — skipped
                "type": "attack-pattern",
                "name": "Phishing",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1566"}
                ],
            },
        ]
    }
    entries = _extract_malware(bundle)
    assert len(entries) == 1
    assert entries[0]["name"] == "Emotet"
    assert entries[0]["aliases"] == ["Emotet", "Geodo"]


def test_mitre_names_feed_extractor():
    bundle = {
        "objects": [
            {
                "type": "malware",
                "name": "Emotet",
                "x_mitre_aliases": ["Emotet", "Geodo"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "S0367"}
                ],
            }
        ]
    }
    mn = MalwareNames.from_entries(_extract_malware(bundle))
    from iocflow import extract_malware_families

    assert extract_malware_families("infected by Geodo", mn) == ["Emotet"]
