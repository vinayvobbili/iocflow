"""Tests for iocflow Layer 4 ATT&CK coverage-gap analysis (no network — models faked)."""
import json
import subprocess
import sys

from iocflow.hunt import (
    CoverageItem,
    CoverageReport,
    CoverageStatus,
    assess_coverage,
)
from iocflow.models import ExtractedEntities


# ------------------------------ fakes -----------------------------

class FakeModel:
    """A CommentaryModel that returns a canned string and records the prompt."""

    name = "fake:test"

    def __init__(self, response, *, raise_exc=None):
        self._response = response
        self._raise = raise_exc
        self.calls = []

    def complete(self, system, user, *, json=False):
        self.calls.append({"system": system, "user": user, "json": json})
        if self._raise:
            raise self._raise
        return self._response


CATALOG = [
    {"name": "Encoded PowerShell", "source": "crowdstrike", "techniques": ["T1059.001"]},
    {"name": "WMI Process Create", "source": "sigma", "techniques": ["T1047"]},
]


# --------------------------- deterministic ------------------------

def test_covered_and_gap_classification():
    report = assess_coverage(techniques=["T1059.001", "T1218.011"], catalog=CATALOG, model=None)
    by_tech = {i.technique: i for i in report.items}
    assert by_tech["T1059.001"].status is CoverageStatus.COVERED
    assert by_tech["T1059.001"].rules[0].name == "Encoded PowerShell"
    assert by_tech["T1218.011"].status is CoverageStatus.GAP
    assert by_tech["T1218.011"].rules == []


def test_summary_counts():
    report = assess_coverage(techniques=["T1059.001", "T1047", "T1218.011"],
                             catalog=CATALOG, model=None)
    assert report.summary() == "2/3 techniques covered, 1 gaps"
    assert len(report.covered) == 2
    assert len(report.gaps) == 1


def test_lenient_subtechnique_satisfied_by_parent_rule():
    catalog = [{"name": "Any PowerShell", "source": "sigma", "techniques": ["T1059"]}]
    report = assess_coverage(techniques=["T1059.001"], catalog=catalog, model=None)
    item = report.items[0]
    assert item.status is CoverageStatus.COVERED
    assert item.rules[0].name == "Any PowerShell"


def test_strict_requires_exact_match():
    catalog = [{"name": "Any PowerShell", "source": "sigma", "techniques": ["T1059"]}]
    report = assess_coverage(techniques=["T1059.001"], catalog=catalog, strict=True, model=None)
    assert report.items[0].status is CoverageStatus.GAP


def test_empty_catalog_all_gaps():
    report = assess_coverage(techniques=["T1059.001", "T1047"], catalog=[], model=None)
    assert all(i.status is CoverageStatus.GAP for i in report.items)
    assert len(report.gaps) == 2


def test_techniques_from_entities():
    entities = ExtractedEntities(mitre_techniques=["T1059.001", "T1047"])
    report = assess_coverage(entities, CATALOG, model=None)
    assert {i.technique for i in report.items} == {"T1059.001", "T1047"}
    assert all(i.status is CoverageStatus.COVERED for i in report.items)


def test_explicit_techniques_override_entities():
    entities = ExtractedEntities(mitre_techniques=["T1047"])
    report = assess_coverage(entities, CATALOG, techniques=["T1218.011"], model=None)
    assert [i.technique for i in report.items] == ["T1218.011"]


def test_normalizes_and_dedups_techniques():
    report = assess_coverage(techniques=["t1059.001", "T1059.001", "not-a-tech", ""],
                             catalog=CATALOG, model=None)
    assert [i.technique for i in report.items] == ["T1059.001"]


def test_no_techniques_is_valid_empty_report():
    report = assess_coverage(techniques=[], catalog=CATALOG, model=None)
    assert report.items == []
    assert report.summary() == "No techniques to assess"


def test_catalog_accepts_platform_and_mitre_techniques_aliases():
    catalog = [{"title": "Alt keys", "platform": "cortex", "mitre_techniques": ["T1047"]}]
    report = assess_coverage(techniques=["T1047"], catalog=catalog, model=None)
    rule = report.items[0].rules[0]
    assert rule.name == "Alt keys"
    assert rule.source == "cortex"


def test_never_raises_on_garbage_catalog():
    # Non-dict rows and missing fields must not crash classification.
    catalog = ["not a dict", {"name": "no techniques"}, {"techniques": None}]
    report = assess_coverage(techniques=["T1047"], catalog=catalog, model=None)
    assert report.items[0].status is CoverageStatus.GAP


# --------------------------- LLM pass -----------------------------

def test_llm_downgrades_covered_to_partial():
    payload = json.dumps({"techniques": [
        {"technique": "T1059.001", "partial": True, "rationale": "rule only catches -enc flag"},
    ]})
    model = FakeModel(payload)
    report = assess_coverage(techniques=["T1059.001", "T1047"], catalog=CATALOG, model=model)
    by_tech = {i.technique: i for i in report.items}
    assert by_tech["T1059.001"].status is CoverageStatus.PARTIAL
    assert "rule only catches" in by_tech["T1059.001"].rationale
    assert by_tech["T1047"].status is CoverageStatus.COVERED  # not in downgrade list
    assert report.error is None
    assert model.calls[0]["json"] is True
    # a partial still counts toward the covered ratio; it's surfaced separately
    assert report.summary() == "2/2 techniques covered, 1 partial, 0 gaps"


def test_llm_never_downgrades_a_gap():
    payload = json.dumps({"techniques": [{"technique": "T1218.011", "partial": True}]})
    report = assess_coverage(techniques=["T1218.011"], catalog=CATALOG, model=FakeModel(payload))
    # T1218.011 has no rule -> stays a GAP even if the model names it
    assert report.items[0].status is CoverageStatus.GAP


def test_llm_error_leaves_deterministic_verdicts():
    model = FakeModel("x", raise_exc=RuntimeError("timeout"))
    report = assess_coverage(techniques=["T1059.001"], catalog=CATALOG, model=model)
    assert report.items[0].status is CoverageStatus.COVERED
    assert report.error and "model error" in report.error


def test_llm_unparseable_output_is_non_fatal():
    report = assess_coverage(techniques=["T1059.001"], catalog=CATALOG,
                             model=FakeModel("not json at all"))
    assert report.items[0].status is CoverageStatus.COVERED
    assert report.error and "unparseable" in report.error


def test_llm_strips_code_fences():
    payload = "```json\n" + json.dumps({"techniques": [
        {"technique": "T1059.001", "partial": True, "rationale": "x"}]}) + "\n```"
    report = assess_coverage(techniques=["T1059.001"], catalog=CATALOG, model=FakeModel(payload))
    assert report.items[0].status is CoverageStatus.PARTIAL


def test_llm_not_called_when_no_coverage():
    # All gaps -> nothing to refine -> model must not be consulted.
    model = FakeModel("{}")
    assess_coverage(techniques=["T1218.011"], catalog=[], model=model)
    assert model.calls == []


# ----------------------- serialization ----------------------------

def test_report_to_dict():
    report = assess_coverage(techniques=["T1059.001", "T1218.011"], catalog=CATALOG, model=None)
    d = report.to_dict()
    assert d["total"] == 2
    assert d["covered"] == 1
    assert d["gaps"] == 1
    assert d["summary"] == report.summary()
    item = next(i for i in d["items"] if i["technique"] == "T1059.001")
    assert item["status"] == "covered"
    assert item["rules"][0]["name"] == "Encoded PowerShell"


def test_item_and_report_types():
    report = assess_coverage(techniques=["T1047"], catalog=CATALOG, model=None)
    assert isinstance(report, CoverageReport)
    assert isinstance(report.items[0], CoverageItem)


# ------------------------------ CLI -------------------------------

def test_cli_coverage(tmp_path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(CATALOG))
    out = subprocess.run(
        [sys.executable, "-m", "iocflow", "coverage",
         "Adversary used T1059.001 and T1218.011", "-c", str(catalog), "--json"],
        capture_output=True, text=True,
    )
    assert out.returncode == 0
    data = json.loads(out.stdout)
    by_tech = {i["technique"]: i for i in data["items"]}
    assert by_tech["T1059.001"]["status"] == "covered"
    assert by_tech["T1218.011"]["status"] == "gap"


def test_cli_coverage_requires_catalog():
    out = subprocess.run(
        [sys.executable, "-m", "iocflow", "coverage", "T1059"],
        capture_output=True, text=True,
    )
    assert out.returncode != 0  # argparse: --catalog is required
