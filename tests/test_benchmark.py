"""Regression guard on extraction accuracy.

Runs the labeled benchmark corpus and asserts the headline precision/recall stay
above a floor. Thresholds sit comfortably below the current scores (overall
precision ~0.98, recall 1.0) so this catches a real regression without being a
brittle pin on the exact numbers. Run ``python -m benchmarks`` to see the full
scorecard.
"""
from benchmarks import SCORED_KINDS, evaluate


def test_overall_accuracy_above_floor():
    overall = evaluate()["overall"]
    assert overall["precision"] >= 0.90, overall
    assert overall["recall"] >= 0.95, overall
    assert overall["f1"] >= 0.92, overall


def test_per_kind_accuracy_above_floor():
    per_kind = evaluate()["per_kind"]
    for kind in SCORED_KINDS:
        row = per_kind[kind]
        # A kind with no labeled examples scores a vacuous 1.0; only assert on
        # kinds the corpus actually exercises.
        if row["tp"] + row["fn"] == 0:
            continue
        assert row["precision"] >= 0.80, (kind, row)
        assert row["recall"] >= 0.80, (kind, row)


def test_corpus_is_nontrivial():
    metrics = evaluate()
    overall = metrics["overall"]
    # Guard the guard: ensure the corpus actually has indicators to find, so the
    # thresholds above can't pass vacuously.
    assert metrics["samples"] >= 10
    assert overall["tp"] >= 30
