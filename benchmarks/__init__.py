"""Accuracy benchmark for iocflow Layer 1 extraction.

A small hand-labeled corpus of threat-report snippets plus a precision/recall
evaluator. Run ``python -m benchmarks`` for a scorecard; ``tests/test_benchmark.py``
asserts the headline metrics stay above a floor so accuracy can't silently
regress.
"""
from benchmarks.accuracy import SCORED_KINDS, evaluate, format_report
from benchmarks.corpus import CORPUS

__all__ = ["CORPUS", "SCORED_KINDS", "evaluate", "format_report"]
