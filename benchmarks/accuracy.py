"""Precision/recall evaluation of ``iocflow.extract`` against the labeled corpus.

For every sample we compare the extractor's output, kind by kind, to the
ground-truth labels and tally true positives / false positives / false
negatives. Metrics are reported per kind and aggregated (micro-averaged over all
indicators). ``python -m benchmarks`` prints the scorecard.
"""
from typing import Dict, List, Set, Tuple

from benchmarks.corpus import CORPUS, Sample
from iocflow import extract

# The kinds scored by the benchmark. These are the ones a bare ``extract()``
# (no alias/malware providers) produces deterministically; ``hashes`` folds the
# three digest buckets into one set.
SCORED_KINDS: Tuple[str, ...] = (
    "ips", "domains", "urls", "emails", "filenames",
    "hashes", "cves", "mitre_techniques", "threat_actors",
)


def _predicted(text: str) -> Dict[str, Set[str]]:
    """Run extraction and flatten the result to ``{kind: set(values)}``."""
    d = extract(text).to_dict()
    pred: Dict[str, Set[str]] = {}
    for kind in SCORED_KINDS:
        if kind == "hashes":
            h = d["hashes"]
            pred[kind] = set(h["md5"]) | set(h["sha1"]) | set(h["sha256"])
        else:
            pred[kind] = set(d.get(kind, []))
    return pred


class Counts:
    """Mutable TP/FP/FN tally with derived precision/recall/F1."""

    __slots__ = ("tp", "fp", "fn")

    def __init__(self) -> None:
        self.tp = self.fp = self.fn = 0

    def add(self, expected: Set[str], predicted: Set[str]) -> None:
        self.tp += len(expected & predicted)
        self.fp += len(predicted - expected)
        self.fn += len(expected - predicted)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 1.0


def evaluate(corpus: List[Sample] = CORPUS) -> Dict[str, object]:
    """Score ``corpus`` and return a metrics dict.

    Returns ``{"per_kind": {kind: {...}}, "overall": {...}, "mismatches": [...]}``.
    ``mismatches`` lists every false positive / false negative for inspection.
    """
    per_kind = {k: Counts() for k in SCORED_KINDS}
    overall = Counts()
    mismatches: List[Dict[str, object]] = []

    for sample in corpus:
        pred = _predicted(sample.text)
        for kind in SCORED_KINDS:
            expected = sample.expected.get(kind, set())
            got = pred[kind]
            per_kind[kind].add(expected, got)
            overall.add(expected, got)
            fp, fn = got - expected, expected - got
            if fp or fn:
                mismatches.append(
                    {"sample": sample.name, "kind": kind,
                     "false_positives": sorted(fp), "false_negatives": sorted(fn)}
                )

    def _row(c: Counts) -> Dict[str, float]:
        return {"precision": c.precision, "recall": c.recall, "f1": c.f1,
                "tp": c.tp, "fp": c.fp, "fn": c.fn}

    return {
        "per_kind": {k: _row(c) for k, c in per_kind.items()},
        "overall": _row(overall),
        "mismatches": mismatches,
        "samples": len(corpus),
    }


def format_report(metrics: Dict[str, object]) -> str:
    """Render a metrics dict as a plain-text scorecard."""
    lines = [
        f"iocflow extraction accuracy  ({metrics['samples']} samples)",
        "",
        f"  {'kind':<16} {'precision':>9} {'recall':>9} {'f1':>7}   tp/fp/fn",
        f"  {'-' * 16} {'-' * 9} {'-' * 9} {'-' * 7}   --------",
    ]
    per_kind = metrics["per_kind"]  # type: ignore[index]
    for kind in SCORED_KINDS:
        r = per_kind[kind]
        lines.append(
            f"  {kind:<16} {r['precision']:>9.3f} {r['recall']:>9.3f} {r['f1']:>7.3f}"
            f"   {r['tp']}/{r['fp']}/{r['fn']}"
        )
    o = metrics["overall"]  # type: ignore[index]
    lines += [
        f"  {'-' * 16} {'-' * 9} {'-' * 9} {'-' * 7}   --------",
        f"  {'OVERALL':<16} {o['precision']:>9.3f} {o['recall']:>9.3f} {o['f1']:>7.3f}"
        f"   {o['tp']}/{o['fp']}/{o['fn']}",
    ]
    mismatches = metrics["mismatches"]  # type: ignore[index]
    if mismatches:
        lines += ["", "  mismatches:"]
        for m in mismatches:
            bits = []
            if m["false_positives"]:
                bits.append(f"+{m['false_positives']}")
            if m["false_negatives"]:
                bits.append(f"-{m['false_negatives']}")
            lines.append(f"    {m['sample']}/{m['kind']}: {' '.join(bits)}")
    return "\n".join(lines)
