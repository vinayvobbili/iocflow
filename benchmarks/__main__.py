"""Print the extraction accuracy scorecard: ``python -m benchmarks``."""
from benchmarks.accuracy import evaluate, format_report

if __name__ == "__main__":
    print(format_report(evaluate()))
