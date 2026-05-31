"""iocflow Layer 3 — AI commentary.

Turn an enrichment report into an analyst-style assessment.

    from iocflow import extract
    from iocflow.enrich import enrich
    from iocflow.ai import comment

    entities = extract(report_text)
    report = enrich(entities)
    note = comment(report, entities=entities, text=report_text)

    print(note.severity.value, "—", note.summary)
    for f in note.key_findings:
        print(" •", f)

The model comes from the environment by default (``IOCFLOW_LLM_API_KEY``,
``IOCFLOW_LLM_BASE_URL``, ``IOCFLOW_LLM_MODEL`` — any OpenAI-compatible
endpoint), or pass one explicitly:

    from iocflow.ai import comment, OpenAIChatModel
    note = comment(report, model=OpenAIChatModel(api_key="...", model="gpt-4o-mini"))

``comment`` never raises: with no model configured (or on a model error) it
returns a deterministic assessment built straight from the report.

Needs the extra: ``pip install "iocflow[ai]"``.
"""
from iocflow.ai.commentary import comment, default_model
from iocflow.ai.models import Commentary, Severity
from iocflow.ai.openai_compat import OpenAIChatModel
from iocflow.ai.protocol import CommentaryModel

__all__ = [
    "comment",
    "default_model",
    "Commentary",
    "Severity",
    "CommentaryModel",
    "OpenAIChatModel",
]
