"""The optional LLM behavioral-hunt path.

Additive and never fatal: if a model is configured it proposes behavioral hunts
on top of the deterministic IOC-sweep queries; any failure (no model, bad
output, transport error) returns no LLM hunts and an explanatory error string,
leaving the deterministic plan intact.

Two robustness layers sit between the model and the returned hunts:

- **Tolerant JSON extraction.** Models wrap output in code fences, add prose, or
  emit several top-level objects instead of one array. :func:`_extract_json`
  scans with ``raw_decode`` to recover the payload in all of those cases.
- **Validate → repair.** Each authored hunt is checked against its dialect
  (:meth:`validate_behavioral`); a broken query is fed back to the model with the
  failure reason for one repair pass. A hunt that still doesn't validate is kept
  with ``validated=False`` and the reason (a suggestion to review, not dropped).
"""
from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any, List, Optional, Tuple

from iocflow.hunt.models import Hunt
from iocflow.hunt.prompt import build_repair_prompt, build_user_prompt, system_prompt
from iocflow.severity import Severity

if TYPE_CHECKING:  # pragma: no cover - typing only
    from iocflow.ai.models import Commentary
    from iocflow.ai.protocol import CommentaryModel
    from iocflow.enrich.models import EnrichmentReport
    from iocflow.hunt.protocol import Dialect
    from iocflow.models import ExtractedEntities

logger = logging.getLogger(__name__)

_MAX_LLM_HUNTS = 8
# Total validation attempts per hunt (1 initial + LLM repairs). On an invalid
# query we feed the reason back to the model and re-validate; after this many
# attempts the hunt is surfaced as-is with ``validated=False``.
_MAX_REPAIR_ATTEMPTS = 2


def llm_hunts(
    report: "Optional[EnrichmentReport]",
    entities: "Optional[ExtractedEntities]",
    commentary: "Optional[Commentary]",
    dialects: list,
    model: "CommentaryModel",
) -> Tuple[List[Hunt], Optional[str]]:
    """Ask the model for behavioral hunts, then validate/repair. Returns ``(hunts, error)``."""
    by_key = {d.key: d for d in dialects}
    system = system_prompt(dialects)
    user = build_user_prompt(report, entities, commentary)
    try:
        raw = model.complete(system, user, json=True)
    except Exception as exc:  # noqa: BLE001 — additive path must never be fatal
        logger.warning("Hunt model failed (%s); skipping behavioral hunts", exc)
        return [], f"behavioral hunts skipped: model error: {type(exc).__name__}: {exc}"

    try:
        hunts = _parse(raw, set(by_key))
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return [], f"behavioral hunts skipped: unparseable model output: {exc}"

    for hunt in hunts:
        _validate_and_repair(hunt, by_key.get(hunt.dialect), model)
    return hunts, None


_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_json(raw: str) -> Any:
    """Recover the JSON payload from a model response. Returns the value or ``None``.

    Tolerant of the common failure modes: code fences, leading/trailing prose,
    and a valid value followed by extra data — plain ``json.loads`` raises
    "Extra data" on the last, so we fall back to ``raw_decode`` scanning from the
    first ``[``/``{`` and collect every consecutive top-level value (a model that
    emits several objects back-to-back instead of one array), flattening arrays.

    Deliberately does NOT slice first-``{`` to last-``}`` — that drops the
    brackets of a JSON *array* and would collapse a list of hunts to one object.
    """
    text = (raw or "").strip()
    if not text:
        return None
    m = _FENCE.search(text)
    if m:
        text = m.group(1).strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    start = min((i for i in (text.find("["), text.find("{")) if i != -1), default=-1)
    if start == -1:
        return None
    decoder = json.JSONDecoder()
    values: List[Any] = []
    idx, n = start, len(text)
    while idx < n:
        while idx < n and text[idx] in " \t\r\n,":
            idx += 1
        if idx >= n:
            break
        try:
            value, end = decoder.raw_decode(text, idx)
        except Exception:
            break
        values.append(value)
        idx = end
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    flat: List[Any] = []
    for v in values:
        flat.extend(v if isinstance(v, list) else [v])
    return flat


def _hunt_items(data: Any) -> List[dict]:
    """Normalize a parsed payload to a list of hunt dicts.

    Accepts ``{"hunts": [...]}``, a bare ``[...]`` array, or a single hunt object.
    """
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        items = data.get("hunts")
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
        if any(k in data for k in ("query", "title", "dialect")):
            return [data]
    return []


def _parse(raw: str, allowed: set) -> List[Hunt]:
    data = _extract_json(raw)
    if data is None:
        raise ValueError("no JSON value in response")
    items = _hunt_items(data)

    hunts: List[Hunt] = []
    for item in items[:_MAX_LLM_HUNTS]:
        dialect = str(item.get("dialect", "")).strip().lower()
        query = str(item.get("query", "")).strip()
        title = str(item.get("title", "")).strip()
        if dialect not in allowed or not query or not title:
            continue
        hunts.append(
            Hunt(
                title=title,
                dialect=dialect,
                query=query,
                rationale=str(item.get("rationale", "")).strip(),
                severity=Severity.coerce(item.get("severity"), Severity.MEDIUM),
                source="llm",
            )
        )
    return hunts


def _validate_and_repair(hunt: Hunt, dialect: "Optional[Dialect]", model: "CommentaryModel") -> None:
    """Validate one behavioral hunt against its dialect; repair via the model if broken.

    Mutates ``hunt`` in place: a repaired query replaces ``hunt.query``; an
    unrepairable hunt gets ``validated=False`` and ``validation_error``. No-ops
    when the dialect has no ``validate_behavioral`` (nothing to check against).
    """
    if dialect is None:
        return
    validate = getattr(dialect, "validate_behavioral", None)
    if validate is None:
        return

    for attempt in range(1, _MAX_REPAIR_ATTEMPTS + 1):
        ok, reason = validate(hunt.query)
        if ok:
            hunt.validated = True
            hunt.validation_error = ""
            return
        hunt.validated = False
        hunt.validation_error = reason
        if attempt >= _MAX_REPAIR_ATTEMPTS:
            break
        fixed = _repair(hunt, dialect, reason, model)
        if not fixed:
            break
        logger.info("Repaired %s hunt %r after: %s", hunt.dialect, hunt.title, reason)
        hunt.query = fixed


def _repair(hunt: Hunt, dialect: "Dialect", error: str, model: "CommentaryModel") -> Optional[str]:
    """Ask the model to fix a failing query. Returns the new query or ``None``."""
    system, user = build_repair_prompt(dialect, hunt.title, hunt.query, error)
    try:
        raw = model.complete(system, user, json=True)
    except Exception as exc:  # noqa: BLE001 — repair must never be fatal
        logger.warning("Hunt repair failed for %r (%s)", hunt.title, exc)
        return None
    data = _extract_json(raw)
    if isinstance(data, dict):
        new_query = str(data.get("query", "")).strip()
        return new_query or None
    return None
