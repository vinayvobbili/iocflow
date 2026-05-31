"""The dialect registry: resolve dialect keys to renderers."""
from __future__ import annotations

from typing import List

from iocflow.hunt.dialects import CortexDialect, CrowdStrikeDialect, SigmaDialect
from iocflow.hunt.protocol import Dialect

# Default render order, also the set built when ``dialects`` is not specified.
DEFAULT_DIALECTS = ("crowdstrike", "cortex", "sigma")

_REGISTRY = {d.key: d for d in (CrowdStrikeDialect(), CortexDialect(), SigmaDialect())}


def get_dialect(key: str) -> Dialect:
    """Resolve a dialect by key, or raise ``ValueError`` for an unknown one."""
    try:
        return _REGISTRY[key]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY))
        raise ValueError(f"unknown dialect {key!r}; known dialects: {known}") from None


def all_dialects() -> List[Dialect]:
    """Every registered dialect, in default order."""
    return [_REGISTRY[k] for k in DEFAULT_DIALECTS]
