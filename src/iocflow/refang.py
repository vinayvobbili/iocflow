"""Re-fang defanged indicators so they can be extracted."""
from __future__ import annotations

import re


def refang_text(text: str) -> str:
    """Convert defanged IOCs back to normal form for extraction.

    Handles the common defanging conventions used in threat-intel reports:

    - ``[.]`` or ``[dot]``  -> ``.``
    - ``[@]`` or ``[at]``   -> ``@``
    - ``hxxp``              -> ``http``
    - ``[://]``             -> ``://``
    """
    result = text
    # Domain / IP defanging
    result = re.sub(r"\[\.\]", ".", result)
    result = re.sub(r"\[dot\]", ".", result, flags=re.IGNORECASE)
    # Email defanging
    result = re.sub(r"\[@\]", "@", result)
    result = re.sub(r"\[at\]", "@", result, flags=re.IGNORECASE)
    # URL defanging
    result = re.sub(r"hxxp", "http", result, flags=re.IGNORECASE)
    result = re.sub(r"\[://\]", "://", result)
    return result
