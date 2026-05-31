"""Contact indicators: email addresses."""
from __future__ import annotations

import re
from typing import List

_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", re.IGNORECASE)

MAX_EMAILS = 20


def extract_emails(text: str) -> List[str]:
    """Extract email addresses, lowercased and de-duplicated."""
    matches = _EMAIL.findall(text)
    return list(dict.fromkeys(e.lower() for e in matches))[:MAX_EMAILS]
