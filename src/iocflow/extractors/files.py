"""File indicators: suspicious filenames and cryptographic hashes."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

# Extensions that indicate a potentially malicious file. ``.com`` is excluded
# because it collides with domain names (github.com).
SUSPICIOUS_EXTENSIONS = {
    # Scripts
    "ps1", "sh", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    # Executables (no .com — avoids domain false positives)
    "exe", "dll", "msi", "scr", "pif",
    # Documents with macros
    "docm", "xlsm", "pptm", "dotm", "xltm",
    # Archives (can carry malware)
    "iso", "img", "vhd", "vhdx",
    # Other
    "hta", "lnk", "jar", "msc",
}

_EXT_ALTERNATION = "|".join(re.escape(ext) for ext in SUSPICIOUS_EXTENSIONS)
_FILENAME = re.compile(rf"\b([a-zA-Z0-9_\-\.]+\.(?:{_EXT_ALTERNATION}))\b", re.IGNORECASE)

MAX_FILENAMES = 20


def extract_filenames(text: str, urls: Optional[List[str]] = None) -> List[str]:
    """Extract suspicious script/executable filenames from text and URLs."""
    filenames: List[str] = []
    seen = set()

    for match in _FILENAME.finditer(text):
        filename = match.group(1)
        if filename.lower() not in seen:
            filenames.append(filename)
            seen.add(filename.lower())

    if urls:
        for url in urls:
            path = url.split("/")[-1]
            if path and "." in path:
                ext = path.rsplit(".", 1)[-1].lower()
                if ext in SUSPICIOUS_EXTENSIONS and path.lower() not in seen:
                    filenames.append(path)
                    seen.add(path.lower())

    return filenames[:MAX_FILENAMES]


_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")


def extract_hashes(text: str) -> Dict[str, List[str]]:
    """Extract MD5, SHA1, and SHA256 hashes.

    Longer hashes are matched first; shorter patterns that are merely a prefix
    of an already-matched longer hash are dropped, so a SHA256 isn't also
    reported as a SHA1 and an MD5.
    """
    hashes: Dict[str, List[str]] = {"md5": [], "sha1": [], "sha256": []}

    hashes["sha256"] = list(dict.fromkeys(h.lower() for h in _SHA256.findall(text)))

    sha256_prefixes_40 = {h[:40] for h in hashes["sha256"]}
    hashes["sha1"] = list(
        dict.fromkeys(
            h.lower() for h in _SHA1.findall(text) if h.lower() not in sha256_prefixes_40
        )
    )

    sha1_prefixes_32 = {h[:32] for h in hashes["sha1"]}
    sha256_prefixes_32 = {h[:32] for h in hashes["sha256"]}
    hashes["md5"] = list(
        dict.fromkeys(
            h.lower()
            for h in _MD5.findall(text)
            if h.lower() not in sha1_prefixes_32 and h.lower() not in sha256_prefixes_32
        )
    )

    return hashes
