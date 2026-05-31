"""Network indicators: IPv4 addresses, domains, and URLs."""
from __future__ import annotations

import re
from typing import List

import tldextract

from iocflow.allowlists import (
    BENIGN_DOMAINS,
    BENIGN_IPS,
    COMMON_FILENAME_STEMS,
    FILE_EXTENSION_TLDS,
    PACKAGE_REGISTRY_HOSTS,
)

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Private RFC1918 prefixes to skip (10/8, 192.168/16, 172.16–172.31).
_PRIVATE_PREFIXES = (
    "10.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)

_DOMAIN_CANDIDATE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b"
)
_VERSION_TRIPLE = re.compile(r"^\d+\.\d+\.\d+$")

_FULL_URL = re.compile(r"https?://[^\s<>\"')\]]+[^\s<>\"')\].,;:!?]", re.IGNORECASE)
_URL_PATH = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/[^\s<>\"')\]]+)",
    re.IGNORECASE,
)

MAX_URLS = 30


def extract_ips(text: str) -> List[str]:
    """Extract public IPv4 addresses, skipping benign, private, and
    version-number-like values."""
    ips: List[str] = []
    seen = set()
    for ip in _IPV4.findall(text):
        if ip in seen or ip in BENIGN_IPS:
            continue
        if ip.startswith(_PRIVATE_PREFIXES):
            continue

        # Skip version-number patterns (e.g. 122.0.0.0 from a Chrome UA string).
        parts = ip.split(".")
        if parts[1] == "0" and parts[2] == "0" and parts[3] == "0":
            continue  # x.0.0.0 — likely a version number
        if parts[2] == "0" and parts[3] == "0" and int(parts[0]) > 100:
            continue  # high first octet with .0.0 ending — likely a version

        ips.append(ip)
        seen.add(ip)
    return ips


def extract_domains(text: str) -> List[str]:
    """Extract domains using tldextract (Mozilla Public Suffix List) for TLD
    validation; benign domains and their subdomains are excluded."""
    domains: List[str] = []
    seen = set()
    for candidate in _DOMAIN_CANDIDATE.findall(text.lower()):
        if candidate in seen or candidate in BENIGN_DOMAINS:
            continue
        if any(candidate.endswith("." + bd) for bd in BENIGN_DOMAINS):
            continue
        if _VERSION_TRIPLE.match(candidate):
            continue

        extracted = tldextract.extract(candidate)
        if not (extracted.domain and extracted.suffix):
            continue

        # Filenames whose extension is also a TLD (install.sh) — only skip when
        # the stem looks like a common filename and there's no subdomain.
        if extracted.suffix in FILE_EXTENSION_TLDS:
            if extracted.domain.lower() in COMMON_FILENAME_STEMS and not extracted.subdomain:
                continue

        domains.append(candidate)
        seen.add(candidate)
    return domains


def _host_of(url: str) -> str:
    """Return the lowercased host of a URL (or bare host/path)."""
    host = re.sub(r"^https?://", "", url.lower())
    return host.split("/")[0].split(":")[0]


def _is_benign(host: str) -> bool:
    """True if ``host`` is benign (or a subdomain of a benign domain)."""
    if host in BENIGN_DOMAINS:
        return True
    return any(host.endswith("." + bd) for bd in BENIGN_DOMAINS)


def _is_package_registry(host: str) -> bool:
    """True if ``host`` is a package-registry host (or a subdomain of one)."""
    if host in PACKAGE_REGISTRY_HOSTS:
        return True
    return any(host.endswith("." + r) for r in PACKAGE_REGISTRY_HOSTS)


def extract_urls(text: str) -> List[str]:
    """Extract URLs, both protocol-qualified and bare ``domain.tld/path`` forms.

    Benign hosts are dropped as references, with one deliberate exception:
    a *path* under a package-registry host (``registry.npmjs.org/<pkg>/``) is
    kept, because the host is benign infrastructure but the path can name a
    malicious package. Bare ``host/path`` forms get an ``https://`` prefix.
    """
    urls: List[str] = []
    seen = set()

    for match in _FULL_URL.findall(text):
        host = _host_of(match)
        if match.lower() in seen:
            continue
        if _is_benign(host) and not _is_package_registry(host):
            continue
        urls.append(match)
        seen.add(match.lower())

    for match in _URL_PATH.finditer(text):
        url_path = match.group(1).rstrip(".,;:!?")
        if not ("/" in url_path and url_path.split("/", 1)[1]):
            continue
        full_url = f"https://{url_path}"
        host = _host_of(full_url)
        if full_url.lower() in seen:
            continue
        if _is_benign(host) and not _is_package_registry(host):
            continue
        urls.append(full_url)
        seen.add(full_url.lower())

    return urls[:MAX_URLS]
