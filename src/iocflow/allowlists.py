"""Allowlists and blocklists used to suppress false positives.

These are deliberately exported as plain module-level sets so callers can
extend or override them, e.g.::

    from iocflow import allowlists
    allowlists.BENIGN_DOMAINS.add("corp.example.net")
"""
from __future__ import annotations

# Benign domains to exclude during extraction. The IOC-hunt flow bypasses
# reputation filtering, so this list is intentionally broad: test/placeholder
# domains, package registries, security-vendor sites, threat-intel references,
# and major cloud/CDN infrastructure that routinely appears in reports.
BENIGN_DOMAINS = {
    # Test / placeholder domains
    "example.com", "example.org", "example.net", "localhost", "test.com",
    "internal.local",
    # Common email providers (email addresses still extracted, just not as domain IOCs)
    "gmail.com", "hotmail.com", "yahoo.com", "outlook.com", "live.com",
    # Package registries — legitimate infrastructure, not IOCs
    "npmjs.org", "registry.npmjs.org", "yarn.npmjs.org",
    "yarnpkg.com", "registry.yarnpkg.com",
    "github.com", "raw.githubusercontent.com", "gist.github.com",
    "pypi.org", "files.pythonhosted.org",
    "rubygems.org", "nuget.org", "crates.io",
    "packagist.org", "mvnrepository.com", "maven.org",
    "docker.io", "docker.com", "hub.docker.com",
    # Cybersecurity vendors — appear as references in reports, not IOCs
    "paloaltonetworks.com", "unit42.paloaltonetworks.com",
    "crowdstrike.com", "falcon.crowdstrike.com",
    "mandiant.com", "cloud.google.com",
    "microsoft.com", "learn.microsoft.com", "security.microsoft.com",
    "cisco.com", "talosintelligence.com",
    "fortinet.com", "fortiguard.com",
    "sentinelone.com", "sentinellabs.com",
    "trendmicro.com",
    "sophos.com", "news.sophos.com",
    "symantec.com", "broadcom.com",
    "mcafee.com", "trellix.com",
    "fireeye.com",
    "elastic.co", "elastic.github.io",
    "zscaler.com",
    "proofpoint.com",
    "checkpoint.com", "research.checkpoint.com",
    "recordedfuture.com",
    "sekoia.io",
    "group-ib.com",
    "kaspersky.com", "securelist.com",
    "eset.com", "welivesecurity.com",
    "bitdefender.com",
    "malwarebytes.com",
    "cybereason.com",
    "rapid7.com",
    "qualys.com",
    "tenable.com",
    "dragos.com",
    "volexity.com",
    "huntress.com",
    "infoblox.com",
    # Threat-intel / research references
    "mitre.org", "attack.mitre.org", "cve.mitre.org",
    "krebsonsecurity.com",
    "bleepingcomputer.com",
    "thehackernews.com",
    "therecord.media",
    "darkreading.com",
    "securityweek.com",
    "threatpost.com",
    "cyberscoop.com",
    "schneier.com",
    "nist.gov", "nvd.nist.gov",
    "cisa.gov", "us-cert.cisa.gov",
    "cert.org",
    "virustotal.com",
    "shodan.io",
    "abuse.ch", "bazaar.abuse.ch", "urlhaus.abuse.ch", "threatfox.abuse.ch",
    "otx.alienvault.com", "alienvault.com",
    "hybrid-analysis.com",
    "any.run", "app.any.run",
    "joesandbox.com", "joesecurity.org",
    "urlscan.io",
    "whois.domaintools.com", "domaintools.com",
    "abuseipdb.com",
    # Cloud / CDN infrastructure
    "amazonaws.com", "azure.com", "azureedge.net",
    "cloudflare.com", "cloudfront.net",
    "akamai.com", "akamaitechnologies.com",
    "googleapis.com",
    "windows.net", "office365.com", "office.com",
    "sharepoint.com", "onedrive.com",
    "google.com", "gstatic.com",
    "linkedin.com", "twitter.com", "x.com",
    "wikipedia.org", "medium.com",
}

# Package-registry hosts: the host is benign infrastructure, but a *path* under
# it (registry.npmjs.org/<pkg>) can name a malicious package, so URL paths on
# these hosts are kept even though the bare host is in BENIGN_DOMAINS.
PACKAGE_REGISTRY_HOSTS = {
    "npmjs.org", "registry.npmjs.org", "yarn.npmjs.org",
    "yarnpkg.com", "registry.yarnpkg.com",
    "pypi.org", "files.pythonhosted.org",
    "rubygems.org", "nuget.org", "crates.io",
    "packagist.org", "mvnrepository.com", "maven.org",
}

# Known benign IPs to exclude (loopback, broadcast, public resolvers).
BENIGN_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "8.8.8.8", "8.8.4.4",  # Google DNS
    "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
}

# Extensions that are also valid TLDs. A bare "word.ext" with one of these is
# usually a filename (install.sh) rather than a domain (openclaw.ai), so it is
# only accepted as a domain when it doesn't look like a common filename.
FILE_EXTENSION_TLDS = {
    "sh", "py", "pl", "rs", "ps", "cc", "md", "so", "la", "do", "to",
    "ai", "st", "fm", "am", "dj", "gs", "ms", "lk", "im", "ws", "nu", "tk",
}

# Common filenames that collide with file-extension TLDs (install.sh, setup.py).
COMMON_FILENAME_STEMS = {
    "install", "setup", "script", "run", "start", "init",
    "main", "index", "test", "build", "deploy", "config",
}

# Common English words that happen to be MITRE malware/tool names.
MALWARE_BLOCKLIST = {
    "anchor", "chaos", "empire", "expand", "flame", "havoc",
    "james", "kevin", "milan", "mango", "meteor", "net", "ninja",
    "ping", "rover", "royal", "ruler", "shark", "snake", "spark",
    "solar", "page", "play",
}

# LOLBins — legitimate Windows/system utilities MITRE tracks as "tools".
SYSTEM_TOOL_BLOCKLIST = {
    "arp", "at", "attrib", "bitsadmin", "certutil", "cipher.exe",
    "cmd", "dsquery", "esentutl", "forfiles", "ftp", "ifconfig",
    "ipconfig", "nbtstat", "nbtscan", "net", "netsh", "netstat",
    "nltest", "ping", "psexec", "pwdump", "rclone", "reg", "route",
    "schtasks", "sdelete", "systeminfo", "tasklist", "tor", "wevtutil",
    "connectwise", "quick assist",
}

# Well-known threat-actor and ransomware names matched by exact word boundary.
WELL_KNOWN_ACTORS = [
    # APT groups
    "Lazarus", "Lazarus Group",
    "Fancy Bear", "Cozy Bear",
    "Sandworm", "Turla",
    "Kimsuky", "Charming Kitten",
    "OceanLotus", "Ocean Lotus",
    "Equation Group",
    "Scattered Spider",
    "Nobelium", "Midnight Blizzard",
    "Volt Typhoon", "Salt Typhoon",
    # Ransomware families
    "ALPHV", "BlackCat",
    "LockBit", "Conti", "REvil",
    "CrazyHunter", "Akira", "Play",
    "Royal", "Black Basta", "BlackBasta",
    "Cl0p", "Clop", "Cuba", "Hive",
    "Medusa", "Rhysida", "BianLian",
    "NoEscape", "Cactus", "Hunters International",
    "Qilin", "INC Ransom", "RansomHub",
    "DragonForce", "Fog", "Lynx",
]

# Capitalized words that precede "ransomware" but are not actor names.
RANSOMWARE_FALSE_POSITIVES = {
    "The", "This", "That", "New", "Old", "Some", "Any", "Each", "Our", "Their",
    "Executed", "Propagated", "Deployed", "Distributed", "Disguised", "Downloaded",
    "Encrypted", "Delivered", "Launched", "Installed", "Targeted", "Modified",
    "Prince",  # Usually "fork of Prince ransomware" — context, not actor
}
