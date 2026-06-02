from __future__ import annotations

import re

# Pola CVE standar: CVE-YYYY-NNNN (jumlah digit terakhir bebas, >=4).
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Keyword untuk routing/enrichment berbasis "regex default" (fixed list).
THREAT_KEYWORDS = [
    "apt", "lazarus", "fancy bear", "cozy bear", "kimsuky",
    "sandworm", "carbanak", "fin7", "turla",
]

MALWARE_KEYWORDS = [
    "wannacry", "emotet", "mirai", "stuxnet", "notpetya",
    "ransomware", "trojan", "rootkit", "cobalt strike",
]

LOG_KEYWORDS = [
    "log", "ssh", "login", "failed", "connection", "brute",
    "intrusion", "anomali", "mencurigakan", "reverse shell", "port scan",
]


def find_cve(text: str) -> str | None:
    """Kembalikan CVE-ID ter-normalisasi (UPPERCASE) bila ada, else None."""
    m = CVE_RE.search(text or "")
    return m.group().upper() if m else None

CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def find_cwe(text: str) -> str | None:
    """Kembalikan CWE-ID ter-normalisasi (UPPERCASE) bila ada, else None."""
    m = CWE_RE.search(text or "")
    return m.group().upper() if m else None
