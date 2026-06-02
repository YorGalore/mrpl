from __future__ import annotations

import re
from typing import Optional

# Pola CVE standar: CVE-YYYY-NNNN (jumlah digit terakhir bebas, >=4).
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
CAPEC_RE = re.compile(r"CAPEC-\d+", re.IGNORECASE)

_ACTOR_RE = re.compile(
    r"\b("
    r"APT[-\s]?\d+"              # APT41, APT 29, APT-28
    r"|FIN\d+"                   # FIN7
    r"|TA\d+"                    # TA505
    r"|UNC\d+"                   # UNC2452
    r"|G\d{4}"                   # MITRE group IDs
    r"|[A-Z][a-zA-Z]+\s+(?:Group|Team|Actor|Bear|Spider|Panda|Tiger|Leopard|Kitten|Lynx|Dragon)"
    r")\b",
    re.IGNORECASE,
)

# Keyword untuk routing/enrichment berbasis "regex default" (fixed list).
THREAT_KEYWORDS = [
    "apt", "lazarus", "fancy bear", "cozy bear", "kimsuky", "sandworm", "carbanak", "fin7", "turla", "equation group",
     "charming kitten", "comment crew", "volt typhoon", "scattered spider", "midnight blizzard", "lockbit", "conti", 
     "revil", "darkside","threat actor", "threat group", "nation state", "advanced persistent threat",
]

MALWARE_KEYWORDS = [
    "wannacry", "emotet", "mirai", "stuxnet", "notpetya", "ransomware", "trojan", "rootkit", "cobalt strike",
    "redline", "formbook", "qakbot", "icedid", "trickbot", "blackcat", "lockbit", "ryuk", "maze", "darkside",
    "metasploit", "mimikatz", "psexec",
]

LOG_KEYWORDS = [
    "log", "ssh", "login", "failed", "connection", "brute", "intrusion", "anomali", "mencurigakan", "reverse shell", 
    "port scan", "anomaly", "anomalies", "traffic", "network flow", "suspicious", "malicious", "unauthorized", 
    "privilege", "firewall", "ids", "ips", "siem", "alert", "incident", "event log",
]

MITRE_GENERAL_KEYWORDS = [
    "lateral movement", "privilege escalation", "credential",
    "persistence", "defense evasion", "discovery", "collection",
    "exfiltration", "command and control", "c2", "c&c",
    "initial access", "execution", "impact",
    "phishing", "spear phishing", "watering hole",
    "dll hijacking", "process injection", "fileless",
    "living off the land", "lolbins",
    "link traffic", "network anomal",   
]


def find_cve(text: str) -> Optional[str]:
    """Kembalikan CVE-ID ter-normalisasi (UPPERCASE) bila ada, else None."""
    m = CVE_RE.search(text or "")
    return m.group().upper() if m else None

def find_cwe(text: str) -> Optional[str]:
    """Kembalikan CWE-ID ter-normalisasi (UPPERCASE) bila ada, else None."""
    m = CWE_RE.search(text or "")
    return m.group().upper() if m else None

def extract_actor_name(text: str) -> Optional[str]:
    m = _ACTOR_RE.search(text or "")
    if m:
        return m.group().strip()

    # Fallback: cari match multi-word THREAT_KEYWORDS (mis. 'fancy bear', 'cozy bear')
    q = (text or "").lower()
    for kw in sorted(THREAT_KEYWORDS, key=len, reverse=True):  # longest first
        if len(kw) > 3 and kw in q:  # skip terlalu pendek seperti 'apt'
            # Kembalikan versi title-case dari keyword
            return kw.title()

    # Fallback terakhir: kembalikan keyword terpendek (termasuk 'apt')
    for kw in THREAT_KEYWORDS:
        if kw in q:
            return kw

    return None