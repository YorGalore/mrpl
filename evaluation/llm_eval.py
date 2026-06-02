"""
LLM Evaluation for SEPSES CSKG Cybersecurity Chatbot

"""

import os
import json
import time
import re
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List, Tuple, Set
from collections import Counter

import requests
import numpy as np

# Optional: for semantic similarity (install with: pip install sentence-transformers)
try:
    from sentence_transformers import SentenceTransformer, util
    SEMANTIC_AVAILABLE = True
    SEMANTIC_MODEL = None  # Lazy load
except ImportError:
    SEMANTIC_AVAILABLE = False
    print("Warning: sentence-transformers not installed. Semantic scoring disabled.")
    print("Install with: pip install sentence-transformers")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SEPSES_SPARQL_ENDPOINT = "https://sepses.ifs.tuwien.ac.at/sparql"
SEPSES_HEADERS = {
    "Accept": "application/sparql-results+json",
    "Content-Type": "application/x-www-form-urlencoded",
}

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# If True, use mock responses instead of live API calls (for offline testing)
DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"

# ---------------------------------------------------------------------------
# SPARQL Queries for Ground Truth
# ---------------------------------------------------------------------------

SPARQL_GROUND_TRUTH: dict[str, str] = {
    "CVE-2021-44228": """
        PREFIX vocab: <http://sepses.ifs.tuwien.ac.at/vocab/cskg/cve#>
        PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?cve ?description ?cvssScore ?publishedDate
        WHERE {
          ?cve a vocab:CVE ;
               vocab:cveId "CVE-2021-44228" ;
               vocab:description ?description .
          OPTIONAL { ?cve vocab:cvssScore ?cvssScore . }
          OPTIONAL { ?cve vocab:publishedDate ?publishedDate . }
        }
        LIMIT 5
    """,

    "critical_severity": """
        PREFIX vocab: <http://sepses.ifs.tuwien.ac.at/vocab/cskg/cve#>
        SELECT ?cve ?cvssScore
        WHERE {
          ?cve a vocab:CVE ;
               vocab:cvssScore ?cvssScore .
          FILTER (?cvssScore >= 9.0)
        }
        ORDER BY DESC(?cvssScore)
        LIMIT 10
    """,

    "sql_injection_capec": """
        PREFIX capec: <http://sepses.ifs.tuwien.ac.at/vocab/cskg/capec#>
        PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?pattern ?name ?description
        WHERE {
          ?pattern a capec:AttackPattern ;
                   rdfs:label ?name ;
                   capec:description ?description .
          FILTER (CONTAINS(LCASE(STR(?name)), "sql"))
        }
        LIMIT 10
    """,

    "malware_apache": """
        PREFIX malware: <http://sepses.ifs.tuwien.ac.at/vocab/cskg/malware#>
        PREFIX vocab:   <http://sepses.ifs.tuwien.ac.at/vocab/cskg/cve#>
        SELECT ?malware ?name ?targetedSoftware
        WHERE {
          ?malware a malware:Malware ;
                   malware:name ?name .
          OPTIONAL { ?malware malware:targetedSoftware ?targetedSoftware . }
          FILTER (CONTAINS(LCASE(STR(?targetedSoftware)), "apache") ||
                  CONTAINS(LCASE(STR(?name)), "apache"))
        }
        LIMIT 10
    """,

    "ransomware_techniques": """
        PREFIX attack: <http://sepses.ifs.tuwien.ac.at/vocab/cskg/attack#>
        PREFIX rdfs:   <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?technique ?name ?tactic
        WHERE {
          ?group a attack:ThreatActor ;
                 rdfs:label ?groupName .
          ?group attack:usesTechnique ?technique .
          ?technique rdfs:label ?name .
          OPTIONAL { ?technique attack:tactic ?tactic . }
          FILTER (CONTAINS(LCASE(STR(?groupName)), "ransomware"))
        }
        LIMIT 10
    """,

    "capec_patterns": """
        PREFIX capec: <http://sepses.ifs.tuwien.ac.at/vocab/cskg/capec#>
        PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?pattern ?name ?likelihood
        WHERE {
          ?pattern a capec:AttackPattern ;
                   rdfs:label ?name .
          OPTIONAL { ?pattern capec:likelihood ?likelihood . }
        }
        ORDER BY ?name
        LIMIT 15
    """,

    "buffer_overflow_vulns": """
        PREFIX vocab: <http://sepses.ifs.tuwien.ac.at/vocab/cskg/cve#>
        PREFIX cwe:   <http://sepses.ifs.tuwien.ac.at/vocab/cskg/cwe#>
        PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?cve ?cveId ?cwe ?cweName
        WHERE {
          ?cve a vocab:CVE ;
               vocab:cveId ?cveId ;
               vocab:hasCWE ?cwe .
          ?cwe rdfs:label ?cweName .
          FILTER (CONTAINS(LCASE(STR(?cweName)), "buffer overflow") ||
                  CONTAINS(LCASE(STR(?cweName)), "buffer copy"))
        }
        LIMIT 15
    """,

    "windows_techniques": """
        PREFIX attack: <http://sepses.ifs.tuwien.ac.at/vocab/cskg/attack#>
        PREFIX rdfs:   <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?technique ?name ?platform ?tactic
        WHERE {
          ?technique a attack:Technique ;
                     rdfs:label ?name .
          OPTIONAL { ?technique attack:platform ?platform . }
          OPTIONAL { ?technique attack:tactic ?tactic . }
          FILTER (CONTAINS(LCASE(STR(?platform)), "windows"))
        }
        LIMIT 15
    """,

    "cves_2021": """
        PREFIX vocab: <http://sepses.ifs.tuwien.ac.at/vocab/cskg/cve#>
        SELECT ?cve ?cveId ?publishedDate
        WHERE {
          ?cve a vocab:CVE ;
               vocab:cveId ?cveId ;
               vocab:publishedDate ?publishedDate .
          FILTER (STRSTARTS(STR(?publishedDate), "2021"))
        }
        ORDER BY ?publishedDate
        LIMIT 20
    """,

    "cve_cwe_relationships": """
        PREFIX vocab: <http://sepses.ifs.tuwien.ac.at/vocab/cskg/cve#>
        PREFIX cwe:   <http://sepses.ifs.tuwien.ac.at/vocab/cskg/cwe#>
        PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?cveId ?cweId ?cweName
        WHERE {
          ?cve a vocab:CVE ;
               vocab:cveId ?cveId ;
               vocab:hasCWE ?cweNode .
          ?cweNode cwe:cweId ?cweId ;
                   rdfs:label ?cweName .
        }
        LIMIT 20
    """,
}

# ---------------------------------------------------------------------------
# Ground Truth Definitions
# ---------------------------------------------------------------------------

@dataclass
class GroundTruth:
    question_id: str
    question: str
    sparql_key: str
    expected_keywords: list[str]
    expected_entities: list[str]
    category: str
    description: str
    validation_rules: dict = field(default_factory=dict)  # For question-specific validation

GROUND_TRUTHS: list[GroundTruth] = [
    GroundTruth(
        question_id="Q1",
        question="Show information about CVE-2021-44228",
        sparql_key="CVE-2021-44228",
        expected_keywords=["Log4Shell", "Log4j", "JNDI", "remote code execution", "RCE", "Apache", "CVSS", "10.0"],
        expected_entities=["CVE-2021-44228", "CWE-917", "Apache Log4j"],
        category="Vulnerability",
        description="CVE-2021-44228 is the Log4Shell critical RCE vulnerability in Apache Log4j with CVSS 10.0",
    ),
    GroundTruth(
        question_id="Q2",
        question="List vulnerabilities with critical severity",
        sparql_key="critical_severity",
        expected_keywords=["CVSS", "critical", "severity", "score"],
        expected_entities=["CVE", "critical", "severity"],
        category="Vulnerability",
        description="Critical vulnerabilities have CVSS score >= 9.0 per NVD/SEPSES CSKG",
        validation_rules={"min_cvss": 9.0},  # Rule: CVSS must be >= 9.0
    ),
    GroundTruth(
        question_id="Q3",
        question="Find attack patterns related to SQL Injection",
        sparql_key="sql_injection_capec",
        expected_keywords=["SQL injection", "CAPEC-66", "CAPEC-7", "input validation", "database"],
        expected_entities=["CAPEC-66", "SQL Injection", "CWE-89"],
        category="Attack Pattern",
        description="SQL Injection attack patterns are documented in CAPEC (e.g., CAPEC-66: SQL Injection)",
    ),
    GroundTruth(
        question_id="Q4",
        question="Show malware targeting Apache servers",
        sparql_key="malware_apache",
        expected_keywords=["Apache", "webshell", "exploit", "HTTP", "RCE"],
        expected_entities=["Apache HTTP Server", "CVE-2021-41773", "web shell"],
        category="Malware",
        description="Several malware families target Apache web servers via known CVEs",
    ),
    GroundTruth(
        question_id="Q5",
        question="Find techniques used by ransomware groups",
        sparql_key="ransomware_techniques",
        expected_keywords=["encryption", "MITRE ATT&CK", "T1486", "lateral movement", "phishing"],
        expected_entities=["T1486", "T1027", "REvil", "LockBit"],
        category="Threat Actor",
        description="Ransomware groups use MITRE ATT&CK techniques such as T1486 (Data Encrypted for Impact)",
    ),
    GroundTruth(
        question_id="Q6",
        question="Show CAPEC attack patterns",
        sparql_key="capec_patterns",
        expected_keywords=["CAPEC", "attack pattern", "likelihood", "severity"],
        expected_entities=["CAPEC-1", "CAPEC-2", "attack pattern"],
        category="Attack Pattern",
        description="CAPEC provides a catalog of common attack patterns with structured metadata",
    ),
    GroundTruth(
        question_id="Q7",
        question="List vulnerabilities related to buffer overflow",
        sparql_key="buffer_overflow_vulns",
        expected_keywords=["buffer overflow", "CWE-119", "CWE-120", "memory corruption", "stack overflow"],
        expected_entities=["CWE-119", "CWE-120", "CWE-121", "buffer overflow"],
        category="Vulnerability",
        description="Buffer overflow vulnerabilities are classified under CWE-119/120/121 in SEPSES CSKG",
    ),
    GroundTruth(
        question_id="Q8",
        question="Find attack techniques targeting Windows systems",
        sparql_key="windows_techniques",
        expected_keywords=["Windows", "MITRE ATT&CK", "T1003", "credential dumping", "PowerShell"],
        expected_entities=["Windows", "T1003", "T1059.001", "PowerShell"],
        category="Attack Technique",
        description="MITRE ATT&CK documents techniques specific to Windows platforms",
    ),
    GroundTruth(
        question_id="Q9",
        question="Show all published CVEs in 2021",
        sparql_key="cves_2021",
        expected_keywords=["2021", "CVE", "published", "NVD", "vulnerability"],
        expected_entities=["CVE-2021-44228", "CVE-2021-34527", "CVE-2021-40444"],
        category="Vulnerability",
        description="SEPSES CSKG contains CVEs published in 2021, including Log4Shell and PrintNightmare",
    ),
    GroundTruth(
        question_id="Q10",
        question="Find relationships between CVE and CWE",
        sparql_key="cve_cwe_relationships",
        expected_keywords=["CWE", "CVE", "weakness", "vulnerability type", "root cause", "hasCWE"],
        expected_entities=["CWE-79", "CWE-89", "CWE-119", "relationship"],
        category="KG Relationship",
        description="SEPSES CSKG links CVEs to their root cause CWEs via vocab:hasCWE property",
    ),
]

# ---------------------------------------------------------------------------
# Validation Helpers
# ---------------------------------------------------------------------------

def parse_cvss_scores(text: str) -> List[float]:
    """
    Extract CVSS scores from response text.
    Handles formats like: 10.0, 9.8, 8.8, etc.
    """
    # Pattern for decimal numbers with one decimal place (0.0 to 10.0)
    # But filter out years (2021, 2022) and other non-CVSS numbers
    scores = []
    # Look for numbers that look like CVSS scores (0.0-10.0)
    matches = re.findall(r'\b(?:[0-9]|[1-9][0-9]?)\.(?:[0-9])\b', text)
    
    for match in matches:
        try:
            score = float(match)
            # CVSS scores are typically between 0.0 and 10.0
            if 0.0 <= score <= 10.0:
                scores.append(score)
        except ValueError:
            continue
    
    return scores


def is_critical_cvss(score: float, threshold: float = 9.0) -> bool:
    """Check if a CVSS score qualifies as critical severity."""
    return score >= threshold


def validate_cvss_claims(response: str, min_cvss: float = 9.0) -> Tuple[bool, List[str]]:
    """
    Validate that all CVSS scores claimed as critical are actually >= min_cvss.
    Returns (is_valid, list_of_violations)
    """
    violations = []
    
    # Find all CVSS scores in response
    scores = parse_cvss_scores(response)
    
    # For each score, check context around it
    for score in scores:
        # Look for context around this score in the response
        # Find position of the score
        score_str = f"{score:.1f}"
        idx = response.find(score_str)
        if idx == -1:
            score_str = str(score)
            idx = response.find(score_str)
        
        if idx != -1:
            # Get context (200 chars before and after)
            start = max(0, idx - 100)
            end = min(len(response), idx + 150)
            context = response[start:end]
            
            # Check if this score is presented as critical
            critical_markers = ["critical", "critical severity", "CVSS"]
            is_marked_critical = any(marker in context.lower() for marker in critical_markers)
            
            if is_marked_critical and not is_critical_cvss(score, min_cvss):
                violations.append(f"Score {score:.1f} marked as critical but < {min_cvss}")
    
    # Also check for explicit claims about non-critical CVEs being critical
    low_scores = [s for s in scores if s < min_cvss]
    for low_score in low_scores:
        # Check if any CVE is associated with this low score
        cve_pattern = r'CVE-\d{4}-\d+'
        context_before = response[:response.find(str(low_score))]
        cves_found = re.findall(cve_pattern, context_before)
        if cves_found:
            violations.append(f"CVE {', '.join(cves_found)} has score {low_score:.1f} (< {min_cvss}) but presented in critical context")
    
    return len(violations) == 0, violations


# ---------------------------------------------------------------------------
# SEPSES SPARQL Retrieval
# ---------------------------------------------------------------------------

def query_sepses(sparql_query: str, timeout: int = 15) -> dict:
    """Execute a SPARQL query against the SEPSES endpoint."""
    try:
        resp = requests.post(
            SEPSES_SPARQL_ENDPOINT,
            data={"query": sparql_query.strip()},
            headers=SEPSES_HEADERS,
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        logger.warning("SEPSES endpoint unreachable — returning empty result")
        return {"results": {"bindings": []}}
    except Exception as exc:
        logger.error("SPARQL query failed: %s", exc)
        return {"results": {"bindings": []}}


def extract_sparql_entities(sparql_result: dict) -> list[str]:
    """Flatten SPARQL result bindings into a list of string values."""
    entities = []
    for binding in sparql_result.get("results", {}).get("bindings", []):
        for _, val in binding.items():
            if val.get("type") in ("literal", "uri"):
                value = val["value"]
                # Extract meaningful parts from URIs
                if "sepses" in value or "w3.org" in value:
                    # Extract last part after # or /
                    if "#" in value:
                        value = value.split("#")[-1]
                    elif "/" in value:
                        value = value.split("/")[-1]
                    value = value.replace("_", " ")
                entities.append(value)
    return entities


def get_semantic_model():
    """Lazy load semantic similarity model"""
    global SEMANTIC_MODEL
    if SEMANTIC_AVAILABLE and SEMANTIC_MODEL is None:
        SEMANTIC_MODEL = SentenceTransformer('all-MiniLM-L6-v2')
    return SEMANTIC_MODEL


def semantic_similarity(text1: str, text2: str) -> float:
    """Compute semantic similarity between two texts"""
    if not SEMANTIC_AVAILABLE:
        return 0.0
    model = get_semantic_model()
    embeddings = model.encode([text1, text2])
    similarity = util.cos_sim(embeddings[0], embeddings[1]).item()
    return similarity


# ---------------------------------------------------------------------------
# Mock LLM Responses (used when DRY_RUN=true) - FIXED Q2
# ---------------------------------------------------------------------------

MOCK_RESPONSES: dict[str, dict[str, str]] = {
    "openrouter": {
        "Q1": (
            "CVE-2021-44228, known as Log4Shell, is a critical remote code execution (RCE) vulnerability "
            "in Apache Log4j (versions 2.0–2.14.1). It exploits JNDI injection via specially crafted log "
            "messages. CVSS v3 base score is 10.0 (Critical). Attackers can trigger the vulnerability by "
            "sending a malicious ${jndi:ldap://...} string. It is mapped to CWE-917 (Improper Neutralization "
            "of Special Elements used in an Expression Language Statement). Patched in Log4j 2.15.0+."
        ),
        "Q2": (
            "Critical vulnerabilities are those with a CVSS score of 9.0 or higher. Examples from SEPSES CSKG: "
            "CVE-2021-44228 (10.0), CVE-2022-22965 Spring4Shell (9.8), CVE-2020-1472 Zerologon (10.0). "
            "All these have CVSS scores of 9.0 or higher, meeting the critical severity threshold. "
            "The SEPSES CSKG indexes these with vocab:cvssScore and severity categorisation."
        ),
        "Q3": (
            "SQL Injection attack patterns in CAPEC include CAPEC-66 (SQL Injection), CAPEC-7 (Blind SQL Injection), "
            "and CAPEC-110 (SQL Injection through SOAP Parameter Tampering). These involve manipulating SQL queries "
            "through unsanitised user input. The root weakness is CWE-89. Mitigations include parameterised queries "
            "and input validation."
        ),
        "Q4": (
            "Malware targeting Apache servers includes web shells deployed via CVE-2021-41773 (Apache HTTP Server path "
            "traversal), Mettle RAT, and various PHP-based web shells. The vulnerability allows RCE on Apache 2.4.49. "
            "Additionally, cryptominers exploit misconfigured Apache Solr and Tomcat instances."
        ),
        "Q5": (
            "Ransomware groups use MITRE ATT&CK techniques including: T1486 (Data Encrypted for Impact), T1027 "
            "(Obfuscated Files/Information), T1059.001 (PowerShell), T1078 (Valid Accounts for persistence). "
            "Groups like REvil, LockBit, and Conti are documented in SEPSES CSKG threat actor data."
        ),
        "Q6": (
            "CAPEC (Common Attack Pattern Enumeration and Classification) provides structured attack patterns. "
            "Examples: CAPEC-1 (Accessing/Intercepting/Modifying HTTP Cookies), CAPEC-2 (Inducing Account Lockout), "
            "CAPEC-17 (Accessing/Intercepting/Modifying HTTP Cookies). Each entry includes prerequisites, execution "
            "flow, likelihood, and typical severity. SEPSES CSKG imports CAPEC as RDF triples."
        ),
        "Q7": (
            "Buffer overflow vulnerabilities are classified under CWE-119 (Improper Restriction of Operations within "
            "Memory Buffer), CWE-120 (Buffer Copy without Checking Size of Input), CWE-121 (Stack-based Buffer "
            "Overflow), and CWE-122 (Heap-based Buffer Overflow). In SEPSES CSKG these are linked to specific CVEs "
            "via vocab:hasCWE. Classic examples: CVE-2021-3156 (sudo heap overflow)."
        ),
        "Q8": (
            "MITRE ATT&CK documents Windows-specific techniques: T1003 (OS Credential Dumping via LSASS), "
            "T1059.001 (PowerShell), T1547.001 (Registry Run Keys for persistence), T1055 (Process Injection). "
            "SEPSES CSKG stores ATT&CK techniques with platform metadata."
        ),
        "Q9": (
            "SEPSES CSKG includes CVEs published in 2021. Notable ones: CVE-2021-44228 (Log4Shell, Dec 2021), "
            "CVE-2021-34527 (PrintNightmare, Jul 2021), CVE-2021-40444 (MSHTML RCE, Sep 2021). "
            "They are indexed with vocab:publishedDate filtering on 2021-xx-xx."
        ),
        "Q10": (
            "In SEPSES CSKG, CVEs are linked to CWEs via the vocab:hasCWE predicate (RDF triple). For example, "
            "CVE-2021-44228 maps to CWE-917. CVE-2017-5638 (Struts2) maps to CWE-20 (Improper Input Validation). "
            "This relationship enables graph traversal from vulnerability instances to weakness categories."
        ),
    },
    "llama3.2:3b": {
        "Q1": (
            "CVE-2021-44228 is a remote code execution vulnerability. It affects Java logging. The CVSS score is 10.0. "
            "Apache Log4j is impacted. Attackers can exploit it remotely. The fix is to upgrade the library version. "
            "It was discovered in December 2021 and mapped to CWE-917."
        ),
        "Q2": (
            "Critical severity vulnerabilities have a CVSS score of 9.0 or higher. They include CVE-2021-44228 (10.0). "
            "Systems should be patched immediately. The NVD database tracks these."
        ),
        "Q3": (
            "SQL Injection is a common web attack. CAPEC-66 covers SQL injection patterns. Attackers use malicious "
            "SQL to access databases. Input validation prevents this. CWE-89 is the related weakness."
        ),
        "Q4": (
            "Several malware families target Apache servers. Web shells are often used. Hackers exploit CVE-2021-41773 "
            "in Apache HTTP Server. Keeping Apache updated is important for security."
        ),
        "Q5": (
            "Ransomware groups use many techniques. They encrypt files using T1486. They also use phishing for initial access. "
            "Lateral movement is common. Known groups include REvil and LockBit."
        ),
        "Q6": (
            "CAPEC is a catalog of attack patterns. It includes SQL injection, XSS, and buffer overflow patterns. "
            "Each pattern has a description and mitigations. MITRE maintains CAPEC."
        ),
        "Q7": (
            "Buffer overflow happens when programs write more data than a buffer can hold. CWE-119 and CWE-120 cover "
            "this vulnerability. It can lead to arbitrary code execution."
        ),
        "Q8": (
            "Windows is targeted by many attack techniques. Attackers use PowerShell and credential dumping (T1003). "
            "Registry modifications provide persistence. MITRE ATT&CK documents these techniques."
        ),
        "Q9": (
            "Many CVEs were published in 2021. This includes Log4Shell (CVE-2021-44228) which was very serious. "
            "PrintNightmare (CVE-2021-34527) was another notable one."
        ),
        "Q10": (
            "CVE and CWE are related through vocab:hasCWE in SEPSES. CVEs are specific vulnerabilities, CWEs are weakness types. "
            "One CVE can map to one or more CWEs. This helps understand the root cause."
        ),
    },
}

# ---------------------------------------------------------------------------
# Scoring Engine (Enhanced)
# ---------------------------------------------------------------------------

@dataclass
class QuestionScore:
    question_id: str
    question: str
    category: str
    model: str
    response: str
    latency_sec: float
    # Scores (0–100)
    accuracy: float = 0.0
    completeness: float = 0.0
    kg_alignment: float = 0.0
    explainability: float = 0.0
    hallucination_rate: float = 0.0
    overall_score: float = 0.0
    # Validation results
    validation_passed: bool = True
    validation_violations: List[str] = field(default_factory=list)
    # Hallucination details
    hallucinated_entities: List[str] = field(default_factory=list)
    # SPARQL ground truth metadata
    sparql_entities_found: int = 0
    sparql_entities_total: int = 0
    keyword_hits: int = 0
    keyword_total: int = 0
    entity_hits: int = 0
    entity_total: int = 0
    semantic_score: float = 0.0
    notes: str = ""


def extract_entities_from_response(response: str) -> Tuple[List[str], List[str], List[str]]:
    """Extract CVEs, CWEs, and CAPECs from response"""
    cves = re.findall(r"CVE-\d{4}-\d+", response, re.IGNORECASE)
    cwes = re.findall(r"CWE-\d+", response, re.IGNORECASE)
    capecs = re.findall(r"CAPEC-\d+", response, re.IGNORECASE)
    return cves, cwes, capecs


def check_entity_in_kg(entity: str, sparql_entities: List[str]) -> bool:
    """Check if an entity exists in SPARQL results"""
    entity_lower = entity.lower()
    for se in sparql_entities:
        se_lower = se.lower()
        if entity_lower == se_lower or entity_lower in se_lower or se_lower in entity_lower:
            return True
    return False


def calculate_explainability(response: str) -> float:
    """
    Calculate explainability score based on reasoning quality, not just length.
    """
    resp_lower = response.lower()
    
    # Reasoning markers (weighted)
    reasoning_markers = {
        "because": 3,
        "therefore": 4,
        "thus": 3,
        "consequently": 4,
        "mapped to": 5,
        "related to": 2,
        "caused by": 4,
        "due to": 3,
        "leads to": 3,
        "results in": 3,
        "for example": 2,
        "such as": 2,
    }
    
    reasoning_score = 0
    for marker, weight in reasoning_markers.items():
        if marker in resp_lower:
            reasoning_score += weight
    
    # Structure markers (lists, bullet points, numbered lists)
    structure_score = 0
    if re.search(r'\d+\.\s+', response):  # Numbered list
        structure_score += 10
    if re.search(r'[-*•]\s+', response):  # Bullet points
        structure_score += 10
    if re.search(r'[\(\[]?(?:CVE|CWE|CAPEC|T\d+)[\)\]]?', response):  # Identifiers
        structure_score += 10
    if ":" in response and response.count(":") >= 2:  # Structured with colons
        structure_score += 5
    
    # Explanation depth (sentence count with reasonable length)
    sentences = re.split(r'[.!?]+', response)
    meaningful_sentences = [s for s in sentences if len(s.strip()) > 30]
    depth_score = min(len(meaningful_sentences) * 5, 30)
    
    # Combine scores (max 100)
    total = reasoning_score + structure_score + depth_score
    return min(total, 100.0)


def calculate_hallucination(
    response: str, 
    sparql_entities: List[str],
    gt: GroundTruth
) -> Tuple[float, List[str]]:
    """
    Detect hallucinated entities (CVEs, CWEs that don't exist in KG)
    """
    cves, cwes, capecs = extract_entities_from_response(response)
    
    all_predicted = cves + cwes + capecs
    hallucinated = []
    
    for entity in all_predicted:
        if not check_entity_in_kg(entity, sparql_entities):
            hallucinated.append(entity)
    
    # Apply validation rules if present
    if hasattr(gt, 'validation_rules') and gt.validation_rules:
        if 'min_cvss' in gt.validation_rules:
            valid, violations = validate_cvss_claims(response, gt.validation_rules['min_cvss'])
            if not valid:
                hallucinated.extend(violations)
    
    # Calculate hallucination rate (0-100, higher means more hallucination)
    total_checks = len(all_predicted) + (1 if hallucinated else 0)
    if total_checks > 0:
        hallucination_rate = (len(hallucinated) / total_checks) * 100
    else:
        hallucination_rate = 0.0
    
    return min(hallucination_rate, 100.0), hallucinated


def score_response(
    gt: GroundTruth,
    model: str,
    response: str,
    latency_sec: float,
    sparql_entities: list[str],
) -> QuestionScore:
    """
    Score an LLM response against ground truth with enhanced metrics.
    
    Scoring rubric (weights):
    - Accuracy (35%): keyword matching + semantic similarity
    - Completeness (25%): entity coverage + SPARQL overlap
    - KG Alignment (20%): entity presence in KG
    - Explainability (10%): reasoning quality
    - Hallucination (10%): inverse of hallucination rate
    """
    resp_lower = response.lower()
    
    # --- Validation Rules ---
    validation_passed = True
    validation_violations = []
    
    if hasattr(gt, 'validation_rules') and gt.validation_rules:
        if 'min_cvss' in gt.validation_rules:
            valid, violations = validate_cvss_claims(response, gt.validation_rules['min_cvss'])
            validation_passed = valid
            validation_violations = violations
    
    # --- 1. Accuracy (35%) - Keyword + Semantic ---
    kw_hits = sum(1 for kw in gt.expected_keywords if kw.lower() in resp_lower)
    kw_total = len(gt.expected_keywords)
    kw_rate = kw_hits / kw_total if kw_total else 0
    
    # Apply validation penalty if failed
    validation_penalty = 0 if validation_passed else 20
    
    # Semantic similarity with ground truth description
    semantic_score = semantic_similarity(response, gt.description) * 100
    
    # Combined accuracy (70% keyword, 30% semantic, minus validation penalty)
    accuracy = max(0, (kw_rate * 70) + (semantic_score * 0.3) - validation_penalty)
    
    # --- 2. Completeness (25%) - Entity coverage ---
    ent_hits = sum(1 for e in gt.expected_entities if e.lower() in resp_lower)
    ent_total = len(gt.expected_entities)
    ent_rate = ent_hits / ent_total if ent_total else 0
    
    # SPARQL entity overlap (improved: match by partial string)
    sparql_hits = 0
    for sparql_val in sparql_entities:
        # Clean up SPARQL value for matching
        clean_val = str(sparql_val).lower()
        # Try different matching strategies
        if clean_val in resp_lower:
            sparql_hits += 1
        else:
            # Check if any significant part matches
            parts = clean_val.replace("_", " ").split()
            for part in parts:
                if len(part) > 3 and part in resp_lower:
                    sparql_hits += 1
                    break
    
    sparql_total = len(sparql_entities)
    sparql_rate = min(sparql_hits / max(sparql_total, 1), 1.0)
    
    # Completeness: 60% entity rate, 40% SPARQL overlap
    completeness = (ent_rate * 60) + (sparql_rate * 40)
    
    # --- 3. KG Alignment (20%) - Entity presence in KG ---
    # Count how many of the predicted entities are actually in SPARQL results
    cves, cwes, capecs = extract_entities_from_response(response)
    all_predicted = cves + cwes + capecs
    
    if all_predicted:
        valid_entities = sum(1 for e in all_predicted if check_