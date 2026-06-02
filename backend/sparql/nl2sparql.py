from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple
from langchain_core.prompts import PromptTemplate

from backend.config import SPARQL_PUBLIC_ENDPOINT, SPARQL_TIMEOUT
from backend.llm.llm_models import LLMProvider, DEFAULT_MODEL
from backend.patterns import CVE_RE
from backend.sparql.client import PREFIXES, SPARQLConfig, VirtuosoClient, bindings_to_rows
from backend.sparql.ontology_context import (ONTOLOGY_CONTEXT)

# Operasi tulis yang dilarang (read-only guard).
_FORBIDDEN = re.compile(
    r"\b(INSERT|DELETE|DROP|CLEAR|LOAD|CREATE|COPY|MOVE|ADD)\b", re.IGNORECASE
)

_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_CAPEC_RE = re.compile(r"\bCAPEC-\d+\b", re.IGNORECASE)

template = """
You are a cybersecurity SPARQL expert.

- Translate the user question into valid SPARQL.
- Use the ontology below. Use OPTIONAL for properties that may be missing.
- Always include PREFIX declarations. Return ONLY SPARQL query.

Ontology:
{ontology}

Question:
{question}

SPARQL:
"""

prompt = PromptTemplate(
    input_variables=["ontology", "question"],
    template=template
)

def _cve_full(cve_id: str) -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?description ?publishedDate ?cweName ?score WHERE {{
  ?cve cve:id "{cve_id}" .
  OPTIONAL {{ ?cve cve:description ?description . }}
  OPTIONAL {{ ?cve cve:publishedDate ?publishedDate . }}
  OPTIONAL {{ ?cve cve:hasCWE ?cwe . ?cwe cwe:name ?cweName . }}
  OPTIONAL {{ ?cve cve:hasCVSS3BaseMetric ?m . ?m cvss:baseScore ?score . }}
}} LIMIT 50"""


def _cve_cvss(cve_id: str) -> str:
    return f"""{PREFIXES}
SELECT ?score ?confImpact WHERE {{
  ?cve cve:id "{cve_id}" .
  OPTIONAL {{ ?cve cve:hasCVSS3BaseMetric ?m3 . ?m3 cvss:baseScore ?score ;
                 cvss:confidentialityImpact ?confImpact . }}
  OPTIONAL {{ ?cve cve:hasCVSS2BaseMetric ?m2 . ?m2 cvss:baseScore ?score ;
                 cvss:confidentialityImpact ?confImpact . }}
}} LIMIT 10"""


def _cve_capec(cve_id: str) -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?cweName ?capecName ?mitigation WHERE {{
  ?cve cve:id "{cve_id}" ; cve:hasCWE ?cwe .
  OPTIONAL {{ ?cwe cwe:name ?cweName . }}
  OPTIONAL {{ ?cwe cwe:hasCAPEC ?capec . ?capec capec:name ?capecName .
             OPTIONAL {{ ?capec capec:mitigation ?mitigation . }} }}
}} LIMIT 50"""
 
 
def _cve_products(cve_id: str) -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?cpe WHERE {{
  ?cve cve:id "{cve_id}" ; cve:hasCPE ?cpe .
}} LIMIT 30"""
 
 
def _cves_by_cwe(cwe_id: str) -> str:
    return f"""{PREFIXES}
SELECT DISTINCT ?cveId WHERE {{
  ?cwe cwe:id "{cwe_id}" .
  ?cve cve:hasCWE ?cwe ; cve:id ?cveId .
}} LIMIT 30"""

def _high_severity_fallback() -> str:
    """Query aman bila tidak ada pola spesifik dikenal."""
    return f"""{PREFIXES}
SELECT DISTINCT ?cveId ?score WHERE {{
  ?cve cve:id ?cveId ; cve:hasCVSS3BaseMetric ?m . ?m cvss:baseScore ?score .
  FILTER(?score >= 9.0)
}} ORDER BY DESC(?score) LIMIT 10"""

#regex tanpa LLM
def regex_sparql(question: str) -> Optional[str]:
    """Fast-path tanpa LLM. None bila tak ada pola dikenal."""
    q = question.lower()

    cve = CVE_RE.search(question)
    if cve:
        cid = cve.group().upper()
        if any(k in q for k in ("cvss", "score", "skor", "severity", "parah")):
            return _cve_cvss(cid)
        if any(k in q for k in ("capec", "attack pattern", "pola serangan", "mitigasi", "mitigation")):
            return _cve_capec(cid)
        if any(k in q for k in ("produk", "product", "cpe", "software", "terdampak", "affected")):
            return _cve_products(cid)
        return _cve_full(cid)

    cwe = _CWE_RE.search(question)
    if cwe:
        return _cves_by_cwe(cwe.group().upper())

    return None

    

# LLM Generator
def llm_generate(question: str, model: str = DEFAULT_MODEL) -> str:
    """Generate SPARQL via LLM. Raise Exception bila LLM tidak tersedia/gagal."""
    llm = LLMProvider.get_model(model)
    chain = prompt | llm
    response = chain.invoke({"ontology": ONTOLOGY_CONTEXT, "question": question})
    return response.content.strip()


def extract_sparql(text: str) -> str:
    match = re.search(r"```(?:sparql)?\s*([\s\S]+?)```", text, re.IGNORECASE)
    query = match.group(1).strip() if match else text.strip()
    if "PREFIX" not in query.upper():
        query = f"{PREFIXES}\n{query}"
    return query


def validate_sparql(query: str) -> bool:
    if _FORBIDDEN.search(query):
        return False
    upper = query.upper()
    has_select = "SELECT" in upper or "ASK" in upper
    return has_select and "{" in query and "}" in query


def generate_sparql(question: str, model: str = DEFAULT_MODEL) -> Tuple[str, str]:
    """
    Kembalikan (query, method). method = 'regex' | 'llm' | 'fallback' | 'fallback_keyword'.
    TIDAK PERNAH raise: selalu mengembalikan query yang dapat dieksekusi.
    FIX BUG 5: LLM error dan SPARQL validation failure ditangkap secara eksplisit,
    fallback query dikembalikan tanpa crash.
    """
    # 1. Fast-path regex
    q = regex_sparql(question)
    if q:
        return q, "regex"

    # 2. LLM generation (opsional — gagal gracefully)
    try:
        raw = llm_generate(question, model=model)
        q = extract_sparql(raw)
        if validate_sparql(q):
            return q, "llm"
        else:
            print(f"[nl2sparql] LLM menghasilkan SPARQL tidak valid, pakai fallback.")
    except Exception as e:
        print(f"[nl2sparql] LLM tidak tersedia atau error: {e}. Pakai fallback.")

    # 3. Fallback — jangan crash
    cve = CVE_RE.search(question)
    if cve:
        return _cve_full(cve.group().upper()), "fallback"

    return _high_severity_fallback(), "fallback_keyword"

 
def run_kg_query(query: str) -> List[Dict[str, str]]:
    """
    Eksekusi SPARQL pada endpoint publik.

    FIX BUG 5: Kembalikan [] jika endpoint tidak tersedia / timeout,
    sehingga caller (orchestrator) tidak crash dan bisa menggunakan sumber lain.
    """
    try:
        client = VirtuosoClient(
            SPARQLConfig(
                endpoint=SPARQL_PUBLIC_ENDPOINT,
                timeout=SPARQL_TIMEOUT,
                infer=False,
            )
        )
        return bindings_to_rows(client.run_query(query))
    except Exception as e:
        print(f"[nl2sparql] run_kg_query gagal (endpoint tidak tersedia?): {e}")
        return []        # FIX: kembalikan list kosong, jangan raise

def execute_question(question: str, model: str = DEFAULT_MODEL) -> dict:

    sparql_query, method = generate_sparql(question, model=model)
    rows = run_kg_query(sparql_query)   # FIX: tidak raise lagi
    if not rows and method not in ("regex",):
        method = f"{method}_no_results"

    return {
        "question": question,
        "method": method,
        "sparql": sparql_query,
        "results": rows,
    }


# Demo
if __name__ == "__main__":
    tests = [
        "Show vulnerabilities related to CVE-2021-44228",
        "What is APT41?",
        "Link traffic anomalies",
        "List CVEs with CVSS score above 9",
    ]
    for q in tests:
        print(f"\n=== QUESTION: {q} ===")
        result = execute_question(q)
        print("METHOD  :", result["method"])
        print("SPARQL  :", result["sparql"][:200])
        print("RESULTS :", result["results"][:3] if result["results"] else "(kosong)")

        