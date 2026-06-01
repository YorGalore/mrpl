from __future__ import annotations

from typing import Dict, List

from backend.config import SPARQL_PUBLIC_ENDPOINT
from backend.sparql.client import (
    PREFIXES,
    SPARQLConfig,
    VirtuosoClient,
    bindings_to_rows,
)

def _client() -> VirtuosoClient:
    return VirtuosoClient(SPARQLConfig(endpoint=SPARQL_PUBLIC_ENDPOINT))


def fetch_attack_chain(cve_id: str, limit: int = 50) -> List[Dict[str, str]]:
    cve_id = cve_id.strip().upper()
    query = f"""{PREFIXES}
SELECT DISTINCT ?description ?score ?cweName ?capecName ?mitigation WHERE {{
  ?cve cve:id "{cve_id}" .
  OPTIONAL {{ ?cve cve:description ?description . }}
  OPTIONAL {{ ?cve cve:hasCVSS3BaseMetric ?m . ?m cvss:baseScore ?score . }}
  OPTIONAL {{
    ?cve cve:hasCWE ?cwe .
    OPTIONAL {{ ?cwe cwe:name ?cweName . }}
    OPTIONAL {{ ?cwe cwe:hasCAPEC ?capec . ?capec capec:name ?capecName .
               OPTIONAL {{ ?capec capec:mitigation ?mitigation . }} }}
  }}
}} LIMIT {int(limit)}"""
    try:
        return bindings_to_rows(_client().run_query(query))
    except Exception:
        return []


def build_attack_chain_context(cve_id: str) -> str:
    """Rantai CVE -> CWE -> CAPEC sebagai teks ringkas untuk konteks LLM."""
    rows = fetch_attack_chain(cve_id)
    if not rows:
        return f"Tidak ada rantai serangan ditemukan di KG untuk {cve_id.upper()}."

    description = next((r["description"] for r in rows if r.get("description")), "")
    score = next((r["score"] for r in rows if r.get("score")), "")
    cwes = sorted({r["cweName"] for r in rows if r.get("cweName")})
    capecs = sorted({r["capecName"] for r in rows if r.get("capecName")})
    mitigation = next((r["mitigation"] for r in rows if r.get("mitigation")), "")

    lines = [f"=== Attack Chain {cve_id.upper()} ==="]
    if score:
        lines.append(f"CVSS3 Base Score : {score}")
    if description:
        lines.append(f"Deskripsi        : {description[:300]}")
    if cwes:
        lines.append(f"Weakness (CWE)   : {', '.join(cwes)}")
    if capecs:
        lines.append(f"Pola Serangan    : {', '.join(capecs)}  (CWE -> CAPEC)")
    if mitigation:
        lines.append(f"Mitigasi         : {mitigation[:300]}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(build_attack_chain_context("CVE-2021-44228"))
