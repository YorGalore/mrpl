from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_SCHEMA_JSON = Path(__file__).resolve().parents[3] / "docs" / "knowledge_graph_schema.json"

FALLBACK_CONTEXT = """\
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX dct: <http://purl.org/dc/terms/>
PREFIX cve: <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cwe: <http://w3id.org/sepses/vocab/ref/cwe#>
PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
PREFIX attack: <http://w3id.org/sepses/vocab/ref/attack#>
PREFIX vuln: <http://w3id.org/sepses/vocab/vulnerability#>
PREFIX cpe: <http://w3id.org/sepses/vocab/ref/cpe#>
PREFIX cvss: <http://w3id.org/sepses/vocab/ref/cvss#>

DATA LOCATION:
- capec / cwe / snortrule  -> Virtuoso lokal
- cve / cvss / cpe         -> endpoint publik SEPSES (data lengkap)

KEY CLASSES:
- cve:CVE
- cwe:CWE
- capec:AttackPattern
- capec:CAPEC
- attack:Technique
- vuln:Vulnerability
- cpe:CPE
- cvss:CVSS

KEY PROPERTIES:
- cve:id                  (string id, mis. "CVE-2021-44228")
- cve:description
- cve:publishedDate
- cve:hasCWE
- cve:hasCPE
- cve:hasCAPEC
- cve:hasCVSS
- cve:hasCPE              (CVE -> CPE)
- cve:hasCVSS2BaseMetric  (CVE -> CVSS2)
- cve:hasCVSS3BaseMetric  (CVE -> CVSS3)
- cvss:baseScore
- cvss:confidentialityImpact
- cwe:name
- cwe:description
- cwe:hasCAPEC
- cwe:hasCommonConsequence
- capec:name
- capec:description
- capec:mitigation
- attack:targets
- attack:uses
- vuln:severity
- vuln:relatedTo

COMMON QUERY SHAPES:
1. CVE lookup by ID:  ?cve cve:id "CVE-2021-44228" ; cve:description ?description .
2. CVE -> CWE:        ?cve cve:id ?id ; cve:hasCWE ?cwe .
3. CVE -> CVSS score: ?cve cve:id ?id ; cve:hasCVSS3BaseMetric ?m . ?m cvss:baseScore ?score .
4. CWE -> CAPEC:      ?cwe cwe:hasCAPEC ?capec . ?capec capec:name ?name .
"""

def _safe_read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def _format_table(rows, columns, limit: int = 10) -> str:
    rows = rows[:limit]
    if not rows:
        return "_No data found._"
    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join(["---"] * len(columns)) + " |"
    body = []
    for row in rows:
        body.append("| " + " | ".join(str(row.get(col, "")) for col in columns) + " |")
    return "\n".join([header, separator] + body)

def _has_data(data: Dict[str, Any]) -> bool:
    """True bila schema report benar-benar berisi (bukan hasil scan graph kosong)."""
    for gr in data.get("graphs_report", []) or []:
        tc = gr.get("triple_count") or []
        if tc and str(tc[0].get("triple_count", "0")) not in ("0", ""):
            return True
    return False

def build_ontology_context(schema_json_path: Path = DEFAULT_SCHEMA_JSON) -> str:
    data = _safe_read_json(schema_json_path)
    if not data:
        return FALLBACK_CONTEXT.strip()

    lines = [FALLBACK_CONTEXT.strip(), "", "DISCOVERED GRAPH SUMMARY:",
             f"- Graph count: {data.get('graph_count', 'n/a')}", ""]

    first_graph = graphs_report[0]
    lines.extend(
        [
            "TOP CLASSES:",
            _format_table(first_graph.get("top_classes", []), ["class", "count"], limit=10),
            "",
            "TOP PREDICATES:",
            _format_table(first_graph.get("top_predicates", []), ["predicate", "count"], limit=10),
            "",
            "CURATED CLASSES:",
            _format_table(first_graph.get("curated_classes", []), ["class", "label", "count"], limit=10),
            "",
            "CURATED RELATIONS:",
            _format_table(first_graph.get("curated_relations", []), ["predicate", "label", "count"], limit=10),
            "",
            "COMMON QUERY SHAPES:",
            '1. CVE lookup by ID: ?cve cve:cveId "CVE-2021-44228" ; cve:description ?description .',
            "2. CVE -> CWE: ?cve cve:cveId ?cveId ; cve:hasCWE ?cwe .",
            "3. CVE -> CAPEC: ?cve cve:cveId ?cveId ; cve:hasCAPEC ?capec .",
            "4. CVE -> CPE: ?cve cve:cveId ?cveId ; cve:hasCPE ?cpe .",
        ]
    )
    
    return "\n".join(lines).strip()

def ontology_summary() -> str:
    return build_ontology_context()

# supaya file lama yang import ONTOLOGY_CONTEXT tetap jalan
ONTOLOGY_CONTEXT = ontology_summary()