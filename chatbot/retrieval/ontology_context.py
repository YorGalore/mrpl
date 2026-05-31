from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_SCHEMA_JSON = Path("docs/knowledge_graph_schema.json")

"""
Ontology context untuk NL2SPARQL.
"""

ONTOLOGY_CONTEXT = """

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

KEY CLASSES:
- cve:CVE
- cwe:CWE
- capec:AttackPattern
- attack:Technique
- vuln:Vulnerability
- cpe:CPE
- cvss:CVSS
- rdfs:Resource

KEY PROPERTIES:
- cve:cveId
- cve:id
- cve:description
- cve:publishedDate
- cve:modifiedDate
- cve:hasCWE
- cve:hasCPE
- cve:hasCAPEC
- cve:hasCVSS
- cwe:cweId
- cwe:description
- capec:capecId
- capec:description
- attack:technique
- vuln:severity
- vuln:relatedTo
- attack:targets
- attack:uses

COMMON QUERY SHAPES:
1. CVE lookup by ID
   SELECT ?description WHERE {
     ?cve cve:cveId "CVE-2021-44228" ;
          cve:description ?description .
   }

2. CVE -> CWE relationship
   SELECT ?cveId ?cwe WHERE {
     ?cve cve:cveId ?cveId ;
          cve:hasCWE ?cwe .
   }

3. CVE -> CPE affected product
   SELECT ?cveId ?cpe WHERE {
     ?cve cve:cveId ?cveId ;
          cve:hasCPE ?cpe .
   }

4. CAPEC / attack pattern exploration
   SELECT ?pattern ?label WHERE {
     ?pattern a capec:AttackPattern ;
              rdfs:label ?label .
   }

RELATIONSHIPS:
- vuln:relatedTo
- attack:targets
- attack:uses
- cve:hasWeakness
"""

def _safe_read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def _format_table(rows: List[Dict[str, Any]], columns: List[str], limit: int = 10) -> str:
    rows = rows[:limit]
    if not rows:
        return "_No data found._"
    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join(["---"] * len(columns)) + " |"
    body = []
    for row in rows:
        body.append("| " + " | ".join(str(row.get(col, "")) for col in columns) + " |")
    return "\n".join([header, separator] + body)

def build_ontology_context(schema_json_path: Path = DEFAULT_SCHEMA_JSON) -> str:
    data = _safe_read_json(schema_json_path)
    if not data:
        return FALLBACK_CONTEXT.strip()

    lines: List[str] = [
        "PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>",
        "PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>",
        "PREFIX dct: <http://purl.org/dc/terms/>",
        "PREFIX cve: <http://w3id.org/sepses/vocab/ref/cve#>",
        "PREFIX cwe: <http://w3id.org/sepses/vocab/ref/cwe#>",
        "PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>",
        "PREFIX attack: <http://w3id.org/sepses/vocab/ref/attack#>",
        "PREFIX vuln: <http://w3id.org/sepses/vocab/vulnerability#>",
        "PREFIX cpe: <http://w3id.org/sepses/vocab/ref/cpe#>",
        "PREFIX cvss: <http://w3id.org/sepses/vocab/ref/cvss#>",
        "",
        "DISCOVERED GRAPH SUMMARY:",
        f"- Graph count: {data.get('graph_count', 'n/a')}",
        "",
    ]

    graphs_report = data.get("graphs_report", [])
    if not graphs_report:
        return "\n".join(lines).strip()

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
    return ONTOLOGY_CONTEXT.strip()