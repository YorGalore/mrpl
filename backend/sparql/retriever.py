from __future__ import annotations
from typing import Dict, Any, List, Optional
from backend.config import DEFAULT_GRAPH
from backend.sparql.client import (
    PREFIXES, bindings_to_rows, run_query, escape_sparql_literal,
)

# Default SEPSES Graph URIs
CAPEC_GRAPH = DEFAULT_GRAPH
CWE_GRAPH = DEFAULT_GRAPH
SNORT_GRAPH = DEFAULT_GRAPH

# Generic Retrieval Helpers
def _run_select(query: str):
    result = run_query(query)
    return bindings_to_rows(result)

def _graph_clause(graph_uri: Optional[str], pattern: str) -> str:
    if graph_uri:
        return f"GRAPH <{graph_uri}> {{ {pattern} }}"
    return pattern

def search_labels(keyword: str, *, graph_uri: Optional[str] = None, limit: int = 10):
    safe = escape_sparql_literal(keyword)
    clause = _graph_clause(
        graph_uri,
        f'?s rdfs:label ?label . FILTER(CONTAINS(LCASE(STR(?label)), LCASE("{safe}")))',
    )
    query = f"""{PREFIXES}
SELECT DISTINCT ?s ?label WHERE {{ {clause} }}
ORDER BY LCASE(STR(?label)) LIMIT {int(limit)}"""
    return _run_select(query)

def get_graph_statistics(graph_uri: Optional[str] = None):
    clause = _graph_clause(graph_uri, "?s ?p ?o .")
    query = f"""{PREFIXES}
SELECT (COUNT(*) AS ?triple_count) WHERE {{ {clause} }}"""
    return _run_select(query)


def list_entity_classes(graph_uri: Optional[str] = None, limit: int = 100):
    clause = _graph_clause(graph_uri, "?s rdf:type ?class .")
    query = f"""{PREFIXES}
SELECT ?class (COUNT(*) AS ?count) WHERE {{ {clause} }}
GROUP BY ?class ORDER BY DESC(?count) LIMIT {int(limit)}"""
    return _run_select(query)


def build_llm_context(rows: List[Dict[str, str]], max_items: int = 10) -> str:
    if not rows:
        return "No relevant cybersecurity knowledge found."
    return "\n".join(
        " | ".join(f"{k}: {v}" for k, v in row.items()) for row in rows[:max_items]
    )

# Quick Testing

if __name__ == "__main__":
    print(get_graph_statistics())