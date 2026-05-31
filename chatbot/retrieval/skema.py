from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from chatbot.api.sparql_client import (
    DEFAULT_GRAPH,
    bindings_to_rows,
    count_distinct_entities,
    count_triples,
    count_instances_of,
    count_predicate_usage,
    describe_entity,
    describe_entity_neighbors,
    list_classes,
    list_named_graphs,
    list_predicates,
    sample_triples,
    sample_instances_of,
    search_labels,
)

CURATED_CLASSES: Sequence[Tuple[str, str]] = (
    ("cve:CVE", "CVE"),
    ("cwe:CWE", "CWE"),
    ("capec:AttackPattern", "CAPEC Attack Pattern"),
    ("attack:Technique", "ATT&CK Technique"),
    ("vuln:Vulnerability", "Vulnerability"),
    ("cpe:CPE", "CPE"),
    ("cvss:CVSS", "CVSS"),
)

CURATED_RELATIONS: Sequence[Tuple[str, str]] = (
    ("cve:hasCWE", "CVE → CWE"),
    ("cve:hasCAPEC", "CVE → CAPEC"),
    ("cve:hasCPE", "CVE → CPE"),
    ("cve:hasCVSS", "CVE → CVSS"),
    ("vuln:relatedTo", "Vulnerability → Related"),
    ("attack:targets", "ATT&CK → Targets"),
    ("attack:uses", "ATT&CK → Uses"),
)

@dataclass
class DiscoveryOptions:
    graph_uri: Optional[str] = None
    class_limit: int = 20
    predicate_limit: int = 20
    sample_limit: int = 10
    label_keyword: Optional[str] = None
    entity_iri: Optional[str] = None

@dataclass
class GraphReport:
    graph_uri: Optional[str]
    triple_count: List[Dict[str, str]] = field(default_factory=list)
    entity_count: List[Dict[str, str]] = field(default_factory=list)
    top_classes: List[Dict[str, str]] = field(default_factory=list)
    top_predicates: List[Dict[str, str]] = field(default_factory=list)
    sample_triples: List[Dict[str, str]] = field(default_factory=list)
    label_hits: List[Dict[str, str]] = field(default_factory=list)
    entity_neighborhood: List[Dict[str, str]] = field(default_factory=list)
    curated_classes: List[Dict[str, str]] = field(default_factory=list)
    curated_relations: List[Dict[str, str]] = field(default_factory=list)

@dataclass
class DiscoveryReport:
    endpoint_graph: Optional[str]
    graph_count: int = 0
    graphs: List[Dict[str, str]] = field(default_factory=list)
    triple_count: Dict[str, Any] = field(default_factory=dict)
    entity_count: Dict[str, Any] = field(default_factory=dict)
    top_classes: List[Dict[str, str]] = field(default_factory=list)
    top_predicates: List[Dict[str, str]] = field(default_factory=list)
    sample_triples: List[Dict[str, str]] = field(default_factory=list)
    label_hits: List[Dict[str, str]] = field(default_factory=list)
    entity_neighborhood: List[Dict[str, str]] = field(default_factory=list)

class SepsesSchemaInspector:
    def __init__(self, graph_uri: Optional[str] = None):
        self.graph_uri = graph_uri or DEFAULT_GRAPH

    def discover_graphs(self) -> List[Dict[str, str]]:
        return bindings_to_rows(list_named_graphs())

    def discover_triple_count(self) -> Dict[str, Any]:
        return count_triples(graph_uri=self.graph_uri)

    def discover_entity_count(self) -> Dict[str, Any]:
        return count_distinct_entities(graph_uri=self.graph_uri)

    def discover_top_classes(self, limit: int = 25) -> List[Dict[str, str]]:
        return bindings_to_rows(list_classes(graph_uri=self.graph_uri, limit=limit))

    def discover_top_predicates(self, limit: int = 25) -> List[Dict[str, str]]:
        return bindings_to_rows(list_predicates(graph_uri=self.graph_uri, limit=limit))

    def discover_sample_triples(self, limit: int = 25) -> List[Dict[str, str]]:
        return bindings_to_rows(sample_triples(graph_uri=self.graph_uri, limit=limit))

    def discover_labels(self, keyword: str, limit: int = 25) -> List[Dict[str, str]]:
        return bindings_to_rows(search_labels(keyword, graph_uri=self.graph_uri, limit=limit))

    def discover_entity_neighborhood(self, entity_iri: str, limit: int = 50) -> List[Dict[str, str]]:
        return bindings_to_rows(
            describe_entity_neighbors(entity_iri, graph_uri=self.graph_uri, limit=limit))

    def discover_curated_class_stats(self, graph_uri: Optional[str], limit: int) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        for class_term, label in CURATED_CLASSES:
            count_rows = bindings_to_rows(count_instances_of(class_term, graph_uri=graph_uri))
            count_value = count_rows[0]["count"] if count_rows else "0"
            samples = bindings_to_rows(sample_instances_of(class_term, graph_uri=graph_uri, limit=limit))
            sample_values = []
            for sample in samples:
                entity = sample.get("entity", "")
                name = sample.get("label", "") or entity
                if name:
                    sample_values.append(name)
            rows.append(
                {
                    "class": class_term,
                    "label": label,
                    "count": count_value,
                    "samples": "; ".join(sample_values[:limit]),
                }
            )
        return rows
        
    def discover_curated_relation_stats(self, graph_uri: Optional[str], limit: int) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        for predicate_term, label in CURATED_RELATIONS:
            count_rows = bindings_to_rows(count_predicate_usage(predicate_term, graph_uri=graph_uri))
            count_value = count_rows[0]["count"] if count_rows else "0"
            rows.append(
                {
                    "predicate": predicate_term,
                    "label": label,
                    "count": count_value,
                }
            )
        return rows

    def build_report(self, options: DiscoveryOptions) -> DiscoveryReport:
        graphs = self.discover_graphs()
        report = DiscoveryReport(
            endpoint_graph=self.graph_uri,
            graph_count=len(graphs),
            graphs=graphs,
            triple_count=bindings_to_rows(self.discover_triple_count()),
            entity_count=bindings_to_rows(self.discover_entity_count()),
            top_classes=self.discover_top_classes(limit=options.class_limit),
            top_predicates=self.discover_top_predicates(limit=options.predicate_limit),
            sample_triples=self.discover_sample_triples(limit=options.sample_limit),
        )
        if options.label_keyword:
            report.label_hits = self.discover_labels(options.label_keyword, limit=options.sample_limit)
        if options.entity_iri:
            report.entity_neighborhood = self.discover_entity_neighborhood(
                options.entity_iri, limit=options.sample_limit
            )
        return report

    @staticmethod
    def render_markdown(report: DiscoveryReport) -> str:
        def table(rows: List[Dict[str, str]], columns: List[str]) -> str:
            if not rows:
                return "_No results._"
            header = "| " + " | ".join(columns) + " |"
            sep = "| " + " | ".join(["---"] * len(columns)) + " |"
            lines = [header, sep]
            for row in rows:
                lines.append("| " + " | ".join(row.get(col, "") for col in columns) + " |")
            return "\n".join(lines)

        triple_count = report.triple_count[0]["triple_count"] if report.triple_count else "n/a"
        subj_count = report.entity_count[0]["subjects"] if report.entity_count else "n/a"
        obj_count = report.entity_count[0]["objects"] if report.entity_count else "n/a"

        md = [
            "# SEPSES CSKG Structure Report",
            "",
            f"- Endpoint graph: `{report.endpoint_graph}`",
            f"- Named graphs discovered: `{report.graph_count}`",
            f"- Triples: `{triple_count}`",
            f"- Distinct subjects: `{subj_count}`",
            f"- Distinct objects: `{obj_count}`",
            "",
            "## Named graphs",
            table(report.graphs[:25], ["graph"]),
            "",
            "## Top classes",
            table(report.top_classes, ["class", "count"]),
            "",
            "## Top predicates",
            table(report.top_predicates, ["predicate", "count"]),
            "",
            "## Sample triples",
            table(report.sample_triples, ["s", "p", "o"]),
        ]
        if report.label_hits:
            md.extend(["", "## Label search results", table(report.label_hits, ["s", "label"])])
        if report.entity_neighborhood:
            md.extend(
                [
                    "",
                    "## Entity neighborhood",
                    table(report.entity_neighborhood, ["direction", "predicate", "predicateLabel", "neighbor"]),
                ]
            )
        return "\n".join(md).strip() + "\n"

    @staticmethod
    def to_json(report: DiscoveryReport) -> Dict[str, Any]:
        return {
            "endpoint_graph": report.endpoint_graph,
            "graph_count": report.graph_count,
            "graphs": report.graphs,
            "graphs_report":[
                {
                    "graph_uri": graph_report.graph_uri,
                    "triple_count": graph_report.triple_count,
                    "entity_count": graph_report.entity_count,
                    "top_classes": graph_report.top_classes,
                    "top_predicates": graph_report.top_predicates,
                    "sample_triples": graph_report.sample_triples,
                    "label_hits": graph_report.label_hits,
                    "entity_neighborhood": graph_report.entity_neighborhood,
                    "curated_classes": graph_report.curated_classes,
                    "curated_relations": graph_report.curated_relations,
                }
                for graph_report in report.graphs_report
            ],
        }

    def save_report(self, report: DiscoveryReport, output_dir: str | Path) -> tuple[Path, Path]:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        json_path = output_path / "sepses_cskg_structure.json"
        md_path = output_path / "sepses_cskg_structure.md"

        json_path.write_text(json.dumps(self.to_json(report), indent=2, ensure_ascii=False), encoding="utf-8")
        md_path.write_text(self.render_markdown(report), encoding="utf-8")
        return json_path, md_path

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect SEPSES CSKG structure through a SPARQL endpoint."
    )
    parser.add_argument("--graph", default=DEFAULT_GRAPH, help="Named graph URI to inspect.")
    parser.add_argument("--class-limit", type=int, default=25)
    parser.add_argument("--predicate-limit", type=int, default=25)
    parser.add_argument("--sample-limit", type=int, default=25)
    parser.add_argument("--label", default=None, help="Keyword for rdfs:label search.")
    parser.add_argument("--entity", default=None, help="Entity IRI to inspect neighborhood.")
    parser.add_argument("--output-dir", default="docs", help="Directory to write JSON/Markdown report.")
    return parser

def main() -> None:
    args = build_arg_parser().parse_args()
    inspector = SepsesSchemaInspector(graph_uri=args.graph)
    options = DiscoveryOptions(
        graph_uri=args.graph,
        class_limit=args.class_limit,
        predicate_limit=args.predicate_limit,
        sample_limit=args.sample_limit,
        label_keyword=args.label,
        entity_iri=args.entity,
    )
    report = inspector.build_report(options)
    json_path, md_path = inspector.save_report(report, args.output_dir)

    print(f"Saved JSON report: {json_path}")
    print(f"Saved Markdown report: {md_path}")
    print()
    print(inspector.render_markdown(report))

if __name__ == "__main__":
    main()
