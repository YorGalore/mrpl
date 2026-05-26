"""
Ontology context untuk NL2SPARQL.
"""

ONTOLOGY_CONTEXT = """

PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

PREFIX cve: <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cwe: <http://w3id.org/sepses/vocab/ref/cwe#>
PREFIX capec: <http://w3id.org/sepses/vocab/ref/capec#>
PREFIX attack: <http://w3id.org/sepses/vocab/ref/attack#>
PREFIX vuln: <http://w3id.org/sepses/vocab/vulnerability#>

CLASSES:
- cve:CVE
- cwe:CWE
- capec:AttackPattern
- attack:Technique
- vuln:Vulnerability

PROPERTIES:
- cve:cveId
- cve:description
- cve:publishedDate
- vuln:severity
- attack:technique


RELATIONSHIPS:
- vuln:relatedTo
- attack:targets
- attack:uses
- cve:hasWeakness

EXAMPLE QUERY:

SELECT ?description
WHERE {
    ?cve cve:cveId "CVE-2021-44228" ;
         cve:description ?description .
}
LIMIT 10

"""