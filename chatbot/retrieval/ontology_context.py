"""
Ontology context untuk NL2SPARQL.
"""

ONTOLOGY_CONTEXT = """

Classes:
- cve:CVE
- attack:AttackPattern
- vuln:Vulnerability

Properties:
- cve:cveId
- cve:description
- cve:publishedDate
- attack:technique
- vuln:severity

Relationships:
- vuln:relatedTo
- attack:targets

Example:
?cve cve:cveId "CVE-2021-44228" .

"""