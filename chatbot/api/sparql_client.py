from SPARQLWrapper import SPARQLWrapper, JSON

# Virtuoso endpoint
SPARQL_ENDPOINT = "http://localhost:8890/sparql"

sparql = SPARQLWrapper(SPARQL_ENDPOINT)

query = """
SELECT ?s ?p ?o
FROM <http://sepses.ifs.tuwien.ac.at/data/capec>
WHERE {
    ?s ?p ?o
}
LIMIT 10
"""

sparql.setQuery(query)
sparql.setReturnFormat(JSON)

results = sparql.query().convert()

for result in results["results"]["bindings"]:
    s = result["s"]["value"]
    p = result["p"]["value"]
    o = result["o"]["value"]

    print("Subject  :", s)
    print("Predicate:", p)
    print("Object   :", o)
    print("-" * 50)