from chatbot.api.sparql_client import run_query

PREFIX = """
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
"""

def retrieve_vulnerability(keyword):
    query = PREFIX + f"""
    SELECT ?s ?label
    WHERE {{
        ?s rdfs:label ?label .
        FILTER(CONTAINS(
            LCASE(str(?label)),
            LCASE("{keyword}")
        ))
    }}
    LIMIT 10
    """

    return run_query(query)