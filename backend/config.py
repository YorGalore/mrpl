import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "gpt-4o-mini")

SPARQL_ENDPOINT = os.getenv("SEPSES_SPARQL_ENDPOINT", "http://localhost:8890/sparql")
SPARQL_PUBLIC_ENDPOINT = os.getenv("SEPSES_PUBLIC_ENDPOINT", "https://sepses.ifs.tuwien.ac.at/sparql")
DEFAULT_GRAPH = os.getenv("SEPSES_DEFAULT_GRAPH", "http://sepses.local")
SPARQL_TIMEOUT = int(os.getenv("SEPSES_SPARQL_TIMEOUT", "60"))

BACKEND_PORT = int(os.getenv("BACKEND_PORT", "8000"))