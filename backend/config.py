import os
from dotenv import load_dotenv

load_dotenv()

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openrouter").strip().lower()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_SITE_URL = os.getenv("OPENROUTER_SITE_URL", "")
OPENROUTER_APP_NAME = os.getenv("OPENROUTER_APP_NAME", "SEPSES CSKG Chatbot")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_NUM_PREDICT = int(os.getenv("OLLAMA_NUM_PREDICT", "1024"))
OLLAMA_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "8192"))

LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "120"))


def _parse_models(raw: "str | None") -> tuple:
    return tuple(m.strip() for m in (raw or "").split(",") if m.strip())

_DEFAULT_MODELS = "openrouter:deepseek/deepseek-r1:free,ollama:llama3.2:3b"
SUPPORTED_MODEL_NAMES = _parse_models(os.getenv("LLM_MODELS", _DEFAULT_MODELS)) or _parse_models(_DEFAULT_MODELS)

DEFAULT_MODEL = os.getenv("DEFAULT_MODEL") or (
    SUPPORTED_MODEL_NAMES[0] if SUPPORTED_MODEL_NAMES else "ollama:llama3.2:3b"
)

SPARQL_PUBLIC_ENDPOINT = os.getenv("SEPSES_PUBLIC_ENDPOINT", "https://sepses.ifs.tuwien.ac.at/sparql")
SPARQL_LOCAL_ENDPOINT = os.getenv("SEPSES_LOCAL_ENDPOINT", "http://localhost:8890/sparql")
def _clean_graph(value: "str | None") -> "str | None":
    if value is None:
        return None
    value = value.strip()
    return value or None
DEFAULT_GRAPH = _clean_graph(os.getenv("SEPSES_DEFAULT_GRAPH", ""))
LOCAL_GRAPH = _clean_graph(os.getenv("SEPSES_LOCAL_GRAPH", "http://sepses.local"))
ENABLE_LOCAL_FALLBACK = os.getenv("SEPSES_ENABLE_LOCAL_FALLBACK", "1").strip() not in (
    "0",
    "false",
    "False",
    "",
)
SPARQL_TIMEOUT = int(os.getenv("SEPSES_SPARQL_TIMEOUT", "20"))
BACKEND_PORT = int(os.getenv("BACKEND_PORT", "8000"))