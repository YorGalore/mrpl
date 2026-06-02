from __future__ import annotations
from backend.config import (
    DEFAULT_MODEL, LLM_PROVIDER, SUPPORTED_MODEL_NAMES, OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL, OPENROUTER_SITE_URL, OPENROUTER_APP_NAME, OLLAMA_BASE_URL, OPENAI_API_KEY, DEEPSEEK_API_KEY,
)
from langchain_openai import ChatOpenAI

_KNOWN_PROVIDERS = {"openrouter", "ollama", "openai", "deepseek"}

def _split_provider(model_name: str):
    """Kembalikan (provider | None, model_id)."""
    if ":" in model_name:
        head, tail = model_name.split(":", 1)
        if head.lower() in _KNOWN_PROVIDERS and tail:
            return head.lower(), tail
    return None, model_name

def _build(provider: str, model_id: str) -> ChatOpenAI:
    if provider == "openrouter":
        if not OPENROUTER_API_KEY:
            raise ValueError(
                "OPENROUTER_API_KEY belum diset. Daftar gratis di https://openrouter.ai "
                "lalu isi OPENROUTER_API_KEY di .env."
            )
        headers = {}
        if OPENROUTER_SITE_URL:
            headers["HTTP-Referer"] = OPENROUTER_SITE_URL
        if OPENROUTER_APP_NAME:
            headers["X-Title"] = OPENROUTER_APP_NAME
        return ChatOpenAI(
            model=model_id,
            temperature=0,
            api_key=OPENROUTER_API_KEY,
            base_url=OPENROUTER_BASE_URL,
            default_headers=headers or None,
        )

    if provider == "ollama":
        # Ollama menyediakan endpoint OpenAI-compatible di /v1; api_key diabaikan
        # oleh Ollama tetapi harus diisi string non-kosong oleh klien OpenAI.
        return ChatOpenAI(
            model=model_id,
            temperature=0,
            api_key="ollama",
            base_url=OLLAMA_BASE_URL,
        )

    if provider == "openai":
        if not OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY belum diset.")
        return ChatOpenAI(model=model_id, temperature=0, api_key=OPENAI_API_KEY)

    if provider == "deepseek":
        if not DEEPSEEK_API_KEY:
            raise ValueError("DEEPSEEK_API_KEY belum diset.")
        return ChatOpenAI(
            model=model_id,
            temperature=0,
            api_key=DEEPSEEK_API_KEY,
            base_url="https://api.deepseek.com",
        )

    raise ValueError(f"Provider LLM tidak dikenal: {provider}")

class LLMProvider:
    @staticmethod
    def get_model(model_name: str = DEFAULT_MODEL):
        name = (model_name or DEFAULT_MODEL).strip()
        provider, model_id = _split_provider(name)
        if provider is None:
            provider = LLM_PROVIDER
        return _build(provider, model_id)


# Dipertahankan untuk kompatibilitas (mis. introspeksi provider tiap model).
SUPPORTED_MODELS = {
    name: {"provider": (_split_provider(name)[0] or LLM_PROVIDER)}
    for name in SUPPORTED_MODEL_NAMES
}
