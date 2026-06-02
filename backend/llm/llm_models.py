from __future__ import annotations
 
from typing import Any, Dict, List, Optional
 
import requests
from langchain_core.callbacks.manager import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage,)
from langchain_core.outputs import ChatGeneration, ChatResult

from langchain_ollama import ChatOllama
 
from backend.config import (
    DEFAULT_MODEL,
    LLM_PROVIDER,
    SUPPORTED_MODEL_NAMES,
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_SITE_URL,
    OPENROUTER_APP_NAME,
    OLLAMA_BASE_URL,
    LLM_TIMEOUT,
)

_KNOWN_PROVIDERS = {"openrouter", "ollama"}

class ChatOpenRouter(BaseChatModel):
    model_name: str
    api_key: str
    base_url: str = "https://openrouter.ai/api/v1"
    temperature: float = 0.0
    timeout: int = 60
    extra_headers: Optional[Dict[str, str]] = None

    model_config = {"protected_namespaces": ()}
 
    @property
    def _llm_type(self) -> str:
        return "openrouter-chat"
 
    @property
    def _identifying_params(self) -> Dict[str, Any]:
        return {"model_name": self.model_name, "base_url": self.base_url}
 
    @staticmethod
    def _role_of(message: BaseMessage) -> str:
        if isinstance(message, SystemMessage):
            return "system"
        if isinstance(message, AIMessage):
            return "assistant"
        if isinstance(message, ToolMessage):
            return "tool"
        return "user"  # HumanMessage & lainnya
 
    def _to_payload_messages(self, messages: List[BaseMessage]) -> List[Dict[str, str]]:
        payload: List[Dict[str, str]] = []
        for m in messages:
            content = m.content if isinstance(m.content, str) else str(m.content)
            payload.append({"role": self._role_of(m), "content": content})
        return payload
 
    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        body: Dict[str, Any] = {
            "model": self.model_name,
            "messages": self._to_payload_messages(messages),
            "temperature": self.temperature,
        }
        if stop:
            body["stop"] = stop

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.extra_headers:
            headers.update(self.extra_headers)

        url = f"{self.base_url.rstrip('/')}/chat/completions"
        resp = requests.post(url, json=body, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()

        if data.get("error"):
            raise RuntimeError(f"OpenRouter error: {data['error']}")

        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError("OpenRouter tidak mengembalikan choices.")

        msg = choices[0].get("message", {}) or {}
        content = msg.get("content") or msg.get("reasoning") or ""

        ai = AIMessage(content=content)
        usage = data.get("usage") or {}
        generation = ChatGeneration(message=ai)
        return ChatResult(
            generations=[generation],
            llm_output={"model_name": data.get("model", self.model_name), "usage": usage},
        )

def _split_provider(model_name: str):
    """Kembalikan (provider | None, model_id)."""
    if ":" in model_name:
        head, tail = model_name.split(":", 1)
        if head.lower() in _KNOWN_PROVIDERS and tail:
            return head.lower(), tail
    return None, model_name

def _normalize_ollama_base_url(url: str) -> str:
    """ChatOllama memakai API native, jadi buang sufiks '/v1' bila ada."""
    url = (url or "").rstrip("/")
    if url.endswith("/v1"):
        url = url[: -len("/v1")]
    return url or "http://localhost:11434"



def _build(provider: str, model_id: str):
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

        return ChatOpenRouter(
            model_name=model_id,
            api_key=OPENROUTER_API_KEY,
            base_url=OPENROUTER_BASE_URL,
            temperature=0,
            timeout=LLM_TIMEOUT,
            extra_headers=headers or None,
        )

    if provider == "ollama":        
        return ChatOllama(
            model=model_id,
            temperature=0,
            api_key="ollama",
            base_url=_normalize_ollama_base_url(OLLAMA_BASE_URL),
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