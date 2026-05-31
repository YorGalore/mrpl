from backend.config import DEEPSEEK_API_KEY, DEFAULT_MODEL, OPENAI_API_KEY
from langchain_openai import ChatOpenAI

SUPPORTED_MODELS = {
    "gpt-4o-mini": {"provider": "openai"},
    "deepseek-chat": {"provider": "deepseek"}
}


class LLMProvider:

    @staticmethod
    def get_model(model_name: str = DEFAULT_MODEL):

        if model_name not in SUPPORTED_MODELS:
            raise ValueError(f"Unsupported model: {model_name}")

        provider = SUPPORTED_MODELS[model_name]["provider"]

        if provider == "openai":

            if not OPENAI_API_KEY:
                raise ValueError("OPENAI_API_KEY belum diset")

            return ChatOpenAI(model=model_name, temperature=0,
                api_key=OPENAI_API_KEY
            )

        if provider == "deepseek":
            if not DEEPSEEK_API_KEY:
                raise ValueError("DEEPSEEK_API_KEY belum diset")

            return ChatOpenAI(
                model="deepseek-chat",
                temperature=0,
                api_key=DEEPSEEK_API_KEY,
                base_url="https://api.deepseek.com"
            )