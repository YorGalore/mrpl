from dotenv import load_dotenv
import os

from langchain_openai import ChatOpenAI

load_dotenv()

#env
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEFAULT_MODEL = os.getenv(
    "DEFAULT_MODEL",
    "gpt-4o-mini"
)

class LLMProvider:
    @staticmethod
    def get_model(model_name: str = DEFAULT_MODEL):
        model_lower = model_name.lower()

        # OPENAI
        if "gpt" in model_lower or "openai" in model_lower:
            if not OPENAI_API_KEY:
                raise ValueError("OPENAI_API_KEY belum diset")
            return ChatOpenAI(
                model=model_name,
                temperature=0,
                api_key=OPENAI_API_KEY
            )

        # DEEPSEEK
        elif "deepseek" in model_lower:
            if not DEEPSEEK_API_KEY:
                raise ValueError("DEEPSEEK_API_KEY belum diset")
            return ChatOpenAI(
                model="deepseek-chat",
                temperature=0,
                api_key=DEEPSEEK_API_KEY,
                base_url="https://api.deepseek.com"
            )
        # FALLBACK
        else:
            raise ValueError(f"Model tidak dikenali: {model_name}")

