from __future__ import annotations

import time
from typing import Optional

import requests

from backend.config import (
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    DEFAULT_MODEL,
    OPENROUTER_AUTO_CHEAPEST,
    OPENROUTER_CHEAPEST_FREE_ONLY,
    OPENROUTER_PRICING_TTL,
    SUPPORTED_MODEL_NAMES,
)

def _safe_fallback() -> str:
    for name in (DEFAULT_MODEL, *SUPPORTED_MODEL_NAMES):
        if name and name != OPENROUTER_AUTO_CHEAPEST:
            # buang prefix "openrouter:" bila ada
            return name.split("openrouter:", 1)[-1] if name.startswith("openrouter:") else name
    return "meta-llama/llama-3.3-70b-instruct:free"

_cache: dict[bool, tuple[str, float]] = {}


def _is_text_chat_model(model: dict) -> bool:
    arch = model.get("architecture") or {}
    inputs = [s.lower() for s in (arch.get("input_modalities") or [])]
    outputs = [s.lower() for s in (arch.get("output_modalities") or [])]
    if inputs or outputs:
        # Bila metadata modalitas tersedia: wajib bisa terima & keluarkan teks.
        return ("text" in inputs) and ("text" in outputs)
    # Fallback ke string modality (mis. "text->text") bila array kosong.
    modality = (arch.get("modality") or "").lower()
    return "text->text" in modality or modality == ""


def _price_of(model: dict) -> float:
    pricing = model.get("pricing") or {}
    try:
        prompt = float(pricing.get("prompt", "0") or 0)
        completion = float(pricing.get("completion", "0") or 0)
    except (TypeError, ValueError):
        return float("inf")
    return prompt + completion


def fetch_models() -> list[dict]:
    """Ambil katalog model OpenRouter (GET /models)."""
    url = f"{OPENROUTER_BASE_URL.rstrip('/')}/models"
    headers = {}
    if OPENROUTER_API_KEY:
        headers["Authorization"] = f"Bearer {OPENROUTER_API_KEY}"
    resp = requests.get(url, headers=headers, timeout=20)
    resp.raise_for_status()
    return resp.json().get("data", [])


def resolve_cheapest_model(free_only: Optional[bool] = None) -> str:
    """Kembalikan model id OpenRouter termurah.

    free_only=True  -> hanya model berharga $0 (gratis). Aman untuk demo/skripsi.
    free_only=False -> model berbayar termurah pun ikut dipertimbangkan.
    Jatuh ke DEFAULT_MODEL bila API gagal / katalog kosong.
    """
    if free_only is None:
        free_only = OPENROUTER_CHEAPEST_FREE_ONLY

    cached = _cache.get(free_only)
    if cached and (time.time() - cached[1]) < OPENROUTER_PRICING_TTL:
        return cached[0]

    try:
        models = fetch_models()
    except Exception:
        return _safe_fallback()  # offline/API error -> jangan mematikan chat

    candidates = []
    for m in models:
        mid = m.get("id") or ""
        if not mid or "auto" in mid.lower():  # hindari router rekursif
            continue
        if not _is_text_chat_model(m):
            continue
        price = _price_of(m)
        if free_only and price > 0:
            continue
        candidates.append((price, mid))

    if not candidates:
        return _safe_fallback()

    # Termurah dulu; pada harga sama: nama lebih pendek lalu alfabetis (deterministik).
    candidates.sort(key=lambda x: (x[0], len(x[1]), x[1]))
    cheapest = candidates[0][1]
    _cache[free_only] = (cheapest, time.time())
    return cheapest


if __name__ == "__main__":
    print("Cheapest FREE :", resolve_cheapest_model(free_only=True))
    print("Cheapest ANY  :", resolve_cheapest_model(free_only=False))