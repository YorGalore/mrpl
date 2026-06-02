from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from backend.config import DEFAULT_MODEL, SPARQL_PUBLIC_ENDPOINT, SUPPORTED_MODEL_NAMES
from backend.llm.llm_models import LLMProvider
from backend.logs.vector_store import search_logs
from backend.patterns import LOG_KEYWORDS, MALWARE_KEYWORDS, MITRE_GENERAL_KEYWORDS, THREAT_KEYWORDS, extract_actor_name, find_cve, find_cwe
from backend.pipeline.prompts import system_prompt_for
from backend.sparql.client import PREFIXES, SPARQLConfig, VirtuosoClient, bindings_to_rows
from backend.sparql.graph_context import build_attack_chain_context
from backend.sparql.nl2sparql import generate_sparql, run_kg_query
from backend.threat.modul_threat import get_malware_context, get_threat_context, search_mitre_general
from backend.threat.modul_vulnerability import get_vuln_context

def _local_name(uri: str) -> str:
    parts = re.split(r"[#/]", uri.rstrip("#/"))
    return parts[-1] if parts and parts[-1] else uri

def query_router(mode: str, message: str) -> Dict[str, bool]:
    """Tentukan sumber data berdasarkan mode + isi pertanyaan (Issue #04)."""
    q = message.lower()
    want_kg = mode in ("threat_intelligence", "combined")
    want_logs = mode in ("log_analysis", "combined") or any(kw in q for kw in LOG_KEYWORDS)
    want_mitre_general = any(kw in q for kw in MITRE_GENERAL_KEYWORDS)
    return {"kg": want_kg, "logs": want_logs, "mitre_general": want_mitre_general}

def _cve_triples(cve_id: str, limit: int = 25) -> List[Dict[str, str]]:
    """Relasi CVE dari endpoint SEPSES publik untuk visualisasi graph (Issue #03)."""
    try:
        client = VirtuosoClient(
            SPARQLConfig(endpoint=SPARQL_PUBLIC_ENDPOINT, default_graph=None, infer=False)
        )
        query = f"""{PREFIXES}
        SELECT ?p ?o WHERE {{
            ?cve cve:id "{cve_id}" .
            ?cve ?p ?o .
        }} LIMIT {int(limit)}"""
        rows = bindings_to_rows(client.run_query(query, default_graph=None, infer=False))
        return [
            {
                "subject": cve_id,
                "predicate": _local_name(r.get("p", "")),
                "object": _local_name(r.get("o", "")),
                "source": SPARQL_PUBLIC_ENDPOINT,
            }
            for r in rows
        ]
    except Exception:
        return []


def _cwe_triples(cwe_id: str, limit: int = 25) -> List[Dict[str, str]]:
    try:
        client = VirtuosoClient(
            SPARQLConfig(endpoint=SPARQL_PUBLIC_ENDPOINT, default_graph=None, infer=False)
        )
        query = f"""{PREFIXES}
        SELECT ?p ?o WHERE {{
            ?cwe cwe:id "{cwe_id}" .
            ?cwe ?p ?o .
        }} LIMIT {int(limit)}"""
        rows = bindings_to_rows(client.run_query(query, default_graph=None, infer=False))
        return [
            {
                "subject": cwe_id,
                "predicate": _local_name(r.get("p", "")),
                "object": _local_name(r.get("o", "")),
                "source": SPARQL_PUBLIC_ENDPOINT,
            }
            for r in rows
        ]
    except Exception:
        return []
    
    
def _kg_retrieve(message: str, model: str) -> Dict[str, Any]:
    """Retrieval dari knowledge graph (Issue #03): konteks, triples, sources, sparql, method."""
    parts: List[str] = []
    sources: List[str] = []
    triples: List[Dict[str, str]] = []
    sparql_used: Optional[str] = None
    method: Optional[str] = None

    q = message.lower()

    # --- Enrichment human-readable untuk pola yang dikenal (regex/keyword default) ---
    cve_id = find_cve(message)
    cwe_id = find_cwe(message)
    if cve_id:
        try:
            parts.append(get_vuln_context(cve_id))
            parts.append(build_attack_chain_context(cve_id))
            sources.append(SPARQL_PUBLIC_ENDPOINT)
        except Exception as e:
            parts.append(f"[vuln lookup gagal: {e}]")
        triples.extend(_cve_triples(cve_id))

    if cwe_id and not cve_id:
        triples.extend(_cwe_triples(cwe_id))
        sources.append(SPARQL_PUBLIC_ENDPOINT)

    if any(kw in q for kw in THREAT_KEYWORDS):
        actor_name = extract_actor_name(message)       # mis. 'APT41' bukan 'apt'
        if actor_name:
            try:
                ctx = get_threat_context(actor_name)
                parts.append(ctx)
                sources.append("MITRE ATT&CK")
            except Exception as e:
                parts.append(f"[threat lookup gagal untuk '{actor_name}': {e}]")

    if any(kw in q for kw in MALWARE_KEYWORDS):
        # Ambil keyword malware terpanjang yang match (lebih spesifik)
        matched_kw = max(
            (kw for kw in MALWARE_KEYWORDS if kw in q),
            key=len,
            default=None,
        )
        if matched_kw:
            try:
                ctx = get_malware_context(matched_kw)
                parts.append(ctx)
                sources.append("MITRE ATT&CK")
            except Exception as e:
                parts.append(f"[malware lookup gagal untuk '{matched_kw}': {e}]")

    if any(kw in q for kw in MITRE_GENERAL_KEYWORDS):
        try:
            ctx = search_mitre_general(message)
            if ctx:
                parts.append(ctx)
                sources.append("MITRE ATT&CK (Techniques)")
        except Exception as e:
            parts.append(f"[mitre general search gagal: {e}]")

    # --- NL2SPARQL: jalur generik (regex fast-path lalu LLM) ---
    # FIX BUG 5: Bungkus seluruh blok dalam try/except yang lebih ketat.
    try:
        sparql_used, method = generate_sparql(message, model=model)
        rows = run_kg_query(sparql_used)
        if rows:
            preview = rows[:10]
            lines = [" | ".join(f"{k}: {v}" for k, v in row.items()) for row in preview]
            parts.append("=== Hasil SPARQL (KG) ===\n" + "\n".join(lines))
            sources.append("SEPSES CSKG (SPARQL)")
    except Exception as e:
        # Jangan crash — catat sebagai info debug, bukan append ke parts
        print(f"[orchestrator] NL2SPARQL/SPARQL gagal (non-fatal): {e}")
        # Hanya set method jika belum ada hasil lain
        if not parts:
            method = "error"

    return {
        "context": "\n\n".join(p for p in parts if p),
        "sources": sources,
        "triples": triples,
        "sparql": sparql_used,
        "method": method,
    }


def _history_messages(history: Optional[List[Dict[str, str]]]):
    msgs = []
    for item in history or []:
        role = (item.get("role") or "").lower()
        content = item.get("content") or ""
        if not content:
            continue
        if role == "user":
            msgs.append(HumanMessage(content=content))
        elif role == "assistant":
            msgs.append(AIMessage(content=content))
    return msgs

MAX_CONTEXT_CHARS = 6000

def _collect_context(
    message: str,
    mode: str,
    model: str,
    history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:

    route = query_router(mode, message)
    parts: List[str] = []
    sources: List[str] = []
    triples: List[Dict[str, str]] = []
    sparql_used: Optional[str] = None
    method: Optional[str] = None

    if route["kg"]:
        kg = _kg_retrieve(message, model)
        if kg["context"]:
            parts.append(kg["context"])
        sources.extend(kg["sources"])
        triples.extend(kg["triples"])
        sparql_used = kg["sparql"]
        method = kg["method"]

    if not route["kg"] and route.get("mitre_general"):
        try:
            ctx = search_mitre_general(message)
            if ctx:
                parts.append(ctx)
                sources.append("MITRE ATT&CK (Techniques)")
        except Exception as e:
            print(f"[orchestrator] mitre_general gagal: {e}")

    if route["logs"]:
        try:
            log_result = search_logs(message)
            if log_result:
                parts.append(log_result)
            sources.append("Local security logs (ChromaDB)")
        except Exception as e:
            parts.append(f"[log search gagal: {e}]")

    context = "\n\n".join(p for p in parts if p)
    if len(context) > MAX_CONTEXT_CHARS:
        context = context[:MAX_CONTEXT_CHARS] + "\n…[konteks dipotong agar LLM tetap responsif]"

    return {
        "context": context,
        "sources": list(dict.fromkeys(sources)),
        "triples": triples,
        "sparql": sparql_used,
        "method": method,
    }


def _synthesize(
    context: str,
    message: str,
    mode: str,
    model: str,
    history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:

    if context:
        user_msg = f"Konteks data keamanan:\n{context}\n\nPertanyaan: {message}"
    else:
        user_msg = (
            f"Pertanyaan: {message}\n"
            "(Tidak ada data spesifik ditemukan di knowledge graph / MITRE untuk pertanyaan ini. "
            "Jawab berdasarkan pengetahuan umum keamanan siber.)"
        )

    resolved_model = model
    try:
        llm = LLMProvider.get_model(model)
        resolved_model = getattr(llm, "model_name", None) or model
        messages = [SystemMessage(content=system_prompt_for(mode))]
        messages.extend(_history_messages(history))
        messages.append(HumanMessage(content=user_msg))
        resp = llm.invoke(messages)
        return {"message": resp.content, "llmUsed": resolved_model, "ok": True, "error": None}
    except Exception as e:
        msg = (
            f"⚠️ Model '{model}' gagal menjawab: {e}\n\n"
            "Catatan: ini hanya memengaruhi model ini; model pembanding lain tetap berjalan "
            "independen. Untuk model 'openrouter:...' pastikan OPENROUTER_API_KEY valid di .env; "
            "untuk model 'ollama:...' pastikan `ollama serve` berjalan & model sudah di-pull.\n\n"
            + (f"Konteks GraphRAG yang berhasil diambil:\n{context}" if context else "")
        )
        return {"message": msg, "llmUsed": resolved_model, "ok": False, "error": str(e)}


def answer(
    message: str,
    mode: str = "threat_intelligence",
    model: str = DEFAULT_MODEL,
    history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Jawaban dari SATU LLM (alur chat normal). Dipakai endpoint /api/chat."""
    ctx = _collect_context(message, mode, model, history)
    syn = _synthesize(ctx["context"], message, mode, model, history)
    return {
        "message": syn["message"],
        "triples": ctx["triples"],
        "llmUsed": syn["llmUsed"],
        "sources": ctx["sources"],
        "method": ctx["method"],
        "sparql": ctx["sparql"],
    }


def compare(
    message: str,
    models: Optional[List[str]] = None,
    mode: str = "threat_intelligence",
    history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Bandingkan beberapa LLM atas KONTEKS YANG SAMA (fokus utama proyek).

    Retrieval GraphRAG dijalankan SEKALI, lalu tiap model menjawab konteks yang
    identik -> perbandingan adil (perbedaan jawaban murni dari kemampuan model,
    bukan dari data yang berbeda). Dipakai endpoint /api/compare.
    """
    use_models = [m for m in (models or list(SUPPORTED_MODEL_NAMES)) if m]
    if not use_models:
        use_models = [DEFAULT_MODEL]

    # NL2SPARQL memakai model pertama HANYA untuk membangun query; konteks dipakai bersama.
    ctx = _collect_context(message, mode, use_models[0], history)

    answers: List[Dict[str, Any]] = []
    for m in use_models:
        start = time.perf_counter()
        syn = _synthesize(ctx["context"], message, mode, m, history)
        latency = round(time.perf_counter() - start, 3)
        answers.append({
            "model": m,
            "llmUsed": syn["llmUsed"],
            "message": syn["message"],
            "ok": syn["ok"],
            "error": syn["error"],
            "latencySec": latency,
        })

    return {
        "question": message,
        "mode": mode,
        "answers": answers,
        "triples": ctx["triples"],
        "sources": ctx["sources"],
        "method": ctx["method"],
        "sparql": ctx["sparql"],
    }


if __name__ == "__main__":
    import json
    print("=== Test: APT41 ===")
    print(json.dumps(answer("What is APT41?"), indent=2, ensure_ascii=False))
    print()
    print("=== Test: Link traffic anomalies ===")
    print(json.dumps(answer("Link traffic anomalies"), indent=2, ensure_ascii=False))
    print()
    print("=== Test: CVE-2017-0144 ===")
    print(json.dumps(answer("Apa bahaya dari CVE-2017-0144?"), indent=2, ensure_ascii=False))