"""
RAG/GraphRAG orchestrator.
Lebur dari modul_a3/prompt_engineering.py (routing konteks) + modul_a3/use_case.py (alur).
Sumber: kontribusi modul_a3 (anggota tim) — disatukan di backend/pipeline/.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from langchain_core.messages import HumanMessage, SystemMessage

from backend.config import DEFAULT_MODEL, SPARQL_PUBLIC_ENDPOINT
from backend.llm.llm_models import LLMProvider
from backend.logs.vector_store import search_logs
from backend.threat.modul_threat import get_malware_context, get_threat_context
from backend.threat.modul_vulnerability import get_vuln_context

SYSTEM_PROMPT = """Kamu adalah analis keamanan siber yang ahli.
Jawab pertanyaan pengguna HANYA berdasarkan konteks data yang diberikan.
Jangan mengarang informasi di luar konteks.
Berikan jawaban yang jelas, terstruktur, dan actionable.
Jika data tidak tersedia, katakan dengan jujur."""

THREAT_KEYWORDS = ["apt", "lazarus", "fancy bear", "cozy bear", "kimsuky", "sandworm", "carbanak", "fin7", "turla"]
MALWARE_KEYWORDS = ["wannacry", "emotet", "mirai", "stuxnet", "notpetya", "ransomware", "trojan", "rootkit", "cobalt strike"]
LOG_KEYWORDS = ["log", "ssh", "login", "failed", "connection", "brute", "intrusion", "anomali", "mencurigakan", "reverse shell", "port scan"]

CVE_RE = re.compile(r"cve-\d{4}-\d+", re.IGNORECASE)

def _gather_context(message: str, mode: str) -> Dict[str, Any]:
    q = message.lower()
    parts: List[str] = []
    sources: List[str] = []
    cve_ids: List[str] = []

    want_threat = mode in ("threat_intelligence", "combined")
    want_logs = mode in ("log_analysis", "combined")

    if want_threat:
        m = CVE_RE.search(q)
        if m:
            cve_id = m.group().upper()
            cve_ids.append(cve_id)
            try:
                parts.append(get_vuln_context(cve_id))
                sources.append(SPARQL_PUBLIC_ENDPOINT)
            except Exception as e:
                parts.append(f"[vuln lookup gagal: {e}]")
        for kw in THREAT_KEYWORDS:
            if kw in q:
                parts.append(get_threat_context(kw))
                sources.append("MITRE ATT&CK")
                break
        for kw in MALWARE_KEYWORDS:
            if kw in q:
                parts.append(get_malware_context(kw))
                sources.append("MITRE ATT&CK")
                break

    if want_logs and (mode == "combined" or any(kw in q for kw in LOG_KEYWORDS)):
        try:
            parts.append(search_logs(message))
            sources.append("Local security logs (ChromaDB)")
        except Exception as e:
            parts.append(f"[log search gagal: {e}]")

    return {
        "context": "\n\n".join(p for p in parts if p),
        "sources": list(dict.fromkeys(sources)),
        "cve_ids": cve_ids,
    }


def _cve_triples(cve_id: str, limit: int = 25) -> List[Dict[str, str]]:
    """Ambil relasi CVE dari endpoint SEPSES publik untuk visualisasi graph."""
    try:
        from backend.sparql.client import (PREFIXES, SPARQLConfig,
                                            VirtuosoClient, bindings_to_rows)

        client = VirtuosoClient(SPARQLConfig(
            endpoint=SPARQL_PUBLIC_ENDPOINT, default_graph=None, infer=False))
        query = f"""{PREFIXES}
        SELECT ?p ?o WHERE {{
            ?cve cve:id "{cve_id}" .
            ?cve ?p ?o .
        }} LIMIT {int(limit)}"""
        rows = bindings_to_rows(client.run_query(query, default_graph=None, infer=False))

        def local(uri: str) -> str:
            parts = re.split(r"[#/]", uri.rstrip("#/"))
            return parts[-1] if parts and parts[-1] else uri

        return [
            {"subject": cve_id, "predicate": local(r.get("p", "")),
             "object": local(r.get("o", "")), "source": SPARQL_PUBLIC_ENDPOINT}
            for r in rows
        ]
    except Exception:
        return []


def answer(message: str, mode: str = "threat_intelligence",
           model: str = DEFAULT_MODEL) -> Dict[str, Any]:
    g = _gather_context(message, mode)

    if g["context"]:
        user_msg = f"Konteks data keamanan:\n{g['context']}\n\nPertanyaan: {message}"
    else:
        user_msg = (f"Pertanyaan: {message}\n"
                    "(Tidak ada data spesifik ditemukan di knowledge graph untuk pertanyaan ini.)")

    try:
        llm = LLMProvider.get_model(model)
        resp = llm.invoke([SystemMessage(content=SYSTEM_PROMPT),
                           HumanMessage(content=user_msg)])
        answer_text = resp.content
    except Exception as e:
        answer_text = f"⚠️ Gagal memanggil LLM ({model}): {e}"

    triples: List[Dict[str, str]] = []
    for cve_id in g["cve_ids"]:
        triples.extend(_cve_triples(cve_id))

    return {"message": answer_text, "triples": triples,
            "llmUsed": model, "sources": g["sources"]}


if __name__ == "__main__":
    import json
    print(json.dumps(answer("Apa bahaya dari CVE-2017-0144?"), indent=2, ensure_ascii=False))