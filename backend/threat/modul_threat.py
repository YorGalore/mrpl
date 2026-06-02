#Ditambah 
from __future__ import annotations
from functools import lru_cache
from pathlib import Path
from typing import List

from mitreattack.stix20 import MitreAttackData
from backend.patterns import MITRE_GENERAL_KEYWORDS

_ROOT = Path(__file__).resolve().parents[2]
# Urutan pencarian dataset: lokasi standar (data/) dulu, lalu yang ikut ter-commit (modul_a3/).
_CANDIDATE_PATHS = [
    _ROOT / "data" / "enterprise-attack.json",
    _ROOT / "modul_a3" / "enterprise-attack.json",
]

def _resolve_dataset_path() -> Path:
    for path in _CANDIDATE_PATHS:
        if path.exists():
            return path
    raise FileNotFoundError(
        "enterprise-attack.json tidak ditemukan di "
        f"{[str(p) for p in _CANDIDATE_PATHS]}. "
        "Jalankan: python scripts/download_mitre.py"
    )

@lru_cache(maxsize=1)
#ditambah
def _get_mitre() -> MitreAttackData:
    return MitreAttackData(str(_resolve_dataset_path()))

def get_threat_context(actor_keyword: str) -> str:
    try:
        mitre = _get_mitre()  
        groups = mitre.get_groups()
        hasil = []
        for group in groups:
            name = group.get("name", "")
            aliases = group.get("aliases", [])
            desc = group.get("description", "")
            if (actor_keyword.lower() in name.lower() or
                any(actor_keyword.lower() in a.lower() for a in aliases)):
                hasil.append({
                    "nama": name,
                    "aliases": aliases,
                    "deskripsi": desc[:300]
                })
        if not hasil:
            return f"Tidak ada threat actor ditemukan untuk: {actor_keyword}"
        context = f"=== Threat Actor: '{actor_keyword}' ===\n"
        for h in hasil:
            context += f"Nama     : {h['nama']}\n"
            context += f"Alias    : {', '.join(h['aliases'])}\n"
            context += f"Deskripsi: {h['deskripsi']}...\n"
        return context
    except Exception as e:
        return f"Error: {e}"

def get_malware_context(malware_keyword: str) -> str:
    try:
        mitre = _get_mitre()
        softwares = mitre.get_software()
        hasil = []
        for sw in softwares:
            name = sw.get("name", "")
            desc = sw.get("description", "")
            platforms = sw.get("x_mitre_platforms", [])
            if malware_keyword.lower() in name.lower():
                hasil.append({
                    "nama": name,
                    "platform": platforms,
                    "deskripsi": desc[:300]
                })
        if not hasil:
            return f"Tidak ada malware ditemukan untuk: {malware_keyword}"
        context = f"=== Malware: '{malware_keyword}' ===\n"
        for h in hasil:
            context += f"Nama     : {h['nama']}\n"
            context += f"Platform : {', '.join(h['platform'])}\n"
            context += f"Deskripsi: {h['deskripsi']}...\n"
        return context
    except Exception as e:
        return f"Error: {e}"

def _attack_id(obj) -> str:
    """Ambil ID ATT&CK (mis. T1021) dari external_references."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "") or ""
    return ""

def _tactic_names(obj) -> List[str]:
    """Ambil nama tactic (kill chain phase) ATT&CK, dinormalisasi tanpa tanda hubung."""
    names = []
    for phase in obj.get("kill_chain_phases", []) or []:
        if phase.get("kill_chain_name") == "mitre-attack":
            names.append((phase.get("phase_name", "") or "").replace("-", " "))
    return [n for n in names if n]

def search_mitre_general(query: str, max_results: int = 6) -> str:

    try:
        q = (query or "").lower().strip()
        if not q:
            return ""

        terms = [kw for kw in MITRE_GENERAL_KEYWORDS if kw in q]
        if not terms:
            terms = [q]

        mitre = _get_mitre()
        techniques = mitre.get_techniques(include_subtechniques=True)

        hasil = []
        seen = set()
        for tech in techniques:
            if tech.get("revoked") or tech.get("x_mitre_deprecated"):
                continue

            name = (tech.get("name", "") or "")
            desc = (tech.get("description", "") or "")
            name_l = name.lower()
            desc_l = desc.lower()
            tactics = _tactic_names(tech)
            tactics_l = " ".join(tactics).lower()

            matched = False
            for term in terms:
                if (term in name_l) or (term in tactics_l) or (term in desc_l):
                    matched = True
                    break
            if not matched:
                continue

            tid = _attack_id(tech)
            key = tid or name
            if key in seen:
                continue
            seen.add(key)

            hasil.append({
                "id": tid,
                "nama": name,
                "tactics": tactics,
                "deskripsi": desc[:300],
            })
            if len(hasil) >= max_results:
                break

        if not hasil:
            return f"Tidak ada teknik MITRE ATT&CK ditemukan untuk: {query}"

        label = ", ".join(terms)
        context = f"=== MITRE ATT&CK Techniques: '{label}' ===\n"
        for h in hasil:
            prefix = f"[{h['id']}] " if h["id"] else ""
            context += f"Teknik   : {prefix}{h['nama']}\n"
            if h["tactics"]:
                context += f"Tactic   : {', '.join(h['tactics'])}\n"
            if h["deskripsi"]:
                context += f"Deskripsi: {h['deskripsi']}...\n"
            context += "\n"
        return context.rstrip() + "\n"
    except Exception as e:
        return f"Error: {e}"


if __name__ == "__main__":
    print(get_threat_context("APT28"))
    print()
    print(get_threat_context("Lazarus"))
    print()
    print(get_malware_context("WannaCry"))
    print()
    print(get_malware_context("Emotet"))
    print()
    print(search_mitre_general("lateral movement"))
    print()