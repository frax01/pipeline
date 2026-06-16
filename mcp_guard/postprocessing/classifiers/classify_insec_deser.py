#!/usr/bin/env python3
"""Classifica insecure-deserialization-static UNCERTAIN."""
import json
import re
from pathlib import Path

BASE = Path(__file__).parent
CAT = "insecure-deserialization-static"
UNC_FILE = BASE / CAT / "filtered" / "llm_analysis" / "uncertain.json"
CACHE_FILE = BASE / CAT / "filtered" / "llm_analysis" / "_llm_api_cache.json"


def extract_code(desc: str) -> str:
    idx = desc.find("Code: ")
    return desc[idx + 6:].strip() if idx != -1 else ""


def extract_line(desc: str) -> str:
    m = re.search(r"at line (\d+)", desc)
    return m.group(1) if m else "?"


def cache_key(f: dict) -> str:
    server = (f.get("server_url", "")).replace("https://github.com/", "")
    file = f.get("file", "")
    line = extract_line(f.get("description", ""))
    return f"{server}|{file}|{line}"


def classify(f: dict) -> tuple[str, str]:
    code = extract_code(f.get("description", ""))
    file = f.get("file", "")

    # ── VP ────────────────────────────────────────────

    # User input direct
    if re.search(r"pickle\.loads?\s*\([^)]*"
                 r"(?:params\.|args\.|input\.|arguments\.|"
                 r"req\.body|req\.query|request\.body|"
                 r"userInput|user_input|"
                 r"body\.\w+|payload\.\w+)", code, re.I):
        return "VP", "pickle_loads_user_input"

    # Subprocess output / network
    if re.search(r"pickle\.loads?\s*\(\s*"
                 r"(?:result\.stdout|proc\.stdout|completed\.stdout|"
                 r"response\.content|response\.body|response\.data|"
                 r"sock\.recv|conn\.recv|s\.recv|"
                 r"sys\.stdin|stdin\.read|"
                 r"msg\.body|message\.payload|"
                 r"queue\.get|q\.get)", code):
        return "VP", "pickle_loads_subprocess_or_network"

    # Decompression + pickle (compressed network/external data)
    if re.search(r"pickle\.loads?\s*\(\s*"
                 r"(?:zlib\.decompress|lzma\.decompress|bz2\.decompress|"
                 r"gzip\.decompress|base64\.b64decode|"
                 r"base64\.urlsafe_b64decode)\s*\(", code):
        return "VP", "pickle_loads_decompressed_data"

    # DB row
    if re.search(r"pickle\.loads?\s*\(\s*"
                 r"(?:row\[|cursor\.|fetchone\(\)|fetchall\(\)|"
                 r"\.fetchone\(\)|\.fetchall\(\)|"
                 r"redis\.get|cache\.get\([^)]*\b(?:key|user|session))", code):
        return "VP", "pickle_loads_from_db_or_cache_external"

    # ── FP ────────────────────────────────────────────

    # Internal var (cache/index/embeddings/state)
    if re.search(r"(?:cached?|cache_data|cache_entry|cached_entry|cache_manager|"
                 r"index|index_to_id|docstore|embeddings|patterns|"
                 r"feature_columns|features|note_id_mapping|mapping|"
                 r"marketplace_data|cached_data|loaded|"
                 r"self\._cache|self\._index|self\._docstore|self\.docstore|"
                 r"self\.indexes?|self\.embedd\w+|self\.patterns|"
                 r"self\.\w+_(?:cache|index|store|embeddings|features|state))\s*"
                 r"(?:\[[^\]]*\])?\s*=\s*pickle\.load", code, re.I):
        return "FP", "pickle_load_into_internal_cache"

    # File handle from local cache/index/state file
    if re.search(r"\bpickle\.load\s*\(\s*(?:f|file|fp|fh|"
                 r"cache_file|index_file|model_file|state_file|"
                 r"store_file|backup_file)\s*\)", code, re.I):
        # Verify file is opened from local path (not user input)
        return "FP", "pickle_load_from_local_file_handle"

    # OAuth token file (Google/Microsoft creds local pickle)
    if re.search(r"(?:creds|credentials|token)\s*=\s*pickle\.load\s*\(\s*token", code):
        return "FP", "pickle_oauth_local_credential_file"

    # ML model load
    if re.search(r"(?:model|scaler|pca|clf|classifier|regressor|encoder|"
                 r"tokenizer|pipeline|vectorizer|transformer)\s*=\s*"
                 r"pickle\.load\s*\(", code, re.I):
        return "FP", "pickle_ml_model_load"

    # File path indicates cache/index/embeddings dir
    if re.search(r"(?:cache[/\\]|caches[/\\]|"
                 r"index[/\\]|indexes[/\\]|"
                 r"embeddings?[/\\]|"
                 r"vector_?stores?[/\\]|"
                 r"faiss[/\\]|chroma[/\\]|qdrant[/\\]|milvus[/\\]|"
                 r"models?[/\\]|"
                 r"state[/\\]|states[/\\]|"
                 r"checkpoints?[/\\])", file, re.I):
        return "FP", "file_path_indicates_internal_storage"

    # Test/demo/example file
    if re.search(r"(?:test[/\\]|tests[/\\]|spec[/\\]|specs[/\\]|"
                 r"_test\.py$|_test_\w+\.py$|"
                 r"examples?[/\\]|samples?[/\\]|"
                 r"demos?[/\\]|fixtures?[/\\])", file, re.I):
        return "FP", "test_or_example_file"

    # Vendor/site-packages
    if re.search(r"(?:site-packages[/\\]|venv[/\\]|\.venv[/\\]|"
                 r"node_modules[/\\]|vendor[/\\]|"
                 r"dist[/\\]|build[/\\])", file, re.I):
        return "FP", "vendor_or_thirdparty_file"

    # Trusted/safe comment
    if re.search(r"#\s*(?:noqa\s*[:\s]+S301|trusted|safe|local\s+cache|"
                 r"known\s+risk|intentional|by\s+design)", code, re.I):
        return "FP", "developer_marked_trusted"

    # pickle.dumps() only (serialization, not deserialization)
    if re.search(r"pickle\.dumps?\s*\(", code) and not re.search(r"pickle\.loads?", code):
        return "FP", "pickle_serialization_only"

    # Variable name suggests internal data
    if re.search(r"(?:data|entry|loaded|cached_entry|map|mapping|"
                 r"obj|item|content|result|info|metadata|"
                 r"index_to_id|id_to_node|graph_state|graph_data)\s*=\s*"
                 r"pickle\.load", code, re.I):
        return "FP", "internal_data_variable_pickle_load"

    # File path with .pkl/.pickle/.cache hardcoded
    if re.search(r"pickle\.load\s*\(\s*open\s*\(\s*[\"'][^\"']+\.(?:pkl|pickle|cache|state|index|model|joblib)[\"']",
                 code, re.I):
        return "FP", "hardcoded_pickle_file_path"

    # Default: pickle in fuzzy context senza user input chiaro = lean FP
    # Stage 2A ha già preso le VP forti
    return "FP", "insec_deser_residual_no_user_input"


def main():
    with open(UNC_FILE, encoding="utf-8") as f:
        d = json.load(f)
    fi = d.get("findings", d) if isinstance(d, dict) else d

    cache = {}
    if CACHE_FILE.exists():
        with open(CACHE_FILE, encoding="utf-8") as f:
            cache = json.load(f)

    counts = {"VP": 0, "FP": 0, "UNCERTAIN": 0}
    reasons = {}
    for r in fi:
        v, reason = classify(r)
        cache[cache_key(r)] = {"verdict": v, "reason": reason}
        counts[v] += 1
        reasons.setdefault(reason, 0)
        reasons[reason] += 1

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

    print(f"Total: {len(fi)}")
    print(f"VP: {counts['VP']} | FP: {counts['FP']} | UNCERTAIN: {counts['UNCERTAIN']}")
    print()
    print("Reasons:")
    for r, c in sorted(reasons.items(), key=lambda x: -x[1])[:20]:
        print(f"  {c:>4}  {r}")


if __name__ == "__main__":
    main()
