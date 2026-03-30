import json
from pathlib import Path
from config import CACHE_PATH

def load_hash_cache() -> dict:
    if CACHE_PATH.exists():
        return json.loads(CACHE_PATH.read_text())
    return {}

def save_hash_cache(cache: dict):
    CACHE_PATH.write_text(json.dumps(cache, indent=2))

def is_duplicate(hash_cache: dict, server_hash: str) -> bool:
    return server_hash in hash_cache

def register_hash(hash_cache: dict, server_hash: str, server_name: str):
    hash_cache[server_hash] = server_name
