#!/usr/bin/env python3
"""Helper script per classificare hardcoded-credential-static UNCERTAIN in-chat."""
import json
import re
from collections import Counter
from pathlib import Path

BASE = Path(__file__).parent
CAT = "hardcoded-credential-static"
UNC_FILE = BASE / CAT / "filtered" / "llm_analysis" / "uncertain.json"
CACHE_FILE = BASE / CAT / "filtered" / "llm_analysis" / "_llm_api_cache.json"


def load_uncertain():
    with open(UNC_FILE, encoding="utf-8") as f:
        d = json.load(f)
    return d.get("findings", d) if isinstance(d, dict) else d


def extract_code(desc: str) -> str:
    idx = desc.find("Code: ")
    return desc[idx + 6:].strip() if idx != -1 else ""


def extract_line(desc: str) -> str:
    m = re.search(r"at line (\d+)", desc)
    return m.group(1) if m else "?"


def cache_key(f: dict, cat: str) -> str:
    server = (f.get("server_url", "")).replace("https://github.com/", "")
    file = f.get("file", "")
    line = extract_line(f.get("description", ""))
    payload = f.get("payload", "")
    if payload:
        return f"{server}|{cat}|{payload[:40]}"
    return f"{server}|{file}|{line}"


def cluster(fi):
    """Cluster findings by pattern."""
    clusters = {
        "value_test_keyword": [],         # value contiene "test"/"demo"/"sample"
        "value_admin_dev": [],            # value contiene "admin"/"dev"/"local"
        "value_short_word": [],           # value short alphabetic word
        "value_db_default": [],           # postgres/redis/mysql defaults
        "value_uuid_or_hash": [],         # uuid pattern
        "value_long_random_alpha": [],    # mixed-case alphanum 16+
        "value_long_lowercase": [],       # lowercase 16+
        "value_long_hex": [],             # pure hex 16+
        "value_quoted_in_log": [],        # console.log/print con cred
        "value_path_filesystem": [],      # /home/, C:\\, /tmp/
        "value_url": [],                  # http://, https://
        "comment_or_string_concat": [],   # // # /* concat
        "key_eq_string_compare": [],      # if X == "Y", line.startswith
        "value_object_reference": [],     # var = something.field
        "value_function_call": [],        # var = func(...)
        "other": [],
    }
    for r in fi:
        code = extract_code(r.get("description", ""))
        # Sniff value
        m = re.search(r"[=:]\s*[\"']([^\"'\n]{0,80})[\"']", code)
        if not m:
            m2 = re.search(r"[=:]\s*([^\"'\n;,)]{1,80})", code)
            if m2:
                val = m2.group(1).strip()
                clusters["value_object_reference"].append(r)
                continue
            clusters["other"].append(r)
            continue
        val = m.group(1)
        low = val.lower()

        if re.search(r"\b(?:test|demo|sample|example|fake|mock|dummy|placeholder)\b|test\d|demo\d", low):
            clusters["value_test_keyword"].append(r)
        elif re.search(r"^(admin|root|toor|user|operator|guest|anonymous|public|private|local|dev|prod|staging)\d*$", low):
            clusters["value_admin_dev"].append(r)
        elif re.search(r"^(?:postgres|redis|mysql|mongo|kibana|jasper|elastic)\w*$", low):
            clusters["value_db_default"].append(r)
        elif re.match(r"^[0-9a-f]{8,}-[0-9a-f]{4,}-[0-9a-f]{4,}-[0-9a-f]{4,}-[0-9a-f]{8,}$", low):
            clusters["value_uuid_or_hash"].append(r)
        elif re.search(r"console\.(?:log|info|debug|warn|error)|print\s*\(|logger\.\w+\s*\(|fmt\.Print", code):
            clusters["value_quoted_in_log"].append(r)
        elif re.search(r"^(?:[A-Z]:[\\\\/]|/(?:home|tmp|root|usr|etc|var|opt))", val) or "\\\\Users\\\\" in val:
            clusters["value_path_filesystem"].append(r)
        elif re.search(r"^https?://|^ftp://|^ws://|^postgres://", val):
            clusters["value_url"].append(r)
        elif re.search(r"\.(?:startsWith|endsWith|includes|contains|indexOf)\s*\(|line\.startswith", code):
            clusters["key_eq_string_compare"].append(r)
        elif re.search(r"^\s*(?:#|//|\*|>>>)", code):
            clusters["comment_or_string_concat"].append(r)
        elif re.search(r"=\s*(?:await\s+)?\w+\.\w+\(|=\s*\w+\(\)", code):
            clusters["value_function_call"].append(r)
        elif re.match(r"^[a-z]{1,12}$", val):
            clusters["value_short_word"].append(r)
        elif re.match(r"^[0-9a-f]{16,}$", low) and not re.search(r"[g-z]", low):
            clusters["value_long_hex"].append(r)
        elif re.match(r"^[a-z0-9]{16,}$", low):
            clusters["value_long_lowercase"].append(r)
        elif (re.search(r"[A-Z]", val) and re.search(r"[a-z]", val) and re.search(r"[0-9]", val)
              and len(val) >= 16):
            clusters["value_long_random_alpha"].append(r)
        else:
            clusters["other"].append(r)

    return clusters


def main():
    fi = load_uncertain()
    cls = cluster(fi)
    print(f"Total UNC: {len(fi)}\n")
    print("Cluster breakdown:")
    for k, v in sorted(cls.items(), key=lambda x: -len(x[1])):
        if v:
            print(f"  {len(v):>4}  {k}")
    # Sample 3 from each cluster
    print()
    for k, items in cls.items():
        if not items:
            continue
        print(f"\n=== {k} ({len(items)}) — 3 samples ===")
        for r in items[:3]:
            code = extract_code(r.get("description", ""))[:160]
            file = r.get("file", "")[:50]
            print(f"  {file}: {code}")


if __name__ == "__main__":
    main()
