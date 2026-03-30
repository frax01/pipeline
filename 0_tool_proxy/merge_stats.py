import json
import copy
import os
from pathlib import Path

# All 14 deterministic cause keys
DETERMINISTIC_KEYS = [
    "total", "command_injection", "ssh_private_keys", "suspicious_file_access",
    "sql_injection", "container_isolation_violation", "entropy_secrets",
    "pii_detection", "prompt_injection", "important_tag_injection",
    "shadow_hijack", "cross_origin_access", "xss_injection",
    "base64_encoded_payload", "invisible_unicode_injection"
]

INTENT_KEYS = ["benign", "malicious", "jailbreak_combined", "encoding_evasion"]


def _empty_deterministic():
    return {k: 0 for k in DETERMINISTIC_KEYS}


def _empty_intent_block():
    return {
        "deterministic_causes": _empty_deterministic(),
        "tool_call_causes": 0,
        "tool_response_causes": 0,
        "failed": 0
    }


def merge_proxy_stats(stats_files, output_file):
    merged = {
        "last_index": 0,
        "total": 0,
        "range_start": 0,
        "range_end": 60205,
        "remaining": 0,
        "languages": {},
        "proxy": {
            "total_server": 0,
            "percentage": 0.0,
            "languages": {},
            "total_tools": 0,
            "total_trials": 0,
            "total_failed": 0,
            "tool_blocked": {
                "total": 0,
                "percentage": 0.0,
                "benign": _empty_intent_block(),
                "malicious": _empty_intent_block(),
                "jailbreak_combined": _empty_intent_block(),
                "encoding_evasion": _empty_intent_block(),
            },
            "prompt": {
                "total_prompt": 0,
                "total_blocked": 0,
                "total_allowed": 0,
                "percentage": 0.0,
                "deterministic_causes": _empty_deterministic(),
                "tool_call_causes": 0,
                "tool_response_causes": 0
            },
            "failure_reasons": {
                "total": 0,
                "percentage": 0.0,
                "counts": {}
            }
        }
    }

    all_data = []
    for f in stats_files:
        if os.path.exists(f):
            with open(f, 'r', encoding='utf-8') as file:
                all_data.append(json.load(file))

    if not all_data:
        print("No stats files found.")
        return

    for data in all_data:
        # Global fields
        merged["total"] += data.get("total", 0)
        merged["last_index"] = max(merged["last_index"], data.get("last_index", 0))
        merged["remaining"] += data.get("remaining", 0)

        for lang, count in data.get("languages", {}).items():
            merged["languages"][lang] = merged["languages"].get(lang, 0) + count

        # proxy-specific fields
        src = data.get("proxy", {})
        dst = merged["proxy"]

        dst["total_server"] += src.get("total_server", 0)
        dst["total_tools"] += src.get("total_tools", 0)
        dst["total_trials"] += src.get("total_trials", 0)
        dst["total_failed"] += src.get("total_failed", 0)

        # Merge languages
        for lang, count in src.get("languages", {}).items():
            dst["languages"][lang] = dst["languages"].get(lang, 0) + count

        # Merge tool_blocked per intent
        src_tb = src.get("tool_blocked", {})
        dst_tb = dst["tool_blocked"]

        for intent in INTENT_KEYS:
            si = src_tb.get(intent, {})
            di = dst_tb[intent]

            # Deterministic causes
            si_det = si.get("deterministic_causes", {})
            di_det = di["deterministic_causes"]
            for key in DETERMINISTIC_KEYS:
                di_det[key] += si_det.get(key, 0)

            # LLM causes
            di["tool_call_causes"] += si.get("tool_call_causes", 0)
            di["tool_response_causes"] += si.get("tool_response_causes", 0)
            di["failed"] += si.get("failed", 0)

        # Merge prompt
        src_p = src.get("prompt", {})
        dst_p = dst["prompt"]

        dst_p["total_prompt"] += src_p.get("total_prompt", 0)
        dst_p["total_blocked"] += src_p.get("total_blocked", 0)
        dst_p["total_allowed"] += src_p.get("total_allowed", 0)
        dst_p["tool_call_causes"] += src_p.get("tool_call_causes", 0)
        dst_p["tool_response_causes"] += src_p.get("tool_response_causes", 0)

        src_pdet = src_p.get("deterministic_causes", {})
        dst_pdet = dst_p["deterministic_causes"]
        for key in DETERMINISTIC_KEYS:
            dst_pdet[key] += src_pdet.get(key, 0)

        # Merge failure_reasons
        src_fr = src.get("failure_reasons", {})
        dst_fr = dst["failure_reasons"]
        dst_fr["total"] += src_fr.get("total", 0)
        for reason, count in src_fr.get("counts", {}).items():
            dst_fr["counts"][reason] = dst_fr["counts"].get(reason, 0) + count

    # Recalculate derived values
    dst = merged["proxy"]

    if merged["total"] > 0:
        dst["percentage"] = round(dst["total_server"] / merged["total"] * 100, 2)

    # Recalculate total blocked
    total_blocked = 0
    for intent in INTENT_KEYS:
        ib = dst["tool_blocked"][intent]
        total_blocked += ib["deterministic_causes"]["total"]
        total_blocked += ib["tool_call_causes"]
        total_blocked += ib["tool_response_causes"]
    dst["tool_blocked"]["total"] = total_blocked

    if dst["total_tools"] > 0:
        dst["tool_blocked"]["percentage"] = round(total_blocked / dst["total_tools"] * 100, 2)

    # Prompt percentage
    if dst["prompt"]["total_prompt"] > 0:
        dst["prompt"]["percentage"] = round(
            dst["prompt"]["total_blocked"] / dst["prompt"]["total_prompt"] * 100, 2
        )

    # Failure percentage
    if merged["total"] > 0:
        dst["failure_reasons"]["percentage"] = round(
            dst["failure_reasons"]["total"] / merged["total"] * 100, 2
        )

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=4, ensure_ascii=False)
    print(f"Merged proxy stats saved to {output_file}")


def merge_proxy_servers(server_files, output_file):
    """Merge per-VM server log files into one."""
    merged = {}
    for f in server_files:
        if os.path.exists(f):
            try:
                with open(f, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                merged.update(data)
            except Exception:
                pass

    if merged:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(merged, f, indent=4, ensure_ascii=False)
        print(f"Merged {len(merged)} server entries -> {output_file}")
    else:
        print("No server log files found to merge.")


if __name__ == "__main__":
    proxy_dir = Path(__file__).parent
    # Stats merge
    stats_files = [str(proxy_dir / f"vm{i}_stats.json") for i in range(1, 10)]
    existing = [f for f in stats_files if Path(f).exists()]
    print(f"Found {len(existing)}/9 stats files")
    if existing:
        merge_proxy_stats(existing, str(proxy_dir / "proxy_stats.json"))

    # Servers merge
    server_files = [str(proxy_dir / f"vm{i}_servers.json") for i in range(1, 10)]
    existing_srv = [f for f in server_files if Path(f).exists()]
    if existing_srv:
        merge_proxy_servers(existing_srv, str(proxy_dir / "proxy_servers.json"))
