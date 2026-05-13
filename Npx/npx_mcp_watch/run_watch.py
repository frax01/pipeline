import sys
import os
import json
import copy
import time
import signal
import argparse
import gc
import shutil
import subprocess
from pathlib import Path

SERVER_TIMEOUT = 600
MIN_FREE_MEMORY_MB = 200

SEVERITY_LEVELS = ("critical", "high", "medium", "low")

KNOWN_CATEGORIES = (
    "toxic-flow",
    "credential-leak",
    "tool-poisoning",
    "prompt-injection",
    "tool-mutation",
    "data-exfiltration",
    "steganographic-attack",
    "protocol-violation",
    "input-validation",
    "server-spoofing",
    "access-control",
)

ID_DESCRIPTIONS = {
    "ANSI_ESCAPE_INJECTION":            "ANSI escape sequences - can hide malicious instructions",
    "WHITESPACE_INJECTION":             "Excessive whitespace - potential hidden content",
    "CONVERSATION_EXFILTRATION_TRIGGER":"Conversation history exfiltration trigger detected",
    "HARDCODED_CREDENTIALS":            "Hardcoded credentials detected",
    "PLAINTEXT_STORAGE":                "Plaintext credential storage detected",
    "INSECURE_CREDENTIAL_PERMISSIONS":  "Credentials with world-readable permissions",
    "COMMAND_INJECTION_RISK":           "Command injection vulnerability - append && rm -rf /",
    "SSRF_VULNERABILITY":               "SSRF vulnerability - fetches any URL",
    "PATH_TRAVERSAL":                   "Path traversal vulnerability - accesses files outside directory",
    "MAGIC_PARAMETER_INJECTION":        "Magic parameter detected - extracts sensitive AI context",
    "UNUSED_SENSITIVE_PARAMETER":       "Unused parameter with sensitive name",
    "DATA_EXFILTRATION":                "Potential data exfiltration detected",
    "CONSENT_FATIGUE_RISK":             "Repeated consent requests - fatigue attack risk",
    "EXCESSIVE_PERMISSIONS":            "Excessive permissions - violates least privilege",
    "TOOL_DESCRIPTION_INJECTION":       "Suspicious prompt injection in tool description",
    "RETRIEVAL_AGENT_DECEPTION":        "RADE pattern detected - hidden commands in retrieval content",
    "SESSION_ID_IN_URL":                "Session ID in URL - exposes sensitive identifiers",
    "INSECURE_TRANSPORT":               "Insecure HTTP transport detected",
    "SUSPICIOUS_SERVER_NAME":           "Server name mimics popular service - potential spoofing",
    "CROSS_SERVER_SHADOWING":           "Cross-server call interception detected",
    "HIDDEN_TOOL_INSTRUCTIONS":         "Hidden malicious instructions in tool description",
    "DECEPTIVE_TOOL_NAMING":            "Tool with deceptive name/description mismatch",
    "DYNAMIC_TOOL_MUTATION":            "Dynamic tool mutation detected - rug-pull risk",
    "TOOL_NAME_COLLISION":              "Tool name collision risk",
    "UNTRUSTED_DATA_PROCESSING":        "External data processed without sanitization",
    "AUTOMATIC_CONTENT_PUBLISHING":     "Automatic content publishing - data exfiltration risk",
    "GENERIC_TOXIC_FLOW_CHAIN":         "Complete toxic flow: external input -> privileged access -> public output",
}

def check_memory_available() -> bool:
    def _get_free_mb():
        try:
            import psutil
            return psutil.virtual_memory().available / (1024 * 1024)
        except ImportError:
            try:
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemAvailable:"):
                            return int(line.split()[1]) / 1024
            except (FileNotFoundError, ValueError):
                pass
        return None

    free_mb = _get_free_mb()
    if free_mb is None:
        return True
    if free_mb >= MIN_FREE_MEMORY_MB:
        return True

    print(f"[RAM] LOW MEMORY: {free_mb:.0f}MB available (minimum: {MIN_FREE_MEMORY_MB}MB)")
    try:
        from functions.helper import cleanup_orphan_processes, _kill_orphan_server_processes, cleanup_caches
        cleanup_orphan_processes()
        _kill_orphan_server_processes()
        cleanup_caches(force=True)
    except Exception:
        pass
    gc.collect()

    wait_count = 0
    while True:
        time.sleep(15)
        wait_count += 1
        free_mb = _get_free_mb()
        if free_mb is None or free_mb >= MIN_FREE_MEMORY_MB:
            print(f"  [RAM] Memory recovered after {wait_count * 15}s: {free_mb:.0f}MB free")
            return True
        if wait_count % 4 == 0:
            print(f"  [RAM] Still waiting... {free_mb:.0f}MB free - cleaning again...")
            try:
                from functions.helper import cleanup_orphan_processes, _kill_orphan_server_processes, cleanup_caches
                cleanup_orphan_processes()
                _kill_orphan_server_processes()
                cleanup_caches(force=True)
            except Exception:
                pass
            gc.collect()

class ServerTimeoutError(Exception):
    pass

def _timeout_handler(signum, frame):
    raise ServerTimeoutError("Server processing exceeded timeout")

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from functions.helper import (
    update_global, periodic_cache_cleanup,
    cleanup_orphan_processes, _kill_orphan_server_processes
)
from frameworks.mcpWatch import execute_mcp_watch
from functions.buildConfig import write_mcp_config
from functions.stats import update_framework
from functions.config import EXCEL_PATH_NPX

CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "mcp_watch_stats.json"
LOG_FILE = CURRENT_DIR / "mcp_watch_servers.json"

DEFAULT_EXCEL = EXCEL_PATH_NPX

INIT_STATS = {
    "last_index": 0,
    "total": 0,
    "range_start": 0,
    "range_end": 0,
    "remaining": 0,
    "languages": {},
    "mcp-watch": {
        "total": 0,
        "percentage": 0.0,
        "languages": {},
        "categories": {},
        "percentage_of_vulnerability": {},
        "vulnerabilities": {
            "total": 0,
            "average_per_server": 0,
            "counts": {},
            "percentage_of_severity": {}
        },
        "failure_reasons": {
            "total": 0,
            "percentage": 0.0,
            "counts": {}
        }
    }
}

def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result

def load_local_stats():
    if not STATS_FILE.exists():
        return copy.deepcopy(INIT_STATS)
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not data:
            return copy.deepcopy(INIT_STATS)
        return _deep_merge(INIT_STATS, data)
    except Exception:
        return copy.deepcopy(INIT_STATS)

def save_local_stats(data):
    tmp_file = STATS_FILE.with_suffix(".tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    tmp_file.replace(STATS_FILE)

def load_local_log():
    if not LOG_FILE.exists():
        return {}
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_local_log(data):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def _category_dir(category: str) -> Path:
    return CURRENT_DIR / category

def _category_file(category: str, severity: str) -> Path:
    prefix = category.replace("-", "_")
    return _category_dir(category) / f"{prefix}_{severity}.json"

def _cat_default(category: str, severity: str) -> dict:
    return {"category": category, "severity": severity, "total": 0, "findings": []}

def load_category_file(category: str, severity: str) -> dict:
    p = _category_file(category, severity)
    if not p.exists():
        return _cat_default(category, severity)
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return _cat_default(category, severity)

def save_category_file(category: str, severity: str, data: dict):
    p = _category_file(category, severity)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    tmp.replace(p)

def reset_all_output_files():
    for cat in KNOWN_CATEGORIES:
        _category_dir(cat).mkdir(parents=True, exist_ok=True)
        for sev in SEVERITY_LEVELS:
            save_category_file(cat, sev, _cat_default(cat, sev))

def flatten_vulnerabilities(mcp_watch_result: dict) -> list:
    vulns = []
    cat_block = mcp_watch_result.get("category", {})
    for category_name, items in cat_block.items():
        if not isinstance(items, dict):
            continue
        for item in items.values():
            if not isinstance(item, dict):
                continue
            location = item.get("location", "") or ""
            file_path, line_num = "", None
            if location:
                parts = location.rsplit(":", 1)
                file_path = parts[0]
                if len(parts) == 2:
                    try:
                        line_num = int(parts[1])
                    except ValueError:
                        file_path = location
            vuln_id = item.get("id")
            vulns.append({
                "id":          vuln_id,
                "severity":    item.get("severity"),
                "category":    category_name,
                "description": item.get("title") or ID_DESCRIPTIONS.get(vuln_id),
                "file":        file_path,
                "line":        line_num,
                "evidence":    item.get("evidence"),
                "source":      item.get("source"),
            })
    return vulns

def _finding(server_name, server_url, language, v: dict) -> dict:
    return {
        "server_name": server_name,
        "github_url":  server_url,
        "language":    language,
        "id":          v["id"],
        "category":    v["category"],
        "description": v["description"],
        "file":        v["file"],
        "line":        v["line"],
        "evidence":    v["evidence"],
        "source":      v["source"],
    }

def update_output_files(server_name: str, server_url: str, language: str, flat_vulns: list):
    by_cat_sev = {}
    for v in flat_vulns:
        sev = (v.get("severity") or "").lower()
        cat = (v.get("category") or "").lower()
        if sev not in SEVERITY_LEVELS:
            continue
        by_cat_sev.setdefault((cat, sev), []).append(v)

    for (cat, sev), vulns in by_cat_sev.items():
        data = load_category_file(cat, sev)
        for v in vulns:
            data["findings"].append(_finding(server_name, server_url, language, v))
        data["total"] = len(data["findings"])
        save_category_file(cat, sev, data)

def read_npx_servers(excel_path: str):
    import pandas as pd
    df = pd.read_excel(excel_path)
    return df["Link"].dropna().tolist()

def prepare_npx_server(package_name: str):
    """Write MCP config. mcp-watch doesn't need config but we write it for consistency."""
    write_mcp_config(
        server_name=package_name,
        command="npx",
        args=["-y", package_name],
        cwd=Path.cwd()
    )
    return {
        "server_name": package_name,
        "server_language": "nodejs",
        "command": "npx",
        "elem": ["-y", package_name]
    }

def main(start_idx: int, end_idx: int = None, reset: bool = False, excel_path: str = None):
    if excel_path is None:
        excel_path = str(DEFAULT_EXCEL)

    stats = load_local_stats()
    last_index = stats.get("last_index", 0)

    if reset or start_idx == 0:
        print(f"Resetting stats and logs for MCP Watch NPX (start: {start_idx})")
        stats = copy.deepcopy(INIT_STATS)
        save_local_stats(stats)
        save_local_log({})
        reset_all_output_files()
    elif start_idx == -1:
        start_idx = last_index
        print(f"Resuming from index: {start_idx}")

    print(f"=== Running MCP Watch (NPX) ===")
    print(f"Excel: {excel_path}")

    servers = read_npx_servers(excel_path)
    total_servers = len(servers)
    print(f"Total NPX servers: {total_servers}")

    if end_idx is None:
        end_idx = total_servers

    stats["range_start"] = start_idx
    stats["range_end"] = end_idx
    stats["remaining"] = end_idx - start_idx
    save_local_stats(stats)

    total_in_range = end_idx - start_idx
    print(f"Range: {start_idx} - {end_idx} ({total_in_range} servers)")

    use_alarm = hasattr(signal, 'SIGALRM')
    if use_alarm:
        signal.signal(signal.SIGALRM, _timeout_handler)

    for idx in range(start_idx, end_idx):
        start_time = time.time()
        package_name = servers[idx]
        language = "nodejs"

        print("\n" + "=" * 50)
        print(f"Index: {idx}")
        print(f"Package: {package_name}")

        check_memory_available()

        stats = load_local_stats()
        server_log = load_local_log()

        _status = "failed"
        failure_reason = ""

        if use_alarm:
            signal.alarm(SERVER_TIMEOUT)

        try:
            server_data = prepare_npx_server(package_name)

            print("\n=== MCP WATCH ===")
            # mcp-watch needs: server_url, server_language
            # For NPX packages, we pass the package name as server_url
            # mcp-watch works on the npm registry / GitHub, so package_name is fine
            framework_result = execute_mcp_watch(
                package_name,
                "nodejs"
            )

            _status = framework_result.get("mcp-watch", {}).get("status", "failed")

            if _status == "failed":
                failure_reason = "execution_failed"
            elif _status != "completed":
                failure_reason = "no_output"

        except ServerTimeoutError:
            print(f"SERVER TIMEOUT ({SERVER_TIMEOUT}s) - skipping {package_name}")
            _status = "timeout_global"
            failure_reason = "server_timeout"
        except Exception as e:
            print(f"Error: {e}")
            _status = "error"
            failure_reason = "execution_error"
        finally:
            if use_alarm:
                signal.alarm(0)

        # Update global stats
        stats = update_global(stats, language, idx + 1)

        # Update framework stats on success
        if _status == "completed":
            try:
                update_framework(stats, framework_result["mcp-watch"], "mcp-watch", language)
            except Exception as e:
                print(f"Error updating framework stats: {e}")

            # Per-category/severity output files
            try:
                flat_vulns = flatten_vulnerabilities(framework_result["mcp-watch"])
                update_output_files(package_name, package_name, language, flat_vulns)
            except Exception as e:
                print(f"Error updating output files: {e}")

        # Track failure
        if failure_reason:
            fr_block = stats["mcp-watch"].setdefault("failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}})
            fr_block["total"] += 1
            fr_block["counts"][failure_reason] = fr_block["counts"].get(failure_reason, 0) + 1

            server_log[package_name] = f"nodejs {failure_reason}"
            save_local_log(server_log)
        elif _status == "completed":
            if package_name in server_log:
                del server_log[package_name]
                save_local_log(server_log)

        # Recalculate failure percentage
        fr_block = stats["mcp-watch"].get("failure_reasons")
        if fr_block:
            total_processed = stats.get("total", 0)
            if total_processed > 0:
                fr_block["percentage"] = round((fr_block["total"] / total_processed) * 100, 2)

        processed = idx + 1 - start_idx
        stats["remaining"] = total_in_range - processed

        save_local_stats(stats)

        cleanup_orphan_processes()
        _kill_orphan_server_processes()

        end_time = time.time()
        remaining = stats["remaining"]
        print(f"[mcp-watch-npx] {idx}/{end_idx} | nodejs | {_status} | {end_time - start_time:.2f}s | remaining: {remaining}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Watch on NPX servers")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (-1 = resume)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs")
    parser.add_argument("--excel", type=str, default=None, help="Path to NPX Excel file")
    args = parser.parse_args()

    main(args.start, args.end, args.reset, args.excel)
