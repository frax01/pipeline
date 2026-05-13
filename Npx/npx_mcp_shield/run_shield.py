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
from frameworks.mcpShield import execute_mcp_shield
from frameworks.llmAnalysis import run_llm_analysis
from functions.buildConfig import write_mcp_config
from functions.stats import update_framework, update_summary_llm_risk
from functions.config import EXCEL_PATH_NPX

CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "mcp_shield_stats.json"
LOG_FILE = CURRENT_DIR / "mcp_shield_servers.json"

DEFAULT_EXCEL = EXCEL_PATH_NPX

INIT_STATS = {
    "last_index": 0,
    "total": 0,
    "range_start": 0,
    "range_end": 0,
    "remaining": 0,
    "languages": {},
    "mcp-shield": {
        "total": 0,
        "percentage": 0.0,
        "languages": {},
        "tools": {
            "total": 0,
            "safe": 0,
            "vulnerable": {
                "total": 0,
                "average_vulnerable_per_server": 0.0,
                "static-analysis": {
                    "categories": {},
                    "percentage_of_vulnerability": {},
                    "counts": {},
                    "percentage_of_severity": {},
                },
                "llm-description-analysis": {
                    "LOW": 0,
                    "MEDIUM": 0,
                    "HIGH": 0
                }
            },
            "average_per_server": 0.0,
            "percentage_of_vulnerability": {
                "safe": 0.0,
                "vulnerable": 0.0
            }
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

def _update_category_file(base_dir: Path, category: str, risk: str, item: dict):
    """Append a finding to <base_dir>/<category>/<category>_<RISK>.json."""
    base_dir.mkdir(parents=True, exist_ok=True)
    cat_dir = base_dir / category
    cat_dir.mkdir(parents=True, exist_ok=True)
    file_name = f"{category.replace('-', '_')}_{risk.upper()}.json"
    file_path = cat_dir / file_name
    data = {"total": 0, "findings": []}
    if file_path.exists():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            pass
    data["findings"].append(item)
    data["total"] = len(data["findings"])
    tmp_path = file_path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    tmp_path.replace(file_path)

def update_output_files(server_url: str, server_name: str, mcp_shield_data: dict,
                        llm_tools: dict = None, llm_status: str = None,
                        llm_error: str = None, tool_descriptions: dict = None):
    """Write per-category/risk findings under <CURRENT_DIR>/<category>/."""
    tools = mcp_shield_data.get("tools", {})
    if llm_tools is None:
        llm_tools = {}
    if tool_descriptions is None:
        tool_descriptions = {}

    for tool_name, tool_data in tools.items():
        if tool_data.get("status") != "vulnerable":
            continue
        risk = (tool_data.get("risk") or "UNKNOWN").upper()
        llm_tool_data = llm_tools.get(tool_name, {})
        llm_risk = llm_tool_data.get("overallRisk", None)
        llm_analysis = llm_tool_data.get("analysis", None)

        cats = tool_data.get("category", {})
        for category_name, instances in cats.items():
            descriptions = [
                inst.get("description", "")
                for inst in instances.values()
                if inst.get("description")
            ]
            item = {
                "server_url":       server_url,
                "server_name":      server_name,
                "tool_name":        tool_name,
                "tool_description": tool_descriptions.get(tool_name, ""),
                "category":         category_name,
                "risk":             risk,
                "descriptions":     descriptions,
            }
            if llm_risk:
                item["llm_risk"] = llm_risk
                item["llm_analysis"] = llm_analysis
            elif llm_status and llm_status != "completed":
                item["llm_risk"] = "NOT_COMPLETED"
                item["llm_analysis"] = f"LLM analysis not completed: {llm_error or llm_status}"
            else:
                item["llm_risk"] = "NOT_AVAILABLE"
                item["llm_analysis"] = "LLM analysis was not executed"

            _update_category_file(CURRENT_DIR, category_name, risk, item)

def reset_all_output_files():
    """Remove all category subfolders under CURRENT_DIR (preserving python files / hidden)."""
    for folder in CURRENT_DIR.iterdir():
        if folder.is_dir() and not folder.name.startswith(".") and not folder.name.startswith("_"):
            try:
                shutil.rmtree(folder)
            except Exception:
                pass

def read_npx_servers(excel_path: str):
    import pandas as pd
    df = pd.read_excel(excel_path)
    return df["Link"].dropna().tolist()

def prepare_npx_server(package_name: str):
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

    if start_idx == -1:
        start_idx = last_index
        print(f"Resuming from index: {start_idx}")
    elif start_idx == 0 or reset:
        print(f"Starting from index {start_idx} -> Resetting stats and logs")
        stats = copy.deepcopy(INIT_STATS)
        save_local_stats(stats)
        save_local_log({})
        reset_all_output_files()
    else:
        print(f"Starting from index {start_idx} (keeping existing data)")

    print(f"=== Running MCP Shield (NPX) ===")
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
        periodic_cache_cleanup(idx)

        stats = load_local_stats()
        server_log = load_local_log()

        _status = "failed"
        failure_reason = ""
        framework_result = None
        llm = None

        if use_alarm:
            signal.alarm(SERVER_TIMEOUT)

        try:
            server_data = prepare_npx_server(package_name)

            print("\n=== MCP SHIELD ===")
            framework_result, status = execute_mcp_shield(Path.cwd())
            _status = status

            if status == "completed":
                # Update framework stats before LLM analysis
                pass
            else:
                failure_reason = "execution_failed"

            # LLM Description Analysis (only if shield succeeded)
            if _status == "completed":
                print("\n=== LLM ANALYSIS ===")
                try:
                    llm = run_llm_analysis(
                        framework_result["mcp-shield"],
                        Path.cwd(),
                        server_data["command"],
                        server_data["elem"]
                    )
                    llm_status = llm.get("status")
                    print(f"LLM Analysis status: {llm_status}")
                except Exception as e:
                    print(f"LLM Analysis error: {e}")
                    llm = {"status": "error", "error": str(e), "tools": {}}

        except ServerTimeoutError:
            print(f"SERVER TIMEOUT ({SERVER_TIMEOUT}s) - skipping {package_name}")
            _status = "timeout_global"
            failure_reason = "execution_timeout"
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
        if _status == "completed" and framework_result is not None:
            try:
                update_framework(stats, framework_result["mcp-shield"], "mcp-shield", language)
            except Exception as e:
                print(f"Error updating framework stats: {e}")

            # Update LLM risk if available
            try:
                if llm and llm.get("status") == "completed":
                    update_summary_llm_risk(stats, llm, "static", 0, "", 0)
            except Exception:
                pass

            # Per-category/risk output files
            try:
                mcp_shield_data = framework_result.get("mcp-shield", {})
                total_vulns = mcp_shield_data.get("total-vulnerabilities", 0)
                if total_vulns > 0:
                    llm_tools = llm.get("tools", {}) if llm else None
                    _llm_status = llm.get("status") if llm else None
                    _llm_error = llm.get("error") if llm else None
                    _tool_descriptions = llm.get("tool_descriptions", {}) if llm else {}
                    update_output_files(package_name, package_name, mcp_shield_data,
                                        llm_tools, _llm_status, _llm_error, _tool_descriptions)
            except Exception as e:
                print(f"Error updating output files: {e}")

        # Track failure
        if failure_reason:
            fr_block = stats["mcp-shield"].setdefault("failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}})
            fr_block["total"] += 1
            fr_block["counts"][failure_reason] = fr_block["counts"].get(failure_reason, 0) + 1
            total_processed = stats.get("total", 0)
            if total_processed > 0:
                fr_block["percentage"] = round((fr_block["total"] / total_processed) * 100, 2)

        # Update remaining
        processed = idx + 1 - start_idx
        stats["remaining"] = total_in_range - processed

        save_local_stats(stats)

        server_log[package_name] = f"nodejs {failure_reason or _status}"
        save_local_log(server_log)

        cleanup_orphan_processes()
        _kill_orphan_server_processes()

        end_time = time.time()
        remaining = stats["remaining"]
        print(f"[mcp-shield-npx] {idx}/{end_idx} | nodejs | {_status} | {end_time - start_time:.2f}s | remaining: {remaining}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Shield on NPX servers")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (-1 = resume)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs")
    parser.add_argument("--excel", type=str, default=None, help="Path to NPX Excel file")
    args = parser.parse_args()

    main(args.start, args.end, args.reset, args.excel)
