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

ANALYSIS_TYPES = ("static", "dynamic", "fuzzing", "protocol")

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
from frameworks.mcpGuard import execute_mcp_guard
from functions.buildConfig import write_mcp_config
from functions.stats import update_framework
from functions.config import EXCEL_PATH_NPX

CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "mcp_guard_stats.json"
LOG_FILE = CURRENT_DIR / "mcp_guard_servers.json"

DEFAULT_EXCEL = EXCEL_PATH_NPX

INIT_STATS = {
    "last_index": 0,
    "total": 0,
    "range_start": 0,
    "range_end": 0,
    "remaining": 0,
    "languages": {},
    "mcp-guard": {
        "total": 0,
        "percentage": 0.0,
        "languages": {},
        "percentage_of_vulnerability": {},
        "categories_static": {},
        "categories_dynamic": {},
        "categories_real_fuzzing": {},
        "categories_robustness_fuzzing": {},
        "analysis_types": {
            "static": {"total": 0, "percentage": 0.0},
            "real_fuzzing": {"total": 0, "percentage": 0.0},
            "dynamic": {"total": 0, "percentage": 0.0},
            "robustness_fuzzing": {"total": 0, "percentage": 0.0}
        },
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

def save_vulnerability_entry(server_url: str, server_name: str, language: str, mcp_guard_res: dict):
    """Save vulnerability detail to <analysis_type>/<category>/<vuln_title>.json."""
    categories_block = mcp_guard_res.get("category", {})
    if not categories_block:
        return

    for full_title, instances in categories_block.items():
        for _idx, vuln_info in instances.items():
            analysis_type = vuln_info.get("type", "unknown")
            if ":-" in full_title:
                category, specific_title = full_title.split(":-", 1)
            else:
                category = "other"
                specific_title = full_title
            category = category.strip().lower().replace(" ", "-")
            specific_title = specific_title.strip().lower().replace(" ", "-")

            target_dir = CURRENT_DIR / analysis_type / category
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / f"{specific_title}.json"

            entry = {
                "server_url":  server_url,
                "server_name": server_name,
                "language":    language,
                "severity":    vuln_info.get("severity"),
                "file":        vuln_info.get("file"),
                "description": vuln_info.get("description"),
                "payload":     vuln_info.get("payload"),
                "response":    vuln_info.get("response"),
                "remediation": vuln_info.get("remediation"),
            }

            data = {"total": 0, "vulnerabilities": []}
            if target_file.exists():
                try:
                    with open(target_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    pass
            data["vulnerabilities"].append(entry)
            data["total"] = len(data["vulnerabilities"])
            tmp = target_file.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            tmp.replace(target_file)

def reset_all_output_files():
    """Remove all analysis_type folders (static/, dynamic/, fuzzing/, protocol/)."""
    for atype in ANALYSIS_TYPES:
        folder = CURRENT_DIR / atype
        if folder.exists() and folder.is_dir():
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

    if reset or start_idx == 0:
        print(f"Resetting stats and logs for MCP Guard NPX (start: {start_idx})")
        stats = copy.deepcopy(INIT_STATS)
        save_local_stats(stats)
        save_local_log({})
        reset_all_output_files()
    elif start_idx == -1:
        start_idx = last_index
        print(f"Resuming from index: {start_idx}")

    print(f"=== Running MCP Guard (NPX) ===")
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
        ram_ok = periodic_cache_cleanup(idx)
        if not ram_ok:
            print(f"\n STOPPING: RAM critically high. Resume with: python run_guard.py --start -1 --end {end_idx}")
            break

        stats = load_local_stats()
        server_log = load_local_log()

        _status = "failed"
        failure_reason = ""

        if use_alarm:
            signal.alarm(SERVER_TIMEOUT)

        try:
            server_data = prepare_npx_server(package_name)

            print("\n=== MCP GUARD ===")
            # mcp-guard needs: server_url, repo_path, command, elem
            # For NPX: server_url = package_name, repo_path = cwd
            framework_result = execute_mcp_guard(
                package_name,
                Path.cwd(),
                server_data["command"],
                server_data["elem"]
            )
            _status = framework_result.get("mcp-guard", {}).get("status", "failed")

            if _status == "failed":
                failure_reason = "execution_timeout"
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
                update_framework(stats, framework_result["mcp-guard"], "mcp-guard", language)
            except Exception as e:
                print(f"Error updating framework stats: {e}")

            # Per-analysis-type/category output files
            try:
                save_vulnerability_entry(package_name, package_name, language, framework_result["mcp-guard"])
            except Exception as e:
                print(f"Error updating output files: {e}")

        # Track failure
        if failure_reason:
            fr_block = stats["mcp-guard"].setdefault("failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}})
            fr_block["total"] += 1
            fr_block["counts"][failure_reason] = fr_block["counts"].get(failure_reason, 0) + 1

            server_log[package_name] = f"nodejs {failure_reason}"
            save_local_log(server_log)
        elif _status == "completed":
            if package_name in server_log:
                del server_log[package_name]
                save_local_log(server_log)

        # Recalculate failure percentage
        fr_block = stats["mcp-guard"].get("failure_reasons")
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
        print(f"[mcp-guard-npx] {idx}/{end_idx} | nodejs | {_status} | {end_time - start_time:.2f}s | remaining: {remaining}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Guard on NPX servers")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (-1 = resume)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs")
    parser.add_argument("--excel", type=str, default=None, help="Path to NPX Excel file")
    args = parser.parse_args()

    main(args.start, args.end, args.reset, args.excel)
