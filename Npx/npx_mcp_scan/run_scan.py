import sys
import os
import json
import copy
import time
import signal
import argparse
import gc
import subprocess
from pathlib import Path

# Global per-server timeout (seconds)
SERVER_TIMEOUT = 600  # 10 minutes max per server

# Minimum free memory (MB) required to continue
MIN_FREE_MEMORY_MB = 200

def check_memory_available() -> bool:
    """Check if enough free memory is available. Waits in loop until recovered."""
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
    print("  Killing orphan processes and cleaning caches...")
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

# Add parent directory to sys.path (on VM: Npx/../ = pipeline root with functions/ and frameworks/)
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from functions.helper import (
    save_summary, update_global, load_summary,
    reset_file, periodic_cache_cleanup,
    cleanup_orphan_processes, _kill_orphan_server_processes
)
from frameworks.mcpScan import execute_mcp_scan
from functions.buildConfig import write_mcp_config
from functions.stats import update_framework
from functions.config import EXCEL_PATH_NPX

# Configuration for local storage
CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "mcp_scan_stats.json"
LOG_FILE = CURRENT_DIR / "mcp_scan_servers.json"
VULNS_FILE = CURRENT_DIR / "mcp_scan_vulnerabilities.json"

# NPX Excel path - override via --excel argument or use config default
DEFAULT_EXCEL = EXCEL_PATH_NPX

# Initialization structure for mcp-scan stats
INIT_STATS = {
    "last_index": 0,
    "total": 0,
    "range_start": 0,
    "range_end": 0,
    "remaining": 0,
    "languages": {},
    "mcp-scan": {
        "total": 0,
        "percentage": 0.0,
        "languages": {
            "nodejs": 0
        },
        "percentage_of_vulnerability": {},
        "categories": {},
        "vulnerabilities": {
            "total": 0,
            "average_per_server": 0.0,
            "counts": {},
            "percentage_of_severity": {}
        },
        "server_vulnerabilities": {
            "total": 0,
            "average_per_server": 0.0,
            "counts": {},
            "percentage_of_severity": {},
            "categories": {},
            "percentage_of_vulnerability": {},
            "issue_codes": {}
        },
        "tool_vulnerabilities": {
            "total": 0,
            "average_per_server": 0.0,
            "counts": {},
            "percentage_of_severity": {},
            "categories": {},
            "percentage_of_vulnerability": {},
            "issue_codes": {},
            "trigger_words": {}
        },
        "tools": {
            "total": 0,
            "safe": 0,
            "vulnerable": 0,
            "average_vulnerable_per_server": 0.0,
            "percentage_of_vulnerability": {
                "safe": 0.0,
                "vulnerable": 0.0
            },
            "average_per_server": 0.0
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

def load_vulns():
    if not VULNS_FILE.exists():
        return {}
    try:
        with open(VULNS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_vulns(data):
    tmp_file = VULNS_FILE.with_suffix(".tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    tmp_file.replace(VULNS_FILE)

def _update_category_file(base_dir: Path, code: str, item: dict):
    """Append a vulnerability entry to <base_dir>/<code>.json."""
    base_dir.mkdir(parents=True, exist_ok=True)
    file_path = base_dir / f"{code}.json"
    data = {"total": 0, "vulnerabilities": []}
    if file_path.exists():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            pass
    data["vulnerabilities"].append(item)
    data["total"] = len(data["vulnerabilities"])
    tmp_path = file_path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    tmp_path.replace(file_path)

def update_output_files(server_url: str, mcp_scan_data: dict):
    """Write per-issue-code files under tool-level/ and server-level/."""
    # Server-level issues
    for code, info in mcp_scan_data.get("server_issues", {}).items():
        item = {
            "server_url": server_url,
            "severity":   info.get("severity", "unknown"),
            "message":    info.get("message", ""),
            "extra_data": info.get("extra_data", {}),
        }
        _update_category_file(CURRENT_DIR / "server-level", code, item)

    # Server-level toxic flows
    for code, tf_name in mcp_scan_data.get("toxic_flows", {}).items():
        item = {
            "server_url": server_url,
            "severity":   "critical",
            "message":    f"Toxic Flow: {tf_name}",
            "extra_data": {},
        }
        _update_category_file(CURRENT_DIR / "server-level", code, item)

    # Tool-level issues
    for tool_name, tool_data in mcp_scan_data.get("tools", {}).items():
        if tool_data.get("status") != "vulnerable":
            continue
        cats = tool_data.get("category", {})
        extras = tool_data.get("extra_data", {})
        labels = tool_data.get("labels", {})
        for code, category_name in cats.items():
            item = {
                "server_url": server_url,
                "tool_name":  tool_name,
                "category":   category_name,
                "labels":     labels,
                "extra_data": extras.get(code, {}),
            }
            _update_category_file(CURRENT_DIR / "tool-level", code, item)

def reset_all_output_files():
    """Remove all per-code JSON files under server-level/ and tool-level/."""
    for folder in ("server-level", "tool-level"):
        d = CURRENT_DIR / folder
        if d.exists() and d.is_dir():
            for f in d.iterdir():
                if f.is_file() and f.suffix == ".json":
                    try:
                        f.unlink()
                    except Exception:
                        pass

def read_npx_servers(excel_path: str):
    """Read NPX server list from Excel. Returns list of package names."""
    import pandas as pd
    df = pd.read_excel(excel_path)
    return df["Link"].dropna().tolist()

def prepare_npx_server(package_name: str):
    """Write MCP config for an NPX server. No cloning or building needed."""
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
        save_vulns({})
        reset_all_output_files()
    else:
        print(f"Starting from index {start_idx} (keeping existing data)")

    print(f"=== Running MCP Scan (NPX) ===")
    print(f"Excel: {excel_path}")

    servers = read_npx_servers(excel_path)
    total_servers = len(servers)
    print(f"Total NPX servers in list: {total_servers}")

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

        # Memory check
        check_memory_available()
        periodic_cache_cleanup(idx)

        stats = load_local_stats()
        server_log = load_local_log()

        _status = "failed"
        failure_reason = ""
        framework_result = None

        if use_alarm:
            signal.alarm(SERVER_TIMEOUT)

        try:
            server_data = prepare_npx_server(package_name)

            print("\n=== MCP SCAN ===")
            framework_result, status = execute_mcp_scan(Path.cwd())
            _status = status

            if _status != "completed":
                failure_reason = "execution_failed"

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
                update_framework(stats, framework_result["mcp-scan"], "mcp-scan", language)
            except Exception as e:
                print(f"Error updating framework stats: {e}")

            # Save vulnerabilities
            mcp_scan_data = framework_result.get("mcp-scan", {})
            total_vulns = mcp_scan_data.get("total-vulnerabilities", 0)
            if total_vulns > 0:
                vulns_data = load_vulns()
                vulnerable_tools = {
                    tool_name: tool_data
                    for tool_name, tool_data in mcp_scan_data.get("tools", {}).items()
                    if tool_data.get("status") == "vulnerable"
                }
                vulns_data[package_name] = {
                    "total-vulnerabilities": total_vulns,
                    "tools": vulnerable_tools,
                    "server_issues": mcp_scan_data.get("server_issues", {}),
                    "toxic_flows": mcp_scan_data.get("toxic_flows", {})
                }
                save_vulns(vulns_data)

                # Per-code output files (tool-level/ and server-level/)
                try:
                    update_output_files(package_name, mcp_scan_data)
                except Exception as e:
                    print(f"Error updating output files: {e}")

        # Track failure
        if failure_reason:
            fr_block = stats["mcp-scan"].setdefault("failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}})
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

        # Kill orphan processes
        cleanup_orphan_processes()
        _kill_orphan_server_processes()

        end_time = time.time()
        remaining = stats["remaining"]
        print(f"[mcp-scan-npx] {idx}/{end_idx} | nodejs | {_status} | {end_time - start_time:.2f}s | remaining: {remaining}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Scan on NPX servers")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (-1 = resume)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs")
    parser.add_argument("--excel", type=str, default=None, help="Path to NPX Excel file")
    args = parser.parse_args()

    main(args.start, args.end, args.reset, args.excel)
