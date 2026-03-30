import sys
import os
import json
import copy
import time
import argparse
import shutil
import stat
import signal
import subprocess
import pandas as pd
from pathlib import Path

# Add parent directory to sys.path to allow imports from functions/frameworks
sys.path.append(str(Path(__file__).resolve().parent.parent))

from functions.helper import (
    save_summary, update_global, load_summary,
    reset_file, extract_server_name, detect_language,
    periodic_cache_cleanup
)
from frameworks.mcpWatch import execute_mcp_watch
from functions.buildConfig import clone_repo
from functions.stats import update_framework
from functions.config import EXCEL_PATH, BASE_DIR

# Configuration for local storage
CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "mcp_watch_stats.json"
LOG_FILE = CURRENT_DIR / "mcp_watch_servers.json"

# Initialization structure for mcp-watch stats (subset of frameworks.json)
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
    """Merge override into base, preserving all keys from both."""
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

def cleanup_repo(repo_path: Path):
    """Remove a cloned repo directory, handling read-only files and permission issues."""
    if not repo_path or not os.path.exists(repo_path):
        return

    def onerror(func, p, exc_info):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            if func in (os.rmdir, os.remove, os.unlink):
                func(p)
        except Exception:
            pass

    try:
        if os.path.isdir(repo_path):
            shutil.rmtree(repo_path, onerror=onerror)
        else:
            os.remove(repo_path)
        print(f"Folder deleted: {repo_path.name}")
    except Exception:
        if os.name != 'nt':
            try:
                subprocess.run(['rm', '-rf', str(repo_path)], check=False)
                print(f"Folder deleted (fallback): {repo_path.name}")
            except Exception:
                pass

def prepare_server(server_url: str, stats: dict) -> tuple[dict | None, str]:
    server_name = extract_server_name(server_url)
    print(f"Server: {server_name}")
    print(f"URL: {server_url}")

    # Clone repo
    repo_path = clone_repo(server_url, Path.cwd())
    if repo_path is None or not repo_path.exists():
        return None, "clone_failed"
    try:
        server_language = detect_language(repo_path)
        print(f"Language: {server_language}")
    except Exception as e:
        print(f"ERROR Detecting Language: {e}")
        cleanup_repo(repo_path)
        return None, "language_detection_failed"

    return {
        "server_name": server_name,
        "server_url": server_url,
        "server_language": server_language,
        "repo_path": repo_path
    }, ""

def cleanup_orphan_repos(base_dir: Path):
    """Remove leftover cloned repos from previous crashed runs."""
    keep = {
        "data", "analysis", "frameworks", "functions", "localServer",
        "npm_runner", "Npx", "hashAnalysis", "temp_hash_analysis",
        "promptFilter", "examples", "node_modules",
        "tool_fuzzing", "tool_mcp_check", "tool_mcp_guard",
        "tool_mcp_scan", "tool_mcp_security_scan", "tool_mcp_shield",
        "tool_mcp_validator", "tool_mcp_watch", "tool_scanorama",
    }
    removed = 0
    for entry in base_dir.iterdir():
        if not entry.is_dir():
            continue
        if entry.name in keep or entry.name.startswith(".") or entry.name.startswith("tool_"):
            continue
        try:
            if (entry / ".git").exists():
                print(f"Cleaning orphan repo: {entry.name}")
                cleanup_repo(entry)
                removed += 1
        except (PermissionError, OSError):
            print(f"Skipping {entry.name} (permission denied)")
            continue
    if removed:
        print(f"Cleaned {removed} orphan repo(s) from previous runs")

def main(start_idx: int, end_idx: int = None, reset: bool = False):
    # Load stats to check for resume
    stats = load_local_stats()
    last_index = stats.get("last_index", 0)

    if reset or start_idx == 0:
        print(f"Resetting stats and logs for MCP Watch (start: {start_idx})")
        stats = copy.deepcopy(INIT_STATS)
        save_local_stats(stats)
        server_log = {}
        save_local_log(server_log)
    elif start_idx == -1:
        start_idx = last_index
        print(f"Resuming from index: {start_idx}")

    # Clean up any leftover repos from previous crashed runs
    cleanup_orphan_repos(Path.cwd())

    print(f"=== Running MCP Watch Standalone ===")
    print(f"Range server: {start_idx} - {end_idx if end_idx else 'end'}")

    df_excel = pd.read_excel(EXCEL_PATH)
    if end_idx is None:
        end_idx = len(df_excel)

    # Store range info in stats
    stats["range_start"] = start_idx
    stats["range_end"] = end_idx
    stats["remaining"] = end_idx - start_idx
    save_local_stats(stats)

    total_in_range = end_idx - start_idx
    print(f"Range server: {start_idx} - {end_idx} ({total_in_range} server)")

    for idx, row in df_excel.iloc[start_idx:end_idx].iterrows():
        start_time = time.time()
        server_url = row["Link"]

        print("\n" + "=" * 50)
        print(f"Index: {idx}")
        #periodic_cache_cleanup(idx) non serve sul mac

        stats = load_local_stats()
        server_log = load_local_log()

        # Prepare server (with 120s timeout to avoid npm/git hangs)
        # Prepare server (with 120s timeout to avoid npm/git hangs)
        PREPARE_TIMEOUT = 120
        server_data = None
        failure_reason = ""
        try:
            def _timeout_handler(signum, frame):
                raise TimeoutError("prepare_server timed out")
            old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(PREPARE_TIMEOUT)
            server_data, failure_reason = prepare_server(server_url, stats)
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
        except (TimeoutError, subprocess.TimeoutExpired) as e:
            signal.alarm(0)
            print(f"prepare_server timed out after {PREPARE_TIMEOUT}s ({e}), skipping")
            failure_reason = "prepare_timeout"
            server_name = server_url.rstrip('/').split('/')[-1]
            cleanup_repo(Path.cwd() / server_name)
        except Exception as e:
            signal.alarm(0)
            print(f"prepare_server error: {e}, skipping")
            failure_reason = "prepare_error"
            server_name = server_url.rstrip('/').split('/')[-1]
            cleanup_repo(Path.cwd() / server_name)

        # Secure handling of None
        if server_data is None:
            print("Watch preparation failed, skipping")
            server_log[server_url] = f"unknown {failure_reason if failure_reason else 'preparation_failed'}"
            save_local_log(server_log)
            stats = update_global(stats, "unknown", idx + 1)
            
            if failure_reason:
                fr_block = stats["mcp-watch"].setdefault("failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}})
                fr_block["total"] += 1
                fr_block["counts"][failure_reason] = fr_block["counts"].get(failure_reason, 0) + 1
            
            # Update percentage regardless of whether it failed this time
            fr_block = stats["mcp-watch"].get("failure_reasons")
            if fr_block:
                total_processed = stats.get("total", 0)
                if total_processed > 0:
                    fr_block["percentage"] = round((fr_block["total"] / total_processed) * 100, 2)
            
            save_local_stats(stats)
            end_time = time.time()
            print(f"[mcp-watch] {idx}/{end_idx} | unknown | preparation_failed | {end_time - start_time:.2f}s")
            continue

        repo_path = server_data["repo_path"]
        _status = "error"

        try:
            print("\n=== MCP WATCH ===")

            # Execute MCP Watch
            framework_result = execute_mcp_watch(
                server_data["server_url"],
                server_data["server_language"]
            )

            _status = framework_result.get("mcp-watch", {}).get("status", "failed")

            # Update stats
            stats = update_global(stats, server_data["server_language"], idx + 1)

            if _status == "completed":
                update_framework(stats, framework_result["mcp-watch"], "mcp-watch", server_data["server_language"])
            elif _status == "failed":
                failure_reason = "execution_failed"
            else:
                failure_reason = "no_output"

            save_local_stats(stats)

        except TimeoutError:
            print(f"MCP Watch execution timed out")
            _status = "error"
            failure_reason = "execution_failed"
        except Exception as e:
            print(f"Error executing MCP Watch: {e}")
            _status = "error"
            failure_reason = "execution_error"

        finally:
            # Cleanup
            cleanup_repo(repo_path)
            
            # Track failure reason in stats if not successful
            if _status != "completed" and failure_reason:
                fr_block = stats["mcp-watch"].setdefault("failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}})
                fr_block["total"] += 1
                fr_block["counts"][failure_reason] = fr_block["counts"].get(failure_reason, 0) + 1
                # Update failed server log
                server_log[server_data["server_url"]] = f"{server_data['server_language']} {failure_reason}"
                save_local_log(server_log)
            elif _status == "completed":
                # Remove from failed log if successful
                if server_data["server_url"] in server_log:
                    del server_log[server_data["server_url"]]
                    save_local_log(server_log)
            
            # Recalculate percentage every time, even on success, so it doesn't get stale
            fr_block = stats["mcp-watch"].get("failure_reasons")
            if fr_block:
                total_processed = stats.get("total", 0)
                if total_processed > 0:
                    fr_block["percentage"] = round((fr_block["total"] / total_processed) * 100, 2)
            save_local_stats(stats)

        end_time = time.time()
        print(f"[mcp-watch] {idx}/{end_idx} | {server_data['server_language']} | {_status} | {end_time - start_time:.2f}s")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Watch independently")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (default: resume from last)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs before starting (even with --start N)")
    args = parser.parse_args()

    main(args.start, args.end, args.reset)
