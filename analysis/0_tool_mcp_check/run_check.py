import sys
import os
import json
import copy
import time
import signal
import argparse
import shutil
import stat
import subprocess
import pandas as pd
from pathlib import Path

# Global per-server timeout (seconds) - kills the entire server if exceeded
SERVER_TIMEOUT = 600  # 10 minutes max per server

class ServerTimeoutError(Exception):
    pass

def _timeout_handler(signum, frame):
    raise ServerTimeoutError("Server processing exceeded timeout")

# Add parent directory to sys.path to allow imports from functions/frameworks
sys.path.append(str(Path(__file__).resolve().parent.parent))

from functions.helper import (
    save_summary, update_global, load_summary,
    reset_file, extract_server_name, detect_language,
    periodic_cache_cleanup, cleanup_orphan_processes,
    _kill_orphan_server_processes
)
from frameworks.mcpCheck import execute_mcp_check
from functions.buildConfig import build_mcp_config, clone_repo
from functions.stats import update_framework
from functions.config import EXCEL_PATH, BASE_DIR

# Configuration for local storage
CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "mcp_check_stats.json"
LOG_FILE = CURRENT_DIR / "mcp_check_servers.json"

# Initialization structure for mcp-check stats (subset of frameworks.json)
INIT_STATS = {
    "last_index": 0,
    "total": 0,
    "range_start": 0,
    "range_end": 0,
    "remaining": 0,
    "languages": {},
    "mcp-check": {
        "total": 0,
        "percentage": 0.0,
        "languages": {},
        "suites": {},
        "tests": {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "warnings": 0,
            "success_rate": 0.0
        },
        "errors": {},
        "warnings": {},
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

def prepare_server(server_url: str, stats: dict) -> dict | None:
    server_name = extract_server_name(server_url)
    print(f"Server: {server_name}")
    print(f"URL: {server_url}")

    # Clone repo
    print(f"  [1/3] Cloning...")
    repo_path = clone_repo(server_url, Path.cwd())
    if repo_path is None or not repo_path.exists():
        return None
    try:
        print(f"  [2/3] Detecting language...")
        server_language = detect_language(repo_path)
        print(f"  Language: {server_language}")
    except Exception as e:
        print(f"ERROR Detecting Language: {e}")
        cleanup_repo(repo_path)
        return None

    # Build config (needed for command and elem)
    try:
        print(f"  [3/3] Building config...")
        server_name, command, elem = build_mcp_config(repo_path, server_language)
        print(f"  Config ready: {command} {elem}")
    except json.JSONDecodeError:
        print(f"ERRORE CRITICO: Il file di configurazione è vuoto o corrotto per {server_url}")
        cleanup_repo(repo_path)
        return None
    except Exception as e:
        print(f"ERRORE nella costruzione della config: {e}")
        cleanup_repo(repo_path)
        return None

    if command is None:
        command = "unknown"
    if elem is None:
        elem = ["unknown"]

    return {
        "server_name": server_name,
        "server_url": server_url,
        "server_language": server_language,
        "repo_path": repo_path,
        "command": command,
        "elem": elem
    }

def cleanup_orphan_repos(base_dir: Path):
    """Remove leftover cloned repos from previous crashed runs."""
    keep = {
        "data", "analysis", "frameworks", "functions", "localServer",
        "npm_runner", "Npx", "hashAnalysis", "temp_hash_analysis",
        "promptFilter", "examples", "node_modules",
        "tool_fuzzing", "tool_mcp_check", "tool_mcp_guard",
        "tool_mcp_scan", "tool_mcp_security_scan", "tool_mcp_shield",
        "tool_mcp_validator", "tool_mcp_watch", "tool_scanorama",
        "0_tool_mcp_security_scan", "0_tool_mcp_guard", "0_tool_mcp_scan",
        "0_tool_mcp_shield", "0_tool_mcp_watch", "0_tool_mcp_check",
        "0_tool_fuzzing", "0_tool_scanorama", "0_tool_mcp_validator",
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
        print(f"Resetting stats and logs for MCP Check (start: {start_idx})")
        stats = copy.deepcopy(INIT_STATS)
        save_local_stats(stats)
        server_log = {}
        save_local_log(server_log)
    elif start_idx == -1:
        start_idx = last_index
        print(f"Resuming from index: {start_idx}")

    # Clean up any leftover repos from previous crashed runs
    cleanup_orphan_repos(Path.cwd())

    print(f"=== Running MCP Check Standalone ===")
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

    # Set up signal handler for per-server timeout (Unix only)
    use_alarm = hasattr(signal, 'SIGALRM')
    if use_alarm:
        signal.signal(signal.SIGALRM, _timeout_handler)

    for idx, row in df_excel.iloc[start_idx:end_idx].iterrows():
        start_time = time.time()
        server_url = row["Link"]

        print("\n" + "=" * 50)
        print(f"Index: {idx}")

        # Periodic cache cleanup + RAM check
        ram_ok = periodic_cache_cleanup(idx)
        if not ram_ok:
            print(f"\n⛔ STOPPING: RAM critically high. Saving state and exiting.")
            print(f"   Resume with: python run_check.py --start -1 --end {end_idx}")
            break

        stats = load_local_stats()
        server_log = load_local_log()

        # Determine language and status
        language = "unknown"
        _status = "preparation_failed"
        repo_path = None
        failure_reason = ""

        # Set global per-server timeout
        if use_alarm:
            signal.alarm(SERVER_TIMEOUT)

        try:
            # Prepare server (with timeout protection)
            server_data = None
            PREPARE_TIMEOUT = 120

            try:
                def _prepare_timeout_handler(signum, frame):
                    raise TimeoutError("prepare_server timed out")

                if use_alarm:
                    old_handler = signal.signal(signal.SIGALRM, _prepare_timeout_handler)
                    signal.alarm(PREPARE_TIMEOUT)

                server_data = prepare_server(server_url, stats)

                if use_alarm:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, _timeout_handler)
            except (TimeoutError, subprocess.TimeoutExpired) as e:
                if use_alarm:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, _timeout_handler)
                print(f"prepare_server timed out after {PREPARE_TIMEOUT}s ({e}), skipping")
                failure_reason = "prepare_timeout"
                server_name = server_url.rstrip('/').split('/')[-1]
                cleanup_repo(Path.cwd() / server_name)
            except Exception as e:
                if use_alarm:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, _timeout_handler)
                print(f"prepare_server error: {e}, skipping")
                failure_reason = "prepare_error"
                server_name = server_url.rstrip('/').split('/')[-1]
                cleanup_repo(Path.cwd() / server_name)

            if server_data is not None:
                language = server_data["server_language"]
                repo_path = server_data["repo_path"]
                _status = "error"

                try:
                    print("\n=== MCP CHECK ===")
                    print("repo_path: ", repo_path)
                    print("command: ", server_data["command"])
                    print("elem: ", server_data["elem"])
                    framework_result, status = execute_mcp_check(
                        server_data["repo_path"],
                        server_data["command"],
                        server_data["elem"]
                    )
                    _status = status

                    if status == "completed":
                        pass  # framework stats updated below
                    elif status == "failed":
                        failure_reason = "execution_timeout"
                    else:
                        failure_reason = "no_output"

                except TimeoutError:
                    print(f"MCP Check execution timed out")
                    _status = "error"
                    failure_reason = "execution_timeout"
                except Exception as e:
                    print(f"Error executing MCP Check: {e}")
                    _status = "error"
                    failure_reason = "execution_error"

                finally:
                    cleanup_repo(repo_path)
            else:
                if not failure_reason:
                    failure_reason = "preparation_failed"

        except ServerTimeoutError:
            print(f"SERVER TIMEOUT ({SERVER_TIMEOUT}s) - skipping {server_url}")
            _status = "timeout_global"
            failure_reason = "server_timeout"
            server_name = server_url.rstrip('/').split('/')[-1]
            try:
                cleanup_repo(Path.cwd() / server_name)
            except Exception:
                pass
        finally:
            # Cancel alarm
            if use_alarm:
                signal.alarm(0)

        # ALWAYS update global FIRST (so total is correct for percentage calculations)
        stats = update_global(stats, language, idx + 1)

        # THEN update framework stats
        if server_data is not None and _status == "completed" and framework_result is not None:
            try:
                update_framework(stats, framework_result["mcp-check"], "mcp-check", language)
            except Exception as e:
                print(f"Error updating framework stats: {e}")

        # Track failure reason in stats
        if failure_reason:
            fr_block = stats["mcp-check"].setdefault("failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}})
            fr_block["total"] += 1
            fr_block["counts"][failure_reason] = fr_block["counts"].get(failure_reason, 0) + 1

            server_log[server_url] = f"{language} {failure_reason}"
            save_local_log(server_log)
        elif _status == "completed":
            if server_url in server_log:
                del server_log[server_url]
                save_local_log(server_log)

        # Recalculate failure percentage
        fr_block = stats["mcp-check"].get("failure_reasons")
        if fr_block:
            total_processed = stats.get("total", 0)
            if total_processed > 0:
                fr_block["percentage"] = round((fr_block["total"] / total_processed) * 100, 2)

        # Update remaining counter
        processed = idx + 1 - start_idx
        stats["remaining"] = total_in_range - processed

        save_local_stats(stats)

        # Kill any orphan server processes left after each iteration
        cleanup_orphan_processes()
        _kill_orphan_server_processes()

        end_time = time.time()
        remaining = stats["remaining"]
        print(f"[mcp-check] {idx}/{end_idx} | {language} | {_status} | {end_time - start_time:.2f}s | remaining: {remaining}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Check independently")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (default: resume from last)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs before starting (even with --start N)")
    args = parser.parse_args()

    main(args.start, args.end, args.reset)
