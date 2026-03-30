import sys
import os
import json
import copy
import time
import argparse
import shutil
import stat
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
from frameworks.scanorama import execute_scanorama
from functions.buildConfig import clone_repo
from functions.stats import update_framework
from functions.config import EXCEL_PATH, BASE_DIR

# Configuration for local storage
CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "scanorama_stats.json"
LOG_FILE = CURRENT_DIR / "scanorama_servers.json"

# Initialization structure for scanorama stats (subset of frameworks.json)
INIT_STATS = {
    "last_index": 0,
    "total": 0,
    "range_start": 0,
    "range_end": 0,
    "remaining": 0,
    "languages": {},
    "scanorama": {
        "total": 0,
        "percentage": 0.0,
        "languages": {},
        "tools": {
            "total": 0,
            "average_per_server": 0.0
        },
        "injections": {
            "total": 0,
            "average_per_server": 0.0
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
    repo_path = clone_repo(server_url, Path.cwd())
    try:
        server_language = detect_language(repo_path)
        print(f"Language: {server_language}")
    except Exception as e:
        print(f"ERROR Detecting Language: {e}")
        cleanup_repo(repo_path)
        return None

    return {
        "server_name": server_name,
        "server_url": server_url,
        "server_language": server_language,
        "repo_path": repo_path
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

def main(start_idx: int, end_idx: int = None):
    # Load stats to check for resume
    stats = load_local_stats()
    last_index = stats.get("last_index", 0)

    if start_idx == -1:
        start_idx = last_index
        print(f"Resuming from index: {start_idx}")
    elif start_idx == 0:
        print("Starting from index 0 (forced) -> Resetting stats and logs")
        stats = copy.deepcopy(INIT_STATS)
        save_local_stats(stats)
        server_log = {}
        save_local_log(server_log)

    # Clean up any leftover repos from previous crashed runs
    cleanup_orphan_repos(Path.cwd())

    print(f"=== Running Scanorama Standalone ===")
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
        periodic_cache_cleanup(idx)

        stats = load_local_stats()
        server_log = load_local_log()

        # Prepare server (with timeout protection)
        server_data = None
        try:
            server_data = prepare_server(server_url, stats)
        except subprocess.TimeoutExpired as e:
            print(f"prepare_server timed out ({e}), skipping")
            server_name = server_url.rstrip('/').split('/')[-1]
            cleanup_repo(Path.cwd() / server_name)
        except Exception as e:
            print(f"prepare_server error: {e}, skipping")
            server_name = server_url.rstrip('/').split('/')[-1]
            cleanup_repo(Path.cwd() / server_name)

        if server_data is None:
            print("Scanorama preparation failed, skipping")
            server_log[server_url] = "preparation_failed"
            save_local_log(server_log)
            stats = update_global(stats, "unknown", idx + 1)
            save_local_stats(stats)
            end_time = time.time()
            print(f"[scanorama] {idx}/{end_idx} | unknown | preparation_failed | {end_time - start_time:.2f}s")
            continue

        repo_path = server_data["repo_path"]
        _status = "error"

        try:
            print("\n=== SCANORAMA ===")
            framework_result = execute_scanorama(
                server_data["repo_path"]
            )

            _status = framework_result.get("status", "failed")

            # Update stats
            stats = update_global(stats, server_data["server_language"], idx + 1)

            if _status == "completed":
                update_framework(stats, framework_result, "scanorama", server_data["server_language"])

            save_local_stats(stats)

            # Update log
            server_log[server_data["server_url"]] = f"{server_data['server_language']} {_status}"
            save_local_log(server_log)

        except Exception as e:
            print(f"Error executing Scanorama: {e}")
            server_log[server_data["server_url"]] = f"{server_data['server_language']} error"
            save_local_log(server_log)

        finally:
            # Cleanup
            cleanup_repo(repo_path)

        end_time = time.time()
        print(f"[scanorama] {idx}/{end_idx} | {server_data['server_language']} | {_status} | {end_time - start_time:.2f}s")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Scanorama independently")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (default: resume from last)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    args = parser.parse_args()

    main(args.start, args.end)
