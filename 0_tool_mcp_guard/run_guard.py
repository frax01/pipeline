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
    periodic_cache_cleanup, cleanup_orphan_processes,
    _kill_orphan_server_processes
)
from frameworks.mcpGuard import execute_mcp_guard
from functions.buildConfig import build_mcp_config, clone_repo
from functions.stats import update_framework
from functions.config import EXCEL_PATH, BASE_DIR

# Configuration for local storage
CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "mcp_guard_stats.json"
LOG_FILE = CURRENT_DIR / "mcp_guard_servers.json"

# Results organization
RESULTS_DIR = CURRENT_DIR
ANALYSIS_TYPES = ["static", "dynamic", "fuzzing", "protocol"]


# Initialization structure for mcp-guard stats (subset of frameworks.json)
INIT_STATS = {
    "last_index": 0,
    "total": 0,
    "range_start": 0,
    "range_end": 0,
    "remaining": 0,
    "languages": {},
    "mcp-guard": {
        "total": 0,
        "servers_fuzzed": 0,
            "servers_scanned_static": 0,
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

def save_vulnerability_entry(server_url: str, server_data: dict, mcp_guard_res: dict):
    """Save vulnerability detail to analysis_type/category/vuln_title.json"""
    categories_block = mcp_guard_res.get("category", {})
    if not categories_block:
        return

    for full_title, instances in categories_block.items():
        for idx, vuln_info in instances.items():
            analysis_type = vuln_info.get("type", "unknown")
            if analysis_type not in ANALYSIS_TYPES:
                # Fallback or ignore? Let's use it as is if it's alphanumeric
                pass
            
            # Category and Specific Title split
            if ":-" in full_title:
                category, specific_title = full_title.split(":-", 1)
            else:
                category = "other"
                specific_title = full_title

            category = category.strip().lower().replace(" ", "-")
            specific_title = specific_title.strip().lower().replace(" ", "-")

            target_dir = RESULTS_DIR / analysis_type / category
            target_dir.mkdir(parents=True, exist_ok=True)
            
            target_file = target_dir / f"{specific_title}.json"
            
            entry = {
                "server_url": server_url,
                "server_name": server_data.get("server_name"),
                "language": server_data.get("server_language"),
                "severity": vuln_info.get("severity"),
                "file": vuln_info.get("file"),
                "description": vuln_info.get("description"),
                "payload": vuln_info.get("payload"),
                "response": vuln_info.get("response"),
                "remediation": vuln_info.get("remediation")
            }

            # Load existing if any
            data = {"total": 0, "vulnerabilities": []}
            if target_file.exists():
                try:
                    with open(target_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    pass
            
            # Simple check to avoid duplicated entries for same server (if re-running)
            # Actually, per VM run we usually start fresh or append. 
            # Let's just append for now.
            data["vulnerabilities"].append(entry)
            data["total"] = len(data["vulnerabilities"])
            
            with open(target_file, "w", encoding="utf-8") as f:
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

def prepare_server(server_url: str, hash_cache: dict, stats: dict) -> tuple[dict | None, str]:
    """Returns (server_data, failure_reason). failure_reason is empty string on success."""
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

    # Build config CON GESTIONE ERRORI
    try:
        server_name, command, elem = build_mcp_config(repo_path, server_language)
    except json.JSONDecodeError:
        print(f"ERRORE CRITICO: Il file di configurazione (es. package.json) è vuoto o corrotto per {server_url}")
        cleanup_repo(repo_path)
        return None, "config_json_corrupted"
    except Exception as e:
        print(f"ERRORE nella costruzione della config: {e}")
        cleanup_repo(repo_path)
        return None, "config_build_failed"

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
        print(f"Resetting stats and logs for MCP Guard (start: {start_idx})")
        stats = copy.deepcopy(INIT_STATS)
        save_local_stats(stats)
        server_log = {}
        save_local_log(server_log)
        
        # New: delete category folders
        for atype in ANALYSIS_TYPES:
            folder = RESULTS_DIR / atype
            if folder.exists() and folder.is_dir():
                print(f"Deleting category folder: {folder.name}")
                try:
                    shutil.rmtree(folder)
                except Exception as e:
                    print(f"Error deleting {folder}: {e}")
    elif start_idx == -1:
        start_idx = last_index
        print(f"Resuming from index: {start_idx}")

    # Clean up any leftover repos from previous crashed runs
    cleanup_orphan_repos(Path.cwd())

    print(f"=== Running MCP Guard Standalone ===")
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

        # Periodic cache cleanup + RAM check
        ram_ok = periodic_cache_cleanup(idx)
        if not ram_ok:
            print(f"\n⛔ STOPPING: RAM critically high. Saving state and exiting.")
            print(f"   Resume with: python run_guard.py --start -1 --end {end_idx}")
            break

        stats = load_local_stats()
        server_log = load_local_log()

        # Prepare server (with subprocess timeout, no SIGALRM)
        server_data = None
        failure_reason = ""

        try:
            server_data, failure_reason = prepare_server(server_url, None, stats)
        except (TimeoutError, subprocess.TimeoutExpired) as e:
            print(f"prepare_server timed out ({e}), skipping")
            failure_reason = "prepare_timeout"
            server_name = server_url.rstrip('/').split('/')[-1]
            partial_repo = Path.cwd() / server_name
            cleanup_repo(partial_repo)
        except Exception as e:
            print(f"prepare_server error: {e}, skipping")
            failure_reason = "prepare_error"
            server_name = server_url.rstrip('/').split('/')[-1]
            partial_repo = Path.cwd() / server_name
            cleanup_repo(partial_repo)

        # Determine language and status; always update stats even on failure
        language = "unknown"
        _status = "preparation_failed"
        repo_path = None

        if server_data is not None:
            language = server_data["server_language"]

        # Update global stats BEFORE framework analysis so stats["total"] is current
        stats = update_global(stats, language, idx + 1)

        if server_data is not None:
            repo_path = server_data["repo_path"]
            _status = "error"

            try:
                print("\n=== MCP GUARD ===")
                print("repo_path: ", repo_path)
                print("command: ", server_data["command"])
                print("elem: ", server_data["elem"][0])
                framework_result = execute_mcp_guard(
                    server_data["server_url"],
                    repo_path,
                    server_data["command"],
                    server_data["elem"][0]
                )
                _status = framework_result.get("mcp-guard", {}).get("status", "failed")

                if _status == "completed":
                    update_framework(stats, framework_result["mcp-guard"], "mcp-guard", language)
                    save_vulnerability_entry(server_url, server_data, framework_result["mcp-guard"])
                elif _status == "failed":

                    failure_reason = "execution_timeout"
                else:
                    failure_reason = "no_output"

            except TimeoutError:
                print(f"MCP Guard execution timed out")
                _status = "error"
                failure_reason = "execution_timeout"
            except Exception as e:
                print(f"Error executing MCP Guard: {e}")
                _status = "error"
                failure_reason = "execution_error"

            finally:
                cleanup_repo(repo_path)

        # Track failure reason in stats
        if failure_reason:
            fr_block = stats["mcp-guard"].setdefault("failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}})
            fr_block["total"] += 1
            fr_block["counts"][failure_reason] = fr_block["counts"].get(failure_reason, 0) + 1
                
            # Update failed server log
            server_log[server_url] = f"{language} {failure_reason}"
            save_local_log(server_log)
        elif _status == "completed":
            # Remove from failed log if successful
            if server_url in server_log:
                del server_log[server_url]
                save_local_log(server_log)
                
        # Recalculate percentage every time, even on success, so it doesn't get stale
        fr_block = stats["mcp-guard"].get("failure_reasons")
        if fr_block:
            total_processed = stats.get("total", 0)
            if total_processed > 0:
                fr_block["percentage"] = round((fr_block["total"] / total_processed) * 100, 2)

        # Update remaining counter
        processed = idx + 1 - start_idx
        stats["remaining"] = total_in_range - processed

        save_local_stats(stats)

        # Kill any orphan server processes left by mcp_scanner.py after each iteration
        cleanup_orphan_processes()
        _kill_orphan_server_processes()

        end_time = time.time()
        remaining = stats["remaining"]
        print(f"[mcp-guard] {idx}/{end_idx} | {language} | {_status} | {end_time - start_time:.2f}s | remaining: {remaining}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Guard independently")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (default: resume from last)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs before starting (even with --start N)")
    args = parser.parse_args()

    main(args.start, args.end, args.reset)
