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
    periodic_cache_cleanup
)
from frameworks.mcpScan import execute_mcp_scan
from functions.buildConfig import build_mcp_config, clone_repo, write_mcp_config
from functions.stats import update_framework
from functions.config import EXCEL_PATH, BASE_DIR

# Configuration for local storage
CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "mcp_scan_stats.json"
LOG_FILE = CURRENT_DIR / "mcp_scan_servers.json"
VULNS_FILE = CURRENT_DIR / "mcp_scan_vulnerabilities.json"

# Initialization structure for mcp-scan stats (subset of frameworks.json)
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
            "nodejs": 0,
            "python": 0,
            "go": 0,
            "unknown": 0,
            "docker": 0
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
        # Merge with INIT_STATS to fill any missing keys, but preserve all existing values
        return _deep_merge(INIT_STATS, data)
    except Exception:
        return copy.deepcopy(INIT_STATS)

def save_local_stats(data):
    # Atomic write: write to temp file first, then rename (prevents corruption)
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

def _update_category_file(base_dir: Path, code: str, item: dict):
    """Aggiunge una vulnerabilità al file locale <code/category>.json"""
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
    """Scrive le vulnerabilità per server-level e tool-level."""
    # 1. Server-level issues
    server_issues = mcp_scan_data.get("server_issues", {})
    for code, info in server_issues.items():
        item = {
            "server_url": server_url,
            "severity": info.get("severity", "unknown"),
            "message": info.get("message", ""),
            "extra_data": info.get("extra_data", {})
        }
        _update_category_file(CURRENT_DIR / "server-level", code, item)
        
    # 2. Server-level toxic flows (Trattati al livello server)
    toxic_flows = mcp_scan_data.get("toxic_flows", {})
    for code, tf_name in toxic_flows.items():
        item = {
            "server_url": server_url,
            "severity": "critical",  # Toxic flow usually critical
            "message": f"Toxic Flow: {tf_name}",
            "extra_data": {}
        }
        _update_category_file(CURRENT_DIR / "server-level", code, item)

    # 3. Tool-level issues
    tools = mcp_scan_data.get("tools", {})
    for tool_name, tool_data in tools.items():
        if tool_data.get("status") != "vulnerable":
            continue
        
        cats = tool_data.get("category", {})
        extras = tool_data.get("extra_data", {})
        labels = tool_data.get("labels", {})
        
        for code, category_name in cats.items():
            item = {
                "server_url": server_url,
                "tool_name": tool_name,
                "category": category_name,
                "labels": labels,  # Add the SAST labels
                "extra_data": extras.get(code, {})
            }
            _update_category_file(CURRENT_DIR / "tool-level", code, item)

def reset_all_output_files():
    """Cancella ricorsivamente server-level e tool-level"""
    for folder in ["server-level", "tool-level"]:
        d = CURRENT_DIR / folder
        if d.exists() and d.is_dir():
            for f in d.iterdir():
                if f.is_file() and f.suffix == ".json":
                    f.unlink()

def cleanup_repo(repo_path: Path):
    """Remove a cloned repo directory, handling read-only files (Python 3.12+)."""
    if not repo_path or not os.path.exists(repo_path):
        return

    def onerror(func, p, exc_info):
        """Handler for shutil.rmtree errors."""
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

def prepare_npx_server(package_name: str) -> dict | None:
    """Server NPX: nessun clone. Scrive la config MCP con `npx -y <pkg>` così
    mcp-scan avvia il pacchetto pubblicato e lo ispeziona (analisi dinamica)."""
    server_name = (package_name or "").strip()
    print(f"Server (npx): {server_name}")
    try:
        write_mcp_config(server_name=server_name, command="npx",
                         args=["-y", server_name], cwd=Path.cwd())
    except Exception as e:
        print(f"ERROR writing NPX mcp config: {e}")
        return None
    return {
        "server_name": server_name,
        "server_url": package_name,
        "server_language": "nodejs",
        "repo_path": None,
        "command": "npx",
        "elem": ["-y", server_name],
    }


def prepare_server(server_url: str, stats: dict) -> dict | None:
    server_name = extract_server_name(server_url)
    print(f"Server: {server_name}")
    print(f"URL: {server_url}")

    # Clone repo
    print(f"  [1/3] Cloning...")
    repo_path = clone_repo(server_url, Path.cwd())
    if repo_path is None:
        return None
    try:
        print(f"  [2/3] Detecting language...")
        server_language = detect_language(repo_path)
        print(f"  Language: {server_language}")
    except Exception as e:
        print(f"ERROR Detecting Language: {e}")
        cleanup_repo(repo_path)
        return None

    # Build config (writes claude_desktop_config.json needed by mcp-scan)
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

    if start_idx == -1:
        start_idx = last_index
        print(f"Resuming from index: {start_idx}")
    elif start_idx == 0 or reset:
        print(f"Starting from index {start_idx} -> Resetting stats and logs")
        stats = copy.deepcopy(INIT_STATS)
        save_local_stats(stats)
        server_log = {}
        save_local_log(server_log)
        reset_all_output_files()
    else:
        print(f"Starting from index {start_idx} (keeping existing data)")

    # Clean up any leftover repos from previous crashed runs
    cleanup_orphan_repos(Path.cwd())

    print(f"=== Running MCP Scan Standalone ===")

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

    if "Type" not in df_excel.columns:
        df_excel["Type"] = "github"

    for idx, row in df_excel.iloc[start_idx:end_idx].iterrows():
        start_time = time.time()
        server_url = row["Link"]
        server_type = str(row.get("Type", "github") or "github").strip().lower()

        print("\n" + "=" * 50)
        print(f"Index: {idx} ({server_type})")
        periodic_cache_cleanup(idx)

        stats = load_local_stats()
        server_log = load_local_log()

        # Determine language and status
        language = "unknown"
        _status = "preparation_failed"
        repo_path = None

        # Set global per-server timeout
        if use_alarm:
            signal.alarm(SERVER_TIMEOUT)

        try:
            # Prepare server
            server_data = None
            try:
                if server_type == "npx":
                    server_data = prepare_npx_server(server_url)
                else:
                    server_data = prepare_server(server_url, stats)
            except subprocess.TimeoutExpired as e:
                print(f"prepare_server timed out ({e}), skipping")
                server_name = server_url.rstrip('/').split('/')[-1]
                cleanup_repo(Path.cwd() / server_name)
            except Exception as e:
                print(f"prepare_server error: {e}, skipping")
                server_name = server_url.rstrip('/').split('/')[-1]
                cleanup_repo(Path.cwd() / server_name)

            if server_data is not None:
                language = server_data["server_language"]
                repo_path = server_data["repo_path"]
                _status = "error"
                framework_result = None

                try:
                    print("\n=== MCP SCAN ===")
                    framework_result, status = execute_mcp_scan(
                        server_data["repo_path"]
                    )
                    _status = status

                except Exception as e:
                    print(f"Error executing MCP Scan: {e}")
                    _status = "error"

                finally:
                    cleanup_repo(repo_path)

        except ServerTimeoutError:
            print(f"SERVER TIMEOUT ({SERVER_TIMEOUT}s) - skipping {server_url}")
            _status = "timeout_global"
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

        # THEN update framework stats (now total is already incremented)
        if server_data is not None and _status == "completed" and framework_result is not None:
            try:
                update_framework(stats, framework_result["mcp-scan"], "mcp-scan", language)
            except Exception as e:
                print(f"Error updating framework stats: {e}")
            
            # Aggiorna le nuove cartelle separate per code
            mcp_scan_data = framework_result.get("mcp-scan", {})
            total_vulns = mcp_scan_data.get("total-vulnerabilities", 0)
            
            if total_vulns > 0:
                update_output_files(server_url, mcp_scan_data)

        # Update remaining counter
        processed = idx + 1 - start_idx
        stats["remaining"] = total_in_range - processed

        save_local_stats(stats)

        server_log[server_url] = f"{language} {_status}"
        save_local_log(server_log)

        end_time = time.time()
        remaining = stats["remaining"]
        print(f"[mcp-scan] {idx}/{end_idx} | {language} | {_status} | {end_time - start_time:.2f}s | remaining: {remaining}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Scan independently")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (default: resume from last)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs before starting (even with --start N)")
    args = parser.parse_args()

    main(args.start, args.end, reset=args.reset)
