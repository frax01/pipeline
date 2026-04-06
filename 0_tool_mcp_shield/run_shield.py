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
from frameworks.mcpShield import execute_mcp_shield
from frameworks.llmAnalysis import run_llm_analysis
from functions.buildConfig import clone_repo, build_mcp_config
from functions.stats import update_framework, update_summary_llm_risk
from functions.config import EXCEL_PATH

# Configuration for local storage
CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "mcp_shield_stats.json"
LOG_FILE = CURRENT_DIR / "mcp_shield_servers.json"

# Initialization structure for mcp-shield stats
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
                    "descriptions": {}
                },
                "llm-description-analysis": {
                    "LOW": 0,
                    "MEDIUM": 0,
                    "HIGH": 0,
                    "UNKNOWN": 0,
                    "failures": {
                        "total": 0,
                        "reasons": {}
                    }
                }
            },
            "average_per_server": 0.0,
            "percentage_of_vulnerability": {
                "safe": 0.0,
                "vulnerable": 0.0
            }
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

def _update_category_file(base_dir: Path, category: str, risk: str, item: dict):
    """Aggiunge una vulnerabilità al file locale <code/category>_<risk>.json all'interno della cartella categoria"""
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

def update_output_files(server_url: str, server_name: str, mcp_shield_data: dict, llm_tools: dict = None, llm_status: str = None, llm_error: str = None, tool_descriptions: dict = None):
    """Scrive le vulnerabilità classificate per categoria e score LLM + analisi LLM."""
    tools = mcp_shield_data.get("tools", {})
    if llm_tools is None:
        llm_tools = {}
    if tool_descriptions is None:
        tool_descriptions = {}

    for tool_name, tool_data in tools.items():
        if tool_data.get("status") != "vulnerable":
            continue

        risk = tool_data.get("risk", "UNKNOWN")
        if not risk:
            risk = "UNKNOWN"
        risk = risk.upper()

        # Recupera dati LLM per questo tool
        llm_tool_data = llm_tools.get(tool_name, {})
        llm_risk = llm_tool_data.get("overallRisk", None)
        llm_analysis = llm_tool_data.get("analysis", None)

        cats = tool_data.get("category", {})
        for category_name, instances in cats.items():
            descriptions = [inst.get("description", "") for inst in instances.values() if inst.get("description")]
            item = {
                "server_url": server_url,
                "server_name": server_name,
                "tool_name": tool_name,
                "tool_description": tool_descriptions.get(tool_name, ""),
                "category": category_name,
                "risk": risk,
                "descriptions": descriptions
            }

            # Aggiungi sempre i campi LLM
            if llm_risk:
                item["llm_risk"] = llm_risk
                item["llm_analysis"] = llm_analysis
            elif llm_status and llm_status != "completed":
                # LLM ha girato ma non è riuscita per questo tool o globalmente
                item["llm_risk"] = "NOT_COMPLETED"
                item["llm_analysis"] = f"LLM analysis not completed: {llm_error or llm_status}"
            else:
                # LLM non ha mai girato (es. analisi statica fallita prima)
                item["llm_risk"] = "NOT_AVAILABLE"
                item["llm_analysis"] = "LLM analysis was not executed"

            _update_category_file(CURRENT_DIR, category_name, risk, item)

def reset_all_output_files():
    """Cancella ricorsivamente tutte le cartelle delle categorie in mcp_shield."""
    for folder in CURRENT_DIR.iterdir():
        if folder.is_dir() and folder.name not in [".", ".."]:
            # Rimuovi solo le cartelle categoria (evitando cartelle nascoste o file python)
            if not folder.name.startswith(".") and not folder.name.startswith("_"):
                try:
                    shutil.rmtree(folder)
                except Exception:
                    pass

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


def prepare_server(server_url: str) -> dict | None:
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

    # Build config (writes claude_desktop_config.json needed by mcp-shield and builds TS projects)
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

    print(f"=== Running MCP Shield Standalone ===")

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
                server_data = prepare_server(server_url)
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
                llm = None

                try:
                    if server_data["command"] == "unknown":
                        print(f"Skipping {server_data['server_name']}: not_runnable (no command found)")
                        _status = "skipped"
                    else:
                        print("\n=== MCP SHIELD ===")
                        framework_result, status = execute_mcp_shield(
                            server_data["repo_path"]
                        )
                        _status = status

                    if _status == "completed":
                        # LLM Description Analysis
                        print("\n=== LLM ANALYSIS ===")
                        try:
                            llm = run_llm_analysis(
                                framework_result["mcp-shield"],
                                server_data["repo_path"],
                                server_data["command"],
                                server_data["elem"]
                            )
                            llm_status = llm.get("status")
                            print(f"LLM Analysis status: {llm_status}")
                            if llm_status == "completed":
                                update_summary_llm_risk(stats, llm, "static", 0, "", 0)
                            else:
                                # LLM returned but not completed
                                llm_fail_reason = llm.get("error", llm_status or "unknown_status")
                                llm_failures = stats["mcp-shield"]["tools"]["vulnerable"]["llm-description-analysis"]["failures"]
                                llm_failures["total"] += 1
                                llm_failures["reasons"][llm_fail_reason] = llm_failures["reasons"].get(llm_fail_reason, 0) + 1
                                print(f"LLM Analysis not completed: {llm_fail_reason}")
                        except Exception as e:
                            print(f"LLM Analysis error: {e}")
                            llm = {"status": "error", "error": str(e), "tools": {}}
                            llm_failures = stats["mcp-shield"]["tools"]["vulnerable"]["llm-description-analysis"]["failures"]
                            llm_failures["total"] += 1
                            llm_fail_reason = f"exception: {str(e)[:100]}"
                            llm_failures["reasons"][llm_fail_reason] = llm_failures["reasons"].get(llm_fail_reason, 0) + 1

                except Exception as e:
                    print(f"Error executing MCP Shield: {e}")
                    _status = "error"

                finally:
                    cleanup_repo(repo_path)

        except ServerTimeoutError:
            print(f"⚠️ SERVER TIMEOUT ({SERVER_TIMEOUT}s) - skipping {server_url}")
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

        # ALWAYS update global FIRST
        stats = update_global(stats, language, idx + 1)

        # THEN update framework stats
        if server_data is not None and _status == "completed" and framework_result is not None:
            try:
                update_framework(stats, framework_result["mcp-shield"], "mcp-shield", language)
            except Exception as e:
                print(f"Error updating framework stats: {e}")
            
            # Aggiorna le cartelle di shield estraendo i rank LLM
            mcp_shield_data = framework_result.get("mcp-shield", {})
            total_vulns = mcp_shield_data.get("total-vulnerabilities", 0)
            
            if total_vulns > 0:
                llm_tools = llm.get("tools", {}) if llm else None
                _llm_status = llm.get("status") if llm else None
                _llm_error = llm.get("error") if llm else None
                _tool_descriptions = llm.get("tool_descriptions", {}) if llm else {}
                update_output_files(server_url, server_data["server_name"], mcp_shield_data, llm_tools, _llm_status, _llm_error, _tool_descriptions)

        # Update remaining counter
        processed = idx + 1 - start_idx
        stats["remaining"] = total_in_range - processed

        save_local_stats(stats)

        server_log[server_url] = f"{language} {_status}"
        save_local_log(server_log)

        end_time = time.time()
        remaining = stats["remaining"]
        print(f"[mcp-shield] {idx}/{end_idx} | {language} | {_status} | {end_time - start_time:.2f}s | remaining: {remaining}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Shield independently")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (default: resume from last)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs before starting (even with --start N)")
    args = parser.parse_args()

    main(args.start, args.end, reset=args.reset)
