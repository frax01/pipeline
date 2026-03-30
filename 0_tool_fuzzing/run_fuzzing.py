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
import re
import pandas as pd
from pathlib import Path

# Global per-server timeout (seconds) - kills the entire server if exceeded
SERVER_TIMEOUT = 300  # 5 minutes max per server

# Minimum free memory (MB) required to start fuzzing a new server
MIN_FREE_MEMORY_MB = 200

def check_memory_available() -> bool:
    """Check if enough free memory is available to continue fuzzing.
    Never stops - waits in loop until memory is available."""
    from functions.helper import cleanup_orphan_processes, _kill_orphan_server_processes, cleanup_caches

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
    cleanup_orphan_processes()
    _kill_orphan_server_processes()
    cleanup_caches(force=True)
    import gc
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
            cleanup_orphan_processes()
            _kill_orphan_server_processes()
            cleanup_caches(force=True)
            gc.collect()

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
from frameworks.fuzzing import execute_mcp_fuzzing, update_fuzzing_summary
from functions.buildConfig import build_mcp_config, clone_repo
from functions.config import EXCEL_PATH

# Configuration for local storage
CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "fuzzing_stats.json"
LOG_FILE = CURRENT_DIR / "fuzzing_servers.json"

# Initialization structure for fuzzing stats
INIT_STATS = {
    "last_index": 0,
    "total": 0,
    "range_start": 0,
    "range_end": 0,
    "remaining": 0,
    "languages": {},
    "fuzzing": {
        "total_servers": 0,
        "percentage": 0.0,
        "languages": {},
        "total_tools": 0,
        "total_fuzzing_runs": 0,
        "total_successful": 0,
        "total_exceptions": 0,
        "total_safety_blocked": 0,
        "success_rate": 0.0,
        "exceptions_by_message": {},
        "protocol_types": {
            "total_types_tested": 0,
            "total_runs": 0,
            "total_successful": 0,
            "total_errors": 0,
            "success_rate": 0.0,
            "by_type": {}
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

# =====================================================
# SOTTOCARTELLE: Exceptions + Protocol
# =====================================================

def _sanitize_filename(name: str) -> str:
    """Sanitizza un nome per usarlo come nome file/cartella."""
    name = name.strip()
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    name = re.sub(r'\s+', '_', name)
    name = name[:120]  # limita lunghezza
    return name

def _update_exception_file(base_dir: Path, exception_msg: str, item: dict):
    """Aggiunge un finding al file della exception corrispondente."""
    exc_dir = base_dir / "exceptions"
    exc_dir.mkdir(parents=True, exist_ok=True)

    file_name = _sanitize_filename(exception_msg) + ".json"
    file_path = exc_dir / file_name

    data = {"exception_message": exception_msg, "total": 0, "servers": []}
    if file_path.exists():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            pass

    data["servers"].append(item)
    data["total"] = len(data["servers"])

    tmp_path = file_path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    tmp_path.replace(file_path)

def _update_protocol_file(base_dir: Path, protocol_type: str, item: dict):
    """Aggiunge un finding al file del protocol type corrispondente."""
    proto_dir = base_dir / "protocol"
    proto_dir.mkdir(parents=True, exist_ok=True)

    file_name = _sanitize_filename(protocol_type) + ".json"
    file_path = proto_dir / file_name

    data = {"protocol_type": protocol_type, "total_servers": 0, "total_runs": 0, "total_successful": 0, "total_errors": 0, "servers": []}
    if file_path.exists():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            pass

    data["servers"].append(item)
    data["total_servers"] = len(data["servers"])
    data["total_runs"] += item.get("runs", 0)
    data["total_successful"] += item.get("successful", 0)
    data["total_errors"] += item.get("errors", 0)

    tmp_path = file_path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    tmp_path.replace(file_path)

def update_output_files(server_url: str, server_name: str, fuzzing_data: dict):
    """Salva i risultati nelle sottocartelle exceptions/ e protocol/."""

    # 1. EXCEPTIONS: per ogni tool con exception_details
    tools_detail = fuzzing_data.get("tools_detail", [])
    for tool in tools_detail:
        tool_name = tool.get("name", "unknown")
        exc_details = tool.get("exception_details", [])
        if not exc_details:
            continue

        # Raggruppa per messaggio di exception
        by_msg = {}
        for exc in exc_details:
            msg = exc.get("message", "unknown")
            if msg not in by_msg:
                by_msg[msg] = []
            by_msg[msg].append({
                "type": exc.get("type", "unknown"),
                "arguments": exc.get("arguments", {})
            })

        for exc_msg, inputs in by_msg.items():
            item = {
                "server_url": server_url,
                "server_name": server_name,
                "tool_name": tool_name,
                "runs": tool.get("runs", 0),
                "exceptions": tool.get("exceptions", 0),
                "success_rate": tool.get("success_rate", 0.0),
                "inputs_causing_error": inputs
            }
            _update_exception_file(CURRENT_DIR, exc_msg, item)

    # 2. PROTOCOL: per ogni protocol type testato
    protocol_types = fuzzing_data.get("protocol_types", {})
    by_type = protocol_types.get("by_type", {})
    for proto_type, proto_data in by_type.items():
        runs = proto_data.get("runs", 0)
        if runs == 0:
            continue

        # Estrai error_details per questo server (payload, errore, response)
        error_details = proto_data.get("error_details", [])
        error_inputs = [
            {
                "run": ed.get("run", 0),
                "fuzz_payload": ed.get("fuzz_payload", {}),
                "error_message": ed.get("error_message", "Unknown"),
                "server_response": ed.get("server_response"),
                "invariant_violations": ed.get("invariant_violations", [])
            }
            for ed in error_details
        ]

        item = {
            "server_url": server_url,
            "server_name": server_name,
            "runs": runs,
            "successful": proto_data.get("successful", 0),
            "errors": proto_data.get("errors", 0),
            "success_rate": proto_data.get("success_rate", 0.0),
            "error_details": error_inputs
        }
        _update_protocol_file(CURRENT_DIR, proto_type, item)

def reset_all_output_files():
    """Cancella le sottocartelle exceptions/ e protocol/."""
    for folder_name in ("exceptions", "protocol"):
        folder = CURRENT_DIR / folder_name
        if folder.exists() and folder.is_dir():
            try:
                shutil.rmtree(folder)
            except Exception:
                pass

# =====================================================
# HELPER
# =====================================================

def cleanup_repo(repo_path: Path):
    """Remove a cloned repo directory, handling read-only files."""
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

def prepare_server(server_url: str) -> dict | None:
    server_name = extract_server_name(server_url)
    print(f"Server: {server_name}")
    print(f"URL: {server_url}")

    print(f"  [1/3] Cloning...")
    repo_path = clone_repo(server_url, Path.cwd())
    try:
        print(f"  [2/3] Detecting language...")
        server_language = detect_language(repo_path)
        print(f"  Language: {server_language}")
    except Exception as e:
        print(f"ERROR Detecting Language: {e}")
        cleanup_repo(repo_path)
        return None

    try:
        print(f"  [3/3] Building config...")
        server_name, command, elem = build_mcp_config(repo_path, server_language)
        print(f"  Config ready: {command} {elem}")
    except json.JSONDecodeError:
        print(f"ERRORE CRITICO: config vuota o corrotta per {server_url}")
        cleanup_repo(repo_path)
        return None
    except Exception as e:
        print(f"ERRORE nella costruzione della config: {e}")
        cleanup_repo(repo_path)
        return None

    if command is None:
        cleanup_repo(repo_path)
        return None

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
        "promptFilter", "examples", "node_modules", "recap",
        "tool_fuzzing", "tool_mcp_check", "tool_mcp_guard",
        "tool_mcp_scan", "tool_mcp_security_scan", "tool_mcp_shield",
        "tool_mcp_validator", "tool_mcp_watch", "tool_scanorama",
        "tool_llm_analysis", "tool_llm_proxy", "Pipeline",
        "__pycache__", "venv", "pipeline-env", ".venv",
    }
    removed = 0
    for entry in base_dir.iterdir():
        if not entry.is_dir():
            continue
        if entry.name in keep or entry.name.startswith(".") or entry.name.startswith("tool_"):
            continue
        try:
            resolved = entry.resolve()
            if not str(resolved).startswith(str(base_dir.resolve())):
                continue
        except Exception:
            continue
        try:
            if (entry / ".git").exists():
                print(f"Cleaning orphan repo: {entry.name}")
                cleanup_repo(entry)
                removed += 1
        except (PermissionError, OSError):
            continue
    if removed:
        print(f"Cleaned {removed} orphan repo(s) from previous runs")

# =====================================================
# MAIN
# =====================================================

def main(start_idx: int, end_idx: int = None, reset: bool = False):
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

    cleanup_orphan_repos(Path.cwd())

    print(f"=== Running Fuzzing Standalone ===")

    df_excel = pd.read_excel(EXCEL_PATH)
    if end_idx is None:
        end_idx = len(df_excel)

    stats["range_start"] = start_idx
    stats["range_end"] = end_idx
    stats["remaining"] = end_idx - start_idx
    save_local_stats(stats)

    total_in_range = end_idx - start_idx
    print(f"Range server: {start_idx} - {end_idx} ({total_in_range} server)")

    use_alarm = hasattr(signal, 'SIGALRM')
    if use_alarm:
        signal.signal(signal.SIGALRM, _timeout_handler)

    for idx, row in df_excel.iloc[start_idx:end_idx].iterrows():
        start_time = time.time()
        server_url = row["Link"]

        print("\n" + "=" * 50)
        print(f"Index: {idx}")
        periodic_cache_cleanup(idx)

        check_memory_available()

        stats = load_local_stats()
        server_log = load_local_log()

        language = "unknown"
        _status = "preparation_failed"
        repo_path = None

        if use_alarm:
            signal.alarm(SERVER_TIMEOUT)

        try:
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

                try:
                    if server_data["command"] == "unknown":
                        print(f"Skipping {server_data['server_name']}: not_runnable (no command found)")
                        _status = "skipped"
                    else:
                        print("\n=== FUZZING ===")
                        framework_result = execute_mcp_fuzzing(
                            server_data["repo_path"],
                            server_data["command"],
                            server_data["elem"][0],
                            mode="all"
                        )
                        _status = framework_result.get("mcp-fuzzing", {}).get("status", "failed")

                        if _status == "completed":
                            update_fuzzing_summary(stats, framework_result, language)

                except Exception as e:
                    print(f"Error executing Fuzzing: {e}")
                    _status = "error"

                finally:
                    cleanup_repo(repo_path)

            # Salva nelle sottocartelle exceptions/ e protocol/
            if server_data is not None and _status == "completed" and framework_result is not None:
                try:
                    fuzzing_data = framework_result.get("mcp-fuzzing", {})
                    update_output_files(server_url, server_data["server_name"], fuzzing_data)
                except Exception as e:
                    print(f"Error updating output files: {e}")

        except ServerTimeoutError:
            print(f"⚠️ SERVER TIMEOUT ({SERVER_TIMEOUT}s) - skipping {server_url}")
            _status = "timeout_global"
            server_name = server_url.rstrip('/').split('/')[-1]
            try:
                cleanup_repo(Path.cwd() / server_name)
            except Exception:
                pass
        finally:
            if use_alarm:
                signal.alarm(0)

        stats = update_global(stats, language, idx + 1)

        processed = idx + 1 - start_idx
        stats["remaining"] = total_in_range - processed

        save_local_stats(stats)

        server_log[server_url] = f"{language} {_status}"
        save_local_log(server_log)

        end_time = time.time()
        remaining = stats["remaining"]
        print(f"[fuzzing] {idx}/{end_idx} | {language} | {_status} | {end_time - start_time:.2f}s | remaining: {remaining}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Fuzzing independently")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (default: resume from last)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs before starting")
    args = parser.parse_args()

    main(args.start, args.end, reset=args.reset)
