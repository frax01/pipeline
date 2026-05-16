import sys
import os
import json
import copy
import time
import signal
import argparse
import gc
import re
import shutil
import subprocess
from pathlib import Path

SERVER_TIMEOUT = 180  # FAST profile: 3 minutes hard cap per server
                       # (mcp-fuzzer internal cap is 150s, this is the
                       # outer SIGALRM safety net)
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
from frameworks.fuzzing import execute_mcp_fuzzing, update_fuzzing_summary
from functions.buildConfig import write_mcp_config
from functions.config import EXCEL_PATH_NPX

CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "fuzzing_stats.json"
LOG_FILE = CURRENT_DIR / "fuzzing_servers.json"

DEFAULT_EXCEL = EXCEL_PATH_NPX

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

def _sanitize_filename(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    name = re.sub(r'\s+', '_', name)
    return name[:120]

def _update_exception_file(base_dir: Path, exception_msg: str, item: dict):
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
    proto_dir = base_dir / "protocol"
    proto_dir.mkdir(parents=True, exist_ok=True)
    file_name = _sanitize_filename(protocol_type) + ".json"
    file_path = proto_dir / file_name
    data = {"protocol_type": protocol_type, "total_servers": 0, "total_runs": 0,
            "total_successful": 0, "total_errors": 0, "servers": []}
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
    """Save results into exceptions/ and protocol/ subfolders."""
    if not isinstance(fuzzing_data, dict):
        return
    # 1) EXCEPTIONS per tool
    for tool in (fuzzing_data.get("tools_detail") or []):
        if not isinstance(tool, dict):
            continue
        tool_name = tool.get("name", "unknown")
        exc_details = tool.get("exception_details") or []
        if not exc_details:
            continue
        by_msg = {}
        for exc in exc_details:
            msg = exc.get("message", "unknown")
            by_msg.setdefault(msg, []).append({
                "type": exc.get("type", "unknown"),
                "exception_type":  exc.get("exception_type"),
                "exception_class": exc.get("exception_class"),
                "exception_code":  exc.get("exception_code"),
                "arguments": exc.get("arguments", {}),
                "server_error_response": exc.get("server_error_response"),
            })
        success_inputs = [
            {
                "arguments":     s.get("arguments", {}),
                "result":        s.get("result"),
                "vuln_findings": s.get("vuln_findings", []),
            }
            for s in (tool.get("success_details") or [])
        ]
        for exc_msg, inputs in by_msg.items():
            item = {
                "server_url":           server_url,
                "server_name":          server_name,
                "tool_name":            tool_name,
                "runs":                 tool.get("runs", 0),
                "exceptions":           tool.get("exceptions", 0),
                "success_rate":         tool.get("success_rate", 0.0),
                "inputs_causing_error": inputs,
                "inputs_successful":    success_inputs,
            }
            _update_exception_file(CURRENT_DIR, exc_msg, item)

    # 2) PROTOCOL per type
    by_type = (fuzzing_data.get("protocol_types") or {}).get("by_type") or {}
    for proto_type, proto_data in by_type.items():
        if not isinstance(proto_data, dict):
            continue
        runs = proto_data.get("runs", 0)
        if runs == 0:
            continue
        error_inputs = [
            {
                "run":               ed.get("run", 0),
                "fuzz_data":         ed.get("fuzz_data") or ed.get("fuzz_payload", {}),
                "server_error":      ed.get("server_error") or ed.get("error_message"),
                "exception":         ed.get("exception"),
                "exception_type":    ed.get("exception_type"),
                "exception_class":   ed.get("exception_class"),
                "exception_code":    ed.get("exception_code"),
                "response_error":    ed.get("response_error"),
                "server_response":   ed.get("server_response"),
                "server_error_response": ed.get("server_error_response"),
                "invariant_violations":  ed.get("invariant_violations", []),
            }
            for ed in (proto_data.get("error_details") or [])
        ]
        success_details = [
            {
                "run":                  s.get("run", 0),
                "fuzz_payload":         s.get("fuzz_payload") or s.get("fuzz_data", {}),
                "server_response":      s.get("server_response"),
                "invariant_violations": s.get("invariant_violations", []),
                "vuln_findings":        s.get("vuln_findings", []),
            }
            for s in (proto_data.get("success_details") or [])
        ]
        item = {
            "server_url":      server_url,
            "server_name":     server_name,
            "runs":            runs,
            "successful":      proto_data.get("successful", 0),
            "errors":          proto_data.get("errors", 0),
            "success_rate":    proto_data.get("success_rate", 0.0),
            "error_details":   error_inputs,
            "success_details": success_details,
        }
        _update_protocol_file(CURRENT_DIR, proto_type, item)

def reset_all_output_files():
    """Remove exceptions/ and protocol/ subfolders."""
    for folder_name in ("exceptions", "protocol"):
        folder = CURRENT_DIR / folder_name
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

    print(f"=== Running Fuzzing (NPX) ===")
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

        if use_alarm:
            signal.alarm(SERVER_TIMEOUT)

        try:
            server_data = prepare_npx_server(package_name)

            print("\n=== FUZZING ===")
            framework_result = execute_mcp_fuzzing(
                Path.cwd(),
                server_data["command"],
                server_data["elem"],
                mode="both"
            )
            _status = framework_result.get("mcp-fuzzing", {}).get("status", "failed")

            if _status == "completed":
                update_fuzzing_summary(stats, framework_result, language)
                # Per-exception / protocol output files
                try:
                    fuzzing_data = framework_result.get("mcp-fuzzing", {})
                    update_output_files(package_name, package_name, fuzzing_data)
                except Exception as e:
                    print(f"Error updating output files: {e}")
            elif _status == "failed":
                failure_reason = "execution_failed"
            else:
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

        # Track failure
        if failure_reason:
            fr_block = stats["fuzzing"].setdefault("failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}})
            fr_block["total"] += 1
            fr_block["counts"][failure_reason] = fr_block["counts"].get(failure_reason, 0) + 1
            total_processed = stats.get("total", 0)
            if total_processed > 0:
                fr_block["percentage"] = round((fr_block["total"] / total_processed) * 100, 2)

        processed = idx + 1 - start_idx
        stats["remaining"] = total_in_range - processed

        save_local_stats(stats)

        server_log[package_name] = f"nodejs {failure_reason or _status}"
        save_local_log(server_log)

        cleanup_orphan_processes()
        _kill_orphan_server_processes()

        end_time = time.time()
        remaining = stats["remaining"]
        print(f"[fuzzing-npx] {idx}/{end_idx} | nodejs | {_status} | {end_time - start_time:.2f}s | remaining: {remaining}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Fuzzing on NPX servers")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (-1 = resume)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs")
    parser.add_argument("--excel", type=str, default=None, help="Path to NPX Excel file")
    args = parser.parse_args()

    main(args.start, args.end, args.reset, args.excel)
