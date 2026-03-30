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

# Global per-server timeout (seconds)
# Proxy is slower than other frameworks (LLM calls via Ollama)
SERVER_TIMEOUT = 900  # 15 minutes max per server

# Minimum free memory (MB) required to start proxy analysis
# Higher than other frameworks because Ollama uses 4-8GB RAM
MIN_FREE_MEMORY_MB = 500

# Minimum free disk space (MB) required to continue
MIN_FREE_DISK_MB = 1000  # 1GB minimum


def check_disk_space() -> bool:
    """Check if enough disk space is available.
    If low, cleans caches. If critically low, stops."""
    try:
        disk = shutil.disk_usage(Path.home())
        free_mb = disk.free / (1024 * 1024)
        free_gb = free_mb / 1024

        if free_mb < MIN_FREE_DISK_MB:
            print(f"\n[DISK] LOW SPACE: {free_gb:.1f}GB free (minimum: {MIN_FREE_DISK_MB/1024:.1f}GB)")
            print("  Cleaning caches to free space...")

            # Clean common cache directories
            cache_dirs = [
                Path.home() / ".npm",
                Path.home() / ".cache" / "pip",
                Path.home() / ".cache" / "uv",
                Path.home() / ".cache" / "node-gyp",
                Path.home() / ".cache" / "huggingface",
                Path.home() / ".cache" / "pnpm",
                Path.home() / ".cache" / "prisma",
                Path.home() / ".cache" / "selenium",
                Path.home() / ".rustup",
                Path.home() / ".bun",
                Path.home() / "go" / "pkg",
            ]
            freed = 0
            for d in cache_dirs:
                if d.exists() and d.is_dir():
                    try:
                        size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
                        shutil.rmtree(d, ignore_errors=True)
                        freed += size
                    except Exception:
                        pass

            # Clean /tmp junk
            import glob
            for pattern in ["/tmp/node-gyp-*", "/tmp/v8-compile-cache-*",
                            "/tmp/ncc-cache", "/tmp/bunx-*", "/tmp/nx-native-*"]:
                for d in glob.glob(pattern):
                    try:
                        dp = Path(d)
                        if dp.is_dir():
                            size = sum(f.stat().st_size for f in dp.rglob("*") if f.is_file())
                            shutil.rmtree(dp, ignore_errors=True)
                            freed += size
                    except Exception:
                        pass

            if freed > 0:
                print(f"  Freed {freed / (1024**2):.0f}MB")

            # Re-check after cleanup
            disk = shutil.disk_usage(Path.home())
            free_mb = disk.free / (1024 * 1024)
            if free_mb < MIN_FREE_DISK_MB / 2:
                print(f"  [DISK] CRITICAL: only {free_mb:.0f}MB free after cleanup. STOPPING.")
                return False
            print(f"  [DISK] After cleanup: {free_mb:.0f}MB free")

        return True
    except Exception as e:
        print(f"  Disk check error: {e}")
        return True  # Can't check, continue


def manage_ollama_memory():
    """Tell Ollama to unload the model after each server to free RAM.
    The model will be reloaded on next request (adds ~5s but saves 4-8GB RAM between servers)."""
    try:
        # Set keep_alive to 0 to unload model immediately after use
        subprocess.run(
            ["curl", "-s", "-X", "POST", "http://localhost:11434/api/generate",
             "-d", '{"model": "llama3", "keep_alive": 0}'],
            capture_output=True, timeout=10
        )
    except Exception:
        pass


def check_memory_available() -> bool:
    """Check if enough free memory is available to continue.
    Never stops - waits in loop until memory is available.
    Actively cleans caches and kills orphan processes to free RAM."""
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
        return True  # Can't check, continue anyway

    if free_mb >= MIN_FREE_MEMORY_MB:
        return True

    # Low memory - actively clean up and wait in loop
    print(f"[RAM] LOW MEMORY: {free_mb:.0f}MB available (minimum: {MIN_FREE_MEMORY_MB}MB)")
    print("  Killing orphan processes and cleaning caches...")
    cleanup_orphan_processes()
    _kill_orphan_server_processes()
    cleanup_caches(force=True)
    import gc
    gc.collect()

    # Also kill any lingering Ollama/node processes
    _kill_proxy_orphans()

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
            _kill_proxy_orphans()
            cleanup_caches(force=True)
            gc.collect()


def _kill_proxy_orphans():
    """Kill orphan ts-node/node processes left by previous proxy runs."""
    if os.name == 'nt':
        return
    patterns = [
        "ts-node.*index.ts",
        "node.*NewProxy",
    ]
    for pat in patterns:
        try:
            subprocess.run(
                ["pkill", "-f", pat],
                capture_output=True, timeout=10
            )
        except Exception:
            pass


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
from frameworks.NewProxy.proxyAnalysis import run_llm_proxy_analysis
from functions.buildConfig import build_mcp_config, clone_repo
from functions.stats import update_summary_llm_risk
from functions.config import EXCEL_PATH, BASE_DIR

# Configuration for local storage
CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "proxy_stats.json"
LOG_FILE = CURRENT_DIR / "proxy_servers.json"

# Deterministic causes template (14 validators)
DETERMINISTIC_CAUSES_INIT = {
    "total": 0,
    "command_injection": 0,
    "ssh_private_keys": 0,
    "suspicious_file_access": 0,
    "sql_injection": 0,
    "container_isolation_violation": 0,
    "entropy_secrets": 0,
    "pii_detection": 0,
    "prompt_injection": 0,
    "important_tag_injection": 0,
    "shadow_hijack": 0,
    "cross_origin_access": 0,
    "xss_injection": 0,
    "base64_encoded_payload": 0,
    "invisible_unicode_injection": 0
}

INTENT_BLOCK_INIT = {
    "deterministic_causes": copy.deepcopy(DETERMINISTIC_CAUSES_INIT),
    "tool_call_causes": 0,
    "tool_response_causes": 0,
    "failed": 0
}

# Initialization structure for proxy stats (matches functions/config.py init["proxy"])
INIT_STATS = {
    "last_index": 0,
    "total": 0,
    "range_start": 0,
    "range_end": 0,
    "remaining": 0,
    "languages": {},
    "proxy": {
        "total_server": 0,
        "percentage": 0.0,
        "languages": {},
        "total_tools": 0,
        "total_trials": 0,
        "total_failed": 0,
        "tool_blocked": {
            "total": 0,
            "percentage": 0.0,
            "benign": copy.deepcopy(INTENT_BLOCK_INIT),
            "malicious": copy.deepcopy(INTENT_BLOCK_INIT),
            "jailbreak_combined": copy.deepcopy(INTENT_BLOCK_INIT),
            "encoding_evasion": copy.deepcopy(INTENT_BLOCK_INIT),
        },
        "prompt": {
            "total_prompt": 0,
            "total_blocked": 0,
            "total_allowed": 0,
            "percentage": 0.0,
            "deterministic_causes": copy.deepcopy(DETERMINISTIC_CAUSES_INIT),
            "tool_call_causes": 0,
            "tool_response_causes": 0
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
        print(f"ERRORE CRITICO: Il file di configurazione corrotto per {server_url}")
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
        "tool_proxy",
        "0_tool_mcp_security_scan", "0_tool_mcp_guard", "0_tool_mcp_scan",
        "0_tool_mcp_shield", "0_tool_mcp_watch", "0_tool_mcp_check",
        "0_tool_fuzzing", "0_tool_scanorama", "0_tool_mcp_validator",
        "0_tool_proxy",
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


def _update_proxy_stats(stats: dict, proxy_result: dict, server_language: str):
    """Aggregate proxy analysis results into local stats.
    This is the per-VM equivalent of update_summary_llm_risk for type='proxy'."""
    proxy_summ = stats["proxy"]
    proxy_summ["total_server"] += 1
    proxy_summ["languages"][server_language] = proxy_summ["languages"].get(server_language, 0) + 1

    tool_length = proxy_result.get("tool_length", 0)
    proxy_summ["total_tools"] += tool_length
    proxy_summ["total_trials"] += proxy_result.get("total_trials", 0)
    proxy_summ["total_failed"] += proxy_result.get("total_failed", 0)

    if stats["total"] > 0:
        proxy_summ["percentage"] = round(proxy_summ["total_server"] / stats["total"] * 100, 2)

    # ---- tool_blocked aggregation ----
    proxy_data = proxy_result.get("proxy", {})
    tool_blocked = proxy_summ["tool_blocked"]

    for intent in ("benign", "malicious", "jailbreak_combined", "encoding_evasion"):
        src = proxy_data.get(intent, {})
        dst = tool_blocked[intent]

        # Deterministic causes
        src_det = src.get("deterministic_causes", {})
        dst_det = dst["deterministic_causes"]
        for key in dst_det:
            dst_det[key] += src_det.get(key, 0)

        # LLM causes
        dst["tool_call_causes"] += src.get("tool_call_causes", 0)
        dst["tool_response_causes"] += src.get("tool_response_causes", 0)
        dst["failed"] += src.get("failed", 0)

    # Recalculate total blocked across all intents
    total_blocked = 0
    for intent in ("benign", "malicious", "jailbreak_combined", "encoding_evasion"):
        ib = tool_blocked[intent]
        total_blocked += ib["deterministic_causes"]["total"]
        total_blocked += ib["tool_call_causes"]
        total_blocked += ib["tool_response_causes"]
    tool_blocked["total"] = total_blocked

    if proxy_summ["total_tools"] > 0:
        tool_blocked["percentage"] = round(total_blocked / proxy_summ["total_tools"] * 100, 2)

    # ---- prompt aggregation ----
    prompt_src = proxy_result.get("prompt", {})
    prompt_dst = proxy_summ["prompt"]

    prompt_dst["total_prompt"] += prompt_src.get("total_prompt", 0)
    prompt_dst["total_blocked"] += prompt_src.get("total_blocked", 0)
    prompt_dst["total_allowed"] += prompt_src.get("total_allowed", 0)
    prompt_dst["tool_call_causes"] += prompt_src.get("tool_call_causes", 0)
    prompt_dst["tool_response_causes"] += prompt_src.get("tool_response_causes", 0)

    src_pdet = prompt_src.get("deterministic_causes", {})
    dst_pdet = prompt_dst["deterministic_causes"]
    for key in dst_pdet:
        dst_pdet[key] += src_pdet.get(key, 0)

    if prompt_dst["total_prompt"] > 0:
        prompt_dst["percentage"] = round(prompt_dst["total_blocked"] / prompt_dst["total_prompt"] * 100, 2)


def check_ollama_available() -> bool:
    """Check if Ollama is running and llama3 model is available."""
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return False
        return "llama3" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def main(start_idx: int, end_idx: int = None, reset: bool = False):
    # Check Ollama is available
    if not check_ollama_available():
        print("=" * 60)
        print("ERRORE: Ollama non disponibile o modello llama3 non trovato!")
        print("Installa Ollama e scarica il modello:")
        print("  curl -fsSL https://ollama.com/install.sh | sh")
        print("  ollama pull llama3")
        print("  ollama serve &")
        print("=" * 60)
        return

    # Check Node.js / ts-node
    if not shutil.which("npx"):
        print("ERRORE: npx non trovato nel PATH! Installa Node.js.")
        return

    # Load stats to check for resume
    stats = load_local_stats()
    last_index = stats.get("last_index", 0)

    if reset or start_idx == 0:
        print(f"Resetting stats and logs for LLM Proxy (start: {start_idx})")
        stats = copy.deepcopy(INIT_STATS)
        save_local_stats(stats)
        server_log = {}
        save_local_log(server_log)
    elif start_idx == -1:
        start_idx = last_index
        print(f"Resuming from index: {start_idx}")

    # Clean up any leftover repos from previous crashed runs
    cleanup_orphan_repos(Path.cwd())

    print(f"=== Running LLM Proxy Analysis Standalone ===")
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

        # Check disk space first
        if not check_disk_space():
            print(f"\n  STOPPING: Disk space critically low. Saving state and exiting.")
            print(f"   Resume with: python run_proxy.py --start -1 --end {end_idx}")
            break

        # Check RAM (proxy needs more because of Ollama ~4-8GB baseline)
        if not check_memory_available():
            # Try unloading Ollama model to free RAM
            print("  Unloading Ollama model to free RAM...")
            manage_ollama_memory()
            time.sleep(3)
            ram_ok = periodic_cache_cleanup(idx)
            if not ram_ok:
                print(f"\n  STOPPING: RAM critically high. Saving state and exiting.")
                print(f"   Resume with: python run_proxy.py --start -1 --end {end_idx}")
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
                    print("\n=== LLM PROXY ANALYSIS ===")
                    print("repo_path: ", repo_path)
                    print("command: ", server_data["command"])
                    print("elem: ", server_data["elem"])

                    proxy_result = run_llm_proxy_analysis(
                        server_data["repo_path"],
                        server_data["command"],
                        server_data["elem"]
                    )

                    result_status = proxy_result.get("status", "failed")

                    if result_status == "completed":
                        _status = "completed"
                    else:
                        _status = "failed"
                        failure_reason = "proxy_failed"

                except TimeoutError:
                    print(f"Proxy analysis execution timed out")
                    _status = "error"
                    failure_reason = "execution_timeout"
                except Exception as e:
                    print(f"Error executing Proxy Analysis: {e}")
                    _status = "error"
                    failure_reason = "execution_error"
                finally:
                    # Kill any lingering ts-node/node processes from this run
                    _kill_proxy_orphans()
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
            _kill_proxy_orphans()
        finally:
            # Cancel alarm
            if use_alarm:
                signal.alarm(0)

        # ALWAYS update global FIRST (so total is correct for percentage calculations)
        stats = update_global(stats, language, idx + 1)

        # THEN update proxy-specific stats
        if server_data is not None and _status == "completed" and proxy_result is not None:
            try:
                _update_proxy_stats(stats, proxy_result, language)
            except Exception as e:
                print(f"Error updating proxy stats: {e}")

        # Track failure reason in stats
        if failure_reason:
            fr_block = stats["proxy"].setdefault(
                "failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}}
            )
            fr_block["total"] += 1
            fr_block["counts"][failure_reason] = fr_block["counts"].get(failure_reason, 0) + 1

            server_log[server_url] = f"{language} {failure_reason}"
            save_local_log(server_log)
        elif _status == "completed":
            if server_url in server_log:
                del server_log[server_url]
                save_local_log(server_log)

        # Recalculate failure percentage
        fr_block = stats["proxy"].get("failure_reasons")
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
        _kill_proxy_orphans()

        # Unload Ollama model between servers to free RAM (~4-8GB)
        # It auto-reloads on next request (adds ~5s startup cost)
        manage_ollama_memory()

        end_time = time.time()
        remaining = stats["remaining"]

        # Log RAM/disk status every 10 servers
        if (idx - start_idx) % 10 == 0:
            try:
                import psutil
                mem = psutil.virtual_memory()
                disk = shutil.disk_usage(Path.home())
                print(f"  [RESOURCES] RAM: {mem.percent:.0f}% used ({mem.available/(1024**3):.1f}GB free) | "
                      f"Disk: {disk.free/(1024**3):.1f}GB free")
            except Exception:
                pass

        print(f"[proxy] {idx}/{end_idx} | {language} | {_status} | {end_time - start_time:.2f}s | remaining: {remaining}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run LLM Proxy Analysis independently on a VM")
    parser.add_argument("--start", "-s", type=int, default=-1, help="Start index (default: resume from last)")
    parser.add_argument("--end", "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs before starting (even with --start N)")
    args = parser.parse_args()

    main(args.start, args.end, args.reset)
