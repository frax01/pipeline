import json
from pathlib import Path
import os
import shutil
import stat
import time
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from .config import MCP_GUARD_DIR
import subprocess
import os
os.environ["MallocStackLogging"] = "0"
os.environ["MallocStackLoggingNoCompact"] = "0"


def load_summary(path: Path) -> dict:
    with open(path, "r") as f:
        return json.load(f)
    
def save_summary(path: Path, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def merge_framework_summaries(framework_paths: dict) -> dict:
    """Carica tutti i JSON separati per framework e li unisce in un unico dizionario."""
    merged = {}
    for fw_name, fw_path in framework_paths.items():
        if not Path(fw_path).exists():
            continue
        data = load_summary(fw_path)
        for key, value in data.items():
            if key not in merged:
                merged[key] = value
    return merged

def update_global(summary: dict, server_language: str, idx: int) -> dict:
    summary["total"] += 1
    summary["last_index"] = idx
    summary["languages"][server_language] = summary["languages"].get(server_language, 0) + 1
    
    total_servers = summary["total"]
    if total_servers > 0:
        for fw in summary.values():
            if isinstance(fw, dict) and "percentage" in fw:
                if "total" in fw:
                    fw["percentage"] = round((fw["total"] / total_servers) * 100.0, 2)
                elif "total_servers" in fw:
                    fw["percentage"] = round((fw["total_servers"] / total_servers) * 100.0, 2)
    return summary

def update_global_npx(summary: dict, idx: int) -> dict:
    summary["total"] += 1
    summary["last_index"] = idx
    
    total_servers = summary["total"]
    if total_servers > 0:
        for fw in summary.values():
            if isinstance(fw, dict) and "percentage" in fw:
                if "total" in fw:
                    fw["percentage"] = round((fw["total"] / total_servers) * 100.0, 2)
                elif "total_servers" in fw:
                    fw["percentage"] = round((fw["total_servers"] / total_servers) * 100.0, 2)
    return summary

def reset_mcp_guard_outputs():
    for f in MCP_GUARD_DIR.iterdir():
        if (
            f.is_file()
            and f.name.startswith("mcp_security_scan_")
            and f.suffix == ".json"
        ):
            try:
                f.unlink()
            except Exception:
                pass

def force_delete(path):
    def onerror(func, p, exc_info):
        os.chmod(p, stat.S_IWRITE)
        func(p)

    shutil.rmtree(path, onerror=onerror)

def reset_file(data: dict, file: Path):
    file.write_text(
        json.dumps(data, indent=4, ensure_ascii=False),
        encoding="utf-8"
    )

def extract_server_name(server_url: str) -> str:
    parsed = urlparse(server_url)
    parts = parsed.path.strip("/").split("/")

    if len(parts) >= 2:
        return parts[1]
    return parts[-1]

def failure(name: str):
    match(name):
        case "mcp-scan" | "mcp-shield" | "mcp-security-scan" | "mcp-check" | "mcp-validator":
            return {
                name: {
                    "status": "failed",
                }
            }, "failed"
        case "mcp-watch":
            return {
                name: {
                    "status": "failed",
                }
            }
        case "mcp-guard":
            return {
                name: {
                    "status": "failed",
                }
            }, "unknown"

def update_recap_server(
    recap_server: dict,
    server_name: str,
    repo_url: str,
    language: str,
    hash_status: str,
    mcp_guard_status: str,
    mcp_watch_status: str,
    fuzzing_status: str,
    mcp_scan_status: str,
    mcp_shield_status: str,
    mcp_security_scan_status: str,
    mcp_check_status: str,
    llm_analysis_status: str,
    llm_proxy_status: str,
    scanorama_status: str,
    mcp_validator_status: str,
    path: Path
):
    total = recap_server.get("total_servers", 0) + 1
    recap_server["total_servers"] = total
    recap_server["servers"][server_name] = {
        "repo_url": repo_url,
        "language": language,
        "frameworks": {
            "hash": hash_status,
            "mcp-guard": mcp_guard_status,
            "mcp-watch": mcp_watch_status,
            "fuzzing": fuzzing_status,
            "mcp-scan": mcp_scan_status,
            "mcp-shield": mcp_shield_status,
            "mcp-security-scan": mcp_security_scan_status,
            "mcp-check": mcp_check_status,
            "llm-analysis": llm_analysis_status,
            "llm-proxy": llm_proxy_status,
            "scanorama": scanorama_status,
            "mcp-validator": mcp_validator_status
        }
    }
    path.write_text(
        json.dumps(recap_server, indent=4, ensure_ascii=False),
        encoding="utf-8"
    )

def update_recap_server_npx(
    recap_server: dict,
    server_name: str,
    mcp_scan_status: str,
    mcp_shield_status: str,
    llm_analysis_status: str,
    llm_proxy_status: str,
    path: Path
):
    total = recap_server.get("total_servers", 0) + 1
    recap_server["total_servers"] = total
    recap_server["servers"][server_name] = {
        "frameworks": {
            "mcp-scan": mcp_scan_status,
            "mcp-shield": mcp_shield_status,
            "llm-analysis": llm_analysis_status,
            "llm-proxy": llm_proxy_status
        }
    }
    path.write_text(
        json.dumps(recap_server, indent=4, ensure_ascii=False),
        encoding="utf-8"
    )

def _kill_process_tree(pid: int):
    """Kill a process and all its children (works on Linux and Windows)."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    else:
        # Kill the entire process group, then the process itself
        try:
            os.killpg(os.getpgid(pid), 9)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            os.kill(pid, 9)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def run_process(
    *,
    cmd: list[str],
    cwd,
    timeout: int,
    framework_name: str,
    env: Optional[dict] = None
) -> Tuple[str, str, float, int]:

    start = time.perf_counter()
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    # On Linux, start in a new process group so we can kill the entire tree
    kwargs = {}
    if os.name != "nt":
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=None,  # stream stderr live to parent terminal so we can see progress
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        creationflags=creationflags,
        **kwargs
    )

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - start
        print(f"{framework_name} timeout after {elapsed:.2f}s → killing process tree")

        _kill_process_tree(proc.pid)
        # Reap the zombie process
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

        raise TimeoutError(framework_name)

    elapsed = time.perf_counter() - start
    print(f"{framework_name} execution time: {elapsed:.2f}s")

    print(f"{framework_name} return code: {proc.returncode}")
    if stdout:
        print(f"\n--- {framework_name} STDOUT ---")
        print(stdout)
        print(f"--- END STDOUT ---\n")
    if stderr:
        print(f"\n--- {framework_name} STDERR ---")
        print(stderr)
        print(f"--- END STDERR ---\n")

    return stdout or "", stderr or "", elapsed, proc.returncode

def detect_language(repo_path: str) -> str:
    """Detect MCP server type and extract metadata"""
    try:
        # Check for different server types in order of specificity
        if has_files(repo_path, ['go.mod']) and has_go_files(repo_path):
            return "go"
        elif has_files(repo_path, ['package.json']):
            return "nodejs"
        elif has_files(repo_path, ['pyproject.toml', 'setup.py', 'requirements.txt']):
            return "python"
        elif has_files(repo_path, ['Dockerfile', 'docker-compose.yml']):
            return "docker"
        else:
            return "unknown"
    except Exception as e:
        print(f"Error detecting server type: {e}")
        raise
    
def has_files(repo_path: str, filenames: List[str]) -> bool:
    return any(os.path.exists(os.path.join(repo_path, filename)) for filename in filenames)

def has_go_files(repo_path: str) -> bool:
    """Check if repository contains any Go files"""
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.go'):
                return True
    return False


# --------------- RAM MONITORING ---------------
import psutil

RAM_THRESHOLD_PERCENT = 90  # warn/pause if RAM usage exceeds this
RAM_CRITICAL_PERCENT = 95   # triggers wait loop until RAM drops

def check_ram_usage(threshold: float = RAM_THRESHOLD_PERCENT, critical: float = RAM_CRITICAL_PERCENT) -> bool:
    """Check RAM usage and take action if too high.
    Never stops the process - waits in loop until RAM is safe."""
    import time
    try:
        mem = psutil.virtual_memory()
        used_pct = mem.percent
        available_gb = mem.available / (1024**3)

        if used_pct >= critical:
            print(f"\n[RAM] CRITICAL: {used_pct:.1f}% used ({available_gb:.2f} GB free)")
            print("  Killing orphan processes and cleaning caches...")
            cleanup_orphan_processes()
            _kill_orphan_server_processes()
            cleanup_caches(force=True)
            # Wait in loop until RAM drops below threshold - never stop
            wait_count = 0
            while True:
                time.sleep(15)
                mem = psutil.virtual_memory()
                used_pct = mem.percent
                available_gb = mem.available / (1024**3)
                wait_count += 1
                if used_pct < threshold:
                    print(f"  [RAM] Recovered after {wait_count * 15}s: {used_pct:.1f}% ({available_gb:.2f} GB free)")
                    return True
                # Every 60s, re-run cleanup
                if wait_count % 4 == 0:
                    print(f"  [RAM] Waiting... {used_pct:.1f}% ({available_gb:.2f} GB free) - cleaning again...")
                    cleanup_orphan_processes()
                    _kill_orphan_server_processes()
                    cleanup_caches(force=True)
        elif used_pct >= threshold:
            print(f"\n[RAM] HIGH: {used_pct:.1f}% used ({available_gb:.2f} GB free) - cleaning...")
            cleanup_orphan_processes()
            _kill_orphan_server_processes()
            cleanup_caches(force=True)
            return True
        return True
    except ImportError:
        return True  # psutil not installed, skip check
    except Exception as e:
        print(f"  RAM check error: {e}")
        return True


def _kill_orphan_server_processes():
    """Kill orphan MCP server processes (node/python/go) that were spawned by
    frameworks and left running. Only kills truly orphaned processes (parent is
    init/PID 1). Avoids killing run_*.py processes and active child processes
    of running framework runners."""
    if os.name == "nt":
        return 0

    killed = 0
    # Patterns that match orphan server processes (NOT our runner scripts)
    patterns = [
        "node dist/",
        "node src/",
        "node build/",
        "node index.js",
        "node server.js",
        "node install.js",
        "node-gyp",
        ".cache/puppeteer",
        "mcp-shield --path",
        "snyk-agent-scan",
    ]
    for pattern in patterns:
        try:
            result = subprocess.run(
                ["pgrep", "-f", pattern],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                pids = result.stdout.strip().split("\n")
                for pid_str in pids:
                    try:
                        pid = int(pid_str.strip())
                        # Don't kill our own runner processes
                        cmdline_result = subprocess.run(
                            ["ps", "-p", str(pid), "-o", "ppid=,args="],
                            capture_output=True, text=True, timeout=5
                        )
                        output = cmdline_result.stdout.strip()
                        parts = output.split(None, 1)
                        ppid = int(parts[0]) if parts else 0
                        cmdline = parts[1] if len(parts) > 1 else ""
                        if any(skip in cmdline for skip in ["run_guard", "run_scan", "run_check", "run_security_scan", "run_shield", "run_watch", "run_fuzzing", "run_scanorama", "run_validator"]):
                            continue
                        # Only kill if truly orphaned (parent is init/PID 1)
                        if ppid != 1:
                            continue
                        os.kill(pid, 9)
                        killed += 1
                    except (ValueError, ProcessLookupError, PermissionError):
                        pass
        except Exception:
            pass

    if killed > 0:
        print(f"  Killed {killed} orphan server process(es)")
    return killed


# --------------- CACHE CLEANUP ---------------
CACHE_DIRS = [
    Path.home() / ".cache" / "uv",
    Path.home() / ".cache" / "go-build",
    Path.home() / ".cache" / "puppeteer",
    Path.home() / ".cache" / "ms-playwright",
    Path.home() / ".cache" / "Cypress",
    Path.home() / ".cache" / "electron",
    Path.home() / ".cache" / "node-gyp",
    Path.home() / ".cache" / "pnpm",
    Path.home() / ".cache" / "pip",
    Path.home() / ".cache" / "puccinialin",
    Path.home() / ".cache" / "prisma",
    Path.home() / ".cache" / "node-chromium",
    Path.home() / ".npm" / "_cacache",
    Path.home() / ".npm" / "_npx",
    Path.home() / "go" / "pkg",
    Path.home() / "go" / "pkg" / "mod",
    Path.home() / ".local" / "share" / "pnpm" / "store",
    Path.home() / ".local" / "share" / "pnpm",
    Path.home() / ".local" / "share" / "uv",
    Path.home() / ".pnpm-store",
    Path.home() / ".bun" / "install" / "cache",
    Path("/tmp") / "node-compile-cache",
    Path("/tmp") / "safe",
    Path("/tmp") / "test_fuzz",
    Path("/tmp") / "fastembed_cache",
]

# Go build cache in /tmp (glob pattern)
GO_TMP_PREFIX = "/tmp/go-build"

_last_cache_cleanup = 0.0
CACHE_CLEANUP_INTERVAL = 50  # every 50 servers

def cleanup_caches(force: bool = False):
    """Remove build/package caches to free disk space.
    Called automatically every CACHE_CLEANUP_INTERVAL servers."""
    global _last_cache_cleanup

    if not force and _last_cache_cleanup > 0:
        return  # controlled by counter in periodic_cache_cleanup

    freed = 0
    for d in CACHE_DIRS:
        if d.exists() and d.is_dir():
            try:
                size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
                shutil.rmtree(d, ignore_errors=True)
                freed += size
                print(f"  Cache deleted: {d} ({size / (1024**2):.0f} MB)")
            except Exception as e:
                print(f"  Cache cleanup error {d}: {e}")

    # Clean /tmp/go-build* directories
    if os.name != "nt":
        import glob
        for d in glob.glob(GO_TMP_PREFIX + "*"):
            try:
                dp = Path(d)
                if dp.is_dir():
                    size = sum(f.stat().st_size for f in dp.rglob("*") if f.is_file())
                    shutil.rmtree(dp, ignore_errors=True)
                    freed += size
            except Exception:
                pass

    if freed > 0:
        print(f"  Total freed: {freed / (1024**3):.1f} GB")
    _last_cache_cleanup = time.time()


def cleanup_orphan_processes():
    """Kill orphan MCP server processes left behind by timed-out guard/scan runs.
    Only runs on Linux. Only kills mcp_scanner.py processes whose parent is
    init (PID 1), meaning they are truly orphaned — NOT active children of
    a running framework runner."""
    if os.name == "nt":
        return 0

    killed = 0
    try:
        # Find all mcp_scanner.py processes
        result = subprocess.run(
            ["pgrep", "-f", "mcp_scanner.py"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            pids = result.stdout.strip().split("\n")
            for pid_str in pids:
                try:
                    pid = int(pid_str.strip())
                    # Only kill if truly orphaned (parent is init/PID 1)
                    ppid_result = subprocess.run(
                        ["ps", "-p", str(pid), "-o", "ppid="],
                        capture_output=True, text=True, timeout=5
                    )
                    ppid = int(ppid_result.stdout.strip())
                    if ppid == 1:
                        os.kill(pid, 9)
                        killed += 1
                except (ValueError, ProcessLookupError, PermissionError):
                    pass
    except Exception:
        pass

    if killed > 0:
        print(f"  Killed {killed} orphan mcp_scanner.py processes")
    return killed


def periodic_cache_cleanup(server_index: int) -> bool:
    """Call this every iteration; cleanup runs every CACHE_CLEANUP_INTERVAL servers.
    Returns False if RAM is critically high and process should stop."""
    # Check RAM every iteration
    ram_ok = check_ram_usage()
    if not ram_ok:
        return False

    if server_index > 0 and server_index % CACHE_CLEANUP_INTERVAL == 0:
        print(f"\n--- Periodic cache cleanup (every {CACHE_CLEANUP_INTERVAL} servers) ---")
        cleanup_caches(force=True)
        cleanup_orphan_processes()
        _kill_orphan_server_processes()
    return True