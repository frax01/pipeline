import sys
import os

# Fix Windows console encoding (emoji/unicode in scanner output)
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

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

# ── Paths ─────────────────────────────────────────────────────────────

CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "mcp_watch_stats.json"
LOG_FILE   = CURRENT_DIR / "mcp_watch_servers.json"

SEVERITY_LEVELS = ("critical", "high", "medium", "low")

# category folders  → one subfolder per scanner category, one file per severity inside
KNOWN_CATEGORIES = (
    "toxic-flow",
    "credential-leak",
    "tool-poisoning",
    "prompt-injection",
    "tool-mutation",
    "data-exfiltration",
    "steganographic-attack",
    "protocol-violation",
    "input-validation",
    "server-spoofing",
    "access-control",
)

def _category_dir(category: str) -> Path:
    return CURRENT_DIR / category

def _category_file(category: str, severity: str) -> Path:
    prefix = category.replace("-", "_")
    return _category_dir(category) / f"{prefix}_{severity}.json"

# ── Init Stats ────────────────────────────────────────────────────────

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

# ── ID → description mapping ──────────────────────────────────────────

ID_DESCRIPTIONS = {
    "ANSI_ESCAPE_INJECTION":            "ANSI escape sequences - can hide malicious instructions",
    "WHITESPACE_INJECTION":             "Excessive whitespace - potential hidden content",
    "CONVERSATION_EXFILTRATION_TRIGGER":"Conversation history exfiltration trigger detected",
    "HARDCODED_CREDENTIALS":            "Hardcoded credentials detected",
    "PLAINTEXT_STORAGE":                "Plaintext credential storage detected",
    "INSECURE_CREDENTIAL_PERMISSIONS":  "Credentials with world-readable permissions",
    "COMMAND_INJECTION_RISK":           "Command injection vulnerability - append && rm -rf /",
    "SSRF_VULNERABILITY":               "SSRF vulnerability - fetches any URL",
    "PATH_TRAVERSAL":                   "Path traversal vulnerability - accesses files outside directory",
    "MAGIC_PARAMETER_INJECTION":        "Magic parameter detected - extracts sensitive AI context",
    "UNUSED_SENSITIVE_PARAMETER":       "Unused parameter with sensitive name",
    "DATA_EXFILTRATION":                "Potential data exfiltration detected",
    "CONSENT_FATIGUE_RISK":             "Repeated consent requests - fatigue attack risk",
    "EXCESSIVE_PERMISSIONS":            "Excessive permissions - violates least privilege",
    "TOOL_DESCRIPTION_INJECTION":       "Suspicious prompt injection in tool description",
    "RETRIEVAL_AGENT_DECEPTION":        "RADE pattern detected - hidden commands in retrieval content",
    "SESSION_ID_IN_URL":                "Session ID in URL - exposes sensitive identifiers",
    "INSECURE_TRANSPORT":               "Insecure HTTP transport detected",
    "SUSPICIOUS_SERVER_NAME":           "Server name mimics popular service - potential spoofing",
    "CROSS_SERVER_SHADOWING":           "Cross-server call interception detected",
    "HIDDEN_TOOL_INSTRUCTIONS":         "Hidden malicious instructions in tool description",
    "DECEPTIVE_TOOL_NAMING":            "Tool with deceptive name/description mismatch",
    "DYNAMIC_TOOL_MUTATION":            "Dynamic tool mutation detected - rug-pull risk",
    "TOOL_NAME_COLLISION":              "Tool name collision risk",
    "UNTRUSTED_DATA_PROCESSING":        "External data processed without sanitization",
    "AUTOMATIC_CONTENT_PUBLISHING":     "Automatic content publishing - data exfiltration risk",
    "GENERIC_TOXIC_FLOW_CHAIN":         "Complete toxic flow: external input -> privileged access -> public output",
}

# ── Generic JSON helpers ──────────────────────────────────────────────

def _load_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return copy.deepcopy(default)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return copy.deepcopy(default)

def _save_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    tmp.replace(path)

# ── Stats / log helpers ───────────────────────────────────────────────

def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result

def load_local_stats() -> dict:
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

def save_local_stats(data: dict):
    _save_json(STATS_FILE, data)

def load_local_log() -> dict:
    return _load_json(LOG_FILE, {})

def save_local_log(data: dict):
    _save_json(LOG_FILE, data)

# ── category/ helpers ─────────────────────────────────────────────────

def _cat_default(category: str, severity: str) -> dict:
    return {"category": category, "severity": severity, "total": 0, "findings": []}

def load_category_file(category: str, severity: str) -> dict:
    return _load_json(_category_file(category, severity), _cat_default(category, severity))

def save_category_file(category: str, severity: str, data: dict):
    _save_json(_category_file(category, severity), data)

# ── Reset all output files (called on --start 0) ──────────────────────

def reset_all_output_files():
    # category folders
    for cat in KNOWN_CATEGORIES:
        _category_dir(cat).mkdir(parents=True, exist_ok=True)
        for sev in SEVERITY_LEVELS:
            save_category_file(cat, sev, _cat_default(cat, sev))

# ── flatten + update ──────────────────────────────────────────────────

def flatten_vulnerabilities(mcp_watch_result: dict) -> list:
    """Convert category-grouped dict into a flat list with all fields."""
    vulns = []
    cat_block = mcp_watch_result.get("category", {})
    for category_name, items in cat_block.items():
        if not isinstance(items, dict):
            continue
        for item in items.values():
            if not isinstance(item, dict):
                continue
            # Parse "file.ts:42" -> file, line
            location = item.get("location", "") or ""
            file_path, line_num = "", None
            if location:
                parts = location.rsplit(":", 1)
                file_path = parts[0]
                if len(parts) == 2:
                    try:
                        line_num = int(parts[1])
                    except ValueError:
                        file_path = location

            vuln_id = item.get("id")
            vulns.append({
                "id":          vuln_id,
                "severity":    item.get("severity"),
                "category":    category_name,
                "description": item.get("title") or ID_DESCRIPTIONS.get(vuln_id),
                "file":        file_path,
                "line":        line_num,
                "evidence":    item.get("evidence"),
                "source":      item.get("source"),
            })
    return vulns

def _finding(server_name, github_url, language, v: dict) -> dict:
    return {
        "server_name": server_name,
        "github_url":  github_url,
        "language":    language,
        "id":          v["id"],
        "category":    v["category"],
        "description": v["description"],
        "file":        v["file"],
        "line":        v["line"],
        "evidence":    v["evidence"],
        "source":      v["source"],
    }

def update_output_files(server_name: str, github_url: str, language: str, flat_vulns: list):
    """Update category/ files with the new server's vulnerabilities."""
    by_cat_sev = {}
    for v in flat_vulns:
        sev = (v.get("severity") or "").lower()
        cat = (v.get("category") or "").lower()
        if sev not in SEVERITY_LEVELS:
            continue
        by_cat_sev.setdefault((cat, sev), []).append(v)

    # Write category/ files
    for (cat, sev), vulns in by_cat_sev.items():
        data = load_category_file(cat, sev)
        for v in vulns:
            data["findings"].append(_finding(server_name, github_url, language, v))
        data["total"] = len(data["findings"])
        save_category_file(cat, sev, data)

# ── Repo helpers ──────────────────────────────────────────────────────

def cleanup_repo(repo_path: Path):
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
        if os.name != "nt":
            try:
                subprocess.run(["rm", "-rf", str(repo_path)], check=False)
                print(f"Folder deleted (fallback): {repo_path.name}")
            except Exception:
                pass

def prepare_server(server_url: str, stats: dict) -> tuple[dict | None, str]:
    server_name = extract_server_name(server_url)
    print(f"Server: {server_name}")
    print(f"URL: {server_url}")

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
        "server_name":     server_name,
        "server_url":      server_url,
        "server_language": server_language,
        "repo_path":       repo_path,
    }, ""

def cleanup_orphan_repos(base_dir: Path):
    keep = {
        "data", "analysis", "frameworks", "functions", "localServer",
        "npm_runner", "Npx", "hashAnalysis", "temp_hash_analysis",
        "promptFilter", "examples", "node_modules",
        "tool_fuzzing", "tool_mcp_check", "tool_mcp_guard",
        "tool_mcp_scan", "tool_mcp_security_scan", "tool_mcp_shield",
        "tool_mcp_validator", "tool_mcp_watch", "tool_scanorama",
        "0_tool_mcp_watch", "0_tool_proxy",
        # output folders — never delete these
        *KNOWN_CATEGORIES,
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

# ── Main ──────────────────────────────────────────────────────────────

def main(start_idx: int, end_idx: int = None, reset: bool = False):
    stats = load_local_stats()
    last_index = stats.get("last_index", 0)

    if reset or start_idx == 0:
        print(f"Resetting stats and logs for MCP Watch (start: {start_idx})")
        stats = copy.deepcopy(INIT_STATS)
        save_local_stats(stats)
        save_local_log({})
        reset_all_output_files()
    elif start_idx == -1:
        start_idx = last_index
        print(f"Resuming from index: {start_idx}")

    cleanup_orphan_repos(Path.cwd())

    print(f"=== Running MCP Watch Standalone ===")
    print(f"Range server: {start_idx} - {end_idx if end_idx else 'end'}")

    df_excel = pd.read_excel(EXCEL_PATH)
    if end_idx is None:
        end_idx = len(df_excel)

    stats["range_start"] = start_idx
    stats["range_end"]   = end_idx
    stats["remaining"]   = end_idx - start_idx
    save_local_stats(stats)

    print(f"Range server: {start_idx} - {end_idx} ({end_idx - start_idx} server)")

    for idx, row in df_excel.iloc[start_idx:end_idx].iterrows():
        start_time = time.time()
        server_url = row["Link"]

        print("\n" + "=" * 50)
        print(f"Index: {idx}")
        periodic_cache_cleanup(idx)

        stats      = load_local_stats()
        server_log = load_local_log()

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

        if server_data is None:
            print("Watch preparation failed, skipping")
            server_log[server_url] = f"unknown {failure_reason if failure_reason else 'preparation_failed'}"
            save_local_log(server_log)
            stats = update_global(stats, "unknown", idx + 1)
            stats["remaining"] = end_idx - (idx + 1)

            if failure_reason:
                fr_block = stats["mcp-watch"].setdefault("failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}})
                fr_block["total"] += 1
                fr_block["counts"][failure_reason] = fr_block["counts"].get(failure_reason, 0) + 1

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
        _status   = "error"
        failure_reason = ""

        try:
            print("\n=== MCP WATCH ===")

            framework_result = execute_mcp_watch(
                server_data["server_url"],
                server_data["server_language"],
            )

            _status = framework_result.get("mcp-watch", {}).get("status", "failed")

            # Aggregated stats
            stats = update_global(stats, server_data["server_language"], idx + 1)
            stats["remaining"] = end_idx - (idx + 1)
            if _status == "completed":
                update_framework(stats, framework_result["mcp-watch"], "mcp-watch", server_data["server_language"])
            elif _status == "failed":
                failure_reason = "execution_failed"
            else:
                failure_reason = "no_output"
            save_local_stats(stats)

            # category/ files
            if _status == "completed":
                mcp_result = framework_result["mcp-watch"]
                flat_vulns = flatten_vulnerabilities(mcp_result)
                update_output_files(
                    server_data["server_name"],
                    server_data["server_url"],
                    server_data["server_language"],
                    flat_vulns,
                )

        except TimeoutError:
            print(f"MCP Watch execution timed out")
            _status = "error"
            failure_reason = "execution_failed"
        except Exception as e:
            print(f"Error executing MCP Watch: {e}")
            _status = "error"
            failure_reason = "execution_error"

        finally:
            cleanup_repo(repo_path)

            # Track failure reason in stats if not successful
            if _status != "completed" and failure_reason:
                fr_block = stats["mcp-watch"].setdefault("failure_reasons", {"total": 0, "percentage": 0.0, "counts": {}})
                fr_block["total"] += 1
                fr_block["counts"][failure_reason] = fr_block["counts"].get(failure_reason, 0) + 1
                server_log[server_data["server_url"]] = f"{server_data['server_language']} {failure_reason}"
                save_local_log(server_log)
            elif _status == "completed":
                if server_data["server_url"] in server_log:
                    del server_log[server_data["server_url"]]
                    save_local_log(server_log)

            # Recalculate percentage every time
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
    parser.add_argument("--end",   "-e", type=int, default=None, help="End index")
    parser.add_argument("--reset", action="store_true", help="Reset stats and logs before starting (even with --start N)")
    args = parser.parse_args()
    main(args.start, args.end, args.reset)
