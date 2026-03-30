import sys
import os
import json
import time
import argparse
import shutil
import stat
import subprocess
import signal
import pandas as pd
from pathlib import Path
from collections import defaultdict

# Add parent directory to sys.path to allow imports from functions/frameworks
sys.path.append(str(Path(__file__).resolve().parent.parent))

from functions.helper import (
    update_global, extract_server_name, detect_language
)
from functions.buildConfig import build_mcp_config, clone_repo
from functions.config import EXCEL_PATH

# Local stats and logs
CURRENT_DIR = Path(__file__).parent
STATS_FILE = CURRENT_DIR / "fuzzing_tools_stats.json"
LOG_FILE = CURRENT_DIR / "fuzzing_tools_servers.json"

INIT_STATS = {
    "last_index": 0,
    "total": 0,
    "languages": {},
    "fuzzing_tools": {
        "total_servers": 0,
        "total_tools": 0,
        "total_fuzzing_runs": 0,
        "total_successful": 0,
        "total_exceptions": 0,
        "total_safety_blocked": 0,
        "exceptions_by_message": {}
    }
}

def load_local_stats():
    if not STATS_FILE.exists():
        return INIT_STATS.copy()
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return INIT_STATS.copy()

def save_local_stats(data):
    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

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
    if repo_path and repo_path.exists() and repo_path.is_dir():
        def onerror(func, p, exc_info):
            try:
                os.chmod(p, stat.S_IWRITE)
                func(p)
            except Exception:
                pass
        shutil.rmtree(repo_path, onerror=onerror)
        print(f"Folder deleted: {repo_path.name}")

def find_latest_report(base_path: Path) -> Path | None:
    reports_dir = base_path / "reports" / "sessions"
    if not reports_dir.exists():
        return None
    json_files = list(reports_dir.glob("**/*.json"))
    if not json_files:
        return None
    return max(json_files, key=lambda p: p.stat().st_mtime)

def execute_tools_fuzzing(path: Path, command: str, elem: str) -> dict:
    # Use absolute path for the entry point
    entry_point = path / elem
    abs_path = str(entry_point.resolve())
    
    # On Windows, we must use double backslashes and wrap the path in quotes 
    # inside the endpoint string to match the successful manual test.
    if os.name == 'nt':
        abs_path = abs_path.replace('\\', '\\\\')
        endpoint = f'{command} "{abs_path}"'
    else:
        endpoint = f"{command} {abs_path}"
    
    cmd = [
        "mcp-fuzzer",
        "--mode", "tools",
        "--protocol", "stdio",
        "--endpoint", endpoint,
        "--enable-safety-system",
        "--fs-root", str(Path.home() / "AppData" / "Local" / "Temp" / "mcp-safe"),
    ]
    try:
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=300,
            encoding="utf-8",
            errors="replace"
        )
        
        if result.returncode != 0:
            print(f"Fuzzer exited with code {result.returncode}")
            if result.stdout: print(f"STDOUT: {result.stdout[:500]}...")
            if result.stderr: print(f"STDERR: {result.stderr[:500]}...")

        # Give a small delay to ensure report file is written
        time.sleep(1)
        report_path = find_latest_report(path)
        if report_path:
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
            return report
    except Exception as e:
        print(f"Fuzzing execution error: {e}")
    return None

def update_stats_with_report(stats: dict, report: dict, language: str):
    data = report.get("data", {})
    tools = data.get("tools_tested", [])
    
    target = stats["fuzzing_tools"]
    target["total_servers"] += 1
    target["total_tools"] += len(tools)
    
    for tool in tools:
        target["total_fuzzing_runs"] += tool.get("runs", 0)
        target["total_successful"] += tool.get("successful", 0)
        target["total_exceptions"] += tool.get("exceptions", 0)
        target["total_safety_blocked"] += tool.get("safety_blocked", 0)
        for exc in tool.get("exception_details", []):
            msg = exc.get("message")
            if msg:
                target["exceptions_by_message"][msg] = target["exceptions_by_message"].get(msg, 0) + 1

def main(start_idx: int, end_idx: int = None):
    stats = load_local_stats()
    if start_idx == 0:
        stats = INIT_STATS.copy()
        save_local_log({})
    
    df = pd.read_excel(EXCEL_PATH)
    if end_idx is None:
        end_idx = len(df)
        
    for idx, row in df.iloc[start_idx:end_idx].iterrows():
        print(f"\n{'='*50}\nIndex: {idx}\nURL: {row['Link']}")
        server_url = row["Link"]
        repo_path = clone_repo(server_url, Path.cwd())
        
        try:
            lang = detect_language(repo_path)
            name, cmd, elem = build_mcp_config(repo_path, lang)
            if not cmd:
                print("Skip: config build failed")
                continue
                
            report = execute_tools_fuzzing(repo_path, cmd, elem[0])
            if report:
                update_stats_with_report(stats, report, lang)
                print(f"Fuzzing completed. Tools found: {len(report.get('data', {}).get('tools_tested', []))}")
            else:
                print("Fuzzing failed to produce report")
            
            stats["last_index"] = idx + 1
            stats["total"] += 1
            stats["languages"][lang] = stats["languages"].get(lang, 0) + 1
            save_local_stats(stats)
            
        except Exception as e:
            print(f"Error: {e}")
        finally:
            cleanup_repo(repo_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", "-s", type=int, default=0)
    parser.add_argument("--end", "-e", type=int, default=None)
    args = parser.parse_args()
    main(args.start, args.end)
