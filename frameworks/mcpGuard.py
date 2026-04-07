from pathlib import Path
from functions.config import MCP_GUARD_DIR, TIMEOUT_SECONDS, cmd_guard
import json
import os
import subprocess
import signal
from functions.helper import run_process, reset_mcp_guard_outputs, failure


def _kill_server_processes(server_command: str):
    """Kill any lingering MCP server processes spawned by mcp-guard."""
    if not server_command:
        return

    killed = 0

    if os.name == "nt":
        try:
            term_normalized = server_command.replace("/", "\\")
            result = subprocess.run(
                ["wmic", "process", "where",
                 f"CommandLine like '%{term_normalized}%'",
                 "get", "ProcessId"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line.isdigit():
                        pid = int(line)
                        try:
                            subprocess.run(
                                ["taskkill", "/F", "/T", "/PID", str(pid)],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=5
                            )
                            killed += 1
                        except Exception:
                            pass
        except Exception:
            pass
    else:
        try:
            result = subprocess.run(
                ["pgrep", "-f", server_command],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                for pid_str in result.stdout.strip().split("\n"):
                    try:
                        pid = int(pid_str.strip())
                        ps_result = subprocess.run(
                            ["ps", "-p", str(pid), "-o", "args="],
                            capture_output=True, text=True, timeout=5
                        )
                        cmdline = ps_result.stdout.strip()
                        if any(s in cmdline for s in [
                            "run_security_scan", "run_guard", "run_scan",
                            "run_check", "run_shield", "run_watch",
                            "run_fuzzing", "run_scanorama", "run_validator"
                        ]):
                            continue
                        os.kill(pid, 9)
                        killed += 1
                    except (ValueError, ProcessLookupError, PermissionError):
                        pass
        except Exception:
            pass

def find_mcp_guard_json(mcp_guard_dir: Path) -> Path | None:
    for file in mcp_guard_dir.iterdir():
        if file.is_file() and file.name.startswith("mcp_security_scan_") and file.suffix == ".json":
            return file
    return None

def parse_mcp_guard(json_data: dict) -> tuple[dict, str]:
    # language
    server_type = json_data.get("server_info", {}).get("server_type", "").lower()
    # vulnerabilità
    vulns = json_data.get("vulnerabilities", [])
    total_vulns = len(vulns)

    categories = {}
    severity_counter = {}
    cwe_counter = {}

    for v in vulns:
        category = v.get("title", "unknown").lower().replace(" ", "-")
        severity = v.get("severity", "unknown").lower()
        type_vuln = v.get("type", "unknown").lower()
        cwe = v.get("cwe_id")

        categories.setdefault(category, {})
        idx = str(len(categories[category]) + 1)
        categories[category][idx] = {
            "severity": severity,
            "file": v.get("file_path"),
            "description": v.get("description"),
            "payload": v.get("exploit_payload"),
            "response": v.get("server_response"),
            "remediation": v.get("remediation"),
            "type": type_vuln,
        }

        severity_counter[severity] = severity_counter.get(severity, 0) + 1
        if cwe:
            cwe_counter[cwe.lower()] = cwe_counter.get(cwe.lower(), 0) + 1

    # percentage_of_vulnerability per category
    percentage_of_vulnerability = {}
    if total_vulns > 0:
        for cat, items in categories.items():
            percentage_of_vulnerability[f"{cat}"] = round((len(items) / total_vulns) * 100, 2)

    # risk
    risk_block = json_data.get("summary", {}).get("risk_assessment", {})

    return {
        "mcp-guard": {
            "status": "completed",
            "total-vulnerabilities": total_vulns,
            "risk": {
                "overall-risk": risk_block.get("overall_risk", "").lower(),
                "business-impact": risk_block.get("business_impact", "").lower(),
                "exploitability": risk_block.get("exploitability", "").lower(),
            },
            "category": categories,
            "percentage_of_vulnerability": percentage_of_vulnerability,
            "severity": {
                "counts": severity_counter,
                "percentage_of_severity": {
                    k: round(v / total_vulns, 6) if total_vulns > 0 else 0.0
                    for k, v in severity_counter.items()
                }
            },
            "cwe": cwe_counter,
            "analyses_completed": json_data.get("analyses_completed", {}),
        }
    }, server_type

def execute_mcp_guard(server_url: str, repo_path: Path, command: str, elem: str | list):
    reset_mcp_guard_outputs()
    elem_str = " ".join(elem) if isinstance(elem, list) else str(elem)
    server_command = f"{command} {elem_str}"
    cmd = cmd_guard + [server_url, str(repo_path), command, elem_str]

    try:
        run_process(
            cmd=cmd,
            cwd=str(MCP_GUARD_DIR),
            timeout=TIMEOUT_SECONDS,
            framework_name="MCP Guard"
        )
    except TimeoutError:
        _kill_server_processes(server_command)
        result, _ = failure("mcp-guard")
        return result
    finally:
        _kill_server_processes(server_command)

    try:
        json_file = find_mcp_guard_json(MCP_GUARD_DIR)
        if not json_file:
            result, _ = failure("mcp-guard")
            return result
        json_data = json.loads(json_file.read_text(encoding="utf-8"))
        result_mcp_guard, server_language = parse_mcp_guard(json_data)
        return result_mcp_guard

    except Exception as e:
        print(f"Error processing MCP Guard output: {e}")
        result, _ = failure("mcp-guard")
        return result