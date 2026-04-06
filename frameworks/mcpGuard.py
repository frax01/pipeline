from pathlib import Path
from functions.config import MCP_GUARD_DIR, TIMEOUT_SECONDS, cmd_guard
import json
from functions.helper import run_process, reset_mcp_guard_outputs, failure

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
    cmd = cmd_guard + [server_url, str(repo_path), command, elem_str]

    try:
        run_process(
            cmd=cmd,
            cwd=str(MCP_GUARD_DIR),
            timeout=TIMEOUT_SECONDS,
            framework_name="MCP Guard"
        )
    except TimeoutError:
        result, _ = failure("mcp-guard")
        return result

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