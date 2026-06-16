from pathlib import Path
from functions.helper import run_process, failure
from functions.config import (
    ISSUE_CODE_MAP, UVX, TIMEOUT_SECONDS,
    TOXIC_FLOW_MAP, CONFIG, SKIP_ISSUE_CODES,
)
import os
import json


def parse_mcp_scan(json_text):
    """
    Parse snyk-agent-scan --json output.

    Returns the same structure expected by stats.py:
      {
        "mcp-scan": {
            "status": "completed",
            "total-vulnerabilities": int,
            "tools":  { name: {"status":"safe|vulnerable", "category":{...}, "labels":{...}} },
            "server_issues": { code: {"category":str, "severity":str, "message":str} },
            "toxic_flows": { code: name },
            "percentage_of_vulnerability": { category: pct }
        }
      }, tool_count
    """
    try:
        data = json.loads(json_text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {"mcp-scan": {"status": "failed"}}, 0

    if not isinstance(data, dict):
        return {"mcp-scan": {"status": "failed"}}, 0

    # ── Find the first config entry that contains real servers ──
    config_result = None
    for _path_key, result in data.items():
        if not isinstance(result, dict):
            continue
        svrs = result.get("servers")
        if svrs and isinstance(svrs, list) and len(svrs) > 0:
            # Ensure at least one server has a signature (actually ran)
            for s in svrs:
                if s.get("signature"):
                    config_result = result
                    break
        if config_result:
            break

    if config_result is None:
        return {"mcp-scan": {"status": "failed"}}, 0

    servers = config_result.get("servers") or []
    issues  = config_result.get("issues")  or []
    labels_data = config_result.get("labels") or []

    tools        = {}   # tool_name -> {status, category?, labels?}
    toxic_flows  = {}   # TF code   -> label
    server_issues = {}  # issue code -> {category, severity, message}

    # ── 1. Build the tool list from server signatures ──
    for server_idx, server in enumerate(servers):
        sig = server.get("signature") or {}
        prompts            = sig.get("prompts")            or []
        resources          = sig.get("resources")          or []
        resource_templates = sig.get("resource_templates") or []
        server_tools       = sig.get("tools")              or []

        # Entity order: prompts → resources → resource_templates → tools
        offset = len(prompts) + len(resources) + len(resource_templates)

        server_labels = labels_data[server_idx] if server_idx < len(labels_data) else []

        for tool_idx, tool in enumerate(server_tools):
            tool_name = tool.get("name", f"unknown_tool_{tool_idx}")
            entity_idx = offset + tool_idx

            tool_entry = {"status": "safe"}

            # Attach labels when available
            if entity_idx < len(server_labels):
                tool_entry["labels"] = server_labels[entity_idx]

            tools[tool_name] = tool_entry

    # ── 2. Process issues ──
    for issue in issues:
        code      = issue.get("code", "")
        message   = issue.get("message", "")
        reference = issue.get("reference")
        extra     = issue.get("extra_data") or {}
        severity  = extra.get("severity", "unknown")

        # Skip system/informational codes
        if code in SKIP_ISSUE_CODES:
            continue

        # ── Toxic flows ──
        if code.startswith("TF"):
            toxic_flows[code] = TOXIC_FLOW_MAP.get(code, "unknown-toxic-flow")
            continue

        # ── Server-level issue: reference = [server_idx, None] ──
        if reference and len(reference) >= 2 and reference[1] is None:
            category_name = ISSUE_CODE_MAP.get(code, code.lower())
            server_issues[code] = {
                "category": category_name,
                "severity": severity,
                "message":  message,
                "extra_data": extra,
            }
            continue

        # ── Tool-level issue: reference = [server_idx, entity_idx] ──
        if reference and len(reference) >= 2 and reference[1] is not None:
            ref_srv = reference[0]
            entity_idx = reference[1]

            if ref_srv < len(servers):
                sig = servers[ref_srv].get("signature") or {}
                s_prompts  = sig.get("prompts")            or []
                s_resources = sig.get("resources")         or []
                s_restmpl  = sig.get("resource_templates") or []
                s_tools    = sig.get("tools")              or []

                s_offset  = len(s_prompts) + len(s_resources) + len(s_restmpl)
                tool_idx  = entity_idx - s_offset

                if 0 <= tool_idx < len(s_tools):
                    tool_name = s_tools[tool_idx].get("name", f"unknown_{tool_idx}")

                    # Promote to vulnerable (preserve labels)
                    if tools.get(tool_name, {}).get("status") != "vulnerable":
                        existing_labels = tools.get(tool_name, {}).get("labels", {})
                        tools[tool_name] = {
                            "status":   "vulnerable",
                            "category": {},
                            "labels":   existing_labels,
                            "extra_data": {},
                        }

                    category_name = ISSUE_CODE_MAP.get(code, code.lower())
                    tools[tool_name]["category"][code] = category_name
                    # Store extra_data per issue code (e.g. {"W001": {"words": [...]}})
                    if extra:
                        tools[tool_name]["extra_data"][code] = extra

    # ── 3. Totals & percentages ──
    tool_vuln_count    = sum(
        len(t.get("category", {}))
        for t in tools.values()
        if t.get("status") == "vulnerable"
    )
    server_issue_count = len(server_issues)
    toxic_flow_count   = len(toxic_flows)
    total_vulnerabilities = tool_vuln_count + server_issue_count + toxic_flow_count

    category_counts = {}

    for t in tools.values():
        if t.get("status") != "vulnerable":
            continue
        for _code, name in t.get("category", {}).items():
            category_counts[name] = category_counts.get(name, 0) + 1

    for issue_data in server_issues.values():
        name = issue_data["category"]
        category_counts[name] = category_counts.get(name, 0) + 1

    for name in toxic_flows.values():
        category_counts[name] = category_counts.get(name, 0) + 1

    percentage_of_vulnerability = {}
    if total_vulnerabilities > 0:
        percentage_of_vulnerability = {
            k: round((v / total_vulnerabilities) * 100, 2)
            for k, v in category_counts.items()
        }

    return {
        "mcp-scan": {
            "status":  "completed",
            "total-vulnerabilities": total_vulnerabilities,
            "tools":   tools,
            "server_issues": server_issues,
            "toxic_flows": toxic_flows,
            "percentage_of_vulnerability": percentage_of_vulnerability,
        }
    }, len(tools)

# pkill -f 'python.*run_scan.py'; sleep 1
# cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
# nohup python tool_mcp_scan/run_scan.py --start 0 --end 6689 --reset > scan_output.log 2>&1 &

def execute_mcp_scan(repo_path: Path):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    uvx_command = UVX

    # Persistent storage file at Pipeline root level (enables rug pull detection)
    storage_file = os.path.expanduser("~/Desktop/Pipeline/mcp_scan_storage")

    try:
        # Build command: snyk-agent-scan with --json
        # --dangerously-run-mcp-servers: skip interactive [y/N] consent prompt
        # (necessario quando si gira in nohup senza TTY)
        # --server-timeout 60: i pacchetti NPX richiedono >10s per scaricare+installare+bootare
        if uvx_command.endswith("uv") or uvx_command.endswith("uv.exe"):
            cmd_scan = [
                uvx_command, "tool", "run", "snyk-agent-scan@latest",
                "--json",
                "--storage-file", storage_file,
                "--dangerously-run-mcp-servers",
                "--server-timeout", "60",
                str(CONFIG),
            ]
        else:
            cmd_scan = [
                uvx_command, "snyk-agent-scan@latest",
                "--json",
                "--storage-file", storage_file,
                "--dangerously-run-mcp-servers",
                "--server-timeout", "60",
                str(CONFIG),
            ]

        stdout, stderr, elapsed, code = run_process(
            cmd=cmd_scan,
            cwd=repo_path,
            timeout=TIMEOUT_SECONDS,
            framework_name="MCP Scan",
            env=env,
        )
    except TimeoutError:
        return failure("mcp-scan")

    # ── Parse JSON output ──
    parsed, tool_length = parse_mcp_scan(stdout)

    # ── Failure detection ──
    combined = (stdout or "") + "\n" + (stderr or "")

    print(f"\n--- DEBUG STDOUT ---\n{stdout}")
    print(f"\n--- DEBUG STDERR ---\n{stderr}")
    
    if parsed.get("mcp-scan", {}).get("status") == "failed":
        _log_filtered_stderr(stderr)
        return failure("mcp-scan")

    if "could not start server" in combined.lower() or tool_length == 0:
        _log_filtered_stderr(stderr)
        return failure("mcp-scan")

    return parsed, "completed"


def _log_filtered_stderr(stderr: str | None):
    """Print stderr lines, filtering out noisy npm/uv messages."""
    if not stderr:
        return
    filtered = [
        line for line in stderr.splitlines()
        if not any(
            x in line.lower()
            for x in ["downloading", "installed", "audited", "packages", "npm warn"]
        )
    ]
    final = "\n".join(filtered).strip()
    if final:
        print(f"MCP Scan Failure (Filtered stderr):\n{final}")
