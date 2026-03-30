from pathlib import Path
from functions.config import strip_ansi, NPX, TIMEOUT_SECONDS, CONFIG
import platform
from collections import defaultdict
from functions.helper import run_process, failure
import re

def parse_mcp_shield(text):
    tools = {}
    issue_counters = defaultdict(lambda: defaultdict(int))

    current_tool = None
    current_risk = None

    for line in text.splitlines():
        line = strip_ansi(line).strip()

        # Server
        m = re.match(r"\d+\.\s*Server:\s*(.+)", line)
        if m:
            current_server = m.group(1).strip()
            continue


        # Tool
        m = re.match(r"Tool:\s*(.+)", line)
        if m:
            current_tool = m.group(1).strip()
            tools.setdefault(current_tool, {})
            tools[current_tool].update({
                "status": "vulnerable",
                "risk": None,
                "category": {}
            })
            continue

        # Risk
        m = re.match(r"Risk Level:\s*(HIGH|MEDIUM|LOW)", line, re.IGNORECASE)
        if m:
            current_risk = m.group(1).lower()
            if current_tool and current_tool in tools:
                tools[current_tool]["risk"] = current_risk
            continue

        # Verified tool
        m = re.search(r"[\u2713\u2714]\s+(.+?)\s+[\u2014-]\s+Verified", line)
        if m:
            tool_name = strip_ansi(m.group(1).strip())
            tools.setdefault(tool_name, {
                "status": "safe"
            })
            continue

        # Issue line
        m = re.match(r"[\u2013\-]\s*(.+?):\s*(.+)", line)
        if m and current_tool:
            raw_issue = m.group(1).lower().replace(" ", "-")
            description = m.group(2).strip()

            tools[current_tool]["category"].setdefault(raw_issue, {})

            issue_counters[current_tool][raw_issue] += 1
            idx = str(issue_counters[current_tool][raw_issue])

            tools[current_tool]["category"][raw_issue][idx] = {
                "description": description
            }
            continue

    total_vulns = sum(
        len(instances)
        for tool in tools.values()
        if tool.get("status") == "vulnerable"
        for instances in tool.get("category", {}).values()
    )

    percentage_of_vulnerability = {}

    if total_vulns > 0:
        for tool in tools.values():
            if tool.get("status") != "vulnerable":
                continue

            for category_name, instances in tool.get("category", {}).items():
                percentage_of_vulnerability.setdefault(category_name, 0)
                percentage_of_vulnerability[category_name] += len(instances)

        for k in percentage_of_vulnerability:
            percentage_of_vulnerability[k] = round((percentage_of_vulnerability[k] / total_vulns) * 100, 2)


    return {
        "mcp-shield": {
            "status": "completed",
            "total-vulnerabilities": total_vulns,
            "tools": tools,
            "percentage_of_vulnerability": percentage_of_vulnerability
        }
    }, len(tools)

def execute_mcp_shield(repo_path: Path):
    npx_command = NPX
    try:
        if platform.system() in ("Darwin", "Linux"):
            npx_command = "npx"
        # Reverted fix: use --path as requested and verified on VM.
        cmd_shield = [npx_command, "mcp-shield", "--path", str(CONFIG)]
        stdout, stderr, elapsed, code = run_process(
            cmd=cmd_shield,
            cwd=CONFIG.parent,
            timeout=TIMEOUT_SECONDS,
            framework_name="MCP Shield"
        )
    except TimeoutError:
        return failure("mcp-shield")

    parsed, tool_length = parse_mcp_shield(stdout)
    combined = stdout + "\n" + stderr

    print("\n=== STDOUT MCP-SHIELD ===")
    if stdout:
        try:
            print(stdout.strip())
        except UnicodeEncodeError:
            print(stdout.encode('ascii', 'ignore').decode('ascii').strip())
    else:
        print("vuoto")
    print("=========================\n")
    
    print("\n=== STDERR MCP-SHIELD ===")
    if stderr:
        try:
            print(stderr.strip())
        except UnicodeEncodeError:
            print(stderr.encode('ascii', 'ignore').decode('ascii').strip())
    else:
        print("vuoto")
    print("=========================\n")

    # Allow non-zero exit code if we successfully parsed some tools (vulnerability found)
    is_connection_error = "connection closed" in combined.lower() or "error connecting to server" in combined.lower()
    
    if (is_connection_error and tool_length == 0) or (code != 0 and tool_length == 0):
        if stderr:
             print(f"MCP Shield Failure (stderr or connection error):\n{stderr}")
        return failure("mcp-shield"), "failed"
    
    if tool_length == 0:
        return failure("mcp-shield"), "failed"

    return parsed, "completed"
