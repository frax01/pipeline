from pathlib import Path
import os
import re
from functions.config import MCP_VALIDATOR_DIR
from functions.helper import run_process, failure
import platform

def parse_mcp_validator_report(report_path: Path) -> dict:
    content = report_path.read_text(encoding="utf-8")
    
    # Extract stats using regex
    # - **Total Tests**: 43
    # - **Passed**: 19 (44.2%)
    # - **Failed**: 24 (55.8%)
    # **Compliance Status**: ❌ Non-Compliant (44.2%)
    
    total_match = re.search(r"\- \*\*Total Tests\*\*: (\d+)", content)
    passed_match = re.search(r"\- \*\*Passed\*\*: (\d+)", content)
    failed_match = re.search(r"\- \*\*Failed\*\*: (\d+)", content)
    
    total = int(total_match.group(1)) if total_match else 0
    passed = int(passed_match.group(1)) if passed_match else 0
    failed = int(failed_match.group(1)) if failed_match else 0
    
    compliant_match = re.search(r"\*\*Compliance Status\*\*: (.*)", content)
    compliant_status = compliant_match.group(1) if compliant_match else "Unknown"
    
    is_compliant = "✅ Compliant" in compliant_status or "Success" in compliant_status
    # Check for non-compliant symbol explicitly just in case
    if "❌" in compliant_status or "Non-Compliant" in compliant_status:
        is_compliant = False
    
    return {
        "mcp-validator": {
            "tests": {
                "total": total,
                "passed": passed,
                "failed": failed
            },
            "compliance": {
                "status": is_compliant
            }
        }
    }

def execute_mcp_validator(repo_path: Path, command: str, args: str) -> dict:
    if command == "unknown":
        return failure("mcp-validator")
    
    server_cmd = f"{command} {args}"
    
    # We need to run from MCP_VALIDATOR_DIR
    run_command = "python"
    if platform.system() in ("Darwin", "Linux"):
        run_command = "python3"
    cmd = [
        run_command,
        "-m",
        "mcp_testing.scripts.compliance_report",
        "--server-command",
        server_cmd,
        "--protocol-version",
        "2025-06-18"
    ]
    
    try:
        stdout, stderr, elapsed, returncode = run_process(
            cmd=cmd,
            cwd=str(MCP_VALIDATOR_DIR),
            timeout=300, # 5 minutes
            framework_name="mcp-validator"
        )
        
        # Now find the report.
        # Look for the newest file in reports/
        reports_dir = MCP_VALIDATOR_DIR / "reports"
        if not reports_dir.exists():
            print("Reports directory not found")
            return failure("mcp-validator")
            
        # Get list of files matching cr_*.md
        files = list(reports_dir.glob("cr_*.md"))
        if not files:
            print("No report files found")
            return failure("mcp-validator")
            
        # Sort by modification time
        latest_report = max(files, key=os.path.getmtime)
        
        # Parse the report
        stats = parse_mcp_validator_report(latest_report)
        stats["mcp-validator"]["status"] = "completed"
        return stats
        
    except Exception as e:
        print(f"Error in mcp-validator: {e}")
        return failure("mcp-validator")
