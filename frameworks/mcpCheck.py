from pathlib import Path
from functions.helper import run_process, failure
from functions.config import TIMEOUT_SECONDS, MCP_CHECK_DIR
import os
import json
import subprocess


def _kill_server_processes(server_command: str):
    """Kill any lingering MCP server processes spawned by mcp-check.

    After mcp-check finishes, the server process (node/python/go) may still
    be running. This function finds and kills processes whose command line
    matches the FULL server command used during the test.

    IMPORTANT: Never pkill on short/generic terms like "run", "server.py",
    "index.js" etc. as they can match and kill the runner script itself.
    Always use the full server_command as the search pattern.
    """
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
        # Linux/macOS: use pgrep to find PIDs matching the full command,
        # then kill only those PIDs (avoids killing our own runner script)
        try:
            result = subprocess.run(
                ["pgrep", "-f", server_command],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                for pid_str in result.stdout.strip().split("\n"):
                    try:
                        pid = int(pid_str.strip())
                        # Safety: check cmdline doesn't contain our runner scripts
                        ps_result = subprocess.run(
                            ["ps", "-p", str(pid), "-o", "args="],
                            capture_output=True, text=True, timeout=5
                        )
                        cmdline = ps_result.stdout.strip()
                        if any(s in cmdline for s in [
                            "run_check", "run_security_scan", "run_guard",
                            "run_scan", "run_shield", "run_watch",
                            "run_fuzzing", "run_scanorama", "run_validator"
                        ]):
                            continue
                        os.kill(pid, 9)
                        killed += 1
                    except (ValueError, ProcessLookupError, PermissionError):
                        pass
        except Exception:
            pass

        # Also kill any mcp-check node processes that may be lingering
        try:
            subprocess.run(
                ["pkill", "-f", "mcp-check.js"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
        except Exception:
            pass

        # Kill any Chrome/Puppeteer processes spawned by mcp-check
        try:
            subprocess.run(
                ["pkill", "-f", ".cache/puppeteer"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
        except Exception:
            pass

    if killed > 0:
        print(f"  Killed {killed} lingering server process(es)")


def generate_mcp_check_config(repo_path: Path, command: str, elem: list) -> Path:
    """Generate test-config.json for mcp-check in the repo directory."""
    if isinstance(elem, str):
        elem = [elem]

    if command == "npx":
        target_command = "npx"
        target_args = elem
    else:
        main_file = elem[0]
        full_path = str(repo_path / main_file).replace("\\", "\\\\")
        target_command = command
        target_args = [full_path] + elem[1:]

    config = {
        "target": {
            "type": "stdio",
            "command": target_command,
            "args": target_args
        },
        # No "suites" key - mcp-check will run all available suites
        "reporting": {
            "formats": ["json"],
            "outputDir": str(MCP_CHECK_DIR / "reports").replace("\\", "\\\\"),
            "redaction": {
                "enabled": False
            }
        }
    }

    config_path = repo_path / "test-config.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    return config_path


def parse_mcp_check_report(report_path: Path) -> dict:
    """Parse the JSON report generated by mcp-check."""
    if not report_path.exists():
        return None

    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    summary = data.get("summary", {})
    suites = data.get("suites", [])
    analysis = data.get("analysis", {})

    # Process suites dynamically
    suite_results = {}
    for suite in suites:
        suite_name = suite.get("name")
        cases = suite.get("cases", [])

        passed = sum(1 for c in cases if c.get("status") == "passed")
        failed = sum(1 for c in cases if c.get("status") == "failed")
        warnings = sum(1 for c in cases if c.get("status") == "warning")

        # Capture errors for failed cases
        errors = []
        for c in cases:
            if c.get("status") == "failed":
                error_info = c.get("error", {})
                details = c.get("details", {})
                payload = details.get("input") or details.get("invalidInput")
                
                errors.append({
                    "test": c.get("name"),
                    "type": error_info.get("type", "Unknown"),
                    "message": error_info.get("message", "No message"),
                    "payload": payload if payload else None
                })

        # Capture warnings - warnings is a list of strings
        warning_list = []
        for c in cases:
            if c.get("status") == "warning":
                warns = c.get("warnings", [])
                for warn_msg in warns:
                    warning_list.append({
                        "test": c.get("name"),
                        "message": warn_msg if isinstance(warn_msg, str) else str(warn_msg)
                    })

        suite_results[suite_name] = {
            "status": suite.get("status"),
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "total": len(cases),
            "duration_ms": suite.get("durationMs", 0),
            "errors": errors if errors else None,
            "warning_list": warning_list if warning_list else None
        }

    return {
        "mcp-check": {
            "status": "completed",
            "summary": summary,
            "suites": suite_results,
            "analysis": {
                "success_rate": analysis.get("successRate", 0),
                "total_duration_ms": analysis.get("performanceMetrics", {}).get("totalDuration", 0),
                "avg_test_duration_ms": analysis.get("performanceMetrics", {}).get("averageTestDuration", 0)
            }
        }
    }


def execute_mcp_check(repo_path: Path, command: str, elem: list):
    """Execute mcp-check test runner via subprocess."""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    if isinstance(elem, str):
        elem = [elem]

    # Build the server command string for process cleanup
    if command == "npx":
        server_command = f"npx {' '.join(elem)}"
    elif command == "node":
        server_command = f"node {repo_path / elem[0]}"
    elif command == "python":
        server_command = f"python {repo_path / elem[0]}"
    else:
        server_command = f"{command} {repo_path / elem[0]}"

    # Generate config file for this server
    try:
        config_path = generate_mcp_check_config(repo_path, command, elem)
    except Exception as e:
        print(f"Failed to generate mcp-check config: {e}")
        return failure("mcp-check")

    # Output report path
    report_path = MCP_CHECK_DIR / "reports" / "results.json"

    # Clear old report if exists
    if report_path.exists():
        try:
            report_path.unlink()
        except Exception:
            pass

    try:
        # Build mcp-check command
        cmd = [
            "node",
            str(MCP_CHECK_DIR / "bin" / "mcp-check.js"),
            "test",
            "--config", str(config_path)
        ]

        stdout, stderr, elapsed, code = run_process(
            cmd=cmd,
            cwd=MCP_CHECK_DIR,
            timeout=TIMEOUT_SECONDS,
            framework_name="MCP Check",
            env=env
        )

    except TimeoutError:
        # Kill any lingering server processes on timeout
        _kill_server_processes(server_command)
        return failure("mcp-check")
    except Exception as e:
        print(f"mcp-check execution error: {e}")
        _kill_server_processes(server_command)
        return failure("mcp-check")
    finally:
        # ALWAYS kill lingering server processes after check completes
        _kill_server_processes(server_command)

    # Check if report was created
    if not report_path.exists():
        print(f"mcp-check report not found at {report_path}")
        return failure("mcp-check")

    # Parse the JSON report
    parsed = parse_mcp_check_report(report_path)

    if parsed is None:
        return failure("mcp-check")

    # Clean up config file
    try:
        config_path.unlink()
    except Exception:
        pass

    return parsed, "completed"
