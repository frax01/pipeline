from collections import defaultdict
import json
from pathlib import Path
import subprocess
import os
import time


def _kill_server_processes(server_command: str):
    """Kill any lingering MCP server processes spawned by mcp-fuzzer.

    After mcp-fuzzer finishes, the server process (node/python/go) may still
    be running. This function finds and kills processes whose command line
    matches the FULL server command used during the fuzzing.

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
                            "run_fuzzing", "run_security_scan", "run_guard",
                            "run_scan", "run_check", "run_shield", "run_watch",
                            "run_scanorama", "run_validator"
                        ]):
                            continue
                        os.kill(pid, 9)
                        killed += 1
                    except (ValueError, ProcessLookupError, PermissionError):
                        pass
        except Exception:
            pass

        # Also kill any mcp-fuzzer processes that may be lingering
        try:
            subprocess.run(
                ["pkill", "-f", "mcp-fuzzer"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
        except Exception:
            pass

    if killed > 0:
        print(f"  Killed {killed} lingering server process(es)")

def find_latest_fuzzing_report(base_path: Path) -> Path | None:
    reports_dir = base_path / "reports" / "sessions"
    if not reports_dir.exists():
        return None

    json_files = list(reports_dir.glob("**/*.json"))

    if not json_files:
        return None

    return max(json_files, key=lambda p: p.stat().st_mtime)

def parse_fuzzing_report_json(report_path: Path) -> dict:
    with report_path.open("r", encoding="utf-8") as f:
        report = json.load(f)

    data = report.get("data", {})
    tools = data.get("tools_tested", [])
    protocol_types = data.get("protocol_types_tested", [])

    # Skip only if there's absolutely no data
    if not tools and not protocol_types:
        return None

    total_tools = len(tools)
    total_runs = 0
    total_successful = 0
    total_exceptions = 0
    total_safety_blocked = 0
    exceptions_by_message = defaultdict(int)
    tools_detail = []

    for tool in tools:
        t_runs = tool.get("runs", 0)
        t_successful = tool.get("successful", 0)
        t_exceptions = tool.get("exceptions", 0)
        t_safety = tool.get("safety_blocked", 0)

        total_runs += t_runs
        total_successful += t_successful
        total_exceptions += t_exceptions
        total_safety_blocked += t_safety

        tool_exc_details = []
        for exc in tool.get("exception_details", []):
            msg = exc.get("message")
            if msg:
                exceptions_by_message[msg] += 1
                tool_exc_details.append({
                    "type": exc.get("type", "unknown"),
                    "exception_type": exc.get("exception_type"),
                    "exception_class": exc.get("exception_class"),
                    "exception_code": exc.get("exception_code"),
                    "message": msg,
                    "arguments": exc.get("arguments", {}),
                    "server_error_response": exc.get("server_error_response"),
                })

        tool_success_details = [
            {
                "arguments": s.get("arguments", {}),
                "result": s.get("result"),
                "vuln_findings": s.get("vuln_findings", []),
            }
            for s in tool.get("success_details", [])
        ]

        tools_detail.append({
            "name": tool.get("name", "unknown"),
            "runs": t_runs,
            "successful": t_successful,
            "exceptions": t_exceptions,
            "safety_blocked": t_safety,
            "success_rate": tool.get("success_rate", 0.0),
            "exception_details": tool_exc_details,
            "success_details": tool_success_details
        })

    # Parse protocol types tested
    total_protocol_types = len(protocol_types)
    protocol_runs = 0
    protocol_successful = 0
    protocol_errors = 0
    protocol_by_type = {}

    for pt in protocol_types:
        pt_type = pt.get("type", "unknown")
        pt_runs = pt.get("runs", 0)
        pt_successful = pt.get("successful", 0)
        pt_errors = pt.get("errors", 0)

        protocol_runs += pt_runs
        protocol_successful += pt_successful
        protocol_errors += pt_errors

        # Preserve the full per-run error/success structure (now includes
        # exception_type, exception_class, server_response, server_error_response,
        # invariant_violations).
        protocol_by_type[pt_type] = {
            "runs": pt_runs,
            "successful": pt_successful,
            "errors": pt_errors,
            "success_rate": pt.get("success_rate", 0.0),
            "error_details": pt.get("error_details", []),
            "success_details": pt.get("success_details", []),
        }

    # Overall success rate across tools + protocol
    combined_runs = total_runs + protocol_runs
    combined_successful = total_successful + protocol_successful
    overall_success_rate = round(combined_successful / combined_runs * 100, 2) if combined_runs > 0 else 0.0

    return {
        # status="completed" if EITHER tool fuzzing OR protocol fuzzing
        # produced data. Some servers expose 0 tools (or fail tools/list)
        # but still produce useful protocol_types_tested entries — those
        # must count as completed so total_servers is updated.
        "status": "completed" if (tools or protocol_types) else "no_tools",
        "total_tools": total_tools,
        "total_fuzzing_runs": total_runs,
        "total_successful": total_successful,
        "total_exceptions": total_exceptions,
        "total_safety_blocked": total_safety_blocked,
        "success_rate": overall_success_rate,
        "exceptions_by_message": dict(exceptions_by_message),
        "tools_detail": tools_detail,
        "protocol_types": {
            "total_types": total_protocol_types,
            "total_runs": protocol_runs,
            "total_successful": protocol_successful,
            "total_errors": protocol_errors,
            "success_rate": round(protocol_successful / protocol_runs * 100, 2) if protocol_runs > 0 else 0.0,
            "by_type": protocol_by_type
        },
        "safety_enabled": report.get("metadata", {}).get("safety_enabled", False),
        "total_tests": report.get("metadata", {}).get("total_tests", combined_runs),
    }

def update_fuzzing_summary(summary: dict, result: dict, server_language: str) -> None:
    fuzzing_result = result.get("mcp-fuzzing", {})

    summary["fuzzing"]["total_servers"] += 1
    summary["fuzzing"]["percentage"] = round(summary["fuzzing"]["total_servers"] / summary["total"] * 100.0, 2) if summary["total"] > 0 else 0.0
    summary["fuzzing"]["languages"][server_language] = summary["fuzzing"]["languages"].get(server_language, 0) + 1
    summary["fuzzing"]["total_tools"] += fuzzing_result.get("total_tools", 0)
    summary["fuzzing"]["total_fuzzing_runs"] += fuzzing_result.get("total_fuzzing_runs", 0)
    summary["fuzzing"]["total_successful"] += fuzzing_result.get("total_successful", 0)
    summary["fuzzing"]["total_exceptions"] += fuzzing_result.get("total_exceptions", 0)
    summary["fuzzing"]["total_safety_blocked"] += fuzzing_result.get("total_safety_blocked", 0)

    for msg, count in fuzzing_result.get("exceptions_by_message", {}).items():
        summary["fuzzing"]["exceptions_by_message"][msg] = (
            summary["fuzzing"]["exceptions_by_message"].get(msg, 0) + count
        )

    if summary["fuzzing"]["total_fuzzing_runs"] > 0:
        summary["fuzzing"]["success_rate"] = (
            summary["fuzzing"]["total_successful"]
            / summary["fuzzing"]["total_fuzzing_runs"]
        )

    # Aggregate protocol_types data
    pt_result = fuzzing_result.get("protocol_types", {})
    if pt_result:
        pt_summary = summary["fuzzing"]["protocol_types"]
        pt_summary["total_types_tested"] += pt_result.get("total_types", 0)
        pt_summary["total_runs"] += pt_result.get("total_runs", 0)
        pt_summary["total_successful"] += pt_result.get("total_successful", 0)
        pt_summary["total_errors"] += pt_result.get("total_errors", 0)
        
        # Update success rate
        if pt_summary["total_runs"] > 0:
            pt_summary["success_rate"] = round(
                pt_summary["total_successful"] / pt_summary["total_runs"] * 100, 2
            )
        
        # Aggregate by_type
        for pt_type, pt_data in pt_result.get("by_type", {}).items():
            if pt_type not in pt_summary["by_type"]:
                pt_summary["by_type"][pt_type] = {
                    "runs": 0,
                    "successful": 0,
                    "errors": 0
                }
            pt_summary["by_type"][pt_type]["runs"] += pt_data.get("runs", 0)
            pt_summary["by_type"][pt_type]["successful"] += pt_data.get("successful", 0)
            pt_summary["by_type"][pt_type]["errors"] += pt_data.get("errors", 0)

def execute_mcp_fuzzing(path: Path, command: str, elem: str | list, mode: str = "both") -> dict:

    result = {
        "mcp-fuzzing": {
            "status": "failed",
            "percentage": 0.0,
            "languages": {},
            "total_tools": 0,
            "total_fuzzing_runs": 0,
            "total_successful": 0,
            "total_exceptions": 0,
            "total_safety_blocked": 0,
            "success_rate": 0.0,
            "exceptions_by_message": {},
            "protocol_types": {
                "total_types": 0,
                "total_runs": 0,
                "total_successful": 0,
                "total_errors": 0,
                "success_rate": 0.0,
                "by_type": {}
            }
        }
    }

    elem_str = " ".join(elem) if isinstance(elem, list) else str(elem)
    # Build server command string for process cleanup
    server_command = f"{command} {elem_str}" if command == "npx" else f"{command} {path / elem_str}"

    try:
        endpoint = f"{command} {elem_str}"
        cmd = [
            "mcp-fuzzer",
            "--mode", mode,
            "--phase", "both",
            "--protocol", "stdio",
            "--endpoint", endpoint,
            # Fuzzing intensity — back to original 10/10. The reduced 5/5
            # setting combined with --no-network removal blew up the per-tool
            # time (each network-dependent tool waited 60s per request
            # instead of failing fast), causing SERVER_TIMEOUT to kill every
            # run before the report was generated (0% fuzzed rate).
            "--runs", "10",
            "--runs-per-type", "10",
            # Timeouts
            "--timeout", "60",
            # Concurrency
            "--process-max-concurrency", "2",
            # Safety system — keep both fs sandbox AND no-network. Removing
            # --no-network seemed useful for capturing real responses from
            # network-dependent tools, but in practice it just made every
            # such request hang for the full 60s --timeout, blowing up the
            # per-server runtime far beyond SERVER_TIMEOUT (1100s). Better
            # to fail fast on network attempts and accept that those tools
            # produce TransportFailure exceptions (clearly tagged via
            # Patch 2 exception_type) rather than zero fuzzed servers.
            "--enable-safety-system",
            "--fs-root", "/tmp/safe",
            "--no-network",
            "--safety-report",
            # Output
            "--output-format", "json",
            # Watchdog (kill hung processes) — kept at the original 45/10/90s
            # values used in the first rerun (12.5% fuzzed rate). The tighter
            # 15/5/30s settings caused servers with heavy startup (npm
            # postinstall, lazy SDK loading, DB init, MCP SDK warmup) to be
            # killed before they could answer the first request, dropping
            # the fuzzed rate to 5%.
            "--watchdog-check-interval", "1.0",
            "--watchdog-process-timeout", "45",
            "--watchdog-extra-buffer", "10",
            "--watchdog-max-hang-time", "90",
            # Retry on transient failures
            "--process-retry-count", "3",
            "--process-retry-delay", "2.0",
            # Logging — verbose + DEBUG level for full visibility
            "--verbose",
            "--log-level", "DEBUG",
        ]

        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        # Force unbuffered output from the fuzzer subprocess so we can
        # tail every log line in real time.
        env['PYTHONUNBUFFERED'] = '1'

        # Hard cap on the whole mcp-fuzzer invocation. Back to the original
        # 300s value used in the first rerun (12.5% fuzzed rate). The 1000s
        # bump only matters when --no-network is removed, but with
        # --no-network restored the per-server time stays well under 300s.
        process_timeout = 300 if mode in ("all", "both") else 180

        # Run mcp-fuzzer via Popen and stream stdout/stderr to our own
        # stdout line-by-line. This is the only way to see watchdog /
        # tool_client / tool_fuzzer DEBUG traces in real time — the old
        # subprocess.run(capture_output=True) blocked until exit.
        accumulated_stdout: list[str] = []
        proc = subprocess.Popen(
            cmd,
            cwd=str(path),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge stderr into stdout
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            bufsize=1,                # line-buffered
        )

        deadline = time.time() + process_timeout
        timed_out = False
        try:
            assert proc.stdout is not None
            while True:
                if time.time() > deadline:
                    timed_out = True
                    proc.kill()
                    break
                line = proc.stdout.readline()
                if not line:
                    # EOF — process has exited
                    if proc.poll() is not None:
                        break
                    continue
                # Live echo to our stdout
                print(f"[fuzzer] {line.rstrip()}", flush=True)
                accumulated_stdout.append(line)
            return_code = proc.wait(timeout=10)
        except Exception as stream_exc:
            print(f"Streaming error: {stream_exc}", flush=True)
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
            return_code = -1

        if timed_out:
            # Re-raise as TimeoutExpired so the outer except block handles
            # cleanup the same way the previous code did.
            full_out = "".join(accumulated_stdout)
            raise subprocess.TimeoutExpired(
                cmd, process_timeout, output=full_out
            )

        print(f"Return code: {return_code}", flush=True)

        report_path = find_latest_fuzzing_report(path)
        if report_path is None:
             print(f"Fuzzing failed to produce report for {endpoint}")
             result["mcp-fuzzing"]["status"] = "skipped"
             return result

        # Debug: print report summary
        try:
            with open(report_path, "r", encoding="utf-8") as rf:
                report_raw = json.load(rf)
            data = report_raw.get("data", {})
            tools = data.get("tools_tested", [])
            protocol_types = data.get("protocol_types_tested", [])
            print(f"REPORT: total_tests={report_raw.get('metadata',{}).get('total_tests',0)}, tools={len(tools)}, protocol_types={len(protocol_types)}")
            if tools:
                print(f"FIRST TOOL: {json.dumps(tools[0], indent=2)[:600]}")
            if protocol_types:
                print(f"FIRST PROTOCOL TYPE: {json.dumps(protocol_types[0], indent=2)[:800]}")
        except Exception as dbg_e:
            print(f"Debug read error: {dbg_e}")

        parsed = parse_fuzzing_report_json(report_path)
        if parsed is not None:
            result["mcp-fuzzing"] = parsed
        else:
            print(f"WARNING: parse_fuzzing_report_json returned None for {report_path}")

    except subprocess.TimeoutExpired as e_timeout:
        result["mcp-fuzzing"]["status"] = "timeout"
        print(f"Fuzzing TIMEOUT ({process_timeout}s) for {endpoint}", flush=True)
        # The Popen streaming loop already echoed every line of stdout
        # in real time, so there is no extra dump to do here. The
        # accumulated buffer is preserved in e_timeout.output if needed.
        _kill_server_processes(server_command)
    except Exception as e:
        print(f"Error executing MCP fuzzing: {e}")
        result["mcp-fuzzing"]["status"] = "error"
        _kill_server_processes(server_command)
    finally:
        # ALWAYS kill lingering server processes after fuzzing completes
        _kill_server_processes(server_command)

    return result