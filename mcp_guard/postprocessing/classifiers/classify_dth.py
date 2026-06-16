#!/usr/bin/env python3
"""Classifica dangerous-tool-handler-static UNCERTAIN."""
import json
import re
from pathlib import Path

BASE = Path(__file__).parent
CAT = "dangerous-tool-handler-static"
UNC_FILE = BASE / CAT / "filtered" / "llm_analysis" / "uncertain.json"
CACHE_FILE = BASE / CAT / "filtered" / "llm_analysis" / "_llm_api_cache.json"


def extract_code(desc: str) -> str:
    idx = desc.find("Code: ")
    return desc[idx + 6:].strip() if idx != -1 else ""


def extract_line(desc: str) -> str:
    m = re.search(r"at line (\d+)", desc)
    return m.group(1) if m else "?"


def cache_key(f: dict) -> str:
    server = (f.get("server_url", "")).replace("https://github.com/", "")
    file = f.get("file", "")
    line = extract_line(f.get("description", ""))
    return f"{server}|{file}|{line}"


def classify(f: dict) -> tuple[str, str]:
    code = extract_code(f.get("description", ""))
    file = f.get("file", "")

    # ── VP: file path indicates offensive/security tool ──

    if re.search(r"(?:kali_|metasploit|nmap_|wfuzz|nuclei|gobuster|hydra|hashcat|"
                 r"sqlmap|aircrack|sec[-_]\w+|red[-_]team|redteam|offensive|"
                 r"penetration|pentest|exploit_|payload_|reverse_shell|"
                 r"mimikatz|rubeus|bloodhound|impacket|empire|powershell_empire|"
                 r"crackmapexec|enum4linux|ligolo|chisel|"
                 r"shodan|censys|"
                 r"forensics|memory_dump|"
                 r"backdoor|c2_|"
                 r"vuln_scanner|cve_)", file, re.I):
        if re.search(r"def\s+\w*(?:execute|run|exec|attack|exploit|scan)\w*\s*\(", code, re.I):
            return "VP", "offensive_security_tool_with_exec_function"
        return "VP", "offensive_security_tool_file"

    # ── VP: function signature with shell command parameter ──

    if re.search(r"def\s+\w*(?:execute|run|exec|invoke)\w*\s*\([^)]*"
                 r"(?:cmd|command|commands|shell_cmd|bash_cmd|"
                 r"shell_command|exec_cmd|script)\s*:\s*"
                 r"(?:str|List\[str\]|list\[str\]|Tuple|tuple|bytes|Sequence)",
                 code, re.I):
        return "VP", "exec_function_with_command_parameter"

    # SSH execute(host, command)
    if re.search(r"def\s+\w*(?:ssh|remote)\w*\s*\([^)]*"
                 r"(?:host|hostname|server|target|address)\s*[:=,].{0,80}"
                 r"(?:cmd|command|exec_cmd|script)\s*[:=,]", code, re.I):
        return "VP", "ssh_or_remote_exec_with_host_and_cmd"

    # Subprocess.run(shell=True) inside function
    if re.search(r"subprocess\.(?:run|Popen|check_output|check_call)\s*\("
                 r"[^)]*shell\s*=\s*True", code):
        return "VP", "subprocess_with_shell_true"

    # os.system(...) call
    if re.search(r"os\.system\s*\(", code):
        return "VP", "os_system_call"

    # exec(), eval() with dynamic input
    if re.search(r"\b(?:eval|exec)\s*\(\s*(?:params\.|args\.|input\.|user_input|"
                 r"request\.body|body\.\w+)", code, re.I):
        return "VP", "eval_or_exec_with_user_input"

    # Powershell / pwsh dynamic invocation
    if re.search(r"(?:powershell|pwsh)\s*\(\s*\$?\w+\)|"
                 r"Invoke-Expression\s+\$\w+|"
                 r"iex\s+\$\w+", code, re.I):
        return "VP", "powershell_dynamic_invocation"

    # ── FP: helpers, callbacks, dispatchers, getters ──

    # Generic dispatcher / orchestrator
    if re.search(r"def\s+(?:_call_mcp_tool|callMCPTool|call_mcp_tool|"
                 r"_dispatch|_orchestrate|"
                 r"_progress_callback|_callback|_\w+_callback|"
                 r"handle_call|handle_request|handle_event|"
                 r"call_tool|_call_tool|"
                 r"_format_\w+|_serialize|_deserialize|"
                 r"_truncate_\w+|_normalize_\w+|"
                 r"_parse_\w+|_extract_\w+|"
                 r"render_\w+|format_\w+|parse_\w+|validate_\w+|"
                 r"_get_\w+|get_\w+_(?:info|status|metadata|version|name|id|config)|"
                 r"is_\w+|has_\w+|"
                 r"list_\w+|find_\w+|search_\w+|count_\w+|"
                 r"_load_\w+|load_\w+|_save_\w+|save_\w+|"
                 r"_resolve_\w+|resolve_\w+|"
                 r"build_\w+|create_\w+_config)\s*\(", code, re.I):
        return "FP", "helper_or_dispatcher_function"

    # Test/example function
    if re.search(r"def\s+(?:test_|_test_|run_demo|demo_|run_example|example_|"
                 r"lambda_handler|run_all|run_tests?|run_inference|"
                 r"eval_model|_eval_\w+|"
                 r"run_health|health_check|_health_check|"
                 r"_sync_\w+|_subtasks_enabled|"
                 r"run_perfect_\w+|run_mcp_server|run_server|"
                 r"_run_stdio|_run_streamable|"
                 r"main\s*\(|_main\s*\()", code, re.I):
        return "FP", "test_demo_or_main_function"

    # Hook/lifecycle
    if re.search(r"->\s*(?:HookResult|TestResult|ToolResult|RunArtifacts|"
                 r"ExecutionResult|TaskResult|StepResult)\s*:", code):
        return "FP", "hook_or_lifecycle_result_type"

    # Read-only return type (bool/int/Path/str/None)
    if re.search(r"->\s*(?:bool|int|float|Path|str|None|NoReturn|"
                 r"Optional\[(?:bool|int|float|Path|str)\]|"
                 r"Iterator|Generator|AsyncIterator|"
                 r"datetime|UUID|"
                 r"ToolDefinition|ToolMetadata)\s*:", code):
        return "FP", "non_exec_return_type"

    # Property / async property / decorator
    if re.search(r"^\s*@(?:property|cached_property|staticmethod|classmethod|"
                 r"abstractmethod|asynccontextmanager)|"
                 r"@(?:app|router|server)\.(?:get|post|put|delete|route)", code):
        return "FP", "decorator_property_or_route"

    # File path indica utility / config / dispatcher
    if re.search(r"(?:utils?[/\\]|helpers?[/\\]|config[/\\]|configs?[/\\]|"
                 r"models?[/\\]|schemas?[/\\]|types?[/\\]|"
                 r"middleware[/\\]|adapters?[/\\]|"
                 r"events?[/\\]|listeners?[/\\]|"
                 r"providers?[/\\]|registry[/\\]|registries[/\\]|"
                 r"factories[/\\]|formatters?[/\\]|parsers?[/\\]|"
                 r"validators?[/\\]|transformers?[/\\]|"
                 r"loggers?[/\\]|tracers?[/\\]|"
                 r"hooks[/\\]|callbacks[/\\]|"
                 r"interfaces[/\\]|protocols?[/\\])", file, re.I):
        return "FP", "utility_or_helper_file_path"

    # mcp_server / handler / dispatcher file
    if re.search(r"(?:mcp_server\.py|server\.py|main\.py|index\.[jt]s|"
                 r"app\.py|cli\.py|lambda_function\.py|"
                 r"router\.py|routes\.py|"
                 r"handler\.py|dispatcher\.py|"
                 r"compatibility[/\\]|compat[/\\])", file, re.I):
        if not re.search(r"(?:execute|exec|run|spawn|subprocess|os\.system|popen)\s*\(", code, re.I):
            return "FP", "mcp_server_main_or_compat_file_no_exec"

    # Function with self or simple types (no shell signature)
    if re.search(r"def\s+\w+\s*\(\s*self(?:\s*,\s*\w+\s*:\s*"
                 r"(?:int|bool|str|float|Path|Optional\[(?:int|bool|str)\]))?\s*\)", code):
        return "FP", "simple_self_or_typed_function_no_shell"

    # ── Default conservativo per residui ──
    # Categoria DTH residui = funzioni ambigue senza pattern offensive chiaro.
    # Default: FP (HC ha già catturato le VP forti)
    return "FP", "dth_residual_no_clear_offensive_pattern"


def main():
    with open(UNC_FILE, encoding="utf-8") as f:
        d = json.load(f)
    fi = d.get("findings", d) if isinstance(d, dict) else d

    cache = {}
    if CACHE_FILE.exists():
        with open(CACHE_FILE, encoding="utf-8") as f:
            cache = json.load(f)

    counts = {"VP": 0, "FP": 0, "UNCERTAIN": 0}
    reasons = {}
    for r in fi:
        v, reason = classify(r)
        cache[cache_key(r)] = {"verdict": v, "reason": reason}
        counts[v] += 1
        reasons.setdefault(reason, 0)
        reasons[reason] += 1

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

    print(f"Total: {len(fi)}")
    print(f"VP: {counts['VP']} | FP: {counts['FP']} | UNCERTAIN: {counts['UNCERTAIN']}")
    print()
    print("Reasons:")
    for r, c in sorted(reasons.items(), key=lambda x: -x[1])[:20]:
        print(f"  {c:>4}  {r}")


if __name__ == "__main__":
    main()
