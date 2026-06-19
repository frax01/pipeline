#!/usr/bin/env python3
"""
stage1_filter.py — Stage 1 filter per mcp-guard findings (19 categorie)

Tassonomia output (suffissi espliciti):
  STATIC (9):
    command-injection-static, code-injection-static, insecure-deserialization-static,
    prompt-injection-static, dangerous-tool-handler-static, path-traversal-static,
    sql-injection-static, hardcoded-credential-static, ssrf-static
  FUZZING (6):
    code-injection-fuzzing, information-disclosure-fuzzing, command-injection-fuzzing,
    path-traversal-fuzzing, command-execution-fuzzing, sensitive-info-disclosed-fuzzing
  PROTOCOL (4):
    protocol-information-disclosure, protocol-path-traversal,
    protocol-missing-id, protocol-invalid-jsonrpc-version

Esecuzione:
    py -X utf8 stage1_filter.py
"""

import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

BASE_DIR = Path(__file__).parent

# ── Utility ──────────────────────────────────────────────────────────────────

def extract_code(desc: str) -> str:
    idx = desc.find("Code: ")
    return desc[idx + 6:].strip() if idx != -1 else ""

def load_json(path: Path) -> list:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("vulnerabilities", []) if isinstance(data, dict) else data

def save_filtered(category: str, findings: list, original_total: int) -> Path:
    out_dir = BASE_DIR / category / "filtered"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = category.replace("/", "_").replace("-", "_")
    out_file = out_dir / f"{safe}_filtered.json"
    result = {
        "category": category,
        "original_total": original_total,
        "kept_total": len(findings),
        "findings": findings,
    }
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    pct = len(findings) / original_total * 100 if original_total else 0
    print(f"  [{category}] {original_total:,} → {len(findings):,} ({pct:.1f}%)")
    return out_file

def process(category: str, src_files: list, keep_fn):
    all_findings, total, decont = [], 0, 0
    for p in src_files:
        p = Path(p)
        if not p.exists():
            print(f"  [WARN] non trovato: {p.name}")
            continue
        entries = load_json(p)
        total += len(entries)
        for f in entries:
            f["_source_file"] = p.name
            f["_category"] = category
            # DE-CONTAMINAZIONE NPX: scarta file della pipeline stessa
            if is_pipeline_own(f):
                decont += 1
                continue
            if keep_fn(f):
                all_findings.append(f)
    if decont:
        print(f"     (de-contaminati {decont:,} finding pipeline-own)")
    save_filtered(category, all_findings, total)


# ── Honeypot / scanner noti ──────────────────────────────────────────────────

_HONEYPOT = {
    "malicious_mcp", "vulnerable-notes-mcp", "IMCP", "vulnicheck",
    "mcp-scanner", "agent-security-scanner-mcp", "bishnubista/vulnerable-notes-mcp",
    "nav33n25/IMCP", "AlchemicalChef/MCPServer",
}

def is_honeypot(f: dict) -> bool:
    name = f.get("server_name", "")
    url  = f.get("server_url", "")
    return name in _HONEYPOT or any(h in url for h in _HONEYPOT)


# ── DE-CONTAMINAZIONE NPX ─────────────────────────────────────────────────────
# Il run NPX ha scansionato la working dir della PIPELINE per ogni pacchetto:
# l'80-100% dei finding nelle categorie grosse referenzia file della pipeline
# stessa (frameworks/, generated_code/, NewProxy/, tool_proxy/, ...) NON del
# pacchetto npm. Vanno scartati: non sono codice del server analizzato.
_PIPELINE_OWN = re.compile(
    r"(^|/)(frameworks|tool_proxy|localServer|generated_code|NewProxy|promptFilter|"
    r"monitorVM|analysisAllData|functions|data|npm_runner|handoff-system|mcpTest)/|"
    r"mcpSecurityScan|mcpGuard\b|mcpWatch|mcpScan|mcpShield|mcpCheck|run_proxy|"
    r"/Pipeline/|cursor25xinput|serverLocal\.py|(^|/)launch\.py$|(^|/)deploy\.py$|"
    r"(^|/)vmcheck\.py$|(^|/)mainParallel\.py$|(^|/)main\.py$",
    re.I,
)

def is_pipeline_own(f: dict) -> bool:
    return bool(_PIPELINE_OWN.search(f.get("file", "") or ""))


# ── Filtri globali file-based ────────────────────────────────────────────────

# Test/spec/fixture/mock — versione robusta
# Cattura: test/, _test.go, _test.py, _spec.rb, .test.js, test-prefix.js, verify-*.js, demo-*.py
_TEST_FILE = re.compile(
    r"(?:test[/\\]|spec[/\\]|\.test\.|\.spec\.|__tests__|fixture[/\\]|fixtures[/\\]|"
    r"mock[/\\]|mocks[/\\]|_test\.\w+$|_spec\.\w+$|_tests\.\w+$|"
    r"\.test\.[jt]sx?$|\.spec\.[jt]sx?$|"
    r"e2e[/\\]|tests_e2e[/\\]|"
    r"\.example\.\w+$|\.sample\.\w+$|config-example\.|example\w*\.(?:js|ts|py|go)$|"
    r"examples?[/\\]|samples?[/\\]|demos?[/\\]|"
    # test-/demo-/verify-/sample- prefix (file-level, after path separator or at start)
    r"(?:^|[/\\])(?:test-|demo-|verify-|sample-|example-|setup-)\w|"
    # types/ DefinitelyTyped
    r"(?:^|[/\\])types[/\\]|@types[/\\]|"
    r"\.d\.ts$)",
    re.I,
)

# File minified/vendor/build
_VENDOR_FILE = re.compile(
    r"(?:\.min\.[jt]sx?$|node_modules[/\\]|vendor[/\\]|"
    r"dist[/\\]|build[/\\]|\.bundle\.[jt]sx?$|"
    r"site-packages[/\\])",
    re.I,
)

# File di scanner/security tool propri (own vulnerabilities reference)
_SCANNER_OWN = re.compile(
    r"(?:vulnerabilit(?:y|ies)[/\\]|/sast[/\\]|/scanner[/\\]|/security/(?:rules|tests)[/\\]|"
    r"honeypot[/\\]|payloads?[/\\])",
    re.I,
)

# Codice commentato (linea che inizia con # // * o """ o ''' o -- SQL comment)
_COMMENTED = re.compile(r"^\s*(?:#|//|\*|/\*|--)\s*", re.I)


# ════════════════════════════════════════════════════════════════════════════
# STATIC (9)
# ════════════════════════════════════════════════════════════════════════════

# ── 1. command-injection-static (107) ───────────────────────────────────────
# Go exec.Command(name, args...) NON usa shell → FP
# Node exec.exec(string) usa shell → VP se concat con var
# Solo template literal o concat in exec/execSync = VP

_CIS_GO_EXEC = re.compile(r'^\s*\w*Cmd?\s*[:=]?=?\s*exec\.Command\s*\(\s*["\']', re.I)
_CIS_GO_EXEC_VAR_FIRST = re.compile(r'^\s*\w*Cmd?\s*[:=]?=?\s*exec\.Command\s*\(\s*\w+\s*,', re.I)
_CIS_NODE_EXECFILE = re.compile(r"(?:execFile|spawn)\s*\(\s*[\"'][^\"']+[\"']\s*,", re.I)
_CIS_TEMPLATE_VAR = re.compile(r"(?:exec|execSync|execFile)\s*\(\s*`[^`]*\$\{", re.I)
_CIS_CONCAT = re.compile(r"(?:exec|execSync)\s*\([^)]*[\"`'][^\"`'\n]*[\"`']\s*\+\s*\w", re.I)
_CIS_PYTHON_SHELL_TRUE = re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True", re.I)
_CIS_LITERAL_EXAMPLE = re.compile(r"^['\"]child_process\.|^['\"]exec\(", re.I)

def keep_command_injection_static(f: dict) -> bool:
    if is_honeypot(f): return False
    file = f.get("file", "")
    if _TEST_FILE.search(file) or _VENDOR_FILE.search(file) or _SCANNER_OWN.search(file):
        return False
    code = extract_code(f.get("description", ""))
    if _COMMENTED.match(code): return False
    if _CIS_LITERAL_EXAMPLE.search(code): return False
    # Go exec.Command con primo arg literal e tutti args separati = no shell
    if _CIS_GO_EXEC.search(code) and not re.search(r"\+\s*\w|`[^`]*\$\{", code):
        return False
    # VP keep
    if _CIS_TEMPLATE_VAR.search(code) or _CIS_CONCAT.search(code) or _CIS_PYTHON_SHELL_TRUE.search(code):
        return True
    # ExecFile/spawn con array args = no shell = FP
    if _CIS_NODE_EXECFILE.search(code) and not re.search(r"\$\{|[\"'][^\"']*[\"']\s*\+", code):
        return False
    return True


# ── 2. code-injection-static (318) ──────────────────────────────────────────
# eval/Function/exec con input dinamico

_CI_STATIC_STR = re.compile(r"eval\s*\(\s*[\"'][^\"'$]+[\"']\s*\)", re.I)
_CI_JSON_STRINGIFY = re.compile(r"eval\s*\(\s*JSON\.stringify", re.I)
_CI_BARE_TRUNCATED = re.compile(r"\.eval\s*\(\s*$", re.I)
_CI_SCHEME_EVAL = re.compile(r"\(eval\s+\(read\s+", re.I)  # Scheme/Lisp REPL = FP
_CI_TEMPLATE_VAR = re.compile(r"eval\s*\(\s*`[^`]*\$\{", re.I)
_CI_BACKTICK = re.compile(r"eval\s*\(\s*`", re.I)
_CI_USER_VAR = re.compile(
    r"(?:eval|Function|exec)\s*\([^)]*(?:params|args|input|arguments|req\.body|req\.query|userInput|user_input)\.",
    re.I,
)

def keep_code_injection_static(f: dict) -> bool:
    if is_honeypot(f): return False
    file = f.get("file", "")
    if _TEST_FILE.search(file) or _VENDOR_FILE.search(file) or _SCANNER_OWN.search(file):
        return False
    code = extract_code(f.get("description", ""))
    if _COMMENTED.match(code): return False
    if _CI_STATIC_STR.search(code): return False
    if _CI_JSON_STRINGIFY.search(code): return False
    if _CI_BARE_TRUNCATED.search(code): return False
    if _CI_SCHEME_EVAL.search(code): return False
    return True


# ── 3. insecure-deserialization-static (814) ────────────────────────────────
# pickle.load/loads/joblib.load con input controllato

_ID_HARDCODED_PATH = re.compile(
    r"(?:pickle\.load|joblib\.load|torch\.load|np\.load)\s*\(\s*open\s*\(\s*[\"'][^\"']+\.pkl[\"']",
    re.I,
)
_ID_BUFFER_INTERNAL = re.compile(
    r"pickle\.loads?\s*\(\s*(?:io\.BytesIO|self\.|cls\.|buffer|cached|cache_data)",
    re.I,
)
_ID_USER_INPUT = re.compile(
    r"pickle\.loads?\s*\([^)]*(?:params|args|input|arguments|req\.body|userInput|file|data|payload)\b",
    re.I,
)
_ID_FILE_LITERAL = re.compile(r"\.load\s*\(\s*[\"'][^\"']+\.(?:pkl|joblib|pt|pth|npy)[\"']", re.I)

def keep_insecure_deserialization(f: dict) -> bool:
    if is_honeypot(f): return False
    file = f.get("file", "")
    if _TEST_FILE.search(file) or _VENDOR_FILE.search(file) or _SCANNER_OWN.search(file):
        return False
    code = extract_code(f.get("description", ""))
    if _COMMENTED.match(code): return False
    if _ID_HARDCODED_PATH.search(code): return False
    if _ID_FILE_LITERAL.search(code): return False
    if _ID_BUFFER_INTERNAL.search(code) and not _ID_USER_INPUT.search(code):
        return False
    return True


# ── 4. prompt-injection-static (2016) ───────────────────────────────────────
# overlap mcp-shield: pattern injection in tool description

_PI_USECASE_DOC = re.compile(r"<usecase>", re.I)  # documentazione strutturale = FP
_PI_DOC_FILE = re.compile(r"(?:README|CHANGELOG|HISTORY)\.md$|docs?[/\\]", re.I)

# AWS SDK boilerplate / cloud doc (description con HTML tag e contenuto enterprise)
_PI_AWS_BOILERPLATE = re.compile(
    r"<p>|<b>|<code>|<a\s+href=|<ul>|<li>"
    r"|Amazon\s+(?:Web\s+Services|S3|EC2|IVS|RDS|Lambda|DynamoDB|Service\s+Catalog)"
    r"|AWS\s+(?:Account|IAM|ARN|SDK|CLI)"
    r"|HashiCorp|Terraform|Kubernetes\s+API",
    re.I,
)
# Tool description con istruzioni operative normali (you MUST/SHOULD provide)
_PI_NORMAL_INSTRUCTION = re.compile(
    r"(?:you\s+(?:MUST|must|SHOULD|should)\s+(?:also\s+)?(?:provide|specify|use|include|set)|"
    r"This\s+(?:will|tool|method)|"
    r"Sending\s+a\s+file|"
    r"Specifies\s+the\s+(?:format|name|type|value)|"
    r"is\s+(?:a|the)\s+(?:list|array|string|number|object))",
    re.I,
)
# Auto-generated wrapper (mcp_server/main.py + models.py con boto3-like)
_PI_AUTOGEN_FILE = re.compile(
    r"mcp_server[/\\](?:main|models|client|tools)\.py$",
    re.I,
)
# Pattern di vera injection da KEEP
_PI_REAL_INJECT = re.compile(
    r"<IMPORTANT>|<SYSTEM>|<system>|<hidden>|<secret>|<cmd>|<instructions>(?!\s*</instructions>)"
    r"|Ignore\s+(?:all|previous)\s+instructions"
    r"|NEVER\s+use\s+(?:Read|Write|Bash|Grep|Glob)|ALWAYS\s+use\s+\w+\s+instead\b(?!\s+of)"
    r"|forget\s+everything|act\s+as\s+(?:a|an|root|admin|sudo)"
    r"|disregard\s+(?:above|prior|previous)|pretend\s+to\s+be"
    r"|hidden\s+from\s+(?:user|view)|not\s+visible\s+to\s+(?:user|humans|operator)",
    re.I,
)

def keep_prompt_injection_static(f: dict) -> bool:
    if is_honeypot(f): return False
    file = f.get("file", "")
    if _PI_DOC_FILE.search(file): return False
    if _TEST_FILE.search(file) or _VENDOR_FILE.search(file) or _SCANNER_OWN.search(file):
        return False
    code = extract_code(f.get("description", ""))
    # VP forte: keep
    if _PI_REAL_INJECT.search(code): return True
    if _PI_USECASE_DOC.search(code): return False
    if _PI_AWS_BOILERPLATE.search(code): return False
    if _PI_AUTOGEN_FILE.search(file) and not _PI_REAL_INJECT.search(code):
        return False
    if _PI_NORMAL_INSTRUCTION.search(code) and not _PI_REAL_INJECT.search(code):
        return False
    return True


# ── 5. dangerous-tool-handler-static (3991) ─────────────────────────────────
# function signatures: filtra demo/lambda/health/safe

_DTH_FP_NAME = re.compile(
    r"def\s+(?:run_demo|demo_|lambda_handler|health_check|_health|"
    r"execute_safe_command|run_inference|eval_model|run_all|run_tests?|"
    r"_sync_\w+|_subtasks_enabled|find_runner|find_\w+|"
    r"is_\w+_enabled|_\w+_enabled_for_\w+|is_\w+_running|"
    r"get_runner_info|get_\w+_info|get_\w+_status|"
    r"_run_pip_audit|_run_audit|run_audit|"
    r"_run_check|run_check|check_\w+|"
    r"_resolve_\w+|resolve_\w+|"
    r"render_\w+|format_\w+|parse_\w+|validate_\w+|"
    r"build_\w+|create_\w+_config|load_\w+|save_\w+|"
    r"_progress_callback|_callback|_\w+_callback|"
    r"call_tool|_call_tool|handle_call|handle_request|"
    r"run_mcp_\w+|run_server|run_perfect_\w+|run_workflow|"
    r"_run_stdio_\w+|_run_streamable_\w+|_run_to_\w+|"
    r"_progress|progress_\w+)",
    re.I,
)
# Function with no body shown / generic run — no actual exec
_DTH_GENERIC_RUN = re.compile(
    r"def\s+run\s*\(\s*self\s*\)\s*->\s*\w+",  # def run(self) -> X
    re.I,
)
# return type bool/int/Path/None → likely no shell exec
_DTH_SAFE_RETURN = re.compile(
    r"->\s*(?:bool|int|float|Path|Optional\[(?:str|int|bool|Path)\]|None|NoReturn|Iterator|Generator)\s*:",
    re.I,
)
_DTH_VP_NAME = re.compile(
    r"def\s+(?:execute_curl|run_kubectl|execute_remote|execute_shell|"
    r"_run_command|_run_kubectl|ssh_exec|run_command|exec_command|"
    r"shell_exec|system_exec|run_shell|exec_shell|"
    r"execute_command|execute_bash|execute_powershell|"
    r"run_naabu|run_nmap|run_metasploit|run_sqlmap|run_hydra|"
    r"run_aircrack|run_nuclei|run_gobuster|run_dirb)",
    re.I,
)
# Funzioni "wrapper sicure" che NON eseguono shell
_DTH_NON_EXEC = re.compile(
    r"def\s+(?:_run\b|run\b|execute\b)\s*\(\s*self\s*[,)]"
    r"|->\s*(?:int|bool|Path|str|Optional|List|Dict|None|NoReturn)\s*:",
    re.I,
)
_DTH_FP_FILE = re.compile(
    r"(?:lambda[/\\]|aws[/\\]lambda|examples?[/\\]|demos?[/\\]|"
    r"compatibility[/\\]|compat[/\\]|sample[/\\])",
    re.I,
)

def keep_dangerous_tool_handler(f: dict) -> bool:
    if is_honeypot(f): return False
    file = f.get("file", "")
    if _TEST_FILE.search(file) or _VENDOR_FILE.search(file) or _SCANNER_OWN.search(file):
        return False
    if _DTH_FP_FILE.search(file): return False
    code = extract_code(f.get("description", ""))
    if _COMMENTED.match(code): return False
    # VP forte: keep
    if _DTH_VP_NAME.search(code): return True
    # FP names
    if _DTH_FP_NAME.search(code): return False
    if _DTH_GENERIC_RUN.search(code): return False
    if _DTH_SAFE_RETURN.search(code) and not _DTH_VP_NAME.search(code):
        return False
    return True


# ── 6. path-traversal-static (4740) ──────────────────────────────────────────

_PT_HARDCODED_DIR = re.compile(
    r"(?:path|filepath|os\.path)\.[Jj]oin\s*\(\s*"
    r"(?:__dirname|process\.cwd\(\)|os\.getcwd\(\)|"
    r"BASE_DIR|ROOT_DIR|PROJECT_ROOT|APP_ROOT|DATA_DIR|CACHE_ROOT|TEMP_DIR|"
    r"STORAGE_DIR|UPLOAD_DIR|DOWNLOAD_DIR|CONFIG_DIR|LOG_DIR|OUTPUT_DIR|"
    r"\w+_DIR|\w+_PATH|\w+_ROOT|\w+_FOLDER|"
    r"[\"'][^\"']+[\"'])"
    r"\s*,\s*[\"'][^\"']+[\"']\s*\)",
    re.I,
)
# Pattern: const dir + f-string con suffix
_PT_CONST_DIR_FNAME = re.compile(
    r"(?:path|filepath|os\.path)\.[Jj]oin\s*\(\s*"
    r"(?:[A-Z][A-Z_]+|\w+_DIR|\w+_PATH|\w+_ROOT|temp_dir|save_dir|output_dir)"
    r"[^,)]*,\s*f?[\"'][^{\"']*[\"']\s*\)",
    re.I,
)
# Replace user-input slash → mitigated
_PT_SLASH_REPLACED = re.compile(r"\.replace\s*\(\s*['\"]/['\"]\s*,\s*['\"]\w?['\"]", re.I)
_PT_USER_INPUT = re.compile(
    r"(?:path|filepath|os\.path)\.[Jj]oin\s*\([^)]*"
    r"(?:params\.|args\.|input\.|arguments\.|req\.body|req\.query|userInput|user_input|"
    r"request\.body|request\.query|\.\.\.\w+|"
    r"\bbody\.\w+|\bquery\.\w+|\bopts\.path|filepath_arg|user_path)",
    re.I,
)
# 2nd arg: pure literal string (no var)
_PT_LITERAL_2ND = re.compile(
    r"(?:path|filepath|os\.path)\.[Jj]oin\s*\([^,]+,\s*[\"'][^\"']+[\"']\s*\)",
    re.I,
)
# f-string con solo variabili "interne" (i, idx, count, datetime, uuid, _id, type)
_PT_INTERNAL_VARS_ONLY = re.compile(
    r"f[\"'][^{]*\{(?:i|j|k|n|idx|count|num|len|datetime|uuid|now|_id|type|"
    r"kind|version|model_name|backbone|head|format|mode|stage|step|"
    r"safe_\w+|sanitized_\w+)\}[^{]*[\"']",
    re.I,
)
# Path concat con UPPER_CONST + var literal (no user input keyword)
_PT_CONST_VAR_NO_USER = re.compile(
    r"(?:path|filepath|os\.path)\.[Jj]oin\s*\(\s*"
    r"(?:[A-Z_]{3,}|cfg\.\w+|self\.config\.\w+|config\.\w+|sm\.config\.\w+|"
    r"this\.config\.\w+|opts\.\w+_dir|opts\.\w+_path)",
    re.I,
)
_PT_DUNDER = re.compile(
    r"(?:path|filepath)\.[Jj]oin\s*\(\s*(?:__dirname|__filename|os\.path\.dirname\s*\()",
    re.I,
)

def keep_path_traversal_static(f: dict) -> bool:
    if is_honeypot(f): return False
    file = f.get("file", "")
    if _TEST_FILE.search(file) or _VENDOR_FILE.search(file) or _SCANNER_OWN.search(file):
        return False
    code = extract_code(f.get("description", ""))
    if _COMMENTED.match(code): return False
    if _PT_HARDCODED_DIR.search(code) and not _PT_USER_INPUT.search(code):
        return False
    if _PT_DUNDER.search(code) and not _PT_USER_INPUT.search(code):
        return False
    if _PT_CONST_DIR_FNAME.search(code) and not _PT_USER_INPUT.search(code):
        return False
    if _PT_LITERAL_2ND.search(code) and not _PT_USER_INPUT.search(code):
        return False
    # Solo internal_vars (i, idx, count, datetime, uuid, _id, type) + UPPER_CONST → FP
    if _PT_CONST_VAR_NO_USER.search(code) and _PT_INTERNAL_VARS_ONLY.search(code) \
       and not _PT_USER_INPUT.search(code):
        return False
    if _PT_SLASH_REPLACED.search(code): return False
    # Truncated (no arg visible) — incompleto, lascio HC decidere
    return True


# ── 7. sql-injection-static (4886) ───────────────────────────────────────────

_SQL_TRIPLE_NO_VAR = re.compile(
    r"(?:execute|run|query)\s*\(\s*(?:text\s*\(\s*)?(?:\"\"\"|'{3})(?![^\"']*\{)",
    re.I | re.S,
)
_SQL_FSTRING_NO_VAR = re.compile(r"f['\"][^{'\"]+['\"]", re.I)  # f-string senza {}
_SQL_PARAM_TUPLE = re.compile(r"execute\s*\([^,)]+,\s*(?:\([^)]*\)|\[[^\]]*\])", re.I)
_SQL_SAFE_PREFIX = re.compile(r"\{(?:safe_|validated_|escaped_|quoted_|sanitized_)\w+\}", re.I)
_SQL_USER_VAR = re.compile(
    r"f[\"']{1,3}[^{]*\{(?!self\.|this\.|cls\.|__)\w",
    re.I,
)
_SQL_CONCAT = re.compile(r"(?:execute|run|query)\s*\([^)]*[\"'][^\"']+[\"']\s*\+\s*\w", re.I)
_SQL_FORMAT = re.compile(r"execute\s*\([^)]*\.format\s*\(", re.I)
_SQL_PERCENT = re.compile(r"execute\s*\([^)]*%\s*\(?:?\w", re.I)
_SQL_ORM_SAFE = re.compile(r"session\.exec\s*\(\s*select\(|clickhouse\.exec\s*\(\s*\{", re.I)
_SQL_REGEX_EXEC = re.compile(r"/[^/]+/\.exec\s*\(", re.I)  # JS regex.exec — non SQL

# Truncated call (no arg visible) → snippet incompleto
_SQL_BARE_CALL = re.compile(
    r"(?:execute|run|query|exec)\s*\(\s*$"
    r"|(?:cursor|conn|db|connection|client|c)\s*=\s*\w+\.execute\s*\(\s*$",
    re.I,
)
# String comment with SQL example
_SQL_COMMENT_STR = re.compile(r'^\s*["\']?\s*#\s*Instead\s+of:|^\s*["\']?\s*#\s*Example:', re.I)
# JS template literal regex .exec()
_SQL_JS_REGEX_EXEC = re.compile(r"\)\.exec\s*\(", re.I)
# join() di colonne con `?` placeholder = parametrizzato
_SQL_JOIN_PLACEHOLDER = re.compile(
    r"','\.join\s*\(\s*\[\s*['\"]\?['\"]\s*\]\s*\*", re.I,
)

def keep_sql_injection(f: dict) -> bool:
    if is_honeypot(f): return False
    file = f.get("file", "")
    if _TEST_FILE.search(file) or _VENDOR_FILE.search(file) or _SCANNER_OWN.search(file):
        return False
    if re.search(r"migration[/\\]|seed[/\\]|alembic[/\\]|enhanced_analyzer", file, re.I): return False
    code = extract_code(f.get("description", ""))
    if _COMMENTED.match(code): return False
    if _SQL_COMMENT_STR.search(code): return False
    if _SQL_BARE_CALL.search(code): return False
    if _SQL_REGEX_EXEC.search(code): return False
    if _SQL_ORM_SAFE.search(code): return False
    if _SQL_TRIPLE_NO_VAR.search(code) and "{" not in code: return False
    if _SQL_FSTRING_NO_VAR.search(code) and not re.search(r"\{", code): return False
    if _SQL_JOIN_PLACEHOLDER.search(code): return False
    if _SQL_PARAM_TUPLE.search(code) and not (_SQL_CONCAT.search(code) or _SQL_FORMAT.search(code)):
        return False
    if _SQL_SAFE_PREFIX.search(code) and not _SQL_USER_VAR.search(code): return False
    return True


# ── 8. hardcoded-credential-static (18438) ──────────────────────────────────

_HC_VAR_AS_VAL = re.compile(
    r'([A-Z_][A-Z0-9_]{2,})\s*[=:]\s*["\'](?:ENV_|CONFIG_)?(\1)["\']', re.I
)
_HC_PLACEHOLDER = re.compile(
    r"""["\'](?:
        test_token|test_key|test_secret|test_password|test-token|test-key|
        sample_|example_|dummy_|fake_|placeholder|NEEDS_REPAIR|changeme|
        your[-_]?(?:api[-_]?key|token|secret|password)|
        insert[-_]here|<[^>]+>|\$\{[^}]+\}|
        x{8,}|X{5,}|a{8,}|1234567|password|secret|key_here|
        sk-xxx|sk-XXXX|API_KEY_HERE|TOKEN_HERE|YOUR_(?:API_KEY|TOKEN|SECRET)|
        SAMPLE_|DEFAULT_DEV|dev_secret|local_secret|
        \.\.\.[a-z]+|\[REDACTED\]|REDACTED
    )""",
    re.I | re.X,
)
_HC_ANNOTATION = re.compile(r":\s*(?:str|Optional\[str\]|Union\[str|ClassVar\[str|String\b)", re.I)
_HC_PROVIDER_KEY = re.compile(
    r"""sk-[A-Za-z0-9]{20,}|
        ghp_[A-Za-z0-9]{30,}|
        github_pat_[A-Za-z0-9_]{50,}|
        AKIA[A-Z0-9]{16}|
        AIza[A-Za-z0-9_-]{35,}|
        xox[bpoas]-[A-Za-z0-9-]{20,}|
        mongodb\+srv://[^:]+:[^@\s]+@|
        postgresql?://[^:]+:[^@\s]+@|
        mysql://[^:]+:[^@\s]+@|
        redis://[^:@]+:[^@\s]+@|
        -----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY""",
    re.I | re.X,
)
_HC_DEFAULT_DEV = re.compile(
    r"(?:DEFAULT_DEV|DEV_DEFAULT|LOCAL_DEV|TEST_DEFAULT|EXAMPLE_)",
    re.I,
)
_HC_SHORT_VALUE = re.compile(r'[=:]\s*["\']\w{1,3}["\']', re.I)  # valore <4 chars

def keep_hardcoded_credential(f: dict) -> bool:
    if is_honeypot(f): return False
    file = f.get("file", "")
    if _TEST_FILE.search(file) or _VENDOR_FILE.search(file) or _SCANNER_OWN.search(file):
        return False
    if re.search(r"_test\.\w+$|_spec\.\w+$|tests?[/\\]|specs?[/\\]|fixtures?[/\\]|"
                 r"e2e[/\\]|examples?[/\\]|samples?[/\\]|demos?[/\\]|"
                 r"\.example\b|\.sample\b|debug[-_]token|debug[/\\]", file, re.I):
        return False
    code = extract_code(f.get("description", ""))
    if _COMMENTED.match(code): return False
    if _HC_PROVIDER_KEY.search(code): return True  # VP forte
    if _HC_VAR_AS_VAL.search(code): return False
    if _HC_PLACEHOLDER.search(code): return False
    if _HC_ANNOTATION.search(code) and not re.search(r"=\s*[\"'][\w\-+/=]{8,}[\"']", code):
        return False
    if _HC_DEFAULT_DEV.search(code): return False
    if _HC_SHORT_VALUE.search(code) and not _HC_PROVIDER_KEY.search(code): return False
    return True


# ── 9. ssrf-static (44063) — già aggressivo, estendo lista API SaaS ─────────

_SSRF_DIRECT = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|request)|
         requests\.(?:get|post|put|delete|request)|
         httpx\.(?:get|post|AsyncClient)|
         got\.(?:get|post)|
         urllib\.request\.urlopen|
         http\.get|http\.post|
         superagent|needle\.(?:get|post)
    )\s*\(
    (?:params\.|args\.|input\.|arguments\.|req\.body\.|req\.query\.|
       options\.|config\.|data\.)""",
    re.I | re.X,
)
_SSRF_TEMPLATE_DIRECT = re.compile(
    r"""(?:fetch|axios\.|requests\.|httpx\.|got\.)\s*[(`]
    .*?\$\{(?:params|args|input|arguments|req\.(?:body|query))\.""",
    re.I | re.X,
)
# Lista API SaaS hardcoded — path/query injection NON è SSRF
_SSRF_KNOWN_API = re.compile(
    r"https?://(?:api\.[^/'\"`\s]+\.(?:com|io|net|ai|co|dev|cloud)|"
    r"[^.'\"`\s]+\.googleapis\.com|"
    r"openai\.com|anthropic\.com|huggingface\.co|"
    r"github\.com/api|api\.github\.com)",
    re.I,
)

def keep_ssrf(f: dict) -> bool:
    if is_honeypot(f): return False
    file = f.get("file", "")
    if _TEST_FILE.search(file) or _VENDOR_FILE.search(file) or _SCANNER_OWN.search(file):
        return False
    code = extract_code(f.get("description", ""))
    if _COMMENTED.match(code): return False
    # FP: dominio SaaS hardcoded + solo path/query da utente
    if _SSRF_KNOWN_API.search(code):
        return False
    if _SSRF_DIRECT.search(code) or _SSRF_TEMPLATE_DIRECT.search(code):
        return True
    return False


# ════════════════════════════════════════════════════════════════════════════
# FUZZING (6) — response-based, filtri Stage 1 leggeri (HC fa il grosso)
# ════════════════════════════════════════════════════════════════════════════

# Errori "non eseguito" comuni a tutti fuzzing
_FUZZ_NOT_EXECUTED = re.compile(
    r"(?:not\s+found|No\s+such\s+file\s+or\s+directory|"
    r"command\s+not\s+found|ENOENT|"
    r"Invalid\s+(?:argument|input|parameter)\s*(?:s)?\s*(?:for|to|:)|"
    r"Failed\s+to\s+(?:resolve|connect|fetch|load)|"
    r"getaddrinfo\s+ENOTFOUND|EHOSTUNREACH|ECONNREFUSED|"
    r"Could\s+not\s+resolve\s+hostname|"
    r"timeout\s+(?:of|after))",
    re.I,
)
_FUZZ_EMPTY_RESP = re.compile(r"^\s*(?:''|None|\{\s*\}|\[\s*\])\s*$")

def _resp_str(f): return str(f.get("response", ""))


# ── 10. code-injection-fuzzing (538) ─────────────────────────────────────────
def keep_code_injection_fuzzing(f: dict) -> bool:
    if is_honeypot(f): return False
    resp = _resp_str(f)
    if _FUZZ_EMPTY_RESP.match(resp): return False
    return True


# ── 11. information-disclosure-fuzzing (1360) ───────────────────────────────
def keep_information_disclosure_fuzzing(f: dict) -> bool:
    if is_honeypot(f): return False
    resp = _resp_str(f)
    if _FUZZ_EMPTY_RESP.match(resp): return False
    return True


# ── 12. command-injection-fuzzing (1743) ────────────────────────────────────
def keep_command_injection_fuzzing(f: dict) -> bool:
    if is_honeypot(f): return False
    resp = _resp_str(f)
    if _FUZZ_EMPTY_RESP.match(resp): return False
    return True


# ── 13. path-traversal-fuzzing (2183) ───────────────────────────────────────
def keep_path_traversal_fuzzing(f: dict) -> bool:
    if is_honeypot(f): return False
    resp = _resp_str(f)
    if _FUZZ_EMPTY_RESP.match(resp): return False
    return True


# ── 14. command-execution-fuzzing (2375) ────────────────────────────────────
def keep_command_execution_fuzzing(f: dict) -> bool:
    if is_honeypot(f): return False
    resp = _resp_str(f)
    if _FUZZ_EMPTY_RESP.match(resp): return False
    return True


# ── 15. sensitive-info-disclosed-fuzzing (5626) ─────────────────────────────

_SID_DOC_RESPONSE = re.compile(
    r"""(?:environment\s+variable\s+is\s+(?:not\s+)?set|
         Required\s+parameter|Optional\s+parameter|
         inputSchema|"type":\s*"object"|
         This\s+tool|The\s+tool\s+provides|
         Configure\s+(?:one|them|it)\s+(?:to|with)|
         must\s+be\s+set|is\s+required|not\s+configured|
         No\s+(?:API|api)\s+key|
         please\s+(?:set|provide|configure)|
         Error:\s+.*(?:key|token|secret).*not|
         Missing\s+(?:required|mandatory)|
         cannot\s+find|must\s+first\s+call|
         description.*parameter|
         requires\s+.*(?:API|api)\s+key|
         Failed\s+to\s+load|
         Failed\s+to\s+(?:read|fetch|get)|
         spawnSync\s+\w+\s+ENOENT|
         ENOENT|EACCES|
         not\s+set\s+in\s+environment|
         is\s+not\s+(?:available|enabled|defined)|
         Configuration\s+(?:validation\s+)?failed|
         use\s+enhanced\s+research|
         API\s+key\s+is\s+missing)""",
    re.I | re.X,
)
_SID_ACTUAL_KEY = re.compile(
    r"""(?:-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY|
         (?:api_key|apiKey|password|passwd|secret|token)\s*[=:]\s*["\']?[A-Za-z0-9+/=_-]{20,}|
         sk-[A-Za-z0-9]{20,}|
         ghp_[A-Za-z0-9]{30,}|
         AKIA[A-Z0-9]{16}|
         AIza[A-Za-z0-9_-]{35,}|
         xox[bpoas]-[A-Za-z0-9-]{20,}|
         mongodb\+srv://[^:\s]+:[^@\s]+@|
         postgresql?://[^:\s]+:[^@\s]+@)""",
    re.I | re.X,
)
_SID_MARKDOWN_DOC = re.compile(r"^\s*(?:#{1,6}\s|>\s|\*\s|\d+\.\s)", re.M)

def keep_sensitive_info_disclosed(f: dict) -> bool:
    if is_honeypot(f): return False
    response = f.get("response", "")
    if _SID_ACTUAL_KEY.search(response): return True
    if _SID_DOC_RESPONSE.search(response) and len(response) < 4000: return False
    if _SID_MARKDOWN_DOC.search(response[:500]): return False
    return True


# ════════════════════════════════════════════════════════════════════════════
# PROTOCOL (4) — split protocol in 4 subcategorie
# ════════════════════════════════════════════════════════════════════════════

# ── 16. protocol-information-disclosure (13) ────────────────────────────────
def keep_protocol_info_disclosure(f: dict) -> bool:
    return not is_honeypot(f)


# ── 17. protocol-path-traversal (14) — quasi tutti FP (echo payload) ────────
_PROTO_PT_ECHO_FP = re.compile(
    r"(?:Method\s+not\s+found|Unknown\s+method|未知方法|method\s+\S+\s+not\s+found"
    r"|Resource\s+not\s+found|Invalid\s+resource\s+URI|No\s+diagram\s+type)",
    re.I,
)

def keep_protocol_path_traversal(f: dict) -> bool:
    if is_honeypot(f): return False
    resp = _resp_str(f)
    if _PROTO_PT_ECHO_FP.search(resp): return False
    return True


# ── 18. protocol-missing-id (79) ─────────────────────────────────────────────
def keep_protocol_missing_id(f: dict) -> bool:
    return not is_honeypot(f)


# ── 19. protocol-invalid-jsonrpc-version (509) ───────────────────────────────
def keep_protocol_invalid_jsonrpc_version(f: dict) -> bool:
    return not is_honeypot(f)


# ════════════════════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=== mcp-guard Stage 1 Filter (19 categorie) ===\n")

    S = BASE_DIR / "static" / "other"
    F = BASE_DIR / "fuzzing" / "other"
    SI = BASE_DIR / "fuzzing" / "sensitive-information-disclosed"
    P = BASE_DIR / "protocol" / "other"

    # STATIC (9)
    process("command-injection-static", [
        S / "command-injection-—-string-concatenation-in-exec.command.json",
        S / "command-injection-—-unsanitised-input-in-child_process.exec.json",
        S / "command-injection-—-unsanitised-input-in-subprocess-os-call.json",  # NPX
    ], keep_command_injection_static)

    process("code-injection-static", [
        S / "code-injection-—-eval-with-dynamic-input.json"
    ], keep_code_injection_static)

    process("insecure-deserialization-static", [
        S / "insecure-deserialization-—-pickle-usage.json"
    ], keep_insecure_deserialization)

    process("prompt-injection-static", [
        S / "prompt-injection-—-suspicious-instructions-in-tool-description.json"
    ], keep_prompt_injection_static)

    process("dangerous-tool-handler-static", [
        S / "dangerous-tool-handler-—-system-command-execution-without-visible-input-validation.json"
    ], keep_dangerous_tool_handler)

    process("path-traversal-static", [
        S / "path-traversal-—-unsanitised-input-in-filepath.join.json",
        S / "path-traversal-—-unsanitised-input-in-path-construction.json",
        S / "path-traversal-—-unsanitised-input-in-path.join-resolve.json",  # NPX
    ], keep_path_traversal_static)

    process("sql-injection-static", [
        S / "sql-injection-—-dynamic-query-construction.json"
    ], keep_sql_injection)

    process("hardcoded-credential-static", [
        S / "hardcoded-credential-—-secret-value-in-source-code.json"
    ], keep_hardcoded_credential)

    process("ssrf-static", [
        S / "server-side-request-forgery-(ssrf)-—-user-input-in-http-request-url.json"
    ], keep_ssrf)

    # FUZZING (6)
    process("code-injection-fuzzing", [
        F / "code-injection-payload-was-executed-by-server.json"
    ], keep_code_injection_fuzzing)

    process("information-disclosure-fuzzing", [
        F / "information-disclosure.json"
    ], keep_information_disclosure_fuzzing)

    process("command-injection-fuzzing", [
        F / "command-injection-vulnerability.json"
    ], keep_command_injection_fuzzing)

    process("path-traversal-fuzzing", [
        F / "path-traversal-vulnerability.json"
    ], keep_path_traversal_fuzzing)

    process("command-execution-fuzzing", [
        F / "command-execution-attempt-detected.json"
    ], keep_command_execution_fuzzing)

    sid_files = sorted(SI.glob("*.json"))
    process("sensitive-info-disclosed-fuzzing", sid_files, keep_sensitive_info_disclosed)

    # PROTOCOL (4)
    process("protocol-information-disclosure", [
        P / "information-disclosure.json"
    ], keep_protocol_info_disclosure)

    process("protocol-path-traversal", [
        P / "path-traversal-vulnerability.json"
    ], keep_protocol_path_traversal)

    process("protocol-missing-id", [
        P / "server-accepts-requests-without-required-id-field.json"
    ], keep_protocol_missing_id)

    process("protocol-invalid-jsonrpc-version", [
        P / "server-accepts-invalid-json-rpc-protocol-version.json"
    ], keep_protocol_invalid_jsonrpc_version)

    print("\nStage 1 completato.")
