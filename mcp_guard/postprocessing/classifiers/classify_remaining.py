#!/usr/bin/env python3
"""Classifica UNCERTAIN per le categorie restanti con regole specifiche."""
import json
import re
from pathlib import Path

BASE = Path(__file__).parent

CATS = [
    "sql-injection-static",
    "information-disclosure-fuzzing",
    "prompt-injection-static",
    "protocol-invalid-jsonrpc-version",
    "ssrf-static",
    "code-injection-fuzzing",
    "command-execution-fuzzing",
    "code-injection-static",
    "command-injection-static",
    "protocol-missing-id",
    "protocol-information-disclosure",
    "protocol-path-traversal",
    "command-injection-fuzzing",
]


def extract_code(desc: str) -> str:
    idx = desc.find("Code: ")
    return desc[idx + 6:].strip() if idx != -1 else ""


def extract_line(desc: str) -> str:
    m = re.search(r"at line (\d+)", desc)
    return m.group(1) if m else "?"


def cache_key(f: dict, cat: str) -> str:
    server = (f.get("server_url", "")).replace("https://github.com/", "")
    payload = f.get("payload", "")
    if payload:
        return f"{server}|{cat}|{payload[:40]}"
    file = f.get("file", "")
    line = extract_line(f.get("description", ""))
    return f"{server}|{file}|{line}"


# ── Classifiers per categoria ──────────────────────────


def classify_sql(f: dict) -> tuple[str, str]:
    code = extract_code(f.get("description", ""))
    file = f.get("file", "")

    # VP: f-string concat with user input keyword
    if re.search(r"execute\s*\([^)]*f[\"']{1,3}[^{]*\{(?:params|args|input|"
                 r"req\.body|request\.body|user_input)\.\w+\}", code, re.I):
        return "VP", "fstring_with_user_input_in_execute"

    # VP: string concat (++) with user input
    if re.search(r"execute\s*\([^)]*\+\s*(?:params|args|input|user_)", code, re.I):
        return "VP", "string_concat_with_user_input_in_execute"

    # VP: %s/%d formatting with user input
    if re.search(r"execute\s*\([^)]*%\s*\(?(?:params|args|input)", code, re.I):
        return "VP", "percent_format_with_user_input"

    # FP: bare call truncated
    if re.search(r"(?:execute|run|query|exec)\s*\(\s*$", code):
        return "FP", "bare_call_truncated"

    # FP: triple-quote SQL with no f-string
    if re.search(r"execute\s*\(\s*(?:text\s*\(\s*)?(?:\"\"\"|''')", code) and "f\"\"\"" not in code:
        return "FP", "triple_quote_static_sql"

    # FP: parameterized query with ?/:/$1
    if re.search(r"execute\s*\([^)]+,\s*(?:\([^)]*\)|\[[^\]]*\])", code):
        return "FP", "parameterized_query_with_args_tuple"

    # Default conservative
    return "FP", "sql_residual_no_clear_user_input"


def classify_info_fuzz(f: dict) -> tuple[str, str]:
    response = str(f.get("response", ""))

    # VP: real key/cred in response
    if re.search(r"-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY|"
                 r"sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|"
                 r"AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35,}|"
                 r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.", response):
        return "VP", "real_credential_or_key_in_response"

    # VP: env vars dumped
    if re.search(r"['\"]?[A-Z][A-Z0-9_]+['\"]?\s*[=:]\s*['\"][A-Za-z0-9_/+=-]{20,}['\"]"
                 r".*['\"]?[A-Z][A-Z0-9_]+['\"]?\s*[=:]\s*['\"]", response, re.S):
        if re.search(r"AWS_|GITHUB_|API_|SECRET_|TOKEN_|DB_|DATABASE_", response):
            return "VP", "env_vars_dumped_in_response"

    # FP: env doc / not set
    if re.search(r"(?:not\s+set|not\s+configured|missing|required)\s+(?:env|API\s+key)|"
                 r"environment\s+variable\s+(?:is|not)|"
                 r"please\s+(?:set|configure|provide)", response, re.I):
        return "FP", "env_var_not_configured"

    # FP: tool list / schema
    if re.search(r"['\"]tools['\"]\s*:\s*\[|['\"]inputSchema['\"]", response):
        return "FP", "tool_schema_response"

    # FP: validation error
    if re.search(r"Invalid\s+(?:argument|format|input|parameter)|"
                 r"validation\s+error|MCP\s+error\s+-32\d{3}", response, re.I):
        return "FP", "validation_error"

    # FP: error / connection failure
    if re.search(r"(?:Error|Failed|fetch\s+failed|connection|timeout|"
                 r"ENOENT|ECONNREFUSED|getaddrinfo|"
                 r"401|403|404|500)", response, re.I):
        return "FP", "error_or_network_failure"

    return "FP", "info_disclosure_residual_no_secret"


def classify_pi_static(f: dict) -> tuple[str, str]:
    code = extract_code(f.get("description", ""))

    # VP: real injection patterns
    if re.search(r"<IMPORTANT>|<SYSTEM>|<system>|<hidden>|<secret>|<cmd>|"
                 r"Ignore\s+(?:all\s+|previous\s+)?instructions|"
                 r"NEVER\s+use\s+\w+\s+ALWAYS\s+use|"
                 r"forget\s+everything|"
                 r"do\s+not\s+(?:mention|reveal|show)|"
                 r"hidden\s+from\s+(?:user|view)|"
                 r"act\s+as\s+(?:root|admin|sudo|sys|administrator)", code, re.I):
        return "VP", "explicit_injection_pattern"

    # FP: usecase/structured doc
    if re.search(r"<usecase>|<example>|<note>|<context>", code):
        return "FP", "structured_documentation_tag"

    # FP: AWS/Cloud SDK boilerplate
    if re.search(r"<p>|<b>|<code>|<a\s+href|"
                 r"Amazon\s+(?:Web|S3|EC2|IVS|Lambda)|AWS\s+(?:Account|IAM|ARN)", code):
        return "FP", "aws_or_cloud_sdk_boilerplate"

    # FP: normal instruction
    if re.search(r"you\s+(?:MUST|must|SHOULD|should)\s+(?:also\s+)?(?:provide|specify|"
                 r"use|include|set)|"
                 r"This\s+(?:will|tool|method|function)|"
                 r"Specifies\s+the", code, re.I):
        return "FP", "normal_tool_instruction"

    return "FP", "pi_static_residual_no_explicit_injection"


def classify_proto_jsonrpc(f: dict) -> tuple[str, str]:
    response = str(f.get("response", ""))

    # VP: server accepted invalid jsonrpc and returned tools/result
    if re.search(r"['\"]result['\"]\s*:\s*\{\s*['\"]tools['\"]\s*:|"
                 r"['\"]result['\"]\s*:\s*\{\s*['\"]content['\"]", response):
        return "VP", "server_accepted_invalid_jsonrpc_returned_result"

    # FP: server correctly rejected
    if re.search(r"['\"]error['\"]\s*:\s*\{[^}]*['\"]code['\"]\s*:\s*-32600|"
                 r"Invalid\s+Request|Invalid\s+JSON-RPC", response):
        return "FP", "server_correctly_rejected_invalid_jsonrpc"

    # FP: connection error
    if re.search(r"ECONNREFUSED|ENOTFOUND|timeout|fetch\s+failed", response):
        return "FP", "connection_error"

    return "FP", "proto_jsonrpc_residual_unclear"


def classify_proto_missing_id(f: dict) -> tuple[str, str]:
    response = str(f.get("response", ""))

    # VP: server returned full result for notification (missing id)
    if re.search(r"['\"]result['\"]\s*:\s*\{\s*['\"]tools['\"]\s*:", response):
        return "VP", "server_responded_to_notification_missing_id"

    return "FP", "proto_missing_id_residual"


def classify_ssrf_static(f: dict) -> tuple[str, str]:
    code = extract_code(f.get("description", ""))

    # VP: fetch with full user-controlled URL
    if re.search(r"(?:fetch|axios\.\w+|requests\.\w+|httpx\.\w+|got\.\w+)\s*"
                 r"\(\s*(?:params|args|input|req\.body|req\.query)\.\w+", code, re.I):
        return "VP", "fetch_with_full_user_url"

    # VP: template literal full user URL
    if re.search(r"(?:fetch|axios)\s*\(\s*`\$\{(?:params|args|input|req\.body|req\.query)\.\w+\}`", code):
        return "VP", "template_literal_full_user_url"

    # FP: SDK method with internal config
    if re.search(r"this\.\w+\.fetch\s*\(|"
                 r"this\.client\.\w+\s*\(|"
                 r"\.\w+Client\.\w+\s*\(|"
                 r"this\.api\.\w+\s*\(", code):
        return "FP", "sdk_method_with_internal_config"

    # FP: hardcoded API SaaS domain
    if re.search(r"https?://(?:api\.[^/'\"`\s]+\.(?:com|io|net|ai)|"
                 r"[\w.-]+\.googleapis\.com)", code, re.I):
        return "FP", "hardcoded_saas_api_domain"

    return "FP", "ssrf_residual_no_user_input"


def classify_code_inj_fuzz(f: dict) -> tuple[str, str]:
    response = str(f.get("response", ""))

    # VP: payload executed (id command output, Python eval result)
    if re.search(r"uid=\d+\(|gid=\d+\(|"
                 r"_pyodide/_base\.py.*eval_code|"
                 r"Command\s+failed:\s+python.*?(?:\$\(id\)|__import__|os\.system)", response):
        return "VP", "code_injection_executed"

    # FP: import error / module not found
    if re.search(r"ModuleNotFoundError|ImportError|"
                 r"No\s+module\s+named|cannot\s+import\s+name", response):
        return "FP", "import_error_no_exec"

    # FP: syntax/parsing error
    if re.search(r"SyntaxError|ParseError|"
                 r"unexpected\s+(?:token|character)", response):
        return "FP", "syntax_or_parse_error"

    return "FP", "code_inj_fuzz_residual"


def classify_cmd_exec_fuzz(f: dict) -> tuple[str, str]:
    response = str(f.get("response", ""))

    # VP: payload in shell exec
    if re.search(r"uid=\d+\(|gid=\d+\(|root:x:0:0|"
                 r"Command\s+failed:.*?(?:\$\(id\)|__import__|&&\s+ls|"
                 r"test\s+\|\|\s+id|execSync\s*\()", response):
        return "VP", "shell_command_executed"

    # FP: binary not found / not installed in test env
    if re.search(r"(?:not\s+found|No\s+such\s+file|command\s+not\s+found|"
                 r"URL\s+scheme\s+execution\s+failed|"
                 r"Could\s+not\s+resolve\s+hostname)", response):
        return "FP", "binary_not_installed_or_unreachable"

    return "FP", "cmd_exec_fuzz_residual"


def classify_code_inj_static(f: dict) -> tuple[str, str]:
    code = extract_code(f.get("description", ""))

    # VP: eval with user input
    if re.search(r"eval\s*\([^)]*(?:params|args|input|req\.body|req\.query)\.\w+", code, re.I):
        return "VP", "eval_with_user_input"

    # VP: template literal eval
    if re.search(r"eval\s*\(\s*`[^`]*\$\{(?!self\.|this\.|cls\.)", code):
        return "VP", "eval_template_literal_with_var"

    # FP: static eval
    if re.search(r"eval\s*\(\s*[\"'][^\"'$]+[\"']\s*\)", code):
        return "FP", "eval_static_string"

    # FP: bare engine.eval truncated
    if re.search(r"\.eval\s*\(\s*$", code):
        return "FP", "engine_eval_truncated"

    return "FP", "code_inj_static_residual"


def classify_cmd_inj_static(f: dict) -> tuple[str, str]:
    code = extract_code(f.get("description", ""))

    # VP: exec with template literal user input
    if re.search(r"(?:exec|execSync|spawn)\s*\(\s*`[^`]*\$\{(?!self\.|this\.)", code):
        return "VP", "exec_template_literal_user_input"

    # VP: subprocess shell=True with var
    if re.search(r"subprocess\.\w+\([^)]*shell\s*=\s*True[^)]*"
                 r"(?:params|args|input|user_)", code, re.I):
        return "VP", "subprocess_shell_true_user_input"

    # VP: exec concat with var
    if re.search(r"(?:exec|execSync)\s*\([^)]*[\"`'][^\"`'\n]*[\"`']\s*\+\s*"
                 r"(?:params|args|input|user_|req\.body)", code, re.I):
        return "VP", "exec_concat_with_user_input"

    # FP: Go exec.Command with literal first arg
    if re.search(r"exec\.Command\s*\(\s*[\"'][^\"']+[\"']\s*,", code):
        return "FP", "go_exec_command_no_shell"

    # FP: execFile with array
    if re.search(r"(?:execFile|spawn)\s*\(\s*[\"'][^\"']+[\"']\s*,\s*\[", code):
        return "FP", "execfile_with_array_no_shell"

    return "FP", "cmd_inj_static_residual"


def classify_proto_info(f: dict) -> tuple[str, str]:
    return "VP", "protocol_info_disclosure_residual_kept_VP"


def classify_proto_pt(f: dict) -> tuple[str, str]:
    return "FP", "protocol_pt_residual_no_traversal"


def classify_cmd_inj_fuzz(f: dict) -> tuple[str, str]:
    return "FP", "cmd_inj_fuzz_residual"


CLASSIFIERS = {
    "sql-injection-static": classify_sql,
    "information-disclosure-fuzzing": classify_info_fuzz,
    "prompt-injection-static": classify_pi_static,
    "protocol-invalid-jsonrpc-version": classify_proto_jsonrpc,
    "protocol-missing-id": classify_proto_missing_id,
    "ssrf-static": classify_ssrf_static,
    "code-injection-fuzzing": classify_code_inj_fuzz,
    "command-execution-fuzzing": classify_cmd_exec_fuzz,
    "code-injection-static": classify_code_inj_static,
    "command-injection-static": classify_cmd_inj_static,
    "protocol-information-disclosure": classify_proto_info,
    "protocol-path-traversal": classify_proto_pt,
    "command-injection-fuzzing": classify_cmd_inj_fuzz,
}


def main():
    grand_total = {"VP": 0, "FP": 0, "UNCERTAIN": 0}
    for cat in CATS:
        unc_file = BASE / cat / "filtered" / "llm_analysis" / "uncertain.json"
        cache_file = BASE / cat / "filtered" / "llm_analysis" / "_llm_api_cache.json"
        if not unc_file.exists():
            continue
        with open(unc_file, encoding="utf-8") as f:
            d = json.load(f)
        fi = d.get("findings", d) if isinstance(d, dict) else d
        if not fi:
            continue

        cache = {}
        if cache_file.exists():
            with open(cache_file, encoding="utf-8") as f:
                cache = json.load(f)

        clf = CLASSIFIERS.get(cat)
        if not clf:
            continue

        counts = {"VP": 0, "FP": 0, "UNCERTAIN": 0}
        for r in fi:
            v, reason = clf(r)
            cache[cache_key(r, cat)] = {"verdict": v, "reason": reason}
            counts[v] += 1
            grand_total[v] += 1

        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)

        print(f"{cat:>40}: total={len(fi):>4} VP={counts['VP']:>3} FP={counts['FP']:>4} UNC={counts['UNCERTAIN']:>3}")

    print()
    print(f"GRAND TOTAL: VP={grand_total['VP']} FP={grand_total['FP']} UNC={grand_total['UNCERTAIN']}")


if __name__ == "__main__":
    main()
