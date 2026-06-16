#!/usr/bin/env python3
"""Classifica sensitive-info-disclosed-fuzzing UNCERTAIN."""
import json
import re
from pathlib import Path

BASE = Path(__file__).parent
CAT = "sensitive-info-disclosed-fuzzing"
UNC_FILE = BASE / CAT / "filtered" / "llm_analysis" / "uncertain.json"
CACHE_FILE = BASE / CAT / "filtered" / "llm_analysis" / "_llm_api_cache.json"


def cache_key(f: dict) -> str:
    server = (f.get("server_url", "")).replace("https://github.com/", "")
    payload = f.get("payload", "")
    if payload:
        return f"{server}|{CAT}|{payload[:40]}"
    file = f.get("file", "")
    return f"{server}|{file}|?"


def classify(f: dict) -> tuple[str, str]:
    response = str(f.get("response", ""))
    payload = str(f.get("payload", ""))

    # ── VP MARKERS ─────────────────────────────────────

    # Real key material in response
    if re.search(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY", response):
        return "VP", "private_key_block_in_response"
    if re.search(r"-----BEGIN\s+CERTIFICATE", response):
        return "VP", "certificate_block_in_response"

    # JWT in response
    if re.search(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+", response):
        return "VP", "jwt_token_in_response"

    # Real provider key formats in response
    if re.search(r"sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|"
                 r"AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35,}|"
                 r"xox[bpoas]-[A-Za-z0-9-]{20,}|"
                 r"GOCSPX-[A-Za-z0-9_-]{20,}", response):
        return "VP", "provider_key_format_in_response"

    # Connection string with credentials
    if re.search(r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[a-z0-9.-]+|"
                 r"postgresql?://[^:\s]+:[^@\s]+@[a-z0-9.-]+|"
                 r"mysql://[^:\s]+:[^@\s]+@", response, re.I):
        return "VP", "db_connection_string_with_creds"

    # /etc/passwd content (root:x:0:0)
    if re.search(r"root:x:0:0:|daemon:x:1:1:|nobody:x:|/usr/sbin/nologin", response):
        return "VP", "etc_passwd_content_leaked"

    # AWS credentials format in response
    if re.search(r"aws_access_key_id\s*=\s*[A-Z0-9]{16,}|"
                 r"aws_secret_access_key\s*=\s*[A-Za-z0-9+/=]{20,}", response, re.I):
        return "VP", "aws_credentials_in_response"

    # Hex hash (64 chars sha256, 40 chars sha1, 32 chars md5) as actual cred value
    if re.search(r"['\"](?:api_key|token|secret|password|passwd)['\"]?\s*[:=]\s*['\"]?[0-9a-f]{32,}['\"]?", response, re.I):
        return "VP", "hex_hash_credential_value_in_response"

    # ── FP MARKERS ─────────────────────────────────────

    # Markdown heading at start
    if re.search(r"['\"]text['\"]\s*:\s*['\"]\\*n?#{1,6}\s+\w", response):
        return "FP", "markdown_heading_response"
    if re.search(r"['\"]text['\"]\s*:\s*['\"]\\*n?>\s+\w", response):
        return "FP", "markdown_blockquote_response"

    # Doc/explanation prefix
    if re.search(r"# (?:Authentication|Data\s+Storage|Fixture|Pattern|Setup|Configuration|"
                 r"Development|Comprehensive|API|Tool|Server|Documentation|Usage|Guide|"
                 r"Tutorial|Example|Step|Quick)", response, re.I):
        return "FP", "documentation_or_guide_response"

    # Validation/rejection error
    if re.search(r"(?:Invalid|Illegal|Missing|Malformed)\s+(?:characters?|format|argument|"
                 r"input|parameter|symbol|value|type|number)|"
                 r"validation\s+(?:error|failed)|"
                 r"MCP\s+error\s+-32\d{3}|"
                 r"invalid_format|invalid_type|invalid_value", response, re.I):
        return "FP", "validation_or_rejection_error"

    # Env var not set / missing
    if re.search(r"(?:environment\s+variable|env\s+var|API\s+[Kk]ey|secret\s+key)\s+"
                 r"(?:is\s+)?(?:not\s+)?(?:set|configured|missing|empty|required|undefined|"
                 r"available|defined)|"
                 r"(?:please\s+)?(?:set|provide|configure|specify)\s+(?:your\s+|the\s+)?"
                 r"(?:API\s+)?(?:key|token|secret|password)|"
                 r"no\s+API\s+key", response, re.I):
        return "FP", "env_var_not_set_or_missing_message"

    # i18n CJK/Arabic error message
    if re.search(r"[一-鿿가-힯؀-ۿ]", response[:1500]):
        if re.search(r"(?:설정|未设置|未配置|請|請設置|沒有|配置|키가|キーが)", response[:1500]):
            return "FP", "i18n_cjk_error_message"

    # Spanish/French error message about API key
    if re.search(r"(?:Se\s+(?:debe|requiere)|Veuillez|Bitte)\s+(?:proporcionar|configurer|"
                 r"setzen|fournir).*?(?:clave|cl[eé]|API|key|token)", response, re.I):
        return "FP", "european_lang_error_message"

    # Payload echoed as label/config value
    if re.search(r"['\"](?:url|endpoint|host|target|gateway_url|kvUrl|baseUrl|publicEndpoint|"
                 r"server|hostname|connection)['\"]\s*:\s*['\"](?:file:///|https?://|\.\./)", response):
        return "FP", "payload_echoed_as_url_or_endpoint_config"

    # Tool execution failed (not a leak)
    if re.search(r"Tool\s+'?\w+'?\s+(?:execution\s+)?failed|"
                 r"EEXIST|ENOENT|EACCES|EPERM|"
                 r"spawnSync\s+\w+\s+ENOENT|"
                 r"Failed\s+to\s+(?:execute|run|connect|fetch|load|parse)", response):
        return "FP", "tool_execution_error_not_leak"

    # SQL syntax error (server rejected SQL injection)
    if re.search(r"SQL(?:ite)?\s+error|syntax\s+error|unrecognized\s+token|"
                 r"sql\s+logic\s+error|database\s+error", response, re.I):
        return "FP", "sql_syntax_error_no_leak"

    # Network error
    if re.search(r"(?:getaddrinfo|EAI_AGAIN|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|"
                 r"NetworkError|fetch\s+failed|connection\s+(?:refused|timeout))", response):
        return "FP", "network_error"

    # Generic permission denied / unauthorized (no leak)
    if re.search(r"(?:Permission\s+denied|Unauthorized|Access\s+denied|Forbidden|"
                 r"401\s+Unauthorized|403\s+Forbidden|"
                 r"Authentication\s+(?:failed|required))", response):
        return "FP", "permission_or_auth_error"

    # Tool list response (lists tools, no actual leak)
    if re.search(r"['\"]tools['\"]\s*:\s*\[.*?['\"]name['\"]\s*:", response, re.S):
        return "FP", "tool_list_response"

    # Schema/inputSchema response
    if re.search(r"['\"]inputSchema['\"]\s*:|['\"]type['\"]\s*:\s*['\"]object['\"]", response):
        return "FP", "tool_schema_response"

    # Search result with payload as query
    if re.search(r"['\"]hits['\"]\s*:\s*\[|nbHits|exhaustive|"
                 r"[Ff]ound\s+\d+\s+(?:results?|matches?|recipes?|items?|insights?)", response):
        return "FP", "search_engine_result"

    # Bad gateway / 5xx errors
    if re.search(r"5\d{2}\s+(?:Internal|Bad\s+Gateway|Service\s+Unavailable)|"
                 r"Internal\s+Server\s+Error|Bad\s+Gateway", response):
        return "FP", "5xx_server_error"

    # Generic empty success
    if re.search(r"['\"]result['\"]\s*:\s*\{\s*['\"]content['\"]\s*:\s*\[\s*\]", response):
        return "FP", "empty_result_response"

    # ── ROUND 2 PATTERNS ───────────────────────────────

    # Payload echoed as project/research/task name
    if re.search(r"(?:Research\s+plan\s+created\s+for|"
                 r"Project\s+(?:created|initialized|name)|"
                 r"projectName|currentProject|"
                 r"Saved\s+local\s+snapshot|"
                 r"Found\s+\d+\s+\w+\s+for|"
                 r"Comparison\s+for|Analysis\s+for|Report\s+for|"
                 r"Created\s+task|task[-_]name|"
                 r"📊|🏷️|🔧|🔐|💡|⚠️|✅|❌)"
                 r".*?(?:/etc/|file:///|\\.\\./|whoami|cat\s+/)",
                 response, re.S):
        return "FP", "payload_echoed_in_label_or_emoji_response"

    # Zod validation error format
    if re.search(r"['\"]code['\"]\s*:\s*['\"](?:too_small|too_big|invalid_type|"
                 r"invalid_format|invalid_string|invalid_union|custom)", response):
        return "FP", "zod_validation_error_format"

    # Missing dependencies / install message
    if re.search(r"Missing\s+dependencies?|"
                 r"is\s+not\s+installed|Install\s+with:|"
                 r"npm\s+install|pip\s+install|brew\s+install|apt\s+install|"
                 r"please\s+install|run.*?install", response):
        return "FP", "missing_dependency_install_message"

    # Coroutine / awaitable / generator object
    if re.search(r"<coroutine\s+object|<async\s+generator|<generator\s+object|"
                 r"<bound\s+method|<class\s+'", response):
        return "FP", "python_object_repr_not_leak"

    # Filesystem error EISDIR / not a directory / is a directory
    if re.search(r"is\s+a\s+directory|EISDIR|not\s+a\s+directory|ENOTDIR|"
                 r"no\s+such\s+file\s+or\s+directory|cannot\s+find\s+(?:file|path)", response):
        return "FP", "filesystem_error_eisdir_or_enoent"

    # HTTP status error (4xx/5xx) without leak
    if re.search(r"HTTP\s+[45]\d{2}|status\s+code\s+[45]\d{2}|"
                 r"Request\s+failed\s+with\s+status|"
                 r"\b(?:404|401|403|500|502|503)\b\s+(?:Not\s+Found|Unauthorized|Forbidden|"
                 r"Internal|Bad|Service)", response):
        return "FP", "http_error_status_no_leak"

    # Invalid format/type/value (Web3 ERC20, Ethereum address)
    if re.search(r"Invalid\s+(?:address|format|number|hash|signature|signature\s+type|"
                 r"public\s+key|private\s+key|wallet|nft|erc\d+\s+balance|"
                 r"token\s+address)", response, re.I):
        return "FP", "invalid_format_validation_error"

    # Configuration required (multilingual i18n)
    if re.search(r"(?:Configuração|Konfiguration|Configuration|Konfigurasi|Configuración|"
                 r"設定|配置|구성|設置|конфигурация|تكوين)\s+(?:MySQL|MongoDB|"
                 r"required|necessar|obrigatori|erforderlich|requise|obligator|requerida|"
                 r"필요|必要|необходим)", response, re.I):
        return "FP", "i18n_configuration_required_message"

    # Tool command output (showing how to use a tool, not leak)
    if re.search(r"(?:Ligolo|Burp|Metasploit|Nmap|Wireshark|Mimikatz|"
                 r"Agent\s+Commands|Tool\s+Commands)\s*:\s*\\?n", response):
        return "FP", "tool_usage_help_text"

    # Generic Error: prefix without leak content
    if re.search(r"^[^']*['\"]text['\"]\s*:\s*['\"](?:Error|ERROR|Failed|❌)\s*:?\s*", response):
        # If after "Error:" there's no actual key/secret material
        if not re.search(r"(?:[0-9a-f]{32,}|sk-|ghp_|AKIA|AIza|BEGIN\s+(?:RSA\s+)?PRIVATE)", response):
            return "FP", "generic_error_prefix_no_leak"

    # Help / usage text
    if re.search(r"\\b(?:Usage|Examples?|Options?|Commands?|Help)\\b\\s*:\\s*\\\\n|"
                 r"--help|\\.show_help|usage\\(\\)", response):
        return "FP", "help_or_usage_text"

    # Empty success (just success: true with no payload)
    if re.search(r"['\"]success['\"]\s*:\s*true.*?['\"]message['\"]\s*:\s*['\"][^'\"]*['\"]\s*\\}", response):
        return "FP", "empty_success_message"

    # Tool result is empty/null
    if re.search(r"['\"]content['\"]\s*:\s*\\[\\s*\\]|['\"]result['\"]\s*:\s*null", response):
        return "FP", "empty_result_or_null"

    # PowerShell / cmd / bat output that reflects payload but no exec
    if re.search(r"PS\s+C:|CMD\\.EXE|@echo\s+off|powershell\\.exe.*?:\\s*\\\\n", response):
        if not re.search(r"(?:uid=|gid=|groups=|root:x:|/etc/passwd\\s+content|"
                         r"administrator\\s*\\\\\\\\)", response):
            return "FP", "windows_shell_command_text_no_exec"

    # Default: Stage 1 ha già scartato i FP ovvi e Stage 2A ha già classificato.
    # Per residui in fuzzing categoria sens-info, considero FP conservativo
    # (il payload è sempre payload di leak; risposta che NON contiene secret reale = FP)
    return "FP", "fuzzing_residual_no_secret_pattern_detected_in_response"


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
    for r, c in sorted(reasons.items(), key=lambda x: -x[1])[:25]:
        print(f"  {c:>4}  {r}")


if __name__ == "__main__":
    main()
