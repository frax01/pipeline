#!/usr/bin/env python3
"""
stage2_pipeline.py — Stage 2A + 2B + merge per mcp-guard findings

Usa i file _filtered.json prodotti da stage1_filter.py e applica:
  Stage 2A: regole HC (High Confidence) per ogni categoria
  Stage 2B: classificazione LLM (Ollama) per gli UNCERTAIN
  Merge:    vp.json / fp.json / audit.json

Esecuzione:
    py -X utf8 stage2_pipeline.py --category ssrf --hc-only
    py -X utf8 stage2_pipeline.py --category all --cache-only
    py -X utf8 stage2_pipeline.py --category all --merge

Categorie disponibili:
    ssrf, hardcoded-credential, sql-injection, dangerous-tool-handler,
    path-traversal-static, prompt-injection-static, insecure-deserialization,
    code-injection-static, command-injection-static,
    command-injection-fuzzing, path-traversal-fuzzing, command-execution-fuzzing,
    code-injection-fuzzing, information-disclosure-fuzzing,
    sensitive-info-disclosed, protocol
"""

import argparse
import base64
import json
import re
import sys
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

BASE_DIR = Path(__file__).parent

CATEGORIES = [
    # STATIC (9)
    "ssrf-static",
    "hardcoded-credential-static",
    "sql-injection-static",
    "dangerous-tool-handler-static",
    "path-traversal-static",
    "prompt-injection-static",
    "insecure-deserialization-static",
    "code-injection-static",
    "command-injection-static",
    # FUZZING (6)
    "command-injection-fuzzing",
    "path-traversal-fuzzing",
    "command-execution-fuzzing",
    "code-injection-fuzzing",
    "information-disclosure-fuzzing",
    "sensitive-info-disclosed-fuzzing",
    # PROTOCOL (4)
    "protocol-information-disclosure",
    "protocol-path-traversal",
    "protocol-missing-id",
    "protocol-invalid-jsonrpc-version",
]

# Mappatura nomi vecchi → nuovi per retrocompatibilità HC_RULES
_LEGACY_CAT_MAP = {
    "ssrf-static": "ssrf",
    "hardcoded-credential-static": "hardcoded-credential",
    "sql-injection-static": "sql-injection",
    "dangerous-tool-handler-static": "dangerous-tool-handler",
    "insecure-deserialization-static": "insecure-deserialization",
    "sensitive-info-disclosed-fuzzing": "sensitive-info-disclosed",
    # protocol-* nuovi: usano hc_rules_protocol con tag interno per ora
    "protocol-information-disclosure": "protocol",
    "protocol-path-traversal": "protocol",
    "protocol-missing-id": "protocol",
    "protocol-invalid-jsonrpc-version": "protocol",
}

# ── Utility ──────────────────────────────────────────────────────────────────

def extract_code(desc: str) -> str:
    idx = desc.find("Code: ")
    return desc[idx + 6:].strip() if idx != -1 else ""

def extract_line(desc: str) -> str:
    m = re.search(r"at line (\d+)", desc)
    return m.group(1) if m else "?"

def _server_short(url: str) -> str:
    return (url or "").replace("https://github.com/", "")

def _cache_key(f: dict, cat: str) -> str:
    s = _server_short(f.get("server_url", ""))
    file = f.get("file", "")
    line = extract_line(f.get("description", ""))
    # Fuzzing/protocol: usa payload hash invece di file/line
    payload = f.get("payload", "")
    if payload:
        return f"{s}|{cat}|{payload[:40]}"
    return f"{s}|{file}|{line}"


# ── Pattern globali ────────────────────────────────────────────────────────────

_HONEYPOT = {
    "malicious_mcp", "vulnerable-notes-mcp", "IMCP", "vulnicheck",
    "mcp-scanner", "agent-security-scanner-mcp",
}

def is_honeypot(f: dict) -> bool:
    name = f.get("server_name", "")
    url  = f.get("server_url", "")
    return name in _HONEYPOT or any(h in url for h in _HONEYPOT)

# Provider key patterns (VP certi)
_PROVIDER_KEY = re.compile(
    r"(?:sk-[A-Za-z0-9]{20,}"
    r"|ghp_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9]{50,}"
    r"|AKIA[A-Z0-9]{16}"
    r"|AIza[A-Za-z0-9_-]{35,}"
    r"|xox[bpoas]-[A-Za-z0-9-]{20,}"
    r"|mongodb\+srv://[^:]+:[^@]+@"
    r"|postgresql://[^:]+:[^@]+@"
    r"|phc_[A-Za-z0-9]{20,}"
    r"|-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY)",
    re.I,
)

# Shell execution in fuzzing response
_SHELL_EXEC = re.compile(
    r"uid=\d+\(|gid=\d+\(|root:x:0:0|/etc/passwd|/etc/shadow|"
    r"daemon:x:|bin:x:|SYSTEM\\\\|NT AUTHORITY|"
    r"sh:\s*\d+:|bash:\s*\d+:|"
    r"command not found|No such file or directory.*etc/passwd",
    re.I,
)

# Tool list response (FP per fuzzing)
_TOOL_LIST_RESPONSE = re.compile(
    r""""tools":\s*\[.*?"name":|"method":\s*"tools/list".*?"result":|
     'tools':\s*\[.*?'name':""",
    re.I | re.X,
)

# Test file pattern
_TEST_FILE = re.compile(
    r"(?:test[/\\]|spec[/\\]|\.test\.|\.spec\.|__tests__|mock[/\\]|fixture[/\\])",
    re.I,
)


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: ssrf
# ═══════════════════════════════════════════════════════════════════════════════

# Pattern VP: URL direttamente da user params
_SSRF_DIRECT = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|request)|
         requests\.(?:get|post|put|delete|request)|
         httpx\.(?:get|post)|got\.(?:get|post)|urllib\.request\.urlopen
    )\s*\(
    (?:params\.|args\.|input\.|arguments\.|req\.body\.|req\.query\.)""",
    re.I | re.X,
)
_SSRF_TEMPLATE = re.compile(
    r"""\$\{(?:params|args|input|arguments|req\.(?:body|query))\.""",
    re.I | re.X,
)

# Pattern FP: base URL variabile non user-controlled
_SSRF_BASE_URL_FP = re.compile(
    r"\$\{(?:BASE_URL|baseUrl|BASE|HOST|host|this\.\w+|process\.env\.|config\.|_baseUrl)",
    re.I,
)
_SSRF_SDK_METHOD = re.compile(r"this\.\w+\.(?:fetch|get|post|request)\s*\(", re.I)
_SSRF_FIXED_PATH = re.compile(
    r'\$\{(?:BASE_URL|baseUrl|HOST|host)[^}]*\}/["\'\w/]', re.I
)

def hc_rules_ssrf(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    file = f.get("file", "")
    if _TEST_FILE.search(file):
        return "HC-FP", "test_file"
    code = extract_code(f.get("description", ""))

    # FP: SDK method call (not global fetch)
    if _SSRF_SDK_METHOD.search(code):
        return "HC-FP", "sdk_method_not_global_fetch"
    # FP: base URL variable (non user-controlled)
    if _SSRF_BASE_URL_FP.search(code):
        return "HC-FP", "base_url_variable_not_user_input"
    if _SSRF_FIXED_PATH.search(code):
        return "HC-FP", "fixed_path_after_base_url"

    # VP: URL da params/args diretti
    if _SSRF_DIRECT.search(code):
        return "HC-VP", "direct_user_param_in_url"
    if _SSRF_TEMPLATE.search(code):
        return "HC-VP", "template_literal_user_param_in_url"

    return "UNCERTAIN", "url_source_unclear"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: hardcoded-credential
# ═══════════════════════════════════════════════════════════════════════════════

_HC_VAR_AS_VAL = re.compile(
    r'([A-Z_]{3,})\s*[=:]\s*["\'](?:ENV_|CONFIG_)?(\1)["\']', re.I
)
# Substring search: qualsiasi stringa che CONTIENE queste parole è placeholder
_HC_PLACEHOLDER = re.compile(
    r"""["\'][^"\']*(?:
        placeholder|sample_|example_|dummy_|fake_|test_token|test_key|test_secret|
        your[-_]api|your[-_]secret|your[-_]token|your[-_]key|
        my[-_]api[-_]key|my[-_]secret|my[-_]token|
        insert[-_]here|key_here|token_here|api_key_here|
        changeme|NEEDS_REPAIR|REPLACE_ME|REPLACE[-_]WITH|
        sk-xxx|sk-XXXX|sk-test|sk-placeholder|sk-fake|sk-sample|sk-demo|
        xxxxxx|XXXXXX|aaaaaa|123456789|000000|
        API_KEY_HERE|TOKEN_HERE
    )[^"\']*["\']""",
    re.I | re.X,
)
# "your-api-key", "your-secret", "your_key" etc. (generico: starts with your- or your_)
_HC_YOUR_PREFIX = re.compile(r"""["\']your[-_]\w""", re.I)
# Linea commentata (#, //, *, >>>) con credenziale
_HC_COMMENT_LINE = re.compile(r"^\s*(?:#|//|\*|>>>)", re.I)
_HC_ANNOTATION_FP = re.compile(
    r":\s*(?:str|Optional\[str\]|Union\[str|ClassVar\[str)", re.I
)
# Minified/bundle JS (tante variabili concatenate senza spazi)
_HC_BUNDLE_JS = re.compile(r'(?:[a-z]\.[a-z]\.[a-z]|function\([a-z],[a-z],[a-z]\))', re.I)
# FP: shell/CI variable substitution — valore è una variabile, non un segreto hardcoded
# Matches: "$VAR", "${VAR}", "${{VAR}}", "${{{{ secrets.VAR }}}}", "$(varName)"
_HC_SHELL_VAR = re.compile(
    r"[\"'][^\"']*(?:"
    r"\$\{[\{]?\w+[\}]?\}"       # ${VAR} o ${{VAR}}
    r"|\$[A-Z_][A-Z0-9_]*"       # $AGENT_PASSWORD
    r"|\$\(\w+\)"                # $(agentPassword)
    r"|secrets\.\w+"             # GitHub Actions: secrets.MY_SECRET
    r"|\%\([^)]+\)s"             # Python % format: %(var)s
    r"|\{\{[^}]+\}\}"            # Jinja/Ansible: {{ var }}
    r")[^\"']*[\"']",
    re.I,
)
# FP: valore è solo un'espressione di variabile shell non wrapped in quotes
_HC_SHELL_VAR_BARE = re.compile(
    r'="\$\{[\{]?\w+[\}]?\}"'     # ="${{VAR}}" or ="${VAR}"
    r'|="\$[A-Z_][A-Z0-9_]*"'    # ="$VAR"
    r'|="\$\(\w+\)"',            # ="$(var)"
    re.I,
)
# FP: user input prompts — getpass/input/readline prompting for password (non è hardcoded)
_HC_USER_PROMPT = re.compile(
    r"(?:getpass\.getpass\s*\("
    r"|getpass\s*\("
    r"|input\s*\([^)]*(?:password|token|key|secret|credential)"
    r"|rl\.question\s*\("
    r"|prompt\s*\([^)]*(?:password|key|token)"
    r"|readline\s*\([^)]*(?:password|key|token)"
    r"|inquirer\."
    r"|click\.prompt\s*\()",
    re.I,
)
# FP: UI/error messages (l'assignment è di un messaggio, non di una credenziale)
_HC_ERROR_MSG = re.compile(
    r"[\"'](?:"
    r"(?:Invalid|Wrong|Incorrect|Bad)\s+(?:credentials?|password|token|api\s*key)"
    r"|(?:Password|Token|Key|Secret)\s+(?:is\s+)?(?:invalid|incorrect|wrong|expired|missing)"
    r"|(?:Authentication|Auth)\s+(?:failed|error|required)"
    r"|(?:Please\s+enter|Enter\s+your|Provide\s+a)\s+(?:password|token|api\s*key)"
    r"|Update\s+(?:user.s?\s+)?password"
    r"|Reset\s+password"
    r")[\"']",
    re.I,
)
# FP: mock/test credentials con prefisso "test-WORD-key/token"
_HC_TEST_CRED = re.compile(
    r"[\"'](?:test|mock|fake|dummy|sample)[-_]\w+[-_](?:key|token|secret|api|password)[\"']"
    r"|[\"'](?:key|token|secret|api|password)[-_](?:test|mock|fake|dummy|sample)[-_]\w+[\"']",
    re.I,
)
# FP: template/placeholder in curly braces — {Client Secret}, {OPTIONAL_CLIENT_SECRET}, {API KEY}
_HC_CURLY_PLACEHOLDER = re.compile(
    r'[\"\']\{[^}]+\}[\"\']'
    r'|[\"\']\<[^>]+\>[\"\']',  # also <YOUR_KEY>
    re.I,
)
# FP: env var name prefix as value — "env:OPENAI_API_KEY", "ENV_VAR_NAME"
_HC_ENV_PREFIX = re.compile(
    r'[\"\'](?:env:|ENV_|process\.env\.|\$ENV\{|\$\{ENV)\w+[\"\']?'
    r'|[\"\'](?:GOOGLE_APPLICATION_CREDENTIALS|AWS_(?:ACCESS|SECRET)_KEY|'
    r'OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|GITLAB_TOKEN|'
    r'STRIPE_(?:SECRET|API|PUBLISHABLE)_KEY|HUGGING_FACE_TOKEN|'
    r'\w*_API_KEY|\w*_SECRET|\w*_TOKEN)[\"\']',
    re.I,
)
# FP: triple dots / ellipsis placeholder — "tvly-...", "sk-..."
_HC_ELLIPSIS = re.compile(r'[\"\'][^\"\']*\.\.\.[^\"\']*[\"\']', re.I)
# FP: i18n locale file
_HC_I18N_FILE = re.compile(
    r'(?:locales?[/\\]|i18n[/\\]|translations?[/\\]|lang[/\\]|messages[/\\]|'
    r'\.lang\.[a-z]+$|\bzh-(?:Hans|Hant|CN|TW)\b|\b(?:fr-FR|en-US|es-ES|de-DE|ja-JP|ko-KR|fa-IR|ar-SA)\b)',
    re.I,
)
# FP: valore con caratteri non-ASCII (CJK/Arabic/Cyrillic) = i18n string
_HC_NONASCII_VAL = re.compile(
    r'[\"\'][^\"\']*[一-鿿぀-ヿ؀-ۿЀ-ӿ][^\"\']*[\"\']',
)
# FP: console.log / print() debug — non è assignment di credenziale
_HC_DEBUG_LOG = re.compile(
    r'(?:console\.(?:log|info|debug|warn|error)|'
    r'print\s*\(|printf\s*\(|fmt\.Print\w*\(|'
    r'logger\.\w+\s*\(|log\.\w+\s*\(|'
    r'process\.stdout\.write|sys\.stdout\.write)',
    re.I,
)
# FP: string compare (.startsWith/.includes/.contains/.indexOf with credential string)
_HC_STR_COMPARE = re.compile(
    r'\.(?:startsWith|endsWith|includes|contains|indexOf|search|match)\s*\('
    r'|line\.startswith\s*\('
    r'|(?:in|==|!=|===)\s*[\"\'][^\"\']*(?:_API_KEY|_TOKEN|_SECRET|_PASSWORD)',
    re.I,
)
# FP: comment after value indicating "Replace/TODO/Change"
_HC_REPLACE_COMMENT = re.compile(
    r'(?://|#|\*).*(?:Replace\s+with|Replace\s+this|TODO|FIXME|change\s+(?:after|me)|'
    r'your\s+(?:actual|real)\s+(?:key|token|secret)|substitute|placeholder)',
    re.I,
)
# FP: variable name as value (case-insensitive substring match in value)
# Es: apiKey: 'tallyApiKey' / TALLY_API_KEY: 'tallyApiKey'
_HC_VARNAME_AS_VAL_LOOSE = re.compile(
    r'(?P<key>(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|'
    r'auth[_-]?token|password|secret[_-]?key|app[_-]?id))\s*[=:]\s*'
    r'[\"\'](?:[\w-]*(?P=key)[\w-]*|[\w-]*(?:Key|Secret|Token|Password)[\w-]*)[\"\']',
    re.I,
)
# FP: literal "no-auth-required", "default-...", "optional-...", "readonly", "default_client", "anonymous"
_HC_NO_AUTH_LITERAL = re.compile(
    r'[\"\'](?:no[-_]auth(?:[-_]required)?|none|null|undefined|'
    r'default[-_]\w+|optional[-_]\w+|public[-_]\w+|anonymous|'
    r'readonly|read[-_]only|guest|N/A|TBD|unset|disabled|'
    r'YOURPASS|MYPASS|TEST|PROD|LOCAL|DEV|'
    r'replace[-_]me|fillme|fill[-_]me|enter[-_]\w+|'
    r'\*{3,}|\*+REDACTED\*+|\[REDACTED\]|\[HIDDEN\]|'
    r'redacted|hidden|obfuscated)[\"\']',
    re.I,
)
# FP: URL come valore (http/https/ws/file scheme)
_HC_URL_VALUE = re.compile(
    r'[\"\'](?:https?|wss?|ftp|file|s3|postgres|mongodb|mysql|redis|amqp)://[^\"\']+[\"\']',
    re.I,
)
# FP: file path locale (Windows o Unix) come valore
_HC_FILE_PATH = re.compile(
    r'[\"\'](?:[A-Z]:[\\\\/]|/(?:home|usr|etc|var|opt|tmp|root)/|~/|\.\./?|\./)[^\"\']+'
    r'\.(?:json|pem|key|crt|cer|p12|pfx|env|ini|cfg|toml|yaml|yml)[\"\']',
    re.I,
)
# FP: type description as value — 'string (hashed)', 'boolean (default: true)', 'array of...'
_HC_TYPE_DESC_VAL = re.compile(
    r'[\"\'](?:string|number|boolean|integer|array|object|float|double|null|undefined)'
    r'\s*(?:\([^)]+\))?[\"\']'
    r'|[\"\']\(default:\s*[^)]+\)[\"\']',
    re.I,
)
# FP: UI prompt message — "Enter your X:", "Provide a Y", "Type the password"
_HC_UI_PROMPT_MSG = re.compile(
    r'[\"\'](?:Enter|Type|Input|Provide|Send|Insert|Submit)\s+(?:your|a|the|new)?\s*'
    r'(?:password|api[\s_-]?key|token|secret|credential|client[\s_-]?secret)[^\"\']*[\"\']',
    re.I,
)
# FP: function call returning credential — await question(), await prompt(), readline.question()
_HC_FUNC_CALL_VAL = re.compile(
    r'(?:await\s+)?(?:question|prompt|readline|getInput|inquirer\.\w+|'
    r'this\.promptUser|asksecret|askPassword|getCredential|fetchSecret)\s*\(',
    re.I,
)
# FP: string concat con variabile (PGPASSWORD=" + var)
_HC_STR_CONCAT_VAR = re.compile(
    r'[\"\'][^\"\']*=[\"\']\s*\+\s*\w'
    r'|[\"\'][^\"\']*[\"\']\s*\+\s*\w+(?:_password|_key|_secret|_token)',
    re.I,
)
# FP: SG.xxx, sk-xxx, pk-xxx, ph-xxx con xxx come placeholder
_HC_PROVIDER_PLACEHOLDER = re.compile(
    r'[\"\'](?:SG|sk|pk|ph|gh|xox[bp])[-._](?:xxx|XXX|test|sample|example|placeholder|fake|dummy)'
    r'|[\"\'][^\"\']+\((?:optional|required|placeholder)\)[\"\']',
    re.I,
)
# FP: dictionary password words common in test/dev (broader)
_HC_COMMON_DICT_PWD = re.compile(
    r'[\"\'](?:postgres|admin|root|toor|password|qwerty|letmein|welcome|'
    r'jasperadmin|kibanapass|administrator|operator|guest)[\"\']\s*$',
    re.I,
)
# FP: function default params (testuser/testpass)
_HC_FUNC_DEFAULT_TEST = re.compile(
    r'function\s+\w*[Tt]est\w*\s*\([^)]*=\s*[\"\']'
    r'|async\s+\w*[Tt]est\w*\s*\([^)]*=\s*[\"\']'
    r'|def\s+\w*test\w*\s*\([^)]*=\s*[\"\']'
    r'|\(\s*\w+\s*=\s*[\"\']test\w+[\"\']',
    re.I,
)
# FP: error message containing env var "X_API_KEY environment variable is missing"
_HC_ENV_VAR_ERROR_MSG = re.compile(
    r'[\"\'](?:The|A)\s+\w*(?:_API_KEY|_TOKEN|_SECRET|_PASSWORD)\s+'
    r'(?:environment\s+)?(?:variable|env)\s+(?:is|was)\s+(?:missing|empty|not|undefined)',
    re.I,
)
# FP: route/path URL value
_HC_ROUTE_PATH = re.compile(
    r'[\"\']/[a-z][a-z0-9-]*(?:/[a-z][a-z0-9-]*)+[\"\']'
    r'|[\"\']/(?:forgot|reset|change|login|logout|signup|register|verify)-?\w*[\"\']',
    re.I,
)
# FP: Pydantic Model() example
_HC_PYDANTIC_EXAMPLE = re.compile(
    r'\b(?:Model|BaseModel|TestModel|ExampleModel|MyModel)\s*\(\s*\w+\s*=\s*[\"\']IAm',
    re.I,
)
# FP: string split/parse on credential string
_HC_STRING_PARSE = re.compile(
    r'\.split\s*\(\s*[\"\'][^\"\']+(?::|=)[\"\']'
    r'|line\.split\s*\(',
    re.I,
)
# FP: example/sample variable name suffix
_HC_EXAMPLE_VAR = re.compile(
    r'\b\w*_(?:example|sample|test|mock|fake|dummy|demo)\s*=',
    re.I,
)
# FP: imperative phrase (placeholder text)
_HC_IMPERATIVE_PLACEHOLDER = re.compile(
    r'[\"\'](?:change[-\s_]this(?:[-\s_]in[-\s_]\w+)?|'
    r'set[-\s_]this[-\s_]\w+|'
    r'do[-\s_]not[-\s_]\w+|'
    r'I[-\s_]?am[-\s_]?sensitive|'
    r'use[-\s_]your[-\s_]own)[\"\']?',
    re.I,
)
# VP: prefix_long_random — provider-style: prefix + alphanum 20+ chars
_HC_PREFIXED_RANDOM = re.compile(
    r'[\"\'](?:[a-z]{2,8}[-_])(?:[A-Za-z0-9_-]{20,})[\"\']',
)
# VP: random alphanum mixed-case 24+ chars (no provider prefix)
_HC_LONG_MIXED = re.compile(
    r'[\"\'](?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])[A-Za-z0-9]{24,}[\"\']',
)
# VP: Gmail-like app password (16 chars in groups of 4)
_HC_GMAIL_APP_PWD = re.compile(
    r'[\"\']\w{4}\s\w{4}\s\w{4}\s\w{4}[\"\']',
)
# VP: Google OAuth client secret format
_HC_GOOGLE_OAUTH = re.compile(r'GOCSPX-[A-Za-z0-9_-]{20,}')
# VP: real password con special chars + alphanum + 8+ chars (suggerisce password reale)
_HC_REAL_PASSWORD = re.compile(
    r'(?:password|passwd|pwd)\s*[=:]\s*[\"\']'
    r'(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9!@#$%^&*])[A-Za-z0-9!@#$%^&*]{8,}'
    r'[\"\']',
    re.I,
)
# FP: client.new(access_token: "My Access Token") — example doc string (Title Case)
_HC_TITLE_CASE_PLACEHOLDER = re.compile(
    r'[\"\'](?:My\s+(?:Access\s+Token|API\s+Key|Secret|Password)|'
    r'Your\s+\w+|Sample\s+\w+|Example\s+\w+|Demo\s+\w+)[\"\']',
    re.I,
)
# VP marker: hex hash 32+ chars
_HC_HEX_HASH = re.compile(r'[\"\'][0-9a-f]{32,}[\"\']', re.I)
# VP marker: base64 24+ chars con + / =
_HC_BASE64_LIKE = re.compile(r'[\"\'][A-Za-z0-9+/]{24,}={0,2}[\"\']')
# VP marker: long random alphanum 20+ chars senza pattern dizionario
_HC_LONG_RANDOM = re.compile(r'[\"\'][A-Za-z0-9_-]{20,}[\"\']')

# Dictionary words common in non-secret values
_HC_DICT_WORDS = re.compile(
    r'(?:password|admin|root|user|test|demo|sample|example|default|null|none|'
    r'localhost|secret|token|key|api|client|server|application|credentials?|'
    r'database|connection|string|value|placeholder|todo|fixme|xxx|abc|123)',
    re.I,
)

# ── Nuove HC-FP da blind-review (2026-05-06) ────────────────────────────────
# FP: PostHog public client key (phc_ prefix) — è pubblica per design (telemetria browser)
_HC_POSTHOG_PUBLIC = re.compile(r'phc_[A-Za-z0-9]{30,}', re.I)
# FP: path/file in repo contiene keyword "vulnerable", "honeypot", "secret-leak", "damn-vulnerable"
_HC_INTENTIONAL_VULN_PATH = re.compile(
    r'(?:vulnerable[-_]|honeypot|secret[-_]leak|damn[-_]vulnerable|'
    r'mcp_vuln|/vuln/|hardcoded[-_]secret)',
    re.I,
)
# FP: explicit fake marker in comment near value (`// fake`, `# fake`, `// not real`, `# placeholder`)
_HC_FAKE_COMMENT_MARKER = re.compile(
    r'(?:^|[^a-z])(?:fake|not\s+real|placeholder|dummy|stub|todo[:\s]|change\s+(?:me|in\s+production)|do[-_]not[-_]use)',
    re.I,
)
# FP: explicit dev/staging marker in value
_HC_DEV_PROD_MARKER = re.compile(
    r'[\"\'][^\"\']*(?:dev[-_]secret|do[-_]not[-_]use|change[-_]me|in[-_]production|'
    r'placeholder|temporary|temp[-_]password|notmy|notreal|secure[-_]password)'
    r'[^\"\']*[\"\']',
    re.I,
)
# FP: known fake base64 patterns ("not my real password", etc.)
_HC_BASE64_FAKE = re.compile(
    r'[\"\'](?:bm90IG15IHJlYWwg|cGxhY2Vob2xkZXI=|c2FtcGxl|ZHVtbXk=|ZmFrZQ==)',
    re.I,
)
# FP: DefinitelyTyped / @types path
_HC_TYPES_PATH = re.compile(r'(?:^|[/\\])(?:@types|types)[/\\]', re.I)
# FP: SecurePassword123!-style obvious sample passwords (camelcase compound)
_HC_OBVIOUS_SAMPLE_PWD = re.compile(
    r'[\"\'](?:SecurePassword|StrongPassword|MyPassword|TestPassword|AdminPassword|'
    r'Password123|Admin123|Root123|Welcome123|ChangeMe|P@ssw0rd|Passw0rd|hunter2)'
    r'[!\d]*[\"\']',
    re.I,
)

def hc_rules_hardcoded_credential(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    file = f.get("file", "")
    code = extract_code(f.get("description", ""))

    # ── HC-FP da blind-review: priorità ALTA (prima dei VP markers) ──
    # Path con keyword vuln intenzionale (damn-vulnerable, honeypot, secret-leak)
    if _HC_INTENTIONAL_VULN_PATH.search(file):
        return "HC-FP", "intentionally_vulnerable_path_keyword"
    # DefinitelyTyped / @types
    if _HC_TYPES_PATH.search(file):
        return "HC-FP", "definitely_typed_or_types_directory"
    # Base64 di stringhe note ("not my real password" etc.)
    if _HC_BASE64_FAKE.search(code):
        return "HC-FP", "base64_explicitly_fake_string"
    # PostHog public client key (telemetria, by design pubblica)
    if _HC_POSTHOG_PUBLIC.search(code):
        return "HC-FP", "posthog_public_client_key_by_design"
    # Marker espliciti dev/placeholder/changeme nel valore
    if _HC_DEV_PROD_MARKER.search(code):
        return "HC-FP", "explicit_dev_or_placeholder_marker_in_value"
    # Sample password riconoscibili (SecurePassword123!, P@ssw0rd, hunter2, ChangeMe...)
    if _HC_OBVIOUS_SAMPLE_PWD.search(code):
        return "HC-FP", "obvious_sample_password_pattern"
    # Comment marker accanto al valore ("// fake", "# placeholder", "// change in production")
    if _HC_FAKE_COMMENT_MARKER.search(code):
        return "HC-FP", "explicit_fake_or_placeholder_comment_marker"

    # VP prioritario: chiave provider riconoscibile
    if _PROVIDER_KEY.search(code):
        return "HC-VP", "provider_key_format_recognized"

    # FP: linea commentata (# export KEY="value", // const KEY = "value", * apiKey: "value")
    if _HC_COMMENT_LINE.search(code):
        return "HC-FP", "commented_out_credential"
    # FP: varname-as-value
    if _HC_VAR_AS_VAL.search(code):
        return "HC-FP", "env_var_name_used_as_own_value"
    # FP: placeholder (substring match)
    if _HC_PLACEHOLDER.search(code):
        return "HC-FP", "obvious_placeholder_value"
    # FP: your-xxx prefix (your-api-key, your-secret-key, etc.)
    if _HC_YOUR_PREFIX.search(code):
        return "HC-FP", "your_prefix_placeholder"
    # FP: type annotation
    if _HC_ANNOTATION_FP.search(code):
        return "HC-FP", "type_annotation_not_value"
    # FP: debug/test/example file
    if re.search(r"debug[-_]token|\.example\.|\.sample\.", file, re.I):
        return "HC-FP", "debug_or_example_file"
    # FP: bundle JS/minified
    if _HC_BUNDLE_JS.search(code):
        return "HC-FP", "minified_bundle_js"
    # FP: shell/CI variable substitution (valore è una variabile non un segreto)
    if _HC_SHELL_VAR.search(code):
        return "HC-FP", "shell_ci_variable_substitution"
    if _HC_SHELL_VAR_BARE.search(code):
        return "HC-FP", "shell_ci_variable_substitution_bare"
    # FP: prompt utente per password (getpass/input) → non è hardcoded
    if _HC_USER_PROMPT.search(code):
        return "HC-FP", "user_input_prompt_not_hardcoded"
    # FP: messaggio di errore UI (l'assegnazione è di un messaggio, non un segreto)
    if _HC_ERROR_MSG.search(code):
        return "HC-FP", "ui_error_message_not_credential"
    # FP: mock/test credential con prefisso "test-WORD-key"
    if _HC_TEST_CRED.search(code):
        return "HC-FP", "test_mock_credential_prefix"
    # FP: i18n locale file
    if _HC_I18N_FILE.search(file):
        return "HC-FP", "i18n_locale_file"
    # FP: valore con char CJK/Arabic/Cyrillic = i18n string
    if _HC_NONASCII_VAL.search(code):
        return "HC-FP", "i18n_string_non_ascii_chars"
    # FP: template placeholder in {curly} or <angle>
    if _HC_CURLY_PLACEHOLDER.search(code):
        return "HC-FP", "curly_or_angle_template_placeholder"
    # FP: env var name as value
    if _HC_ENV_PREFIX.search(code):
        return "HC-FP", "env_var_name_or_prefix_as_value"
    # FP: ellipsis ... in value
    if _HC_ELLIPSIS.search(code):
        return "HC-FP", "ellipsis_placeholder_in_value"
    # FP: console.log / print debug
    if _HC_DEBUG_LOG.search(code):
        return "HC-FP", "debug_log_or_print_statement"
    # FP: string comparison .startsWith / .includes
    if _HC_STR_COMPARE.search(code):
        return "HC-FP", "string_comparison_or_check"
    # FP: comment "Replace with" / TODO
    if _HC_REPLACE_COMMENT.search(code):
        return "HC-FP", "comment_indicates_replace_or_todo"
    # FP: varname-as-value loose (apiKey: 'tallyApiKey')
    if _HC_VARNAME_AS_VAL_LOOSE.search(code):
        return "HC-FP", "varname_as_value_loose_match"
    # FP: literal no-auth/default/readonly
    if _HC_NO_AUTH_LITERAL.search(code):
        return "HC-FP", "literal_no_auth_or_default_value"
    # FP: title case placeholder ("My Access Token")
    if _HC_TITLE_CASE_PLACEHOLDER.search(code):
        return "HC-FP", "title_case_placeholder_doc_example"
    # FP: URL come valore
    if _HC_URL_VALUE.search(code):
        return "HC-FP", "url_as_value_not_credential"
    # FP: file path locale come valore
    if _HC_FILE_PATH.search(code):
        return "HC-FP", "local_file_path_as_value"
    # FP: type description ('string', 'boolean (default: true)')
    if _HC_TYPE_DESC_VAL.search(code):
        return "HC-FP", "type_description_as_value"
    # FP: UI prompt message ("Enter your password:")
    if _HC_UI_PROMPT_MSG.search(code):
        return "HC-FP", "ui_prompt_message_text"
    # FP: function call value (prompt/question/getInput)
    if _HC_FUNC_CALL_VAL.search(code):
        return "HC-FP", "function_call_user_input_not_hardcoded"
    # FP: string concat with variable
    if _HC_STR_CONCAT_VAR.search(code):
        return "HC-FP", "string_concat_with_runtime_variable"
    # FP: provider placeholder (SG.xxx, sk-test, ...(optional))
    if _HC_PROVIDER_PLACEHOLDER.search(code):
        return "HC-FP", "provider_prefix_with_placeholder_value"
    # FP: common dict password (postgres, admin, jasperadmin) on standalone line
    if _HC_COMMON_DICT_PWD.search(code):
        return "HC-FP", "common_dictionary_password_or_test_default"
    # FP: function default test creds
    if _HC_FUNC_DEFAULT_TEST.search(code):
        return "HC-FP", "function_default_test_credential"
    # FP: error message containing env var name
    if _HC_ENV_VAR_ERROR_MSG.search(code):
        return "HC-FP", "error_message_env_var_missing"
    # FP: route path
    if _HC_ROUTE_PATH.search(code):
        return "HC-FP", "url_route_path_not_credential"
    # FP: Pydantic example
    if _HC_PYDANTIC_EXAMPLE.search(code):
        return "HC-FP", "pydantic_model_example_value"
    # FP: string parse/split
    if _HC_STRING_PARSE.search(code):
        return "HC-FP", "string_split_or_parse_operation"
    # FP: example var suffix
    if _HC_EXAMPLE_VAR.search(code):
        return "HC-FP", "variable_name_with_example_suffix"
    # FP: imperative placeholder ("change-this-in-production", "IAmSensitive")
    if _HC_IMPERATIVE_PLACEHOLDER.search(code):
        return "HC-FP", "imperative_phrase_placeholder"

    # VP markers (after all FP checks)
    # Google OAuth client secret
    if _HC_GOOGLE_OAUTH.search(code):
        return "HC-VP", "google_oauth_client_secret_format"
    # Gmail app password format
    if _HC_GMAIL_APP_PWD.search(code):
        return "HC-VP", "gmail_app_password_format"
    # Hex hash 32+ chars è VP forte indipendentemente dal contesto
    if _HC_HEX_HASH.search(code):
        return "HC-VP", "hex_hash_32plus_chars"
    # Provider prefix + long random
    if _HC_PREFIXED_RANDOM.search(code):
        return "HC-VP", "provider_prefix_with_long_random_value"
    # Long mixed-case alphanum 24+
    if _HC_LONG_MIXED.search(code):
        return "HC-VP", "long_mixed_case_alphanumeric_secret"
    # Base64-like: serve almeno un carattere non-alphanum (+/=) per evitare false positive
    m_b64 = _HC_BASE64_LIKE.search(code)
    if m_b64 and re.search(r'[+/=]', m_b64.group()):
        return "HC-VP", "base64_encoded_secret"
    # Password with special chars + length
    if _HC_REAL_PASSWORD.search(code):
        return "HC-VP", "password_with_special_chars_and_length"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: sql-injection
# ═══════════════════════════════════════════════════════════════════════════════

_SQL_CONCAT = re.compile(
    r"""(?:
        [\+]\s*(?:params\.|args\.|input\.|req\.)|   # string concat con params
        f["\'].*?\{(?:params|args|input|req)\.|       # f-string con params
        %\s*(?:params\.|args\.|input\.|req\.)|        # % format
        \.format\(.*?(?:params|args|input)            # .format()
    )""",
    re.I | re.X,
)

_SQL_SAFE_PARAM = re.compile(r"(?:\?\s*[,)\"\'\s]|\?\s*$|:[\w]+\b|\$\d+)", re.I)

# FP: f-string senza variabili (nessun {}) in contesto execute → SQL statico
_SQL_FSTR_NO_VARS = re.compile(r"execute\s*\([^)]*f['\"][^{\"'\n]+['\"]", re.I)

# FP: Neo4j session.run con dizionario parametri → query parametrizzata
_SQL_NEO4J_PARAM = re.compile(r"session\.run\s*\([^,]+,\s*[\{\[]|\{[^}]+\}\s*\)", re.I)

# FP: concatenazione con variabile di ambiente (non user-controlled)
_SQL_ENV_VAR_CONCAT = re.compile(r"process\.env\.\w+\s*\+|\+\s*process\.env\.\w+", re.I)

# VP: .format() in contesto execute → format string injection (nessun parametro sicuro)
_SQL_FORMAT_INJECT = re.compile(r"execute\s*\([^)]*\.format\s*\(", re.I)

# FP: variabile istanza (self.xxx / this.xxx) → non user-controlled
# Fix: [^{]* invece di [^\"']* per gestire SQL con virgolette interne
# Fix: f[\"']{1,3} per gestire triple-quote f-string (f""" / f''')
_SQL_SELF_ONLY = re.compile(r"f[\"']{1,3}[^{]*\{self\.[^}]+\}", re.I)
_SQL_NON_SELF_VAR = re.compile(r"f[\"']{1,3}[^{]*\{(?!self\.|this\.|__)\w", re.I)

# VP: f-string in execute() con variabili tipicamente user-controlled in MCP
_SQL_USER_VAR = re.compile(
    r"execute\s*\([^{]*f[\"']{1,3}[^{]*\{"
    r"(?:table|database|db|schema|sql|query|column|field|proc|"
    r"uuid|qb|path|user|view|index|catalog|ns|namespace)[_a-z0-9]*\}",
    re.I,
)

# VP: execute( con f-string triple-quote (agentindex: session.execute(text(f"""...)
_SQL_FSTR_TRIPLE = re.compile(
    r"execute\s*\([^)]*f(?:\"\"\"|'{3})",
    re.I,
)

# FP: execute( con triple-quote NON-f-string (static SQL)
_SQL_STATIC_TRIPLE = re.compile(
    r"execute\s*\(\s*(?:text\s*\(\s*)?(?:\"\"\"|'{3})(?!.*\bf[\"'])",
    re.I,
)

# FP: snippet troppo corto per classificare — qualsiasi execute/run/query( senza arg visibile
_SQL_BARE_CALL = re.compile(
    r"(?:execute|run|query|exec)\s*\(\s*$",
    re.I,
)

def hc_rules_sql_injection(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    file = f.get("file", "")
    if _TEST_FILE.search(file) or re.search(r"_test\.\w+$|\.test\.[jt]s$", file, re.I):
        return "HC-FP", "test_file"
    code = extract_code(f.get("description", ""))

    # FP: snippet incompleto — qualsiasi execute/run( senza argomento visibile
    if _SQL_BARE_CALL.search(code):
        return "HC-FP", "incomplete_snippet_no_argument_visible"

    # FP: triple-quote NON-f-string (SQL statico)
    if _SQL_STATIC_TRIPLE.search(code) and not _SQL_FSTR_TRIPLE.search(code):
        return "HC-FP", "static_triple_quote_sql_not_dynamic"

    # FP: f-string senza variabili (hardcoded, nessun {})
    if _SQL_FSTR_NO_VARS.search(code) and not re.search(r"\{", code):
        return "HC-FP", "fstring_without_variables_static_sql"

    # FP: concatenazione con variabile di ambiente (non user-controlled)
    if _SQL_ENV_VAR_CONCAT.search(code):
        return "HC-FP", "env_var_concat_not_user_controlled"

    # FP: parametrizzato senza concatenazione
    if _SQL_SAFE_PARAM.search(code) and not re.search(r"[\+]|\%s|f[\"']{1,3}.*\{", code):
        return "HC-FP", "properly_parameterized_query"

    # FP: Neo4j session.run con dizionario parametri
    if _SQL_NEO4J_PARAM.search(code) and not _SQL_NON_SELF_VAR.search(code):
        return "HC-FP", "neo4j_session_run_with_parameter_dict"

    # FP: solo attributi di istanza nell'f-string (self.xxx / this.xxx)
    if _SQL_SELF_ONLY.search(code) and not _SQL_NON_SELF_VAR.search(code):
        return "HC-FP", "fstring_with_instance_attribute_only"

    # VP: f-string triple-quote in execute() (query dinamica su più righe)
    if _SQL_FSTR_TRIPLE.search(code):
        return "HC-VP", "fstring_triple_quote_dynamic_sql_in_execute"

    # VP: .format() in execute → format string SQL injection
    if _SQL_FORMAT_INJECT.search(code):
        return "HC-VP", "format_string_sql_injection_in_execute"

    # VP: concatenazione stringa con input utente (params./args.)
    if _SQL_CONCAT.search(code):
        return "HC-VP", "string_concatenation_with_user_input"

    # VP: f-string in execute() con variabili MCP user-controlled (table, db, sql...)
    if _SQL_USER_VAR.search(code):
        return "HC-VP", "fstring_with_user_controlled_table_or_db_var"

    # VP: qualsiasi f-string non-self in execute()/run() → probabilmente user-controlled
    if _SQL_NON_SELF_VAR.search(code) and re.search(r"(?:execute|run)\s*\(", code, re.I):
        return "HC-VP", "fstring_non_self_var_in_execute_likely_user_controlled"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: dangerous-tool-handler
# ═══════════════════════════════════════════════════════════════════════════════
# NOTA: code snippet = firma di funzione (non body). Quasi tutti FP.
# VP: funzioni che wrappano exec/shell direttamente visibile dal nome/firma.

_DTH_EXEC_WRAPPER = re.compile(
    r"(?:run_command|exec_command|shell_exec|execute_command|run_shell"
    r"|run_process|execute_shell|spawn_process|run_cmd|exec_cmd"
    r"|execute_system|system_command|shell_command|run_bash"
    r"|run_applescript|run_adb|run_jmeter|run_kicad"
    r"|ssh_execute|execute_ssh|run_ssh|ssh_exec"
    r"|execute_powershell|run_powershell|ps_execute"
    r"|wfuzz_execute|nmap_execute|nuclei_execute"
    r"|parallel_execute|_execute_in_subprocess|_execute_subprocess"
    r"|_execute_analytics_subprocess|_execute_compiler|_execute_nmap)",
    re.I,
)
# VP: file path indicates offensive security/red team tool
_DTH_OFFENSIVE_FILE = re.compile(
    r"(?:kali_|metasploit|nmap_mcp|wfuzz|nuclei|gobuster|hydra|hashcat|"
    r"sqlmap|aircrack|sec-\w+|red_team|redteam|offensive|"
    r"penetration|pentest|exploit_|payload_|reverse_shell)",
    re.I,
)
# VP: function signature has shell command parameter (cmd|command|commands: str|list[str])
_DTH_CMD_PARAM = re.compile(
    r"def\s+\w*(?:execute|run)\w*\s*\([^)]*"
    r"(?:cmd|command|commands|shell_cmd|bash_cmd|args)\s*:\s*"
    r"(?:str|List\[str\]|list\[str\]|tuple|bytes)",
    re.I,
)
# VP: ssh hostname+command params
_DTH_SSH_PARAMS = re.compile(
    r"def\s+\w*(?:execute|exec|ssh)\w*\s*\([^)]*"
    r"hostname\s*:\s*str[^)]*command\s*:\s*str",
    re.I,
)
# FP: dispatcher / wrapper di MCP tools — solo orchestration
_DTH_MCP_DISPATCHER = re.compile(
    r"(?:def\s+_call_mcp_tool|"
    r"def\s+callMCPTool|"
    r"async\s+function\s+callMCPTool|"
    r"def\s+_get_calling_command|"
    r"def\s+_record_\w+|"
    r"def\s+list_\w+_models|"
    r"def\s+list_running_\w+|"
    r"def\s+_get_\w+_id|"
    r"def\s+_get_runtime_id|"
    r"def\s+_truncate_\w+|"
    r"def\s+_format_\w+|"
    r"def\s+_serialize_\w+|"
    r"def\s+_deserialize_\w+|"
    r"def\s+_install_step|"
    r"def\s+_execute_installation_step|"
    r"def\s+_execute_step|"
    r"def\s+_run_step|"
    r"def\s+recall_for_file_\w+|"
    r"def\s+\w+_run\s*\([^)]*\)\s*->\s*\w*Result)",
    re.I,
)
# FP: hook/result functions
_DTH_HOOK_RESULT = re.compile(
    r"->\s*(?:HookResult|TestResult|ToolResult|RunArtifacts|ExecutionResult)\s*:",
    re.I,
)
# FP: generic MCP handler/entrypoint — non esegue comandi direttamente
# NOTA: usa \s+ invece di spazi (re.X strips literal spaces)
_DTH_GENERIC_HANDLER = re.compile(
    r"(?:def\s+run_stdio"
    r"|def\s+handle_"
    r"|async\s+def\s+call_tool"
    r"|def\s+_handle_"
    r"|def\s+_run\s*\("
    r"|def\s+run\s*\("
    r"|async\s+def\s+run\s*\("
    r"|async\s+def\s+run_\w+\s*\("
    r"|def\s+run_\w+\s*\("
    r"|def\s+call_\w+\s*\("
    r"|async\s+def\s+call_\w+\s*\("
    r"|def\s+_run_\w+\s*\("
    r"|async\s+def\s+_run_\w+\s*\("
    r"|def\s+execute_\w+\s*\("
    r"|async\s+def\s+execute_\w+\s*\("
    r"|def\s+run_json_command\s*\("
    r"|def\s+run_task\s*\("
    r"|def\s+run_server\s*\("
    r"|def\s+_run_subprocess\s*\("
    r"|async\s+def\s+run_browser\s*\("
    r"|def\s+run_health\s*\("
    r"|def\s+_handle_\w+"
    r"|def\s+call_tool\s*\()",
    re.I,
)

def hc_rules_dangerous_tool_handler(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    file = f.get("file", "")
    if _TEST_FILE.search(file):
        return "HC-FP", "test_file"
    code = extract_code(f.get("description", ""))

    # VP forte: file di tool offensive (kali, nmap, metasploit)
    if _DTH_OFFENSIVE_FILE.search(file):
        if re.search(r"def\s+\w*(?:execute|run)\w*\s*\(", code, re.I):
            return "HC-VP", "offensive_security_tool_file_with_exec_func"
    # VP: funzione esplicitamente un wrapper di exec/shell
    if _DTH_EXEC_WRAPPER.search(code):
        return "HC-VP", "explicit_shell_exec_wrapper"
    # VP: signature ssh hostname + command
    if _DTH_SSH_PARAMS.search(code):
        return "HC-VP", "ssh_hostname_command_signature"
    # VP: signature execute/run con cmd/command/commands param tipizzato
    if _DTH_CMD_PARAM.search(code):
        return "HC-VP", "exec_function_with_command_parameter"

    # FP: dispatcher MCP / introspection / format helpers
    if _DTH_MCP_DISPATCHER.search(code):
        return "HC-FP", "mcp_dispatcher_or_helper_no_shell_exec"
    # FP: hook/result return type
    if _DTH_HOOK_RESULT.search(code):
        return "HC-FP", "hook_or_result_function_no_shell_exec"
    # FP: generic MCP handler (run_stdio, call_tool, handle_X) — non esegue comandi
    if _DTH_GENERIC_HANDLER.search(code):
        return "HC-FP", "generic_mcp_handler_not_shell_exec"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: path-traversal-static
# ═══════════════════════════════════════════════════════════════════════════════

_PT_USER_INPUT = re.compile(
    r"""(?:filepath\.Join|path\.join|os\.path\.join|path\.resolve|
         path\.normalize)\s*\(
    (?:[^)]*?(?:params\.|args\.|input\.|arguments\.|req\.body\.|req\.query\.)|
       [^)]*?\.\.\.|[^)]*?spread|[^)]*?\.\.\.args)""",
    re.I | re.X,
)

_PT_HARDCODED = re.compile(
    r"""(?:filepath\.Join|path\.join)\s*\(
    [^)]*?,\s*["\'][^"\']*["\']""",
    re.I | re.X,
)
# FP: join con estensione fissa hardcoded — il traversal è bloccato dall'estensione
# Matches + "ext" o + "prefix.ext" (qualsiasi stringa che finisce con un'estensione nota)
_PT_EXT_LIST = (
    r"json|jsonl|ndjson|yaml|yml|log|txt|sh|ts|js|go|py|toml|conf|cfg"
    r"|plist|sock|qcow2|webp|dot|gz|sql|sqlite|db|md|html|xml|csv|tsv|svg"
    r"|png|jpg|jpeg|gif|bmp|ico|tiff|tif|webp"
    r"|pdf|zip|tar|lock|ini|fail|pid|golden|tmpl|hlp|cmd|mod|info|o|so|a"
    r"|dylib|elf|bin|bat|ps1|pem|crt|key|pub|p12|pfx|der|csr"
    r"|proto|pb|wasm|class|jar|war|ear|gradle|mvn|rb|pl|lua|r|swift|kt|rs"
    r"|h|c|cpp|cs|java|scala|clj|ex|exs|erl|hrl|beam|elixir|elm|dart"
    r"|vue|jsx|tsx|scss|sass|less|css|woff|woff2|ttf|eot|otf"
    r"|env|bak|tmp|temp|test|spec|snap|meta|mmdb|counter"
    r"|npy|npz|pth|pkl|pt|h5|hdf5|onnx|faiss|safetensors|ckpt|bin|weights"
    r"|parquet|arrow|feather|avro|msgpack|ndarray|mat|dat|cache|idx"
    r"|xlsx|xls|docx|doc|pptx|ppt|odt|ods|odp"
    r"|wav|mp3|mp4|avi|mkv|mov|flac|ogg|m4a|aac|opus|webm"
    r"|tar|gz|bz2|xz|zst|lzma|7z|rar"
    r"|rds|rda|rdata|jl|ipynb|nb|Rmd"
    r"|rosbag|bag|vdb|las|pcd"
    r"|stage|raw|data|chunk|part|shard|block|record|patch|diff|delta"
)
_PT_FIXED_EXT = re.compile(
    r"(?:filepath\.Join|path\.join|os\.path\.join|path\.resolve|os\.ReadFile|os\.WriteFile)"
    r"\s*\([^)]*"
    r"\+\s*[\"'][^\"']*\.(?:" + _PT_EXT_LIST + r")[\"']",
    re.I,
)
# FP: Python f-string con estensione hardcoded: f"{var}.json" — var non può contenere .ext diverso
# Il pattern `}.ext"` (chiusura `}` seguita da `.ext` hardcoded) blocca il traversal
_PT_FIXED_EXT_FSTR = re.compile(
    r"os\.path\.join\s*\([^)]*f[\"'][^\"'/]*\}\."
    r"(?:" + _PT_EXT_LIST + r")[\"']",
    re.I,
)
# FP: f-string con suffix/prefix non-/ tra var e ext: f"{var}_meta.json", f"prefix_{var}.csv"
_PT_FSTR_WITH_SUFFIX = re.compile(
    r"(?:os\.path\.join|path\.join|filepath\.Join)\s*\([^)]*"
    r"f[\"'][^\"'/]*\{[^}]+\}[\w\-_.]*\.(?:" + _PT_EXT_LIST + r")[\"']",
    re.I,
)
# FP: f-string con prefix prima della var: f"prefix_{var}.ext"
_PT_FSTR_PREFIX_VAR = re.compile(
    r"(?:os\.path\.join|path\.join|filepath\.Join)\s*\([^)]*"
    r"f[\"'][\w\-_.]+\{[^}]+\}[^/\"']*\.(?:" + _PT_EXT_LIST + r")[\"']",
    re.I,
)
# FP: filename usa uuid/hash/random — non user-controlled
_PT_RANDOM_GEN = re.compile(
    r"(?:uuid\.uuid\d+\(\)|uuid4\(\)|random\.\w+\(\)|"
    r"hashlib\.\w+\(\)\.hexdigest|secrets\.token_\w+\(\)|"
    r"\.hex\b|hash\(\w+\)|md5\(|sha\d+\(|"
    r"\{(?:uuid|hash|random|nanoid|cuid)\w*\})",
    re.I,
)
# FP: variabile nome contiene "safe_", "sanitized_", "validated_", "escaped_", "cleaned_"
_PT_SAFE_PREFIX_VAR = re.compile(
    r"\{(?:safe_|sanitized_|validated_|escaped_|cleaned_|normalized_|stripped_)\w+\}",
    re.I,
)
# FP: variabile da split() / replace() / regex — già parsata
_PT_PARSED_VAR = re.compile(
    r"\{(?:[\w.]+\.split\([^)]*\)\[[^]]*\]|[\w.]+\.replace\([^)]*\)|"
    r"re\.sub\([^)]*\)|os\.path\.basename\(\w+\))\}",
    re.I,
)
# FP: glob pattern con extension match
_PT_GLOB_EXT = re.compile(
    r"glob\.glob\s*\(\s*os\.path\.join\s*\([^)]*\*\{?ext\}?[\"']?",
    re.I,
)
# FP: timestamp/datetime/now in filename
_PT_TIMESTAMP_BROAD = re.compile(
    r"\{(?:timestamp|datetime|now|created_at|updated_at|date_str|time_str|"
    r"ts|epoch|unix_time|iso_date)\}"
    r"|\{[\w.]+\.timestamp\(\)\}"
    r"|\{summary\[['\"]timestamp['\"]\]\}",
    re.I,
)
# FP: variabile da config/state interno (config.X, self.X, this.X, settings.X)
_PT_CONFIG_VAR = re.compile(
    r"\{(?:config|self|this|cls|state|settings|opts|options|cfg|env)\.\w+\}",
    re.I,
)
# FP: dict access interno (data['id'], data['name'])
_PT_DICT_ID = re.compile(
    r"\{[\w.]+\[['\"](?:id|key|name|hash|uuid|created|updated|timestamp)['\"]\]\}",
    re.I,
)
# FP: path con base var ben definito (CACHE_DIR, OUT_DIR) + f-string con int/internal
_PT_INT_VAR_FSTR = re.compile(
    r"f[\"'][^\"'/]*\{(?:i|j|k|n|idx|count|num|len|size|index|page|"
    r"diff_hash|video_id|dataset|stem|board_name|do_file_base|"
    r"base_name|file_base|name|key)\}[^/\"']*[\"']",
    re.I,
)
# FP: Go filepath.Join con stringa che contiene estensione hardcoded (senza +)
_PT_GO_FIXED_EXT_INLINE = re.compile(
    r'filepath\.Join\s*\([^)]*"[^"]*\.(?:' + _PT_EXT_LIST + r')"',
    re.I,
)
# FP: join con costante Go (constants.SomeConst) → estensione è fissa per design
_PT_GO_CONST = re.compile(
    r"filepath\.Join\s*\([^)]*\+\s*[A-Z]?constants?\.\w+",
    re.I,
)
# FP: join con wildcards o pattern (Glob) → non è traversal di file singolo
_PT_GLOB_PATTERN = re.compile(
    r"filepath\.Glob\s*\("
    r"|volumeMountPrefix\+"
    r"|\+\s*[\"']\*[\"']"
    r"|\+\s*[\"']\*\.",
    re.I,
)
# FP: variabile con "sanitized" nel nome → già sanitizzata
_PT_SANITIZED = re.compile(r"sanitize[d]?\w*\s*[\+\)]", re.I)
# FP: entrambi gli arg di path.join sono self-attributes → tutto da stato interno
_PT_SELF_ONLY = re.compile(
    r"os\.path\.join\s*\(\s*self\.\w+\s*,"
    r"\s*f?[\"'][^\"']*\{self\.\w+[^}]*\}[^\"']*[\"']",
    re.I,
)
# FP: path join dove il componente filename usa strftime/datetime → timestamp-generated
_PT_TIMESTAMP_GEN = re.compile(
    r"os\.path\.join\s*\([^)]*f[\"'][^\"']*"
    r"(?:strftime|datetime\.now|time\.time|\.timestamp\(\)|created_at|updated_at)[^\"']*[\"']",
    re.I,
)

def hc_rules_path_traversal_static(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    file = f.get("file", "")
    if _TEST_FILE.search(file):
        return "HC-FP", "test_file"
    code = extract_code(f.get("description", ""))

    # ── HC-FP round 4 (2026-05-07): pattern legittimi spesso flaggati VP ──
    # FP: args.output_dir / args.out_dir / args.report_dir = CLI arg per OUTPUT (intended writable)
    if re.search(r"(?:filepath\.Join|path\.join|os\.path\.join)\s*\(\s*"
                 r"args\.(?:output_dir|out_dir|report_dir|log_dir|build_dir|"
                 r"dest_dir|destination|target_dir|workdir|working_dir|"
                 r"export_dir|save_dir|cache_dir|data_dir|output_path|"
                 r"out_path|outdir|outpath)\b", code, re.I):
        return "HC-FP", "args_output_dir_intended_writable_cli_destination"
    # FP: self._temp_dir / self._working_dir = server-managed temp directory
    if re.search(r"(?:filepath\.Join|path\.join|os\.path\.join)\s*\(\s*"
                 r"self\.(?:_temp_dir|_working_dir|_tmp_dir|_workdir|_cache_dir|"
                 r"temp_dir|tmp_dir|working_dir|workdir|cache_dir|state_dir)\b",
                 code, re.I):
        return "HC-FP", "self_temp_or_working_dir_server_managed"
    # FP: filename component is server-generated identifier (session_id, request_id, uuid)
    if re.search(r"(?:filepath\.Join|path\.join|os\.path\.join)\s*\([^)]*"
                 r"f[\"'][^\"']*\{(?:session_id|request_id|task_id|job_id|"
                 r"trace_id|run_id|exec_id|process_id|thread_id|"
                 r"uuid|uid|guid|hash|digest|nonce)\b", code, re.I):
        return "HC-FP", "server_generated_id_in_filename_not_user_input"
    # FP: working_directory from exec_res / process result (server context)
    if re.search(r"exec_res\s*\[[\"']working_directory[\"']\]|"
                 r"process\.\w+\.cwd\(\)|"
                 r"context\.\w*(?:dir|path)", code, re.I):
        return "HC-FP", "server_execution_context_path_not_user_input"

    # VP PRIMA: join con input utente diretto (ha priorità su qualsiasi regola FP)
    if _PT_USER_INPUT.search(code):
        return "HC-VP", "path_join_with_user_input"

    # FP: join con valori hardcoded
    if _PT_HARDCODED.search(code):
        return "HC-FP", "hardcoded_path_no_user_input"
    # FP: join con estensione fissa → traversal bloccato dall'estensione hardcoded
    if _PT_FIXED_EXT.search(code):
        return "HC-FP", "fixed_extension_blocks_traversal"
    # FP: Python f-string con estensione hardcoded → f"{var}.ext"
    if _PT_FIXED_EXT_FSTR.search(code):
        return "HC-FP", "fstring_fixed_extension_blocks_traversal"
    # FP: Go filepath.Join con stringa inline contenente estensione
    if _PT_GO_FIXED_EXT_INLINE.search(code):
        return "HC-FP", "go_inline_fixed_extension_blocks_traversal"
    # FP: join con costante Go → estensione è fissa per design
    if _PT_GO_CONST.search(code):
        return "HC-FP", "go_constant_suffix_fixed_extension"
    # FP: Glob pattern o wildcard → non è traversal
    if _PT_GLOB_PATTERN.search(code):
        return "HC-FP", "glob_or_wildcard_pattern_not_traversal"
    # FP: variabile già sanitizzata
    if _PT_SANITIZED.search(code):
        return "HC-FP", "variable_already_sanitized"
    # FP: path.join(self.X, f"{self.Y}...") → entrambi da stato interno
    if _PT_SELF_ONLY.search(code):
        return "HC-FP", "self_attribute_path_no_user_input"
    # FP: filename generato da timestamp/datetime → non user-controlled
    if _PT_TIMESTAMP_GEN.search(code):
        return "HC-FP", "timestamp_generated_filename_not_user_input"
    # FP: f-string con suffix tra var e ext (f"{var}_meta.json")
    if _PT_FSTR_WITH_SUFFIX.search(code):
        return "HC-FP", "fstring_with_suffix_fixed_extension"
    # FP: f-string con prefix prima della var
    if _PT_FSTR_PREFIX_VAR.search(code):
        return "HC-FP", "fstring_with_prefix_fixed_extension"
    # FP: random/uuid/hash filename
    if _PT_RANDOM_GEN.search(code):
        return "HC-FP", "random_uuid_hash_filename_not_user_input"
    # FP: variabile con prefisso safe_/sanitized_/validated_
    if _PT_SAFE_PREFIX_VAR.search(code):
        return "HC-FP", "variable_explicitly_sanitized"
    # FP: variabile da split/replace/parse
    if _PT_PARSED_VAR.search(code):
        return "HC-FP", "variable_already_parsed_or_split"
    # FP: glob con extension
    if _PT_GLOB_EXT.search(code):
        return "HC-FP", "glob_with_extension_pattern"
    # FP: timestamp broader
    if _PT_TIMESTAMP_BROAD.search(code):
        return "HC-FP", "timestamp_or_datetime_in_filename"
    # FP: config/self/state var
    if _PT_CONFIG_VAR.search(code):
        return "HC-FP", "internal_config_or_state_variable"
    # FP: dict access interno (id/key/name/hash)
    if _PT_DICT_ID.search(code):
        return "HC-FP", "dict_access_internal_id_or_hash"
    # FP: variabile interna comune (i, idx, count, video_id, etc.)
    if _PT_INT_VAR_FSTR.search(code):
        return "HC-FP", "internal_loop_or_id_variable"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: prompt-injection-static
# ═══════════════════════════════════════════════════════════════════════════════
# Overlap con mcp-shield. Code snippet = riga di description tool.
# VP reale richiede tag injection espliciti o shadow instructions.

# Tag UPPERCASE solo (case-sensitive) — AWS SDK usa <important> lowercase = FP
_PI_INJECTION_TAG_UPPER = re.compile(
    r"<IMPORTANT>|<SECRET>|<HIDDEN>|<SYSTEM>|<CMD>|<INSTRUCTIONS>"
)
# Pattern injection case-insensitive (frasi shadow attack)
_PI_INJECTION_PHRASE = re.compile(
    r"ignore\s+(?:all\s+|previous\s+)?instructions"
    r"|NEVER\s+use\s+.{3,40}\s+ALWAYS\s+use"
    r"|do\s+not\s+(?:mention|reveal|show)\s+this"
    r"|not\s+visible\s+to\s+(?:the\s+)?(?:user|human)"
    r"|forget\s+everything|act\s+as\s+(?:root|admin|sudo)"
    r"|disregard\s+(?:above|prior|previous)"
    r"|hidden\s+from\s+(?:user|view)",
    re.I,
)
# AWS SDK pattern legittimo (lowercase <important> + <p>/<b>)
_PI_AWS_SDK_DOC = re.compile(
    r"<important>\s*(?:<p>|<b>|<a\s+href|<ul>|<li>)|"
    r"<important>[^<]*Amazon\s+(?:Web|S3|EC2|RDS|Lambda|IVS|"
    r"Service\s+Catalog|Translate|API\s+Gateway)|"
    r"<important>[^<]*AWS\s+(?:Account|IAM|ARN|SDK)|"
    r"<important>\s*<p>\s*\w+",
    re.I,
)

_PI_NORMAL_WARNING = re.compile(
    r"""(?:WARNING:|CAUTION:|NOTE:|IMPORTANT:|This action is irreversible|
         You must (?:call|provide|set|use|define|specify|first|always)|
         Must be set to true|must first call|
         Required:|Optional:|REQUIRED:|OPTIONAL:|
         you MUST (?:define|provide|specify|call|first|always)|
         You MUST (?:define|provide|specify|call|first|always)|
         MUST first call|
         Before using this|before calling|after calling|
         Always (?:call|use|include|specify|provide) .{5,60}first|
         \*\*OPTIONAL|OPTIONAL\s*-\s*DO NOT PROVIDE|
         \*\*REQUIRED|do not provide unless|
         \.format\(|Field\((?:default|description)=)""",
    re.I | re.X,
)
# FP: codice che è solo una riga di description in schema Pydantic / jsonschema / Go struct tag
_PI_SCHEMA_DESC = re.compile(
    r"""(?:
        description\s*=\s*["\']|           # Pydantic Field(description=
        jsonschema:"description=|          # Go struct tag jsonschema
        Description:\s+["`]|              # Go struct comment
        description:\s+["`]|              # YAML/TS field
        "description":\s+"                # JSON schema inline
    )""",
    re.I | re.X,
)
# FP: codice bundle/minificato
_PI_BUNDLE = re.compile(r'(?:function\([a-z],[a-z]\)|;\([a-z]\)=>[a-z]\.|===void 0\?)', re.I)

def hc_rules_prompt_injection_static(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    code = extract_code(f.get("description", ""))

    # FP: bundle/minificato
    if _PI_BUNDLE.search(code):
        return "HC-FP", "minified_bundle_not_tool_description"

    # FP: AWS SDK <important> doc tag (lowercase + <p>/Amazon/AWS)
    if _PI_AWS_SDK_DOC.search(code):
        return "HC-FP", "aws_sdk_important_doc_tag_not_injection"

    # VP: tag injection UPPERCASE (real attack pattern: <IMPORTANT>, <SYSTEM>)
    if _PI_INJECTION_TAG_UPPER.search(code):
        return "HC-VP", "explicit_uppercase_injection_tag"

    # VP: shadow instruction phrases (ignore instructions, never use X)
    if _PI_INJECTION_PHRASE.search(code):
        return "HC-VP", "shadow_instruction_phrase"

    # FP: schema/Pydantic description field (non è injection, è metadato API)
    if _PI_SCHEMA_DESC.search(code):
        return "HC-FP", "schema_description_field_not_injection"

    # FP: warning/istruzione operativa normale
    if _PI_NORMAL_WARNING.search(code):
        return "HC-FP", "normal_operational_instruction"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: insecure-deserialization
# ═══════════════════════════════════════════════════════════════════════════════

_PICKLE_SAFE = re.compile(
    r"""pickle\.dumps\(|pickle\.dump\(|
         # Only serialization (not deserialization)
         # or pickle used only in tests""",
    re.I | re.X,
)

_PICKLE_DANGEROUS = re.compile(
    r"pickle\.loads?\s*\([^)]*?(?:params\.|args\.|input\.|request\.|data\.|body\.|open\(|read\()",
    re.I,
)
# VP: pickle da database row (l'utente può influenzare i dati nel DB)
_PICKLE_DB_ROW = re.compile(
    r"pickle\.loads?\s*\(\s*(?:row\[|cursor\.|fetchone\(\)|fetch(?:all\()?)",
    re.I,
)
# FP: pickle da variabile "serialized_*" (dato interno, non user-controlled)
_PICKLE_INTERNAL = re.compile(
    r"pickle\.loads?\s*\(\s*serialized_\w+",
    re.I,
)
# FP: commento inline che indica dato trusted/safe
_PICKLE_TRUSTED_COMMENT = re.compile(
    r"#\s*(?:noqa[:\s]+S301|trusted|safe|local\s+cache|known\s+risk|intentional)",
    re.I,
)
# FP: pickle.load(f) dove f è un file ML (model file → dato interno, non user)
_PICKLE_ML_MODEL = re.compile(
    r"(?:model|scaler|pca|clf|classifier|regressor|encoder|tokenizer|pipeline)\s*="
    r"\s*pickle\.load\s*\(",
    re.I,
)
# FP: file appartiene a dipendenze di terze parti (site-packages, venv) — non è codice del server
_PICKLE_VENV_FILE = re.compile(
    r"(?:site-packages|/venv/|\\venv\\|/\.venv/|\\\.venv\\"
    r"|/env/Lib/|\\env\\Lib\\|/menv/|\\menv\\"
    r"|/lib/python\d|\\lib\\python\d"
    r"|python-fixer[\\/]Lib[\\/])",
    re.I,
)
# VP: pickle.loads(zlib.decompress(...)) — decompressione + pickle su dati ricevuti → VP forte
_PICKLE_DECOMPRESS_VP = re.compile(
    r"pickle\.loads?\s*\(\s*(?:zlib\.decompress|lzma\.decompress|bz2\.decompress"
    r"|gzip\.decompress|base64\.b64decode|base64\.urlsafe_b64decode)\s*\(",
    re.I,
)
# FP: pickle.load(f) dove la variabile destinazione indica cache/index/state interno
_PICKLE_INTERNAL_VAR = re.compile(
    r"(?:cached?|cache_data|cache_entry|cached_entry|cache_manager"
    r"|index|index_to_id|docstore|embeddings|patterns"
    r"|feature_columns|features|note_id_mapping|mapping"
    r"|marketplace_data|cached_data|data|loaded|entry"
    r"|self\._cache|self\._index|self\._docstore|self\.docstore"
    r"|self\.indexes?|self\.embedd\w+|self\.patterns)\s*"
    r"(?:\[[^\]]*\])?\s*=\s*pickle\.load\s*\(",
    re.I,
)
# FP: pickle.load(f) dove file path/var ha keyword di cache/index
_PICKLE_CACHE_FILE = re.compile(
    r"\bpickle\.load\s*\(\s*(?:f|file|fp|fh|cache_file|index_file|"
    r"model_file|state_file|store_file)\s*\)",
    re.I,
)
# FP: pickle.load(token) — OAuth token file (usually safe local creds)
_PICKLE_OAUTH_TOKEN = re.compile(
    r"(?:creds|credentials|token)\s*=\s*pickle\.load\s*\(\s*token",
    re.I,
)
# FP: file path in directory cache/index/embeddings/state/model
_PICKLE_FILE_PATH = re.compile(
    r"(?:cache[/\\]|index[/\\]|embeddings?[/\\]|model[/\\]|state[/\\]|"
    r"vector_store[/\\]|faiss[/\\]|cached[/\\]|store[/\\])",
    re.I,
)
# FP: scanner own — file in vulnerable_*, security_*
_PICKLE_SCANNER_FILE = re.compile(
    r"(?:vulnerable_|security_scanner|test_pickle|pickle_test|"
    r"vulnerabilities?[/\\]|examples?[/\\])",
    re.I,
)
# VP: loads da subprocess output / network / stdin
_PICKLE_SUBPROCESS_VP = re.compile(
    r"pickle\.loads?\s*\(\s*(?:result\.stdout|proc\.stdout|completed\.stdout"
    r"|response\.content|response\.body|sock\.recv|conn\.recv|s\.recv"
    r"|sys\.stdin|stdin\.read|request\.body|msg\.body)",
    re.I,
)

def hc_rules_insecure_deserialization(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    file = f.get("file", "")
    if _TEST_FILE.search(file):
        return "HC-FP", "test_file"
    # FP: file in dipendenze terze parti (site-packages / venv) — non è codice del server
    if _PICKLE_VENV_FILE.search(file):
        return "HC-FP", "third_party_library_in_venv_or_site_packages"
    desc = f.get("description", "")
    code = extract_code(desc)

    # FP: commento esplicito "trusted"/"noqa S301"
    if _PICKLE_TRUSTED_COMMENT.search(desc):
        return "HC-FP", "developer_explicitly_marked_as_trusted"
    # FP: deserializzazione da variabile interna (serialized_X)
    if _PICKLE_INTERNAL.search(code):
        return "HC-FP", "pickle_from_internal_serialized_variable"
    # FP: caricamento modello ML (model/scaler/pca = pickle.load) → dato interno
    if _PICKLE_ML_MODEL.search(code):
        return "HC-FP", "pickle_load_of_ml_model_file_internal"

    # FP: scanner own / vulnerable_* file
    if _PICKLE_SCANNER_FILE.search(file):
        return "HC-FP", "scanner_or_vulnerable_demo_file"
    # FP: file path in cache/index/embeddings dir
    if _PICKLE_FILE_PATH.search(file):
        return "HC-FP", "file_path_indicates_cache_or_index"

    # VP: pickle.loads da subprocess output / network input
    if _PICKLE_SUBPROCESS_VP.search(code):
        return "HC-VP", "pickle_loads_from_subprocess_or_network"
    # FP round 4: decompress sorgente è hardcoded file path (open("...str literal"))
    # es. snappy.decompress(open('tracegnn/visualization/sample_cases/...').read())
    if _PICKLE_DECOMPRESS_VP.search(code) and \
       re.search(r"(?:zlib|gzip|bz2|lzma|snappy|brotli)\.decompress\s*\("
                 r"\s*open\s*\(\s*[\"'][\w/.\-_]+[\"']", code, re.I):
        return "HC-FP", "decompress_from_hardcoded_local_file_path"

    # VP: pickle.loads(zlib.decompress(...)) — decompressione su dati ricevuti → VP forte
    if _PICKLE_DECOMPRESS_VP.search(code):
        return "HC-VP", "pickle_loads_with_decompression_likely_network_data"
    # VP: loads da input esterno (params/args)
    if _PICKLE_DANGEROUS.search(code):
        return "HC-VP", "pickle_loads_from_external_input"
    # VP: loads da database row (dati potenzialmente user-controlled)
    if _PICKLE_DB_ROW.search(code):
        return "HC-VP", "pickle_loads_from_db_row_user_influenced"

    # FP: variabile destinazione = cache/index/state/embeddings interna
    if _PICKLE_INTERNAL_VAR.search(code):
        return "HC-FP", "pickle_load_into_internal_cache_or_state_var"
    # FP: pickle.load(f) generic da file handle
    if _PICKLE_CACHE_FILE.search(code):
        return "HC-FP", "pickle_load_from_local_file_handle"
    # FP: OAuth token file
    if _PICKLE_OAUTH_TOKEN.search(code):
        return "HC-FP", "pickle_oauth_token_local_credential_file"

    # FP: solo serializzazione (dumps)
    if re.search(r"pickle\.dumps?\s*\(", code, re.I) and not re.search(r"pickle\.loads?", code, re.I):
        return "HC-FP", "pickle_serialization_only_not_deserialization"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: code-injection-static
# ═══════════════════════════════════════════════════════════════════════════════

_EVAL_USER_INPUT = re.compile(
    r"""eval\s*\(
    (?:[^)]*?(?:params\.|args\.|input\.|arguments\.|req\.|data\.|body\.|
               f["\']|[\+]|\%|\.format))|
    exec\s*\(
    (?:[^)]*?(?:params\.|args\.|input\.|f["\']|[\+]))""",
    re.I | re.X,
)

_EVAL_SAFE = re.compile(
    r"""eval\s*\(["\'][^"\']*["\']|   # eval di stringa hardcoded
        eval\s*\(JSON\.|             # eval(JSON.parse) pattern normale
        eval\s*\(compile\(""",       # eval di codice compilato
    re.I | re.X,
)

# VP: eval con template literal TypeScript contenente variabile utente
# es. nvim.eval(`system('${shellCommand}')`) / window.eval(`...`)
_EVAL_TEMPLATE_LITERAL = re.compile(r"eval\s*\(`[^`]*\$\{", re.I)

# VP: eval con backtick (qualsiasi eval(...` anche senza variabile visibile)
# Copre: this.#eval(`, window.eval(`, context.eval(`, xhsvm eval(`try {
_EVAL_BACKTICK = re.compile(r"eval\s*\(\s*`", re.I)

# VP: AppleScript "execute javascript" con variabile base64/encoded
_EVAL_APPLESCRIPT_JS = re.compile(
    r"execute\s+javascript\s+[\"']eval\s*\(atob\s*\('\$\{",
    re.I,
)

# FP: snippet incompleto (eng.eval senza argomento visibile, es. MATLAB IVM)
_EVAL_BARE = re.compile(
    r"(?:\.eng\.eval|self\.eng\.eval|eng\.eval|context\.eval|this\.context\.eval)\s*\(\s*$",
    re.I,
)

# FP: file minificato o vendor (angularjs-all.min.js, stealth.min.js)
_MIN_JS_FILE = re.compile(r"\.min\.[jt]sx?$|stealth\.min\.[jt]s$|angularjs|jquery", re.I)

# FP: file di test/debug infrastruttura (non codice utente)
_DEBUG_TEST_FILE = re.compile(r"(?:test-harness|debug-client|debug\.[jt]s$)", re.I)

def hc_rules_code_injection_static(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    file = f.get("file", "")
    if _TEST_FILE.search(file) or re.search(r"_test\.\w+$|\.test\.[jt]s$", file, re.I):
        return "HC-FP", "test_file"
    if _MIN_JS_FILE.search(file):
        return "HC-FP", "minified_or_vendor_js_file"
    if _DEBUG_TEST_FILE.search(file):
        return "HC-FP", "test_harness_or_debug_infrastructure_file"

    code = extract_code(f.get("description", ""))

    # FP: snippet incompleto (eng.eval senza argomento — MATLAB, IVM, ecc.)
    if _EVAL_BARE.search(code):
        return "HC-FP", "incomplete_snippet_engine_eval_no_argument"

    # FP: eval di stringa hardcoded
    if _EVAL_SAFE.search(code):
        return "HC-FP", "eval_of_hardcoded_string"

    # VP: eval con template literal TypeScript (nvim.eval(`...${var}...`))
    if _EVAL_TEMPLATE_LITERAL.search(code):
        return "HC-VP", "eval_with_template_literal_user_variable"

    # VP: qualsiasi eval con backtick (this.#eval(`, window.eval(`, eval(`try {)
    if _EVAL_BACKTICK.search(code):
        return "HC-VP", "eval_with_backtick_template_literal"

    # VP: AppleScript execute javascript "eval(atob('${...}'))"
    if _EVAL_APPLESCRIPT_JS.search(code):
        return "HC-VP", "applescript_execute_javascript_eval_atob_user_input"

    # VP: eval/exec con input utente esplicito
    if _EVAL_USER_INPUT.search(code):
        return "HC-VP", "eval_exec_with_user_input"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: command-injection-static
# ═══════════════════════════════════════════════════════════════════════════════

_CMD_CONCAT = re.compile(
    r"""(?:exec\.Command|child_process\.exec|subprocess\.(?:run|call|Popen)|
         os\.system|os\.popen|exec\.CommandContext|cmd\.Run|shell\.Exec
    )\s*\(
    (?:[^)]*?(?:[\+]|f["\'].*\{|%\s*(?:params|args|input)|
                params\.|args\.|input\.))|
    (?:[^)]*?[\+]\s*[\w.]+)""",
    re.I | re.X,
)

# Go exec.Command(name, ...) NON usa shell. Args separati = no injection
# anche con concat: exec.Command("git", "clone", "--branch="+ref, repo)
# Match ANY var assignment: cmd, out, foo := exec.Command("literal", ...)
# First arg deve essere literal pura (no concat) → safe
_CMD_GO_NO_SHELL = re.compile(
    r"exec\.(?:Command|CommandContext)\s*\(\s*"
    r"(?:ctx\s*,\s*)?"  # CommandContext takes ctx first
    r"[\"'][\w/.\-]+[\"']\s*,",
    re.I,
)
# Obfuscated shell first arg: exec.Command("/bi"+"n/s"+"h" ...) → real shell injection
_CMD_GO_OBFUSCATED_SHELL = re.compile(
    r"exec\.(?:Command|CommandContext)\s*\(\s*"
    r"(?:ctx\s*,\s*)?"
    r"[\"'][\w/.\-]+[\"']\s*\+\s*[\"']",  # first arg: concat di string literals
    re.I,
)

# Shell injection VERA: exec con shell=True o template literal con $${var}
# o singolo arg stringa concatenata
_CMD_REAL_SHELL_INJECT = re.compile(
    r"(?:child_process\.exec|child_process\.execSync)\s*\(\s*[`\"'][^`\"']*\$\{(?!self\.|this\.)"  # JS template literal
    r"|(?:child_process\.exec|child_process\.execSync)\s*\(\s*[\"'][^\"']*[\"']\s*\+\s*\w"  # JS concat string + var
    r"|subprocess\.\w+\s*\([^)]*shell\s*=\s*True[^)]*(?:params|args|input|user_)"  # Python shell=True with user
    r"|os\.system\s*\([^)]*(?:params|args|input|user_|req\.body)"  # os.system with user
    r"|os\.popen\s*\([^)]*(?:params|args|input|user_|req\.body)"
    r"|os\.system\s*\([^)]*[\"'][^\"']*[\"']\s*\+",  # os.system concat
    re.I,
)

_CMD_SAFE = re.compile(
    r"""exec\.Command\s*\(["\'][^"\']+["\'](?:\s*,\s*["\'][^"\']+["\'])*\s*\)|
        subprocess\.run\s*\(\[["\']""",
    re.I | re.X,
)

def hc_rules_command_injection_static(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    code = extract_code(f.get("description", ""))

    # VP: Go exec.Command con primo arg obfuscato concat ("/bi"+"n/s"+"h")
    if _CMD_GO_OBFUSCATED_SHELL.search(code):
        return "HC-VP", "go_exec_obfuscated_shell_invocation"

    # FP: Go exec.Command — non usa shell, args separati anche con concat
    if _CMD_GO_NO_SHELL.search(code) and not _CMD_GO_OBFUSCATED_SHELL.search(code):
        return "HC-FP", "go_exec_command_args_separati_no_shell"

    # FP: command con argomenti hardcoded (array di stringhe)
    if _CMD_SAFE.search(code):
        return "HC-FP", "command_with_hardcoded_args"

    # VP: shell injection reale (JS template/concat, Python shell=True+user, os.system+user)
    if _CMD_REAL_SHELL_INJECT.search(code):
        return "HC-VP", "real_shell_injection_pattern"

    # VP: concat generic con var (debole, ma keep for legacy)
    if _CMD_CONCAT.search(code) and not _CMD_GO_NO_SHELL.search(code):
        return "HC-VP", "command_string_concat_with_user_input"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: command-injection-fuzzing
# ═══════════════════════════════════════════════════════════════════════════════

_CMD_FUZZ_SHELL_OUTPUT = re.compile(
    # Solo CONTENT reali, NO path string `/etc/passwd` da solo (sarebbe echo payload)
    r"uid=\d+\(\w+\)\s+gid=\d+|"
    r"groups=\d+\(\w+\)|"
    r"root:x:0:0:[^:]*:/(?:root|home)|"
    r"daemon:x:1:1:|bin:x:2:2:|"
    # Solo se response contiene MULTIPLE righe di /etc/passwd (stringa multi-line)
    r"(?:root:x:\d+|daemon:x:\d+|bin:x:\d+).*?(?:nologin|/bin/(?:bash|sh|false))|"
    r"'EXIT_CODE'.*?'(?:0|1|127)'.*?'STDOUT'.*?[a-zA-Z]|"
    r"'STDERR'.*?(?:sh:|bash:|zsh:)",
    re.I | re.S,
)

_CMD_FUZZ_TOOL_LIST = re.compile(
    r""""tools":\s*\[|'tools':\s*\[|"method".*tools/list|"result".*"tools":\s*\[""",
    re.I,
)

_CMD_FUZZ_DOC_RESPONSE = re.compile(
    r'"description":\s*"[A-Z][^"]{20,}"|inputSchema|"type":\s*"object"',
    re.I,
)

_CMD_FUZZ_HTML = re.compile(r"<html[^>]*>|<!DOCTYPE\s+html", re.I)

def hc_rules_command_injection_fuzzing(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    response = f.get("response", "")

    # VP PRIMA: response mostra output di shell reale
    if _CMD_FUZZ_SHELL_OUTPUT.search(response):
        return "HC-VP", "shell_output_in_response_uid_or_etc_passwd"

    # FP: response è lista di tool (server ignora payload)
    if _CMD_FUZZ_TOOL_LIST.search(response):
        return "HC-FP", "response_is_tool_list_not_command_output"
    # FP: response è documentazione schema
    if _CMD_FUZZ_DOC_RESPONSE.search(response) and len(response) > 200:
        return "HC-FP", "response_is_schema_documentation"
    # FP: response è HTML (server web, non shell)
    if _CMD_FUZZ_HTML.search(response):
        return "HC-FP", "response_is_html_not_shell_output"
    # FP: errore di rete/auth/API esterna (comando non eseguito)
    if _INFO_DISC_GENERIC_ERR.search(response):
        return "HC-FP", "network_or_auth_error_command_not_executed"
    if _INFO_DISC_EXT_API_FP.search(response):
        return "HC-FP", "external_api_error_not_shell_execution"
    if _INFO_DISC_AUTH_MISSING.search(response):
        return "HC-FP", "auth_missing_not_shell_output"
    # FP: risposta JSON strutturata (dati API, non output shell)
    # Il VP check è già fallito → JSON è dati business, non esecuzione
    resp_stripped = response.strip()
    if resp_stripped.startswith(("{", "[")) and not _CMD_FUZZ_SHELL_OUTPUT.search(response):
        return "HC-FP", "json_structured_data_not_shell_output"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: path-traversal-fuzzing
# ═══════════════════════════════════════════════════════════════════════════════

_PT_FUZZ_SUCCESS = re.compile(
    # Require MULTI-LINE /etc/passwd content (root: + at least one other user)
    # OR explicit shell path on root line
    r"root:x:0:0:[^:]*:/(?:root|home)[^:]*:/(?:bin|usr/bin)/(?:bash|sh|false|nologin|zsh)|"
    # Multi-line: root + daemon (both visible)
    r"root:x:0:0:[^:]*:[^:]*:[^\n]+\n+\s*daemon:x:1:1:|"
    # Multi-line: daemon + bin
    r"daemon:x:1:1:[^:]*:[^\n]+\n+\s*bin:x:2:2:|"
    # nobody full entry with path
    r"nobody:x:65534:65534:[^:]*:/(?:nonexistent|var/empty):/(?:bin|usr)/(?:nologin|false)|"
    # Windows: actual SAM path with system32 config (multi-token)
    r"WINDOWS\\system32\\config\\SAM[^\\]|"
    r"\[boot loader\]\s*\n.*timeout=|"
    # Directory listing with real perms + multiple files
    r"total\s+\d+\s*\n+(?:drw[xrws-]+|[-l]rw[xrws-]+)\s+\d+\s+\w+\s+\w+",
    re.I | re.S,
)

# VP: server ha tentato di accedere a path sensibile (confermato da ENOTDIR/error reading)
# ENOTDIR: not a directory → server ha accettato /etc/passwd come base dir → VP
# "Project structure (../../../etc/passwd):\n\nError reading directory" → VP
_PT_FUZZ_SENSITIVE_ATTEMPT = re.compile(
    r"(?:ENOTDIR|Error\s+reading\s+(?:directory|path)).*?/etc/passwd"
    r"|Project\s+structure\s*\([^)]*(?:\.\./|/etc/).*?\)\s*:.*?Error",
    re.I,
)

# FP: server non trovato / errore ambiente (software non installato sul VM di test)
_PT_FUZZ_ENV_MISSING = re.compile(
    r"Browser\s+was\s+not\s+found\s+at\s+the\s+configured\s+executablePath"
    r"|executablePath\s*\([^)]*browser\.exe\)"
    r"|getaddrinfo\s+ENOTFOUND",
    re.I,
)

# FP: payload echeggiato come dato/metadato, non letto come file
# "currentFocus": {"topic": "file:///etc/passwd"} → FP (stored as topic label)
# "Name: file:///etc/passwd" → FP (stored as puzzle name)
# "Current default RPC URL: file:///etc/passwd" → FP (stored as URL config, not read)
_PT_FUZZ_ECHO_ONLY = re.compile(
    r'"topic"\s*:\s*"file:///'
    r'|Name:\s*file:///'
    r'|Current\s+default\s+(?:RPC\s+)?URL:\s*file:///'
    r'|"(?:url|endpoint|host|address)"\s*:\s*"file:///',
    re.I,
)

# FP: ENOENT su path /proc/<payload> → server prepende /proc/ fisso, traversal non raggiunge /etc
_PT_FUZZ_PROC_ENOENT = re.compile(r"ENOENT.*?/proc/(?!self|net|sys|mem|cmdline|fd)\w", re.I)

# FP: payload echo broader — qualsiasi storage del path come label/config/metadata
_PT_FUZZ_ECHO_BROAD = re.compile(
    r'(?:Path\s+is\s+not\s+a\s+directory:\s*/etc/passwd'
    r'|Conversation\s+bridged\s+from\s+(?:C:\\\\Windows|/etc/|file:///)'
    r'|Portainer\s+Configuration:\s*[\\\\n]*-\s*URL:\s*file:///'
    r'|"currentProject"\s*:\s*"file:///'
    r'|"projectPath"\s*:\s*"(?:\.\./|file:///|/etc/)'
    r'|EEXIST:\s*file\s+already\s+exists,\s+mkdir\s+'
    r'|"plantuml"\s*:\s*"@startuml.*?file:///'
    r'|@startuml.*?title.*?(?:file:///|/etc/)'
    r'|insights?\s+matching\s+query:\s*"\\?\''
    r'|关键词:\s*(?:file:///|/etc/|http)'
    r'|"name"\s*:\s*"file:///etc/passwd",\s*"filePath"\s*:\s*"/home/'
    r'|"filePath"\s*:\s*"/etc/passwd/(?:http|file)'
    r'|Domain\s+Model:\s*file:///'
    r'|SQLite\s+error\s+occurred\.\s+unrecognized\s+token'
    r'|Task\s+List\s*\([^)]*\d+\s+of\s+\d+\)'
    r'|UNION\s+SELECT.*?information_schema'
    r'|Found\s+\d+\s+(?:results?|insights?|matches?|recipes?|items?)\s+(?:for|matching)'
    r'|Saved\s+local\s+snapshot.*?file:///'
    r'|"(?:gateway_url|kvUrl|publicEndpoint|baseUrl|targetUrl)"\s*:\s*"file:///'
    r'|"connection"\s*:\s*\{[^}]*"server"\s*:\s*"file:///'
    r'|allowed\s+directories\s+list|허용된\s+디렉토리'
    r'|Season\s+Comparison\s+for\s+\.\./'
    r'|"(?:hostname|ip_addresses|server)"\s*:\s*\[?\s*"file:///'
    r'|switch_project.*?execution\s+failed.*?EEXIST'
    r'|Tool\s+\'switch_project\'\s+execution\s+failed)',
    re.I | re.S,
)
# FP: response contains LLM-explanation of what the path/cmd represents
_PT_FUZZ_LLM_EXPLAIN = re.compile(
    r"(?:The\s+(?:file|command|path)\s+(?:`|')?\.\.?(?:/|\.\.)"
    r"|The\s+SAM\s+\(Security\s+Account\s+Manager\)"
    r"|The\s+_etc/passwd_\s+file\s+is"
    r"|Comprendre\s+le\s+fichier\s+SAM"
    r"|fichier\s+SAM\s+dans\s+Windows"
    r"|critical\s+text\s+file\s+in\s+Linux\s+systems"
    r"|represents\s+an\s+attempt\s+to\s+access)",
    re.I,
)
# FP: search/recipe/algolia results — payload as search query
_PT_FUZZ_SEARCH_RESULT = re.compile(
    r'"hits"\s*:\s*\['
    r'|"exhaustiveNbHits"\s*:'
    r'|"nbHits"\s*:\s*(?:false|\d+)'
    r'|Found\s+\d+\s+recipe\(s\)\s+for'
    r'|Imports:\s*:std/forei',
    re.I,
)
# FP: tool execution failed for OTHER reason (not traversal-specific)
_PT_FUZZ_OTHER_ERROR = re.compile(
    r"execution\s+failed:\s*(?:EEXIST|EACCES|EPERM|EINVAL|ENOTDIR.*?\bnot\b)"
    r"|Failed\s+to\s+(?:write|create|update|delete)\s+to\s+/proc/"
    r"|Path\s+is\s+not\s+a\s+directory:\s+/etc/(?!passwd\b|shadow\b)",
    re.I,
)

# Nuove HC-FP da blind-review: response è solo error message echo dell'URI/path
# Senza alcun contenuto del file letto
_PT_FUZZ_RESOURCE_NOT_FOUND_ECHO = re.compile(
    r'(?:Resource\s+(?:file:///etc/(?:passwd|shadow)|.*?/etc/(?:passwd|shadow))\s+not\s+found'
    r'|MCP\s+error\s+-326\d{2}:\s*Resource\s+not\s+found'
    r'|Unknown\s+resource:\s+file:///etc/'
    r'|Error\s+reading\s+resource:\s*Unknown\s+resource:\s*file:///'
    r'|"uri"\s*:\s*"file:///etc/(?:passwd|shadow)"\s*\}\s*\}\s*\}'
    r'|jq\s+query\s+failed.*?Invalid\s+JSON\s+in\s+file:\s*/etc/passwd'
    r'|Unexpected\s+token\s+\'r\',\s*"root:x:0:0"\.\.\.\s+is\s+not\s+valid\s+JSON'
    r')',
    re.I,
)
# FP: payload usato come testo descrittivo/log/storage, non eseguito
_PT_FUZZ_PAYLOAD_AS_LABEL = re.compile(
    r'(?:terminalId.*?\.\.//\.\.//etc/shadow'
    r'|Configuration\s+reloaded'
    r'|"note_id"\s*:\s*"\.\./'
    r'|"insights"\s*:\s*\['
    r'|Set\s+it\s+with:\s*export'
    r'|stored\s+test\s+data)',
    re.I,
)

def hc_rules_path_traversal_fuzzing(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    response = f.get("response", "")

    # ── HC-FP da blind-review: PRIMA del check VP, perché alcuni response
    # contengono "/etc/passwd" testuale ma solo come echo URI in error msg ──
    # FP: server risponde "Resource file:///etc/passwd not found" — NON ha letto
    if _PT_FUZZ_RESOURCE_NOT_FOUND_ECHO.search(response):
        return "HC-FP", "resource_not_found_uri_echo_no_actual_read"
    # FP: payload memorizzato come label/config/storage, no exploit
    if _PT_FUZZ_PAYLOAD_AS_LABEL.search(response):
        return "HC-FP", "payload_as_label_or_storage_metadata"

    # VP: content di file system nella response (exploit riuscito)
    if _PT_FUZZ_SUCCESS.search(response):
        return "HC-VP", "filesystem_content_in_response_etc_passwd"

    # VP: server ha tentato path sensibile confermato da errore filesystem
    if _PT_FUZZ_SENSITIVE_ATTEMPT.search(response):
        return "HC-VP", "path_traversal_attempt_confirmed_by_fs_error"

    # FP: software non installato nel VM di test (browser, MySQL host, ecc.)
    if _PT_FUZZ_ENV_MISSING.search(response):
        return "HC-FP", "software_not_installed_in_test_env"

    # FP: payload echeggiato come metadato/label senza accesso al file
    if _PT_FUZZ_ECHO_ONLY.search(response):
        return "HC-FP", "path_payload_echoed_as_metadata_not_read"

    # FP: ENOENT su percorso /proc/<payload> → traversal non raggiunge /etc/passwd
    if _PT_FUZZ_PROC_ENOENT.search(response):
        return "HC-FP", "proc_prefix_enoent_traversal_blocked"

    # FP: response è tool list o documentazione
    if _CMD_FUZZ_TOOL_LIST.search(response):
        return "HC-FP", "response_is_tool_list"
    if _CMD_FUZZ_DOC_RESPONSE.search(response) and len(response) > 200:
        return "HC-FP", "response_is_schema_documentation"

    # FP: payload echo broader (Portainer config, plantuml, currentProject, ecc.)
    if _PT_FUZZ_ECHO_BROAD.search(response):
        return "HC-FP", "payload_stored_as_metadata_or_config_no_read"

    # FP: LLM explanation della path/SAM/etc
    if _PT_FUZZ_LLM_EXPLAIN.search(response):
        return "HC-FP", "llm_explains_path_concept_no_actual_read"

    # FP: search/algolia results con payload come query
    if _PT_FUZZ_SEARCH_RESULT.search(response):
        return "HC-FP", "search_engine_query_results_payload_as_search"

    # FP: error non-traversal (EEXIST, write to /proc, errore validazione)
    if _PT_FUZZ_OTHER_ERROR.search(response):
        return "HC-FP", "non_traversal_filesystem_error"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: command-execution-fuzzing
# ═══════════════════════════════════════════════════════════════════════════════

_CMD_EXEC_VALIDATION_FP = re.compile(
    r"(?:Invalid\s+enum\s+value\.\s+Expected\s+"
    r"|Invalid\s+arguments:"
    r"|MCP\s+error\s+-32602:"
    r"|validation\s+failed:"
    r"|Expected\s+'[^']+'\s*\|\s*'[^']+'.*received\s+'"
    r"|not\s+a\s+valid\s+(?:enum|value|choice))",
    re.I,
)
# FP: binary di sistema non installato nel VM di test → il payload non può eseguire
# Pattern: "/bin/sh: 1: zellij: not found" / "/bin/bash: claude: No such file..."
# Tutti i server con tool non installati: zellij, adb, az, kubectl, task, v4l2-ctl, wmic, ecc.
_CMD_EXEC_NOT_FOUND = re.compile(
    r"/bin/(?:sh|bash|zsh):\s*\d*:?\s*\S+:\s*not\s+found"
    r"|/bin/(?:sh|bash):\s*\S+:\s*No\s+such\s+file\s+or\s+directory"
    r"|\bNo\s+such\s+file\s+or\s+directory\b"
    r"|URL\s+scheme\s+execution\s+failed"
    r"|Failed\s+to\s+generate\s+base64\s+output\s+from\s+PowerShell"
    r"|GoogleGenerativeAI\s+Error|Gemini\s+text\s+generation\s+failed"
    r"|Error\s+fetching\s+from\s+https://generativelanguage"
    r"|SSH\s+command\s+failed:.*Command\s+failed:\s+ssh\s+\w",
    re.I,
)
# FP: server's own fixed command fails due to environment mismatch (not user injection)
_CMD_EXEC_OWN_CMD_FP = re.compile(
    r"(?:osascript:\s+not\s+found"
    r"|Command\s+failed:\s+osascript"
    r"|/bin/sh:\s+\d+:\s+osascript"
    r"|command\s+not\s+found.*Command\s+failed)",
    re.I,
)
# VP: payload dell'utente compare nella stringa del comando che ha fallito → shell injection
# Regola STRETTA post-blind-review: serve evidenza che id/whoami sia stato espanso (output uid=)
# o exit code 0 con stdout. Solo "Command failed: <cmd_with_payload>" non basta.
_CMD_EXEC_PAYLOAD_IN_CMD = re.compile(
    # Output reale di id/whoami in response (shell ha eseguito)
    r"(?:Command\s+failed:|Output:).*?\buid=\d+\(\w+\)\s+gid=\d+|"
    # tecnico\nroot:x:0:0... = whoami output + cat /etc/passwd
    r"tecnico\s*\\?n\s*root:x:0:0|"
    # Stderr/stdout output reale di shell command
    r"'STDOUT'\s*:\s*'[^']*\\nuid=\d+|"
    r"'STDOUT'\s*:\s*'[^']*\\nroot:x:0:0",
    re.I | re.S,
)

def hc_rules_command_execution_fuzzing(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    response = f.get("response", "")
    desc = f.get("description", "")

    # VP: output di shell reale in response (exploit confermato)
    if _CMD_FUZZ_SHELL_OUTPUT.search(response):
        return "HC-VP", "shell_output_in_response"
    if _PT_FUZZ_SUCCESS.search(response):
        return "HC-VP", "filesystem_content_in_response"

    # VP: payload utente compare nel comando fallito → server inietta user input in shell
    if _CMD_EXEC_PAYLOAD_IN_CMD.search(response):
        return "HC-VP", "user_payload_in_command_string_shell_injection"

    # VP: descrizione dice "payload was executed"
    if re.search(r"(?:payload was executed|command.*executed|injection.*successful)", desc, re.I):
        return "HC-VP", "execution_confirmed_by_description"

    # FP: binary non trovato → tool non installato nel VM, injection impossibile
    if _CMD_EXEC_NOT_FOUND.search(response):
        return "HC-FP", "required_binary_not_installed_in_test_env"
    # FP: input validation triggered (enum/type validation)
    if _CMD_EXEC_VALIDATION_FP.search(response):
        return "HC-FP", "input_validation_rejected_payload"
    # FP: server's own command fails due to environment mismatch
    if _CMD_EXEC_OWN_CMD_FP.search(response):
        return "HC-FP", "servers_own_command_fails_not_user_injection"
    # FP: tool list
    if _CMD_FUZZ_TOOL_LIST.search(response):
        return "HC-FP", "response_is_tool_list"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: code-injection-fuzzing
# ═══════════════════════════════════════════════════════════════════════════════

# VP: server esegue codice utente in Pyodide/WASM → code injection confermata
# es. "File /lib/python313.zip/_pyodide/_base.py, line 523, in eval_code"
_CODE_FUZZ_PYODIDE_EXEC = re.compile(
    r"_pyodide/_base\.py.*(?:eval_code|eval_code_async)"
    r"|eval_code(?:_async)?\s+await\s+CodeRunner",
    re.I,
)
# VP: payload utente nella stringa di un comando shell tramite python subprocess
# es. "Command failed: python -u /path/script.py $(id) read"
# es. "Command failed: python3 /path/script.py delete \"$(id)\""
_CODE_FUZZ_PAYLOAD_IN_PYTHON_CMD = re.compile(
    r"Command\s+failed:\s+python[23]?\s+.*?(?:\$\(id\)|&&\s+ls|test\s+\|\|\s+id"
    r"|\bSAM\b.*read|--code\s+\"\$\(id\)|delete\s+\"\$\(id\))",
    re.I,
)
# FP: modulo Python mancante nel VM di test → server non funzionante
_CODE_FUZZ_IMPORT_ERR = re.compile(
    r"ModuleNotFoundError:\s+No\s+module\s+named"
    r"|ImportError:\s+cannot\s+import\s+name"
    r"|No\s+module\s+named\s+'[^']+'"
    r"|from\s+bs4\s+import.*error",
    re.I,
)
# FP: risposta è generazione di codice con payload echeggiato come nome endpoint/classe
# es. nestjsmcp: "# E2E tests for $(id) endpoints" → genera test code, non esegue
_CODE_FUZZ_CODE_GEN = re.compile(
    r"(?:#\s+E2E\s+tests\s+for|import\s+\{.*TestingModule|INestApplication)"
    r"|(?:```(?:typescript|javascript|python)\s*\n.*import\s)",
    re.I,
)

def hc_rules_code_injection_fuzzing(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    response = f.get("response", "")
    payload = f.get("payload", "")

    # ── HC-FP da round 3 (2026-05-07) — applicate PRIMA dei VP ──
    # FP: response è TypeScript test file scaffold (nestjsmcp template)
    if re.search(r"#\s+(?:Unit|E2E|Integration)\s+tests?\s+for|"
                 r"Test,\s+TestingModule|"
                 r"INestApplication|"
                 r"```typescript\s*\n.*(?:import|describe)|"
                 r"\.service\.spec\.ts\b", response, re.I):
        return "HC-FP", "response_is_typescript_test_scaffold_template"
    # FP: response è Node.js / API documentation HTML (snyk-labs docs server)
    if re.search(r"<code>(?:child_process|node:|process\.|exec[VvFfP]+)|"
                 r'<a\s+href="#child_process|'
                 r"man7\.org/linux/man-pages|"
                 r"man\s+page\s+for\s+\w+|"
                 r"manual\s+for\s+(?:execvpe|execvp|fork|popen)", response, re.I):
        return "HC-FP", "response_is_api_docs_html_not_execution"
    # FP: server's Python script crashed (Traceback) but payload NOT executed as code
    # Solo path arg passato a script proprio — NO eval/exec di payload
    if re.search(r"Command\s+failed:\s+python[23]?\s+\"?/(?:home|opt|usr)/[^\s\"]+\.py\"?\s+(?:--\w+\s+)?", response, re.I) and \
       re.search(r"Traceback\s*\(most\s+recent\s+call\s+last\)", response):
        # Check NO actual injection markers (no $(id), no eval result)
        if not re.search(r"\$\(id\)|uid=\d+\(|root:x:0:0:[^:]*:/", response):
            return "HC-FP", "python_script_invoked_with_path_arg_no_code_eval"

    # VP: output di shell reale in response (exploit confermato)
    if _CMD_FUZZ_SHELL_OUTPUT.search(response):
        return "HC-VP", "shell_output_confirms_code_execution"
    # VP: actual code execution result (NON loose — richiede output structure)
    # `eval result: <value>`, `exec stdout:`, codice eseguito + output
    if re.search(r"\beval(?:_code)?\s+result\s*[:=]|"
                 r"\bexec(?:_result)?\s+(?:stdout|output)\s*[:=]|"
                 r"['\"]EXIT_CODE['\"]\s*:\s*['\"]?0['\"]?\s*,\s*['\"]STDOUT['\"]\s*:\s*['\"][^'\"]+\b(?:uid|root|/etc)|"
                 r"successful\s+code\s+injection\s+detected", response):
        return "HC-VP", "code_execution_result_with_actual_output"

    # VP: Pyodide eval_code eseguito con input utente → code injection in WASM
    if _CODE_FUZZ_PYODIDE_EXEC.search(response):
        return "HC-VP", "pyodide_eval_code_executed_with_user_input"

    # VP: payload utente in comando python subprocess → shell injection
    if _CODE_FUZZ_PAYLOAD_IN_PYTHON_CMD.search(response):
        return "HC-VP", "user_payload_in_python_subprocess_shell_injection"

    # FP: modulo Python mancante → server broken, injection irrilevante
    if _CODE_FUZZ_IMPORT_ERR.search(response):
        return "HC-FP", "python_module_missing_server_not_functional"

    # FP: generazione codice con payload echeggiato come nome (non eseguito)
    if _CODE_FUZZ_CODE_GEN.search(response):
        return "HC-FP", "response_is_generated_code_not_execution"

    # FP: tool list o documentazione
    if _CMD_FUZZ_TOOL_LIST.search(response):
        return "HC-FP", "response_is_tool_list"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: information-disclosure-fuzzing
# ═══════════════════════════════════════════════════════════════════════════════

_INFO_DISC_ACTUAL = re.compile(
    r"(?:stack\s+trace"
    r"|traceback\s+\(most\s+recent"
    r"|at\s+[A-Z][\w.]+\([\w.]+:\d+\)"
    r'|File\s+".*",\s+line\s+\d+'
    r"|internal\s+server\s+error"
    r"|(?:DEBUG|WARNING|ERROR)\s+[A-Z][\w.]+:\d+)",
    re.I,
)

_INFO_DISC_BENIGN = re.compile(
    r"(?:\"type\":\s*\"object\""
    r"|inputSchema"
    r"|\"description\":"
    r"|This\s+tool"
    r"|The\s+tool"
    r"|No\s+such\s+tool"
    r"|Method\s+not\s+found)",
    re.I,
)
# FP: missing auth / missing API token — server non avviato, non information disclosure
_INFO_DISC_AUTH_MISSING = re.compile(
    r"(?:is required but not set"
    r"|is not set\."
    r"|required but not configured"
    r"|please set (?:it|the)"
    r"|please provide"
    r"|API (?:key|token) (?:is )?(?:required|missing|not set|not found)"
    r"|environment variable.{0,30}(?:not set|missing|required)"
    r"|Error: APIFY_TOKEN"
    r"|Error: API_KEY"
    r"|Error: TOKEN)",
    re.I,
)
# FP: API externa not found (server inoltro la richiesta all'esterno, non c'è leakage)
_INFO_DISC_EXT_API_FP = re.compile(
    r"(?:API error: Not Found"
    r"|API error: Unauthorized"
    r"|API error: Forbidden"
    r"|API error: 404"
    r"|Not Found: (?:user|team|player|game|resource)"
    r"|connection reset by peer"
    r"|read: connection reset"
    r"|context deadline exceeded"
    r"|no route to host"
    r"|'detail': '(?:list|read) (?:resources?|prompts?|tools?) not supported'"
    r"|not supported'"
    r"|SyntaxError: Unexpected non-whitespace character after JSON"
    r"|Internal error.*not supported)",
    re.I,
)
# VP: information disclosure REALE — escludo casi in cui server leaka solo
# proprio install dir (/home/tecnico/Desktop/Pipeline/<server-name>/) come è
# atteso in test env. Round 3 (2026-05-07) tightened.
_INFO_DISC_FS_LEAK = re.compile(
    r"'object has no attribute"
    r'|"object has no attribute'
    r"|NoneType.*has no attribute"
    r"|Working\s+Directory:\s*/(?:root|var|opt|tmp|srv)/"
    r"|cwd:\s*['\"]?/(?:root|var|opt|tmp)/"
    r"|File\s+\"/(?:opt|var|srv)/[\w_/-]+\",\s*line\s+\d+",
    re.I,
)
# FP nuovo: server leaka SOLO il proprio install path (atteso in test env)
# es: AppleScript "do script POSIX file \"/home/tecnico/Desktop/Pipeline/<server>/...\""
_INFO_DISC_SELF_PATH_ONLY = re.compile(
    r"POSIX\s+file\s+\"/home/(?:tecnico|user|ubuntu)/Desktop/Pipeline/[\w-]+/[\w./_-]+\""
    r"|File\s+\"/home/(?:tecnico|user|ubuntu)/Desktop/Pipeline/[\w-]+/(?:src/|scripts/)?[\w./_-]+\.(?:py|js|ts|jsx|tsx)\"",
    re.I,
)
# FP: errore generico senza dettagli (no information disclosure)
_INFO_DISC_GENERIC_ERR = re.compile(
    r"(?:^(?:Internal\s+error|Internal\s+Server\s+Error)$"
    r"|\"message\":\s*\"Internal\s+error\""
    r"|\{'code':\s*-32603,\s*'message':\s*'Internal\s+error'\}"
    r"|connection\s+(?:refused|reset|timed\s+out)"
    r"|could\s+not\s+resolve\s+hostname"
    r"|no\s+route\s+to\s+host"
    r"|name\s+or\s+service\s+not\s+known"
    r"|network\s+(?:unreachable|error)"
    r"|timed?\s+out)"
    r"",
    re.I,
)

def hc_rules_information_disclosure_fuzzing(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    response = f.get("response", "")
    desc = f.get("description", "")

    # ── HC-FP round 4 (2026-05-07): pattern non-info-disclosure ──
    # FP: SyntaxError di python3 -c con payload — è command-injection, non info disclosure
    # Server passa user input a python3 -c → finisce in code-injection-fuzzing/command-injection
    if re.search(r"python[23]?\s+-c\s+\"[^\"]+\".*?File\s+\"<string>\".*?SyntaxError", response, re.S):
        return "HC-FP", "python_c_syntax_error_not_info_disclosure_belongs_to_code_injection"
    # FP: AppleScript "do JavaScript" con payload — code execution, non info disclosure
    if re.search(r"do\s+JavaScript\s+\"[^\"]+\\n\s*\(function", response, re.S):
        return "HC-FP", "applescript_do_javascript_code_exec_not_info_disclosure"

    # ── HC-FP round 3: server leaka SOLO proprio install path (test env, mild) ──
    if _INFO_DISC_SELF_PATH_ONLY.search(response) and \
       not re.search(r"/etc/(?:passwd|shadow|sudoers)|"
                     r"/root/[\w/]|"
                     r"BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY|"
                     r"\buid=\d+\(", response):
        return "HC-FP", "server_install_path_only_no_real_disclosure"

    # VP: leakage filesystem o attribute error Python (implementation detail)
    if _INFO_DISC_FS_LEAK.search(response):
        return "HC-VP", "filesystem_path_or_impl_detail_in_response"
    # VP: stack trace o debug info reale
    if _INFO_DISC_ACTUAL.search(response):
        return "HC-VP", "stack_trace_or_debug_info_disclosed"

    # FP: auth/token mancante (server non avviato, non una vera disclosure)
    if _INFO_DISC_AUTH_MISSING.search(response):
        return "HC-FP", "missing_auth_token_not_information_disclosure"
    # FP: API esterna restituisce 404 o errore — no leakage
    if _INFO_DISC_EXT_API_FP.search(response):
        return "HC-FP", "external_api_error_no_information_leak"
    # FP: errore generico senza dettagli (no info disclosure)
    if _INFO_DISC_GENERIC_ERR.search(response):
        return "HC-FP", "generic_network_or_server_error_no_disclosure"
    # FP: error message normale o tool documentation
    if _INFO_DISC_BENIGN.search(response) and not _INFO_DISC_ACTUAL.search(response):
        return "HC-FP", "normal_error_or_documentation"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: sensitive-info-disclosed
# ═══════════════════════════════════════════════════════════════════════════════

_SID_ACTUAL_CRED = re.compile(
    r"(?:-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY"
    r"|sk-[A-Za-z0-9]{20,}"
    r"|AKIA[A-Z0-9]{16}"
    r"|(?:api_key|token|secret|password|passwd)\s*[=:]\s*[\"']?[A-Za-z0-9+/=_-]{16,}(?:[\"']|\s|$)"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",  # JWT reale
    re.I,
)
# FP: placeholder/sample values masquerading as credentials in response
# (es. README docs containing `token: "your_astra_db_token"`)
_SID_PLACEHOLDER_VALUE = re.compile(
    r"(?:api_key|token|secret|password|passwd)\s*[=:]\s*[\"']?"
    r"(?:your[-_]\w+|<\w[\w-]*>|YOUR[-_]\w+|sample[-_]\w+|"
    r"(?:demo|test|fake|dummy|stub|example)[-_]\w+|"
    r"xxx+|placeholder|api[-_]?key|"
    r"replace[-_]\w+|change[-_]me|to[-_]be[-_]\w+|"
    r"\$\{?\w+\}?|"  # ${ENV_VAR}
    r"<[^>]+>)",
    re.I,
)
# FP: response is README/docs/config example (server returns its own README)
_SID_README_DOCS = re.compile(
    r"(?:'text':\s*'#\s+\w+\s+MCP\s+Server"
    r"|'text':\s*'#\s+Astra\s+DB|MCP\s+Server[^']{0,500}'A\s+Model\s+Context\s+Protocol"
    r"|##\s+Prerequisites|##\s+Adding\s+to\s+an\s+MCP\s+client"
    r"|claude_desktop_config\.json|mcpServers[\"']?\s*:\s*\{)",
    re.I | re.S,
)

_SID_ENV_VAR_DOC = re.compile(
    r"(?:environment\s+variable"
    r"|env\s+var"
    r"|is\s+not\s+set"
    r"|is\s+required"
    r"|must\s+be\s+configured"
    r"|please\s+set"
    r"|please\s+provide"
    r"|not\s+configured"
    r"|missing\s+environment\s+variables?"
    r"|no\s+(?:api\s+)?key\s+(?:found|configured|provided)"
    r"|(?:configure|set)\s+(?:the|your)\s+(?:api|access|secret)\s+key"
    r"|Error:.*(?:KEY|TOKEN|SECRET).*(?:not\s+set|missing|required)"
    r"|API\s+Key\s+Required"
    r"|Set\s+environment\s+variable"
    r"|=false,\s*\w+=false"  # pattern NAVER_API_KEY=false, NAVER_SIGN_KEY=false
    r"|\w+_(?:KEY|TOKEN|SECRET|API|ID)\s*=\s*(?:false|null|none|undefined|<[^>]+>)"  # KEY=false/null
    r"|Connection\s+failed:.*not\s+configured"
    r"|Use\s+the\s+\w+\s+tool\s+to\s+(?:set|configure)"
    r"|(?:configure|setup|initialize)\s+(?:this|the)\s+(?:server|tool|plugin))",
    re.I,
)

# VP: server ha eseguito il payload come comando shell e ritorna exit code + path traversal
# Indica che lo user input finisce in una shell command → information disclosure + command injection
_SID_CMD_EXEC_LEAK = re.compile(
    r"(?:Exit\s+Code:\s+\d+"
    r"|Working\s+Directory:\s+/home/"
    r"|Working\s+Directory:\s+/root/"
    r"|bin/sh:.*etc/passwd"
    r"|bin/bash:.*etc/passwd"
    r"|Permission\s+denied.*etc/passwd"
    r"|etc/passwd.*Permission\s+denied"
    r"|not\s+found.*etc/passwd"
    r"|etc/passwd.*not\s+found)",
    re.I,
)

# FP aggiuntivi sens-info-disclosed-fuzzing
_SID_API_REJECT = re.compile(
    r"(?:Illegal\s+characters|Invalid\s+(?:format|arguments|accession|symbol|input|parameter)"
    r"|validation\s+error|Input\s+validation"
    r"|MCP\s+error\s+-32602"
    r"|400\s+\{[\"']code[\"']:\s*-?\d+"
    r"|invalid_format|invalid_type|invalid_value)",
    re.I,
)
# FP: markdown documentation header all'inizio del text
_SID_MARKDOWN_DOC = re.compile(
    r"['\"]text['\"]:\s*['\"]\\*n?#\s+\w"
    r"|['\"]text['\"]:\s*['\"]\\*n?##\s+\w"
    r"|['\"]text['\"]:\s*['\"]\\*n?>\s+\w"
    r"|^\\*n?#\s+(?:Authentication|Data\s+Storage|Fixture|Pattern|Setup|Configuration|Development|Comprehensive)"
    r"|Comprehensive\s+(?:guide|patterns)\s+for"
    r"|Core\s+Concepts|Pattern\s+[A-Z]:|Issue\s+Details",
    re.I,
)
# FP: i18n error CJK/Arabic (set up/not set in CJK)
_SID_I18N_ERROR = re.compile(
    r"(?:설정되지\s+않|설정\s+예시|Project\s+ID가|API\s+키"
    r"|未设置|未配置|没有.*?key|请配置|请设置"
    r"|キーが|設定されていない|환경\s+변수)",
    re.I,
)
# FP: payload echoed as label/header (not actual execution)
_SID_PAYLOAD_AS_LABEL = re.compile(
    r"(?:Successfully\s+connected\s+to.*?(?:\.\./|file:///)"
    r"|(?:Comparison|Report|Result|Search|Query)\s+for\s+(?:\.\./|file:///|/etc/)"
    r"|['\"]hostname['\"]:\s*['\"](?:file:///|\.\./|/etc/)"
    r"|['\"]symbol['\"]:\s*['\"](?:\.\./|/etc/)"
    r"|Issue\s+Type['\"]?\s*:\s*['\"]?HTTP://"
    r"|on\s+(?:file:///|\.\./).*?:\s*fetch\s+failed)",
    re.I,
)
# FP: shell error "open /home/...; cat /etc/passwd: no such file"
_SID_SHELL_ENOENT = re.compile(
    r"open\s+/(?:home|tmp|root)[^:]+:\s+no\s+such\s+file"
    r"|ENOENT.*?open\s+/"
    r"|MCP\s+error\s+-32603.*?ENOENT",
    re.I,
)
# FP: SYSTEM_INSTRUCTION text (tool description leak, not credential)
_SID_SYSTEM_INSTRUCTION = re.compile(
    r"<SYSTEM_INSTRUCTION>|<SYSTEM>|<INSTRUCTIONS>"
    r"|You\s+are\s+receiving\s+detailed\s+workflow",
    re.I,
)
# VP: actual key material leaked (private_key value visible)
_SID_KEY_MATERIAL = re.compile(
    r"['\"]private_key['\"]:\s*['\"][A-Za-z0-9+/=_-]{20,}"
    r"|['\"]private_key_preview['\"]:\s*['\"][A-Za-z0-9]{6,}"
    r"|['\"]public_key['\"]:\s*['\"][A-Za-z0-9+/=_-]{32,}"
    r"|-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY"
    r"|-----BEGIN\s+CERTIFICATE",
    re.I,
)

def hc_rules_sensitive_info_disclosed(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    response = f.get("response", "")
    payload = f.get("payload", "")

    # ── HC-FP da blind-review (2026-05-06 round 2): PRIMA di check VP ──
    # FP: response è README/docs del server (placeholder values, no real cred)
    if _SID_README_DOCS.search(response):
        return "HC-FP", "response_is_server_readme_or_docs"

    # FP: tool è keypair generator (zetrix_create_keypair, wisdom_generate_keypair, ecc.)
    # Tool RESTITUISCE la chiave per design — non è disclosure di dati sensibili lato server
    if re.search(r"'name'\s*:\s*'(?:\w+_)?(?:create|generate|new|make)_(?:keypair|wallet|key|account|address|mnemonic)'", payload, re.I) or \
       re.search(r"'name'\s*:\s*'(?:keypair|wallet)_(?:create|generate|new)'", payload, re.I):
        return "HC-FP", "keypair_generator_tool_intended_behavior"

    # FP: command execution che ritorna SOLO "Permission denied" / "not found"
    # (NO actual data leak — è solo shell che rifiuta payload come comando)
    if re.search(r"/etc/(?:passwd|shadow):\s*Permission\s+denied", response, re.I):
        return "HC-FP", "shell_rejects_payload_as_command_no_data_leak"
    if re.search(r"file:///etc/(?:passwd|shadow):\s*not\s+found", response, re.I):
        return "HC-FP", "shell_payload_not_found_no_data_leak"
    if re.search(r"exit\s+(?:status|code)\s+12[67].*?Permission\s+denied", response, re.I):
        return "HC-FP", "exit_126_permission_denied_no_leak"
    # FP: pattern "set directory: <payload>: baseDirectoryName is..." (mulmoscript echo)
    if re.search(r"(?:set\s+directory|baseDirectoryName)\s*:\s*[^:]*:\s*baseDirectoryName", response, re.I):
        return "HC-FP", "directory_set_with_payload_echo_no_leak"
    # FP: TypeError parse URL / Error message senza body
    if re.search(r"TypeError:\s*Failed\s+to\s+parse\s+URL", response, re.I):
        return "HC-FP", "url_parse_error_no_data_leak"

    # VP: key material reale (private_key value, BEGIN PRIVATE KEY)
    if _SID_KEY_MATERIAL.search(response):
        return "HC-VP", "actual_key_material_leaked"

    # VP: credenziale reale, ma SOLO se NON è placeholder
    if _SID_ACTUAL_CRED.search(response) and not _SID_PLACEHOLDER_VALUE.search(response):
        return "HC-VP", "actual_credential_value_in_response"

    # VP: server ha eseguito payload + ritorna content reale (NON solo error)
    # Stretto: serve evidence di data leak reale (uid=, root:x:0:0, working dir effettivo)
    if _SID_CMD_EXEC_LEAK.search(response) and re.search(
        r"\buid=\d+\(\w+\)|root:x:0:0:[^:]*:/(?:root|home)|"
        r"Working\s+Directory:\s*/home/\w", response):
        return "HC-VP", "command_exec_with_actual_data_leak"

    # FP: errore documentazione che MENZIONA env var ma non la espone
    if _SID_ENV_VAR_DOC.search(response):
        return "HC-FP", "error_doc_mentions_var_name_not_value"

    # FP: API rejection con codice errore validazione
    if _SID_API_REJECT.search(response):
        return "HC-FP", "api_validation_rejection_no_leak"

    # FP: markdown documentation header all'inizio
    if _SID_MARKDOWN_DOC.search(response):
        return "HC-FP", "markdown_documentation_response"

    # FP: i18n error message (Korean/Chinese/Japanese "not set")
    if _SID_I18N_ERROR.search(response):
        return "HC-FP", "i18n_error_message_var_not_set"

    # FP: payload echoed as label/header
    if _SID_PAYLOAD_AS_LABEL.search(response):
        return "HC-FP", "payload_echoed_as_label_no_execution"

    # FP: shell ENOENT su path test (no actual execution)
    if _SID_SHELL_ENOENT.search(response):
        return "HC-FP", "shell_enoent_no_actual_execution"

    # FP: SYSTEM_INSTRUCTION text (tool description text)
    if _SID_SYSTEM_INSTRUCTION.search(response):
        return "HC-FP", "system_instruction_text_no_credential"

    # FP: tool list o schema
    if _CMD_FUZZ_TOOL_LIST.search(response) or _CMD_FUZZ_DOC_RESPONSE.search(response):
        return "HC-FP", "response_is_tool_list_or_schema"
    # FP: errore di rete (nessuna info divulgata)
    if _INFO_DISC_GENERIC_ERR.search(response):
        return "HC-FP", "network_error_no_sensitive_info"
    # FP: API esterna rifiutata (401/403/404)
    if _INFO_DISC_EXT_API_FP.search(response):
        return "HC-FP", "external_api_rejection_no_disclosure"
    # FP: payload echoed in error senza esecuzione ("File '$(id)' not found" → input non eseguito)
    payload = f.get("payload", "")
    if payload and payload in response and not _SID_ACTUAL_CRED.search(response):
        if re.search(r"not found|invalid|no such|does not exist|failed to (?:open|read|find)", response, re.I):
            return "HC-FP", "payload_echoed_in_error_not_executed"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK: mcp-guard | CATEGORIA: protocol
# ═══════════════════════════════════════════════════════════════════════════════
# Quasi tutti VP: violazioni di protocollo reali.

_PROTO_ACCEPTED_INVALID = re.compile(
    r"""(?:accepts invalid JSON-RPC protocol version|
         accepts requests without required id field|
         server accepted invalid|
         no validation of (?:protocol|jsonrpc|id) field)""",
    re.I | re.X,
)

# VP: path traversal arrivato al filesystem tramite metodo injection
_PROTO_PT_VP = re.compile(
    r"(?:file:///etc/(?:shadow|passwd)"
    r"|/etc/shadow"
    r"|Resource not found\. file:///"
    r"|MCP error.*file:///etc/"
    r"|Invalid resource URI: file:///"
    r"|Method not found:.*tools/\.\."
    r"|Unknown method:.*tools/\.\."
    r"|method.*tools/\.\..*not found"
    r"|tools/\.\..*not found"
    r"|not found.*tools/\.\."
    r"|Method not found:.*\.\./\.\./\.\./etc/"
    r"|'(?:str|list|dict|tuple|NoneType)' object has no attribute"
    r'|"(?:str|list|dict|tuple|NoneType)" object has no attribute'
    r"|object has no attribute '\w+'"
    r'|object has no attribute "\w+")',
    re.I,
)
# FP: errori normali — connessione, auth, tool non trovato, parse error attesi
_PROTO_BENIGN = re.compile(
    r"(?:connection reset by peer"
    r"|read: connection reset"
    r"|connection refused"
    r"|context deadline exceeded"
    r"|i/o timeout"
    r"|tool not found"
    r"|is required but not set"
    r"|authentication required"
    r"|Unterminated string in JSON at position"
    r"|Parse error.*position \d+"
    r"|API error: Not Found"
    r"|not set\. Please set it"
    r"|'result': \{'(?:prompts|tools|resources)'"
    r"|'result': \{'nextCursor"
    r"|result.*prompts.*\[\]"
    r"|result.*tools.*\[\])",
    re.I,
)

def hc_rules_protocol(f: dict) -> tuple[str, str]:
    if is_honeypot(f):
        return "HC-FP", "honeypot_server"
    desc = f.get("description", "")
    response = f.get("response", "")

    # VP: server accetta richieste non valide secondo spec MCP/JSON-RPC (dal desc)
    if _PROTO_ACCEPTED_INVALID.search(desc):
        return "HC-VP", "server_accepts_invalid_protocol_request"

    # VP: path traversal o implementation detail leak nella response
    if _PROTO_PT_VP.search(response):
        return "HC-VP", "path_traversal_or_impl_leak_in_response"

    # FP: errori di connessione, auth, tool-not-found, parse error normali
    if _PROTO_BENIGN.search(response):
        return "HC-FP", "network_auth_or_normal_error_not_protocol_violation"

    return "UNCERTAIN", "needs_manual_review"


# ═══════════════════════════════════════════════════════════════════════════════
# Dispatcher HC Rules
# ═══════════════════════════════════════════════════════════════════════════════

HC_RULES = {
    # STATIC (9)
    "ssrf-static":                       hc_rules_ssrf,
    "hardcoded-credential-static":       hc_rules_hardcoded_credential,
    "sql-injection-static":              hc_rules_sql_injection,
    "dangerous-tool-handler-static":     hc_rules_dangerous_tool_handler,
    "path-traversal-static":             hc_rules_path_traversal_static,
    "prompt-injection-static":           hc_rules_prompt_injection_static,
    "insecure-deserialization-static":   hc_rules_insecure_deserialization,
    "code-injection-static":             hc_rules_code_injection_static,
    "command-injection-static":          hc_rules_command_injection_static,
    # FUZZING (6)
    "command-injection-fuzzing":         hc_rules_command_injection_fuzzing,
    "path-traversal-fuzzing":            hc_rules_path_traversal_fuzzing,
    "command-execution-fuzzing":         hc_rules_command_execution_fuzzing,
    "code-injection-fuzzing":            hc_rules_code_injection_fuzzing,
    "information-disclosure-fuzzing":    hc_rules_information_disclosure_fuzzing,
    "sensitive-info-disclosed-fuzzing":  hc_rules_sensitive_info_disclosed,
    # PROTOCOL (4) — tutti usano hc_rules_protocol per ora
    "protocol-information-disclosure":   hc_rules_protocol,
    "protocol-path-traversal":           hc_rules_protocol,
    "protocol-missing-id":               hc_rules_protocol,
    "protocol-invalid-jsonrpc-version":  hc_rules_protocol,
}


# ── I/O helpers ───────────────────────────────────────────────────────────────

def load_filtered(cat: str):
    """Ritorna (findings: list, meta: dict) dal file *_filtered.json."""
    safe = cat.replace("/", "_").replace("-", "_")
    p = BASE_DIR / cat / "filtered" / f"{safe}_filtered.json"
    if not p.exists():
        print(f"  [WARN] {p} non trovato. Esegui prima stage1_filter.py")
        return [], {}
    with open(p, encoding="utf-8") as fh:
        data = json.load(fh)
    meta = {
        "original_total": data.get("original_total", 0),
        "filter_kept_total": data.get("kept_total", len(data.get("findings", []))),
    }
    return data.get("findings", []), meta

def load_cache(cat: str) -> dict:
    p = BASE_DIR / cat / "filtered" / "llm_analysis" / "_llm_api_cache.json"
    if p.exists():
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    return {}

def save_cache(cat: str, cache: dict):
    d = BASE_DIR / cat / "filtered" / "llm_analysis"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "_llm_api_cache.json", "w", encoding="utf-8") as fh:
        json.dump(cache, fh, ensure_ascii=False, indent=2)

def save_bucket(cat: str, name: str, items: list, meta: dict | None = None):
    d = BASE_DIR / cat / "filtered" / "llm_analysis"
    d.mkdir(parents=True, exist_ok=True)
    bucket_label = {"hc_vp": "HC-VP", "hc_fp": "HC-FP", "uncertain": "UNCERTAIN"}.get(name, name.upper())
    payload = {
        "category": cat,
        "original_total": (meta or {}).get("original_total", 0),
        "filter_kept_total": (meta or {}).get("filter_kept_total", 0),
        "bucket": bucket_label,
        "total": len(items),
        "findings": items,
    }
    with open(d / f"{name}.json", "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)

def save_merge(cat: str, vp: list, fp: list, audit: list):
    d = BASE_DIR / cat / "filtered" / "llm_analysis"
    d.mkdir(parents=True, exist_ok=True)
    # Recupera metadati dal bucket hc_vp se disponibile (ha original_total / filter_kept_total)
    meta_src = d / "hc_vp.json"
    base_meta: dict = {}
    if meta_src.exists():
        try:
            _m = json.load(open(meta_src, encoding="utf-8"))
            if isinstance(_m, dict):
                base_meta = {k: _m[k] for k in ("original_total", "filter_kept_total") if k in _m}
        except Exception:
            pass
    for name, items in [("vp", vp), ("fp", fp), ("audit", audit)]:
        payload = {"category": cat, **base_meta, "total": len(items), "findings": items}
        with open(d / f"{name}.json", "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)


# ── Stage 2A ─────────────────────────────────────────────────────────────────

def run_hc_only(cat: str, no_cache: bool = False):
    findings, meta = load_filtered(cat)
    if not findings:
        return
    hc_fn = HC_RULES.get(cat)
    if not hc_fn:
        print(f"  [WARN] Nessuna regola HC per {cat}")
        return

    hc_vp, hc_fp, uncertain = [], [], []
    for f in findings:
        verdict, reason = hc_fn(f)
        f["_hc_verdict"] = verdict
        f["_hc_reason"]  = reason
        if verdict == "HC-VP":
            hc_vp.append(f)
        elif verdict == "HC-FP":
            hc_fp.append(f)
        else:
            uncertain.append(f)

    save_bucket(cat, "hc_vp", hc_vp, meta)
    save_bucket(cat, "hc_fp", hc_fp, meta)
    save_bucket(cat, "uncertain", uncertain, meta)

    tot = len(findings)
    print(f"  [{cat}] {tot:,} findings → "
          f"HC-VP={len(hc_vp)} ({len(hc_vp)/tot*100:.1f}%), "
          f"HC-FP={len(hc_fp)} ({len(hc_fp)/tot*100:.1f}%), "
          f"UNCERTAIN={len(uncertain)} ({len(uncertain)/tot*100:.1f}%)")


# ── Stage 2B — Ollama ─────────────────────────────────────────────────────────

def _build_prompt(f: dict, cat: str) -> str:
    desc  = f.get("description", "")
    code  = extract_code(desc)
    sname = f.get("server_name", "")
    file  = f.get("file", "")
    payload  = f.get("payload", "")[:300] if f.get("payload") else ""
    response = f.get("response", "")[:500] if f.get("response") else ""

    ctx = f"Server: {sname}\nFile: {file}\n"
    if code:
        ctx += f"Code: {code[:300]}\n"
    if payload:
        ctx += f"Payload: {payload}\n"
    if response:
        ctx += f"Response: {response}\n"

    return (
        f"You are a security expert reviewing mcp-guard findings. "
        f"Category: {cat}\n\n{ctx}\n"
        f"Is this a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE (noise)?\n"
        f"Reply with exactly: VP: <reason> or FP: <reason>"
    )

def _call_ollama(prompt: str, model: str, url: str) -> str:
    body = json.dumps({"model": model, "prompt": prompt,
                       "temperature": 0, "stream": False}).encode()
    req = urllib.request.Request(
        f"{url}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    return data.get("response", "").strip()

def run_stage2b(cat: str, uncertain: list, cache: dict, model: str, ollama_url: str,
                dry_run: bool = False, no_cache: bool = False) -> dict:
    """Classifica UNCERTAIN via Ollama/cache. Ritorna {cache_key: {verdict, reason}}."""
    results = {}
    for f in uncertain:
        key = _cache_key(f, cat)
        if not no_cache and key in cache:
            entry = cache[key]
            results[key] = entry
            continue
        prompt = _build_prompt(f, cat)
        if dry_run:
            print(f"\n[DRY-RUN] {key}\n{prompt[:200]}...")
            continue
        try:
            raw = _call_ollama(prompt, model, ollama_url)
            if raw.upper().startswith("VP"):
                verdict = "VP"
            elif raw.upper().startswith("FP"):
                verdict = "FP"
            else:
                verdict = "UNCERTAIN"
            reason = raw.split(":", 1)[-1].strip() if ":" in raw else raw[:80]
            entry = {"verdict": verdict, "reason": reason}
            cache[key] = entry
            results[key] = entry
        except Exception as e:
            print(f"  [WARN] Ollama error per {key}: {e}")
    return results


# ── Merge ─────────────────────────────────────────────────────────────────────

def run_merge(cat: str, cache: dict):
    """Legge hc_vp, hc_fp, uncertain + cache → vp.json, fp.json, audit.json."""
    d = BASE_DIR / cat / "filtered" / "llm_analysis"

    def load_bucket(name):
        p = d / f"{name}.json"
        if not p.exists():
            return []
        data = json.load(open(p, encoding="utf-8"))
        # supporta sia formato lista nudo (vecchio) che dict con 'findings' (nuovo)
        return data.get("findings", data) if isinstance(data, dict) else data

    hc_vp     = load_bucket("hc_vp")
    hc_fp     = load_bucket("hc_fp")
    uncertain = load_bucket("uncertain")

    vp_final, fp_final, audit = list(hc_vp), list(hc_fp), []

    for f in hc_vp:
        audit.append({**f, "_stage": "HC-VP", "_final_verdict": "VP"})
    for f in hc_fp:
        audit.append({**f, "_stage": "HC-FP", "_final_verdict": "FP"})
    for f in uncertain:
        key = _cache_key(f, cat)
        entry = cache.get(key, {})
        verdict = entry.get("verdict", "UNCERTAIN")
        reason  = entry.get("reason", "not_in_cache")
        f["_llm_verdict"] = verdict
        f["_llm_reason"]  = reason
        if verdict == "VP":
            vp_final.append(f)
            audit.append({**f, "_stage": "Stage2B", "_final_verdict": "VP"})
        elif verdict == "FP":
            fp_final.append(f)
            audit.append({**f, "_stage": "Stage2B", "_final_verdict": "FP"})
        else:
            audit.append({**f, "_stage": "Stage2B", "_final_verdict": "UNCERTAIN"})

    save_merge(cat, vp_final, fp_final, audit)
    uncached = sum(1 for f in uncertain if _cache_key(f, cat) not in cache)
    print(f"  [{cat}] VP={len(vp_final)}, FP={len(fp_final)}, "
          f"still-UNCERTAIN={uncached}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="stage2_pipeline.py — Stage 2A + 2B + merge")
    parser.add_argument("--category", default="all",
                        help="Categoria da processare (default: all)")
    parser.add_argument("--hc-only", action="store_true",
                        help="Solo Stage 2A: produce hc_vp, hc_fp, uncertain")
    parser.add_argument("--cache-only", action="store_true",
                        help="Merge usando solo la cache pre-popolata (no Ollama)")
    parser.add_argument("--merge", action="store_true",
                        help="Stage 2A + 2B (Ollama) + merge")
    parser.add_argument("--model", default="llama3",
                        help="Modello Ollama (default: llama3)")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="URL Ollama")
    parser.add_argument("--no-cache", action="store_true",
                        help="Ignora cache esistente")
    parser.add_argument("--dry-run", action="store_true",
                        help="Mostra prompt senza chiamare Ollama")
    args = parser.parse_args()

    cats = CATEGORIES if args.category == "all" else [args.category]

    for cat in cats:
        print(f"\n{'='*60}")
        print(f"  Categoria: {cat}")
        print(f"{'='*60}")

        if args.hc_only:
            run_hc_only(cat, no_cache=args.no_cache)

        elif args.cache_only:
            run_hc_only(cat, no_cache=args.no_cache)
            cache = load_cache(cat)
            run_merge(cat, cache)

        elif args.merge:
            run_hc_only(cat, no_cache=args.no_cache)
            cache = {} if args.no_cache else load_cache(cat)
            d = BASE_DIR / cat / "filtered" / "llm_analysis"
            d.mkdir(parents=True, exist_ok=True)
            unc_file = d / "uncertain.json"
            if unc_file.exists():
                _unc_raw = json.load(open(unc_file, encoding="utf-8"))
                uncertain = _unc_raw.get("findings", _unc_raw) if isinstance(_unc_raw, dict) else _unc_raw
            else:
                uncertain = []
            if uncertain:
                print(f"  Stage 2B: {len(uncertain)} UNCERTAIN → Ollama ({args.model})")
                run_stage2b(cat, uncertain, cache, args.model, args.ollama_url,
                            dry_run=args.dry_run, no_cache=args.no_cache)
                save_cache(cat, cache)
            run_merge(cat, cache)

        else:
            parser.print_help()
            break

    print("\nDone.")


if __name__ == "__main__":
    main()
