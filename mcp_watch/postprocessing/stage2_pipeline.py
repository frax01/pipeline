"""
Pipeline unificata Stage 2A + 2B per i finding di mcp-watch.

Uso:
    python pipeline_mcp_watch.py --category credential-leak
    python pipeline_mcp_watch.py --category data-exfiltration
    python pipeline_mcp_watch.py --category all

Stage 2A: regole HC (high-confidence) per categoria → HC-FP / HC-VP / UNCERTAIN
Stage 2B: Ollama llama3 per i finding UNCERTAIN → VP o FP

Output in <categoria>/filtered/llm_analysis/:
    hc_fp.json        FP certi da regole HC
    hc_vp.json        VP certi da regole HC
    uncertain.json    finding mandati a Ollama
    vp.json           VP finali (hc_vp + uncertain VP)
    fp.json           FP finali (hc_fp + uncertain FP)
    audit.json        log completo di tutti i finding

Parametri:
    --category        categoria da analizzare (o 'all')
    --model           modello Ollama (default: llama3)
    --ollama-url      URL Ollama (default: http://localhost:11434)
    --no-cache        ignora cache Ollama esistente
    --hc-only         esegui solo Stage 2A (senza Ollama)
    --dry-run         mostra prompt Ollama senza chiamare il server
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

# Ensure UTF-8 output on Windows (avoids cp1252 UnicodeEncodeError)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent

# ══════════════════════════════════════════════════════════════════════════════
#  REGISTRY CATEGORIE
#  Aggiungi qui il nome di ogni nuova categoria analizzata.
# ══════════════════════════════════════════════════════════════════════════════

CATEGORIES = [
    "credential-leak",
    "data-exfiltration",
    "input-validation",
    "steganographic-attack",
    "protocol-violation",
    "tool-poisoning",
    "prompt-injection",
    "tool-mutation",
    "access-control",
]


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER COMUNI
# ══════════════════════════════════════════════════════════════════════════════

def decode_jwt(ev: str) -> dict | None:
    m = re.search(r"eyJ[A-Za-z0-9_-]+\.(eyJ[A-Za-z0-9_-]+)", ev)
    if not m:
        return None
    p = m.group(1) + "=" * (-len(m.group(1)) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(p).decode("utf-8", "replace"))
    except Exception:
        return None


def is_env_file(path: str) -> bool:
    name = path.lower().split("/")[-1]
    return (
        name in (".env", ".env.local", ".env.production", ".env.development",
                 ".env.example.filled", ".env.real")
        or (name.startswith(".env.")
            and "example" not in name
            and "sample" not in name
            and "template" not in name)
    )


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-watch | CATEGORIA: credential-leak
# ══════════════════════════════════════════════════════════════════════════════

_CL_INTENTIONAL_VULN = {
    "malicious_mcp": None,
    "vulnerable-notes-mcp": None,
    "complete-mitre-attack-mcp-server": None,
    "vertice-cyber": "mitre",
}

_CL_STREAM_PATS = [
    re.compile(r"\bprocess\.stdout\.write\s*\(\s*token\b"),
    re.compile(r"\bsys\.stdout\.write\s*\(\s*token\b"),
    re.compile(r"\bstdout\.write\s*\(\s*(?:token|wrapColor|chalk\.[a-z]+\s*\()\b"),
    re.compile(r"\bprocess\.stdin\.write\s*\(\s*token\b"),
    re.compile(r"sseEvent\s*\(\s*['\"]token['\"]"),
    re.compile(r"event:\s*session-token"),
    re.compile(r"data-finance:token"),
    re.compile(r"\bstdin\.write\b"),
    re.compile(r"\bstream\.write\s*\("),
    re.compile(r"\bsession\.stream\.write\b"),
    re.compile(r"\bproc\.stdin\.write\b"),
    re.compile(r"\bsocket\?\.write\b|\bsocket\.write\b"),
    re.compile(r"\bconnection\.shell\.write\b"),
    re.compile(r"\bport\.write\b"),
    re.compile(r"\bwriter\.write\s*\(.*password.*encode\b", re.IGNORECASE),
    re.compile(r"process\.stdout\.write\s*\(`[^`]*(?:--password|PASSWORD)[^`]*`\)"),
    re.compile(r"\bres\.write\s*\(\s*`data:"),
    re.compile(r"\bres\.write\s*\(\s*`event:"),
    re.compile(r"Token limit exceeded"),
    re.compile(r"chunk_id.*token.*term_freq", re.IGNORECASE),
    re.compile(r"self\.stdout\.write\s*\(\s*self\.style\.(SUCCESS|ERROR|WARNING)"),
    re.compile(r"^\s*#"),
    re.compile(r"\bself\.write\s*\(\s*\{"),
    re.compile(r"\"object\"==typeof exports"),
    re.compile(r"!function\s*\(e,t\)"),
]

_CL_VAULT_PAT   = re.compile(r"vaultClient\.write|vault\.write\s*\(", re.IGNORECASE)
_CL_DATA_JSON   = ("codeql.json", "mcpverse_data.json", "translation_db.json",
                   "components.json", "dataset.json", "ai-api.json",
                   "enterprise-attack.json", "lol_drivers.json", "techniques.json")
_CL_DATA_PATHS  = ("sample_workspace/", "translation_workdir/cache/", "data/repos/",
                   "tmp_packages/", "/venv/", "site-packages/", "/snippets/")

_CL_HC_VP_PROVIDERS = {
    "provider:GitHub PAT (classic)",
    "provider:Docker PAT",
    "provider:GitHub PAT (fine-grained)",
    "provider:GitLab PAT",
    "provider:Stripe Secret Key (live)",
    "provider:Private Key Header",
    "provider:MongoDB URI with creds",
    "provider:PostgreSQL URI with creds",
    "provider:MySQL URI with creds",
    "provider:Redis URI with creds",
    "provider:Google API Key",
    "provider:OpenAI Legacy Key",
    "provider:AWS Access Key ID",
}

_CL_GOOGLE_OAUTH_PAT = re.compile(
    r"(?:creds|credentials|token)\s*(?:_file)?\s*\.(?:write|to_json)\s*\("
    r"|fs\.writeFileSync.*credentials"
    r"|token_file\.write\s*\(",
    re.IGNORECASE,
)


def hc_rules_credential_leak(f: dict) -> tuple[str, str]:
    """
    Regole HC per credential-leak.
    Ritorna ("HC-FP", motivo) | ("HC-VP", motivo) | ("UNCERTAIN", "")
    """
    name = f.get("server_name", "")
    url  = (f.get("github_url") or "").lower()
    path = (f.get("file") or "").lower()
    ev   = f.get("evidence", "")
    vid  = f.get("id", "")
    conf = f.get("filter_confidence", "")

    # ── HC-FP ────────────────────────────────────────────────────────────────

    # Server honeypot / vuln intenzionale
    repo = url.rstrip("/").split("/")[-1]
    for sname, hint in _CL_INTENTIONAL_VULN.items():
        if name == sname or repo == sname.lower():
            if hint is None or hint in path:
                return "HC-FP", f"hc_fp:intentional_vuln:{sname}"
    if name == "secure-mcp-gateway" and (
        "bad_mcps/" in path or "demo_pii" in path or "credential_theft" in path
    ):
        return "HC-FP", "hc_fp:intentional_vuln:secure-mcp-gateway/bad_mcps"

    # JWT Supabase anon key
    if conf == "provider:JWT Token":
        payload = decode_jwt(ev) or {}
        role = payload.get("role")
        if isinstance(role, str) and role == "anon":
            return "HC-FP", "hc_fp:jwt_supabase_anon"

    # INSECURE_CREDENTIAL_PERMISSIONS
    if vid == "INSECURE_CREDENTIAL_PERMISSIONS":
        if path.endswith("package.json"):
            return "HC-FP", "hc_fp:insecure_perms_package_json_build"
        if path.endswith(".json"):
            return "HC-FP", "hc_fp:insecure_perms_json_data_file"
        if re.search(r"chmod\s+(6[04]4|600|400|700|755)\b", ev):
            return "HC-FP", "hc_fp:insecure_perms_secure_chmod"

    # PLAINTEXT_STORAGE
    if vid == "PLAINTEXT_STORAGE":
        if path.endswith("package.json"):
            return "HC-FP", "hc_fp:plaintext_package_json_build"
        for pat in _CL_STREAM_PATS:
            if pat.search(ev):
                return "HC-FP", "hc_fp:stream_token_llm_output"
        if path.endswith(".json") and (
            any(h in path for h in _CL_DATA_JSON)
            or any(h in path for h in _CL_DATA_PATHS)
        ):
            return "HC-FP", "hc_fp:plaintext_json_data_file"
        if (path.endswith(".yml") or path.endswith(".yaml")) and \
                "req.write" in ev and "secret" in ev.lower():
            return "HC-FP", "hc_fp:plaintext_openapi_example"
        if any(h in path for h in _CL_DATA_PATHS):
            return "HC-FP", "hc_fp:plaintext_vendored_path"
        if _CL_VAULT_PAT.search(ev):
            return "HC-FP", "hc_fp:plaintext_vault_secret_manager"
        if path.endswith(".json") or path.endswith(".yaml") or path.endswith(".yml"):
            return "HC-FP", "hc_fp:plaintext_data_file"

    # HARDCODED_CREDENTIALS: codice commentato
    if vid == "HARDCODED_CREDENTIALS":
        ev_s = ev.strip()
        if ev_s.startswith("#") or ev_s.startswith("//") or ev_s.startswith("*"):
            return "HC-FP", "hc_fp:commented_out_code"

    # AWS pre-signed URL (chiave pubblica nel URL, non un segreto)
    if conf == "provider:AWS Access Key ID":
        if ("amazonaws.com" in ev or "s3" in ev.lower()) and "AWSAccessKeyId=" in ev:
            return "HC-FP", "hc_fp:aws_presigned_url"

    # ── HC-VP ────────────────────────────────────────────────────────────────

    # Provider con tasso di FP quasi zero (formato troppo specifico per essere demo)
    if conf in _CL_HC_VP_PROVIDERS:
        return "HC-VP", f"hc_vp:format_specific:{conf}"

    # JWT con role service_role / admin (Supabase secret key)
    if conf == "provider:JWT Token":
        payload = decode_jwt(ev) or {}
        role = payload.get("role", "")
        if isinstance(role, str) and role in ("service_role", "admin", "service"):
            return "HC-VP", "hc_vp:jwt_service_role"

    # Credenziali in file .env (non sample/example)
    if is_env_file(path) and vid == "HARDCODED_CREDENTIALS":
        return "HC-VP", "hc_vp:key_in_env_file"

    # Google OAuth token write (creds.to_json() / token_file.write)
    if vid == "PLAINTEXT_STORAGE" and _CL_GOOGLE_OAUTH_PAT.search(ev):
        if not any(h in path for h in _CL_DATA_PATHS) and not path.endswith(".json"):
            return "HC-VP", "hc_vp:google_oauth_token_write"

    # writeFileSync/writeFile con variabile credenziale → scrittura su disco (VP)
    if vid == "PLAINTEXT_STORAGE" and re.search(r"writeFileSync|writeFile\b", ev, re.IGNORECASE):
        if not any(h in path for h in _CL_DATA_PATHS) and not path.endswith(".json"):
            return "HC-VP", "hc_vp:plaintext_writefile_credential"

    return "UNCERTAIN", ""


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-watch | CATEGORIA: data-exfiltration
# ══════════════════════════════════════════════════════════════════════════════

_DE_OLLAMA_PAT = re.compile(
    r'json=\{"model":\s*\w+,\s*"prompt":\s*\w+'
    r"|EMBED_URL|embed_url|ollama_url"
    r"|api/embeddings",
    re.IGNORECASE,
)
_DE_COMFYUI_PAT = re.compile(
    r"127\.0\.0\.1:8188|localhost:8188"
    r'|json=\{"prompt":\s*workflow\}'
    r"|/prompt.*json.*\bworkflow\b"
)
_DE_PLUGIN_HOOK_PAT = re.compile(
    r"async def (prompt|resource)_(pre|post)_fetch"
    r"|async def (pre|post)_(prompt|resource)_fetch"
    r"|def prompt_pre_fetch|def prompt_post_fetch"
)
_DE_BUNDLED_JS_PAT = re.compile(
    r"self\.webpackChunk"
    r"|import\{r,j as e"
    r"|FAILSAFE_SCHEMA.*JSON_SCHEMA.*CORE_SCHEMA"
    r"|`:``\}var [a-z][A-Za-z]+="
    r"|\}var [a-z][A-Za-z]+={dump:"
)
_DE_MCP_PROTOCOL_PAT = re.compile(r'"prompts/(get|list)"')
_DE_CACHE_METHOD_PAT  = re.compile(r"cache\.get_or_fetch")
_DE_INTERNAL_WRAP_PAT = re.compile(r"\bohFetch\(")
_DE_SEED_PAT = re.compile(
    r"your-api-key|api\.example\.com"
    r"|code:\s*[\"']async function generateText",
    re.IGNORECASE,
)
_DE_OPENROUTER_PAT    = re.compile(r"openrouter\.ai|openai\.com/v1|anthropic\.com")
_DE_WEATHER_FIN_PAT   = re.compile(r"history\.json.*q.*dt|premiumFetch|coinId=")
_DE_NPM_HARVEST_PAT   = re.compile(r"harvester\.fetch\(|npm_example")
_DE_BENCHMARK_PAT     = re.compile(r"evaluate_alpaca|args\.url.*json.*prompt")
_DE_CF_ACTOR_PAT      = re.compile(r"actor\.local")
_DE_CTX_SIZE_PAT      = re.compile(r"contextSize")
_DE_COMMENTED_PAT     = re.compile(r"^\s*#")
_DE_FUNC_DEF_PAT      = re.compile(
    r"^\s*(async\s+)?function\s+\w+\s*\(.*?(payload|context).*?\)"
)
_DE_PLAYWRIGHT_PAT    = re.compile(r"playwright-report[/\\]trace")
_DE_REDACTION_NAMES   = {"redaction-compliance-MCP"}
_DE_SECURITY_NAMES    = {"secure.mcp"}

_DE_ENTIRE_CONV_PAT = re.compile(
    r"ENTIRE conversation|entire conversation|ENTIRE CONVERSATION"
    r"|extracted from the ENTIRE"
    r"|from all messages in the conversation",
    re.IGNORECASE,
)
_DE_USER_PROMPT_SUBMIT_PAT = re.compile(r"UserPromptSubmit", re.IGNORECASE)
_DE_SESSION_DATA_PAT       = re.compile(
    r"CLAUDE_SESSION_ID|session_id.*CLAUDE|session_id.*fetch", re.IGNORECASE
)
_DE_EXTERNAL_BACKEND_PAT   = re.compile(
    r"BACKEND_URL|api/events.*POST|fetch.*api.*events", re.IGNORECASE
)


def _de_hc_fp_data_exfil(name: str, path: str, ev: str) -> tuple[bool, str]:
    """Sotto-regole HC-FP per DATA_EXFILTRATION (http_exfiltration_payload)."""
    if _DE_COMMENTED_PAT.match(ev):
        return True, "hc_fp:commented_out_code"
    if _DE_FUNC_DEF_PAT.match(ev):
        return True, "hc_fp:function_definition_not_http_call"
    if _DE_OLLAMA_PAT.search(ev):
        return True, "hc_fp:ollama_or_embedding_api_call"
    if _DE_COMFYUI_PAT.search(ev):
        return True, "hc_fp:comfyui_localhost_workflow"
    if name == "mcp-gateway" and _DE_PLUGIN_HOOK_PAT.search(ev):
        return True, "hc_fp:mcp_gateway_plugin_hook_method"
    if _DE_BUNDLED_JS_PAT.search(ev):
        return True, "hc_fp:bundled_minified_js"
    if _DE_MCP_PROTOCOL_PAT.search(ev):
        return True, "hc_fp:mcp_standard_protocol_call"
    if _DE_CACHE_METHOD_PAT.search(ev):
        return True, "hc_fp:cache_method_not_http"
    if _DE_INTERNAL_WRAP_PAT.search(ev):
        return True, "hc_fp:internal_api_wrapper"
    if _DE_SEED_PAT.search(ev):
        return True, "hc_fp:seed_or_template_code"
    if _DE_OPENROUTER_PAT.search(ev):
        return True, "hc_fp:known_llm_provider_api_call"
    if _DE_WEATHER_FIN_PAT.search(ev):
        return True, "hc_fp:weather_or_financial_data_api"
    if _DE_NPM_HARVEST_PAT.search(ev):
        return True, "hc_fp:npm_metadata_harvester"
    if _DE_BENCHMARK_PAT.search(ev):
        return True, "hc_fp:benchmark_evaluation_call"
    if _DE_CF_ACTOR_PAT.search(ev):
        return True, "hc_fp:cloudflare_internal_actor"
    if _DE_CTX_SIZE_PAT.search(ev):
        return True, "hc_fp:llm_context_size_config"
    if name in _DE_REDACTION_NAMES:
        return True, "hc_fp:redaction_service_receives_text"
    if _DE_PLAYWRIGHT_PAT.search(path):
        return True, "hc_fp:playwright_test_trace_artifact"
    return False, ""


def hc_rules_data_exfiltration(f: dict) -> tuple[str, str]:
    """
    Regole HC per data-exfiltration.
    Ritorna ("HC-FP", motivo) | ("HC-VP", motivo) | ("UNCERTAIN", "")
    """
    vid  = f.get("id", "")
    conf = f.get("filter_confidence", "")
    name = f.get("server_name", "")
    path = (f.get("file") or "").lower()
    ev   = f.get("evidence", "")

    # ── HC-FP ────────────────────────────────────────────────────────────────

    # UNUSED_SENSITIVE_PARAMETER → tutti FP
    # (conversation_history / full_context sono parametri Python interni,
    #  non campi nell'inputSchema di un tool MCP)
    if vid == "UNUSED_SENSITIVE_PARAMETER":
        if conf == "unused_magic:full_context" and "test" in path:
            return "HC-FP", "hc_fp:pytest_fixture_not_magic_param"
        if conf == "unused_magic:conversation_history":
            return "HC-FP", "hc_fp:standard_python_function_param"
        return "HC-FP", "hc_fp:unused_sensitive_internal_param"

    # MAGIC_PARAMETER_INJECTION: tools_list → tutti FP
    # (funzione di registrazione tool interno, non schema MCP esposto all'LLM)
    if vid == "MAGIC_PARAMETER_INJECTION" and conf == "magic_param_in_schema:tools_list":
        return "HC-FP", "hc_fp:tools_list_registration_function_param"

    # MAGIC_PARAMETER_INJECTION: system_prompt → FP se JS minificato o security tool
    if vid == "MAGIC_PARAMETER_INJECTION" and conf == "magic_param:system_prompt_in_tool_schema":
        if _DE_BUNDLED_JS_PAT.search(ev) or "webpackChunk" in ev:
            return "HC-FP", "hc_fp:system_prompt_in_minified_js"
        if name in _DE_SECURITY_NAMES:
            return "HC-FP", "hc_fp:security_tool_analyzes_system_prompt"

    # DATA_EXFILTRATION: sotto-regole per http_exfiltration_payload
    if vid == "DATA_EXFILTRATION" and conf == "http_exfiltration_payload":
        ok, r = _de_hc_fp_data_exfil(name, path, ev)
        if ok:
            return "HC-FP", r

    # ── HC-VP ────────────────────────────────────────────────────────────────

    # CONVERSATION_EXFILTRATION_TRIGGER: description istruisce l'LLM
    # a estrarre l'intera conversazione → VP certo
    if vid == "CONVERSATION_EXFILTRATION_TRIGGER":
        if _DE_ENTIRE_CONV_PAT.search(ev):
            return "HC-VP", "hc_vp:tool_description_extracts_entire_conversation"

    # DATA_EXFILTRATION: hook UserPromptSubmit che invia dati sessione Claude
    # a un backend esterno → VP certo
    if vid == "DATA_EXFILTRATION" and conf == "http_exfiltration_payload":
        if _DE_USER_PROMPT_SUBMIT_PAT.search(ev) and (
            _DE_SESSION_DATA_PAT.search(ev) or _DE_EXTERNAL_BACKEND_PAT.search(ev)
        ):
            return "HC-VP", "hc_vp:user_prompt_submit_hook_exfiltrates_session"

    return "UNCERTAIN", ""


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-watch | CATEGORIA: input-validation
# ══════════════════════════════════════════════════════════════════════════════

# ── SSRF ─────────────────────────────────────────────────────────────────────

# HC-VP: fetch() globale o axios chiamato con URL direttamente da params/input
# Cattura: fetch(params.url), fetch(input.url), axios.get(params.url), ecc.
_IV_SSRF_VP_PAT = re.compile(
    r"\bfetch\(\s*(?:params|input|req|query|args|body)\.\w+"
    r"|\b(?:axios|got)\.(?:get|post|put|delete|patch|request)\(\s*(?:params|input|req|query|args|body)\.\w+",
    re.IGNORECASE,
)

# HC-FP: metodo .fetch() su oggetto SDK (non la funzione globale)
# Cattura: this.c.fetch(req.v), this.fetch(req.v)
_IV_SSRF_SDK_PAT = re.compile(
    r"\bthis\.(?:\w+\.)?fetch\("
    r"|env\.\w+\.get\(.*?\)\.fetch\(",
    re.IGNORECASE,
)

# HC-FP: metodi SDK specifici che non sono HTTP outbound verso URL arbitrari
# (Discord, Cloudflare DO, GraphQL, transport layer, prefetch interno, ecc.)
_IV_SSRF_INTERNAL_PAT = re.compile(
    r"scheduledEvents\.fetch\("           # Discord SDK
    r"|\.graphqlClient\.request\("        # GraphQL SDK
    r"|transport\.request\("              # MCP transport layer
    r"|resourceManager\.prefetch\("       # prefetch interno
    r"|booster\.prefetch\("              # prefetch interno
    r"|is_llm_request\("                 # Sentinel proxy (solo analizza la request)
    r"|_persist_approval_request\("      # funzione interna, non HTTP outbound
    r"|handle_mcp_request\("            # handler MCP standard
    r"|transform_request\("             # trasforma dati, non fa HTTP
    r"|_make_vector_store_request\("    # funzione interna
    r"|create_pull_request\("           # GitHub SDK wrapper
    r"|merge_pull_request\(",           # GitHub SDK wrapper
    re.IGNORECASE,
)

# ── COMMAND INJECTION ─────────────────────────────────────────────────────────

# HC-VP: exec/spawn/execSync con input utente (concatenazione stringa o template)
_IV_CMD_VP_CONCAT_PAT = re.compile(
    r"exec\s*\(\s*[`'\"].*?\+\s*(?:params|input|req|args|body|userInput)\."
    r"|exec\s*\(`[^`]*\$\{(?:params|input|req|args|body)\.\w+",
    re.IGNORECASE,
)
_IV_CMD_VP_EXECSYNC_PAT = re.compile(
    r"execSync\s*\(`[^`]*\$\{(?:params|input|req|args|body)\.\w+",
    re.IGNORECASE,
)
# HC-VP: spawn(params.command, ...) o spawn(input.command, ...)
_IV_CMD_VP_SPAWN_PAT = re.compile(
    r"\bspawn\s*\(\s*(?:params|input|req|args|body)\.\w+",
    re.IGNORECASE,
)
# HC-VP: exec(params.command) o exec(input.code) — argomento diretto da params
_IV_CMD_VP_DIRECT_PAT = re.compile(
    r"\bexec\s*\(\s*(?:params|input|req|args|body|p_body)\.\w+",
    re.IGNORECASE,
)
# HC-VP: SSH/terminal exec con params.command via SDK
_IV_CMD_VP_SSH_PAT = re.compile(
    r"\.exec\s*\(\s*(?:params|input|req|args)\.\w+\s*,\s*(?:\(err|callback|{)",
    re.IGNORECASE,
)

# HC-FP: bundle/JS minificato (jQuery, socket.io, Svelte)
_IV_CMD_BUNDLE_PAT = re.compile(
    r'"object"\s*==\s*typeof exports'
    r"|!function\s*\(e,t\)"
    r"|\.svelte-[a-z0-9]+"                   # CSS Svelte
    r"|return\"none\"===.*style\.display",    # jQuery compressed
)
# HC-FP: RegExp.exec() — esecuzione di regex, non di comandi OS
_IV_CMD_REGEX_EXEC_PAT = re.compile(
    r"=\s*/[^/]+/[gimsuy]*\.exec\("          # /regex/.exec(
    r"|\bm\s*=\s*\w+\.exec\("               # m = rx.exec(
    r"\bexec\s*=\s*/",                       # exec = /^http.../
)
# HC-FP: ORM/DB exec (SQLAlchemy, Mongoose, ClickHouse)
_IV_CMD_ORM_PAT = re.compile(
    r"session\.exec\(\s*select\("
    r"|query\.lean\(\)\.exec\("
    r"|clickhouse\.exec\(\s*\{"
    r"|exec\(queries\s*:",                   # TypeScript interface definition
    re.IGNORECASE,
)
# HC-FP: callback function chiamata `system` (non il system call OS)
_IV_CMD_SYSTEM_CB_PAT = re.compile(r"\bargs\.system\s*\(", re.IGNORECASE)

# HC-FP: codice commentato
_IV_CMD_COMMENTED_PAT = re.compile(r"^\s*#\s*.*exec|^\s*//.*exec")

# HC-FP: dimostrazione/documentazione di injection (non codice eseguito)
_IV_CMD_DEMO_PAT = re.compile(
    r"console\.log\s*\(.*exec"              # console.log mostra codice
    r"|NEVER use eval\(\) or exec\(\)"      # stringa di avvertimento
    r"|// Should be (?:detected|flagged)"   # commento scanner
    r"|\"exec\('ping '",                    # stringa letterale in remediation guide
    re.IGNORECASE,
)
# HC-FP: file che sono demo/sicurezza/benchmark per natura
_IV_CMD_DEMO_FILE_PAT = re.compile(
    r"vulnerable[_.]|demo[_.]|security.?reminder|vulnerability.?pattern"
    r"|command.?injection\.|sink.?detector|benchmark.?daemon"
    r"|remediation.?guide|security.?linter",
    re.IGNORECASE,
)
# HC-FP: path hardcoded nell'exec (nessun input utente)
_IV_CMD_HARDCODED_PAT = re.compile(
    r"exec\s*\(\s*open\s*\(r['\"]"          # exec(open(r'path')...)
    r"|os\.system\s*\(\s*['\"]"             # os.system("comando fisso")
    r"|os\.system\s*\(\s*f['\"][^{]+['\"]", # os.system(f"rm -f /fixed/path")
    re.IGNORECASE,
)
# HC-FP: browser automation SDK (array come comando, non stringa shell)
_IV_CMD_BROWSER_PAT = re.compile(r"\bthis\.exec\s*\(\s*\[")

# HC-FP: Mongoose/TypeScript ORM .exec() senza argomento di comando
_IV_CMD_LEAN_EXEC_PAT = re.compile(r"\.lean\(\)\.exec\(\)|\.exec\(\s*\)\s*;")

# ── PATH TRAVERSAL ────────────────────────────────────────────────────────────

# HC-VP: path.join con parti controllate dall'utente
_IV_PATH_VP_PAT = re.compile(
    r"path\.join\s*\(\.\.\.(?:args|params|input)\.\w+\)",
    re.IGNORECASE,
)
# HC-FP: URL template building (non filesystem)
_IV_PATH_URL_TEMPLATE_PAT = re.compile(
    r"npath\.join\s*\(.*params\.map\s*\(.*`\{\$\{"  # npath.join URL template
    r"|path:\s*\[\.\.\.(?:params|ctx)\.(?:path|target)",  # path array per OpenAPI/routing
    re.IGNORECASE,
)
# HC-FP: CSS/bundle minificato
_IV_PATH_BUNDLE_PAT = re.compile(r"\.svelte-[a-z0-9]+|flex-shrink:")

# HC-FP: path hardcoded relativo (nessun input utente nel path)
_IV_PATH_HARDCODED_PAT = re.compile(
    r'process_data_file\s*\(\s*["\']\.\./',   # path relativo fisso come 1° arg
)


def hc_rules_input_validation(f: dict) -> tuple[str, str]:
    """
    Regole HC per input-validation.
    Ritorna ("HC-FP", motivo) | ("HC-VP", motivo) | ("UNCERTAIN", "")
    """
    vid  = f.get("id", "")
    ev   = f.get("evidence", "")
    path = (f.get("file") or "").lower()

    # ── SSRF_VULNERABILITY ───────────────────────────────────────────────────
    if vid == "SSRF_VULNERABILITY":
        # HC-FP: metodo SDK su oggetto (non fetch globale)
        if _IV_SSRF_SDK_PAT.search(ev):
            return "HC-FP", "hc_fp:ssrf_sdk_method_not_global_fetch"
        # HC-FP: funzioni interne o SDK non-HTTP
        if _IV_SSRF_INTERNAL_PAT.search(ev):
            return "HC-FP", "hc_fp:ssrf_internal_function_not_http_outbound"
        # HC-VP: fetch/axios globale con URL da params/input
        if _IV_SSRF_VP_PAT.search(ev):
            return "HC-VP", "hc_vp:ssrf_global_fetch_with_user_controlled_url"

    # ── COMMAND_INJECTION_RISK ───────────────────────────────────────────────
    if vid == "COMMAND_INJECTION_RISK":
        # HC-FP: bundle/JS minificato
        if _IV_CMD_BUNDLE_PAT.search(ev):
            return "HC-FP", "hc_fp:cmd_bundled_minified_js"
        # HC-FP: RegExp.exec() (non OS command)
        if _IV_CMD_REGEX_EXEC_PAT.search(ev):
            return "HC-FP", "hc_fp:cmd_regex_exec_not_os_command"
        # HC-FP: ORM/DB exec
        if _IV_CMD_ORM_PAT.search(ev):
            return "HC-FP", "hc_fp:cmd_orm_database_exec"
        # HC-FP: callback system (non syscall)
        if _IV_CMD_SYSTEM_CB_PAT.search(ev):
            return "HC-FP", "hc_fp:cmd_system_callback_function"
        # HC-FP: codice commentato
        if _IV_CMD_COMMENTED_PAT.match(ev):
            return "HC-FP", "hc_fp:cmd_commented_out_code"
        # HC-FP: demo/documentazione nel testo
        if _IV_CMD_DEMO_PAT.search(ev):
            return "HC-FP", "hc_fp:cmd_demo_or_documentation_code"
        # HC-FP: file con nome demo/vulnerability/benchmark
        if _IV_CMD_DEMO_FILE_PAT.search(path):
            return "HC-FP", "hc_fp:cmd_demo_or_security_tool_file"
        # HC-FP: path hardcoded (nessun input utente nel comando)
        if _IV_CMD_HARDCODED_PAT.search(ev):
            return "HC-FP", "hc_fp:cmd_hardcoded_path_no_user_input"
        # HC-FP: browser automation SDK (array come cmd)
        if _IV_CMD_BROWSER_PAT.search(ev):
            return "HC-FP", "hc_fp:cmd_browser_automation_sdk"
        # HC-FP: Mongoose/TypeScript .exec() senza argomento
        if _IV_CMD_LEAN_EXEC_PAT.search(ev):
            return "HC-FP", "hc_fp:cmd_orm_lean_exec"
        # HC-VP: concatenazione stringa o template literal con params
        if _IV_CMD_VP_CONCAT_PAT.search(ev):
            return "HC-VP", "hc_vp:cmd_exec_with_string_concat_or_template"
        if _IV_CMD_VP_EXECSYNC_PAT.search(ev):
            return "HC-VP", "hc_vp:cmd_execsync_with_user_param_template"
        # HC-VP: spawn con comando da params
        if _IV_CMD_VP_SPAWN_PAT.search(ev):
            return "HC-VP", "hc_vp:cmd_spawn_with_user_controlled_command"
        # HC-VP: exec(params.command) o exec(input.code) diretto
        if _IV_CMD_VP_DIRECT_PAT.search(ev):
            return "HC-VP", "hc_vp:cmd_exec_direct_user_param"
        # HC-VP: SSH .exec(params.command, callback)
        if _IV_CMD_VP_SSH_PAT.search(ev):
            return "HC-VP", "hc_vp:cmd_ssh_exec_with_user_command"

    # ── PATH_TRAVERSAL ───────────────────────────────────────────────────────
    if vid == "PATH_TRAVERSAL":
        # HC-FP: CSS/JS bundle minificato
        if _IV_PATH_BUNDLE_PAT.search(ev):
            return "HC-FP", "hc_fp:path_bundled_css_or_js"
        # HC-FP: URL template building (non filesystem path)
        if _IV_PATH_URL_TEMPLATE_PAT.search(ev):
            return "HC-FP", "hc_fp:path_url_template_not_filesystem"
        # HC-FP: path hardcoded come primo argomento (nessun input utente nel path)
        if _IV_PATH_HARDCODED_PAT.search(ev):
            return "HC-FP", "hc_fp:path_hardcoded_relative_path"
        # HC-VP: path.join con parti utente
        if _IV_PATH_VP_PAT.search(ev):
            return "HC-VP", "hc_vp:path_join_with_user_controlled_parts"

    return "UNCERTAIN", ""


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-watch | CATEGORIA: steganographic-attack
# ══════════════════════════════════════════════════════════════════════════════
#
#  IDs rilevati:
#    ANSI_ESCAPE_INJECTION  — codici ANSI nella sorgente (143 finding)
#    WHITESPACE_INJECTION   — whitespace anomalo per riga (217 finding)
#
#  Logica ANSI:
#    Tutti i 143 finding sono codice CLI legittimo (stdout/stderr, progress
#    bar, spinner, keyboard mapping, costanti ANSI). Nessuno inietta codici
#    ANSI in risposte MCP/LLM → tutti HC-FP.
#
#  Logica WHITESPACE:
#    whitespace_in_tool_definition (24) → deep indentation in codice compliance → FP
#    extreme_whitespace in file _commented (23) → documentazione AI → FP
#    extreme_whitespace < 300 chars (≈106) → indentazione profonda plausibile → FP
#    extreme_whitespace ≥ 1000 chars (3, exa-mcp-server) → impossibile come
#      indentazione, steganografia confermata → VP
#    extreme_whitespace 300-999 (≈41) → sospetto, giudizio Ollama → UNCERTAIN
# ══════════════════════════════════════════════════════════════════════════════

# ── ANSI patterns ─────────────────────────────────────────────────────────────

# Scritture su stream di terminale (stdout, stderr, click, socket broadcast)
_SA_ANSI_STDOUT_PAT = re.compile(
    r"process\.std(?:out|err)\.write"
    r"|sys\.std(?:out|err)\.write"
    r"|stdout\.write\s*\("
    r"|output\.write\s*\("
    r"|click\.echo\s*\("
    r"|self\._broker\.broadcast_raw"
    r"|this\.stream\.write\s*\(",
    re.IGNORECASE,
)

# Definizioni di costanti ANSI (color map, keyboard shortcut map, config object)
_SA_ANSI_CONST_PAT = re.compile(
    r"(?:CLEAR_SCREEN|CLEAR_LINE|MOVE_UP|cursorUp|clearLine|clear)\s*[=:]\s*[\"'`]"
    r"|(?:HIDDEN|hidden)\s*:\s*'\\x1b"
    r"|'(?:ctrl|alt|shift)[+\-]\w+'\s*:"        # keyboard shortcuts: 'ctrl+home': '\x1b...'
    r"|'alt-\w+'\s*:"                            # alt-home: '\x1b...'
    r"|_ERASE_\w+_SEQ\s*=",
    re.IGNORECASE,
)

# Detection / stripping di codici ANSI (il codice li rimuove, non li inietta)
_SA_ANSI_DETECT_PAT = re.compile(
    r"Strip CSI|strip.*escape"
    r"|includes\s*\([\"'].*\\x1b"               # buf.includes('\x1b...')
    r"|\.count\s*\(b'\\x1b"                     # data.count(b'\x1b...')
    r"|if\s+b'\\x1b.*in\s+data"                 # if b'\x1b...' in data
    r"|data\.count\s*\(b'\\x1b",
    re.IGNORECASE,
)

# Return di stringa ANSI (per rendering terminale — non output MCP)
_SA_ANSI_RETURN_PAT = re.compile(r"^\s*return\s+[\"'`b].*\\x1b", re.IGNORECASE)

# Template literal con sequenza ANSI (banner, progress bar)
_SA_ANSI_TEMPLATE_PAT = re.compile(
    r"=\s*`[^`]*\\r[^`]*\\x1b|lines\.(?:push|join)\s*\(.*\\x1b", re.IGNORECASE
)


def hc_rules_steganographic_attack(f: dict) -> tuple[str, str]:
    vid  = f.get("id", "")
    ev   = f.get("evidence", "")
    path = (f.get("file") or "").lower()
    conf = f.get("filter_confidence", "")

    # ── ANSI_ESCAPE_INJECTION → tutti HC-FP ──────────────────────────────────
    if vid == "ANSI_ESCAPE_INJECTION":
        # Codice commentato o stripping/detection
        if re.match(r"^\s*[#/*]", ev) or _SA_ANSI_DETECT_PAT.search(ev):
            return "HC-FP", "hc_fp:ansi_commented_or_detection_code"
        # TypeScript declaration file (solo esempi documentativi)
        if path.endswith(".d.ts"):
            return "HC-FP", "hc_fp:ansi_typescript_declaration_file"
        # Write su stdout/stderr/stream (terminal UI)
        if _SA_ANSI_STDOUT_PAT.search(ev):
            return "HC-FP", "hc_fp:ansi_terminal_stdout_write"
        # Definizione costante (color map, keyboard map, config)
        if _SA_ANSI_CONST_PAT.search(ev):
            return "HC-FP", "hc_fp:ansi_constant_definition"
        # Return di sequenza terminale (non output MCP)
        if _SA_ANSI_RETURN_PAT.search(ev):
            return "HC-FP", "hc_fp:ansi_return_terminal_sequence"
        # Template literal / array push (banner, progress bar)
        if _SA_ANSI_TEMPLATE_PAT.search(ev):
            return "HC-FP", "hc_fp:ansi_template_literal_or_array"
        # Catch-all: qualsiasi altra occorrenza di \x1b[ nella sorgente è
        # codice CLI (print/echo/write non catturati sopra), non iniezione MCP
        if r"\x1b[" in ev:
            return "HC-FP", "hc_fp:ansi_cli_terminal_code"

    # ── WHITESPACE_INJECTION ──────────────────────────────────────────────────
    if vid == "WHITESPACE_INJECTION":
        # whitespace_in_tool_definition: indentazione profonda in codice
        # compliance/template, non steganografia nel testo della description
        if conf == "whitespace_in_tool_definition":
            return "HC-FP", "hc_fp:ws_tool_definition_deep_indentation"

        # Estrai il conteggio di whitespace da extreme_whitespace_NNN
        m = re.search(r"extreme_whitespace_(\d+)", conf)
        ws_count = int(m.group(1)) if m else 0

        # File di documentazione AI (_commented): whitespace nel testo, non nel codice
        if "_commented" in path or "/comment" in path:
            return "HC-FP", "hc_fp:ws_ai_documentation_file"

        # < 300 chars: indentazione profonda ma plausibile (Python 60-70 livelli)
        if 0 < ws_count < 300:
            return "HC-FP", "hc_fp:ws_plausible_deep_code_indentation"

        # ≥ 1000 chars: impossibile come indentazione → steganografia accertata
        # (exa-mcp-server: 1152, 2304, 86016 whitespace chars su un singolo '}')
        if ws_count >= 1000:
            return "HC-VP", "hc_vp:ws_extreme_count_confirmed_steganography"

        # 300–999: sospetto (87-250 livelli di indentazione), giudizio Ollama
        return "UNCERTAIN", "needs_llm_judgment"

    return "UNCERTAIN", ""


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-watch | CATEGORIA: protocol-violation
# ══════════════════════════════════════════════════════════════════════════════
#
#  IDs rilevati:
#    INSECURE_TRANSPORT  — URL http:// usato dove dovrebbe esserci https:// (2775)
#    SESSION_ID_IN_URL   — session_id in query string URL (152)
#
#  Logica INSECURE_TRANSPORT:
#    Il filtro mcp-watch flagga qualsiasi URL http:// — FP rate altissima.
#    FP certi: localhost, IP privati, 169.254.x (IMDS), .local/.lan (mDNS),
#    Kubernetes .cluster.local, esempi/placeholder, commenti, messaggi
#    di validazione, mirror pacchetti (alpine/ubuntu/centos), namespace
#    XML/SOAP/XSD, URL di documentazione, copyright, test/spec files, env
#    var con default http://.
#    VP certi: IP esterno (non-RFC1918, non-169.254.x) in chiamata fetch/requests
#    effettiva.
#
#  Logica SESSION_ID_IN_URL:
#    FP: MCP SSE transport (session_id nell'URL è il protocollo MCP), Stripe
#    checkout {CHECKOUT_SESSION_ID}, keyword argument di funzione (non URL),
#    documentazione/log, rsid (document revision), SID non-auth (video/table ID).
#    VP: session di autenticazione reale in URL query string:
#      Pi-hole admin API (?sid=), Synology FileStation (?_sid=),
#      WeChat web API (webwxsync?sid=), Salesforce frontdoor (?sid=),
#      URL di login/upload applicative con session_handle.
# ══════════════════════════════════════════════════════════════════════════════

# ── INSECURE_TRANSPORT patterns ───────────────────────────────────────────────

# IP e domini locali/privati
_PV_LOCAL_PAT = re.compile(
    r"localhost|127\.\d+[\.\d]*|0\.0\.0\.0|::1"
    r"|0177\.\d+\.\d+\.\d+",    # octal loopback (0177.0.0.1 = 127.0.0.1)
    re.IGNORECASE,
)
_PV_PRIVATE_IP_PAT = re.compile(
    r"192\.168\.\d+[\.\d*]+|10\.\d+\.\d+[\.\d*]+"
    r"|172\.(1[6-9]|2\d|3[01])\.\d+[\.\d*]+",
)
_PV_LINKLOCAL_PAT = re.compile(r"169\.254\.\d+\.\d+")  # AWS IMDS, Azure IMDS — no TLS by design
_PV_MDNS_PAT = re.compile(
    r"http://[a-z0-9._-]+\.(?:local|lan|internal)(?:[/\"' :,]|$)",
    re.IGNORECASE,
)
_PV_K8S_PAT = re.compile(
    r"\.cluster\.local|\.svc\.|\.svc\.cluster",
    re.IGNORECASE,
)

# Testo di esempio / placeholder
_PV_EXAMPLE_PAT = re.compile(
    r"e\.g\.|your-domain|your-public-ip|your-server|example\.com"
    r"|placeholder|<host>|<url>|\[host\]|\[url\]|mycoolsite\.com"
    r"|http://google\.com|http://bar\.foo"
    r"|http://\.\.\.|http://\d+\.x\.x\.x"          # http://... or 1.x.x.x placeholder
    r"|http://a\.b(?:[\"' ,]|$)"                   # http://a.b base URL trick
    r"|http://myserver\.|http://mysite\."           # common placeholder names
    r"|http://some-[a-z-]+\.com|http://some-mcp"   # http://some-xxx.com
    r"|http://(?:new|missing|generic|test|demo|sample|foo)\.(?:tool|api|server|service)\."
    r"|http://insecure\.com|http://primary-stream\."  # placeholder domains
    r"|http://exam_ple\.com",  # URL with underscore (never a real domain, used in specs)
    re.IGNORECASE,
)

# Commento o docstring (include Python doctest >>>, RST, markdown list item)
_PV_COMMENT_PAT = re.compile(r"^\s*(?:[#/*]|\*\s|//|>>>|\.\.\.?\s+_|-\s)", re.IGNORECASE)
_PV_COPYRIGHT_PAT = re.compile(r"Copyright.*http://|http://.*copyright", re.IGNORECASE)

# Messaggi di validazione che citano http:// come schema ammesso
_PV_VALIDATOR_PAT = re.compile(
    r"must (?:include|start with)|URL scheme must|cannot start with http"
    r"|ValidationError.*url|Please enter a valid URL"
    r"|Only http:// and https://|http:// or https://"
    r"|missing http:// or https://|URL should not include protocol"
    r"|not include protocol"
    r"|HTTPS required|http:// not allowed|http:// is not allowed"
    r"|sse\+http://|allow-http|allow_http|allowHttp"  # SSE+HTTP transport scheme
    r"|--allow-http|permit.*http://|Permit.*http://"  # CLI flag descriptions
    r"|http://\.\.\.|http://\\.\\.\\.|\.\.\. HTTP endpoint"  # ellipsis placeholder
    r"|defaulting to http://|switching to http://|Using http:// instead"
    r"|such as\s+[\"'`]*http://|like\s+[\"'`]*http://"   # doc "such as http://..."
    r"|Purchase:\s+http://|Upgrade at\s+http://"          # licensing messages
    r"|file:///.*http://|XXE.*http://"                   # XXE attack examples
    r"|Try add http:// or socks|add http:// or socks",  # proxy protocol error
    re.IGNORECASE,
)

# Mirror di pacchetti (usano HTTP per design)
_PV_PKG_MIRROR_PAT = re.compile(
    r"alpinelinux\.org|archive\.ubuntu\.com|centos\.org|debian\.org"
    r"|dl-cdn\.alpinelinux|mirror\.",
    re.IGNORECASE,
)

# Namespace XML/SOAP/XSD (non sono URL di rete reali)
_PV_XML_NS_PAT = re.compile(
    r"xmlns:|xmlns\s*=|xsd:|xsi:|soap:|tempuri\.org|schemas\.microsoft"
    r"|<!DOCTYPE|DTD PLIST|schema\.org|w3\.org/",
    re.IGNORECASE,
)

# URL di documentazione note / identifier standard (non chiamate di rete)
_PV_DOC_URL_PAT = re.compile(
    r"iiif\.io/api|gtkwave\.sourceforge|developer\.[a-z]"
    r"|docs\.[a-z]|sourceforge\.net|readthedocs\."
    r"|pushgateway\.local|fashion-mnist\.s3"
    r"|http://www\.[a-z].*\b(?:org|io|net|com)\b"
    # HL7 / FHIR terminology URIs (identifier, non URL di rete)
    r"|hl7\.org|terminology\.hl7|fhir\.org"
    r"|smarthealthit\.org|nlm\.nih\.gov|rxnorm|joincandidhealth\.com"
    # AWS S3 ACL group URI (non chiamata di rete)
    r"|acs\.amazonaws\.com/groups"
    # XBRL / SEC taxonomy URIs
    r"|xbrl\.|xbrl\.sec\.gov|www\.sec\.gov/edgar"
    # Feed RSS pubblici (usano HTTP per design)
    r"|feeds\.bbci\.co\.uk|feeds\.[a-z].*rss"
    r"|rss\.cnn\.com|rss\.[a-z]|feeds\.reuters\.com"
    r"|search\.yahoo\.com/mrss|wellformedweb\.org/CommentAPI"
    # Riferimenti accademici (arXiv, ROS wiki, UR support)
    r"|arxiv\.org/abs|wiki\.ros\.org|universal-robots\.com/support"
    # URL di sicurezza/test (evil.com, attacker, malicious, burp)
    r"|evil\.com|attacker[\.-]|malicious[-.]|burpcollaborator\.net"
    r"|target\.com|malware|pentest|ctf\.|exploit"
    # Documentazione inline o RST: <http://...>
    r"|http://site\.com|http://jasonformat\.com|alasky\.unistra\.fr"
    # WeChat / QR code scan (URL embedded in QR code data, non chiamata API)
    r"|weixin\.qq\.com/r/|wchat\.finance\.qq\.com"
    # YANG / NETCONF / OpenConfig namespace URIs (non chiamate di rete)
    r"|openconfig\.net/yang|cisco\.com/ns/yang|openconfig\."
    # RDF/ontology URIs — spinrdf, xAPI adlnet, shoobx diff
    r"|spinrdf\.org|adlnet\.gov/expapi|namespaces\.shoobx\.com"
    r"|admin-shell\.io/aasx|nkllon\.com/ontology"
    # OPDS / Atom link relations
    r"|opds-spec\.org/acquisition"
    # Code signing timestamp servers (HTTP by design for signing protocol)
    r"|timestamp\.digicert\.com|timestamp\.comodoca\.com"
    r"|timestamp\.acs\.microsoft\.com|timestamp\.sectigo\.com"
    # Package manager / APT repository lines (non chiamate di rete nel codice)
    r"|dl\.google\.com/linux/chrome|apt\.postgresql\.org"
    r"|li\.nux\.ro/download"
    # Proxy network config in scripts (not application HTTP calls)
    r"|proxy\.company\.com"
    # IPFS gateways, code/data hosting (HTTP by design)
    r"|ipfs\.io|ipfs\.|\.onion"
    # mitmproxy cert page (always HTTP for certificate install)
    r"|mitm\.it"
    # Chinese web analytics / social push (HTTP-only CDN)
    r"|push\.zhanzhang\.baidu\.com|mp\.weixin\.qq\.com"
    r"|mmbiz\.qpic\.cn|xhscdn\.com"
    # URL string containment check / URL comparison (not an HTTP call)
    r"|in url:|url\.startswith\s*\([\"']http://|[\"']http://www\.\s*in\s"
    r"|elif\s+[\"']http://www\.\s*in"
    # IPFS path in URL (HTTP-by-design for IPFS gateways)
    r"|/ipfs/:|/ipfs/:hash|/ipfs/[a-zA-Z0-9]"
    # Path traversal test payloads (security testing, not real URLs)
    r"|etc/passwd|path.traversal|path_traversal|\.\./"
    # Documentation: reference label before URL
    r"|Documentation:\s+http://|Docs:\s+http://"
    # Proxy protocol error message
    r"|proxy protocol.*http://|add http:// or socks"
    # Pattern description for security rules (not a real URL usage)
    r"|pattern:\s+[\"'].*http://|Literal containing http://"
    # Ontology URI (#) — RDF identifier, not a network call
    r"|ontology[#/]|/ontology#|dev/ontology"
    # requires http:// endpoint (config validation error)
    r"|requires http:// endpoint|http:// endpoint"
    # Blog reference with year in path (http://domain.tld/year/month/day/...)
    r"|http://[a-z0-9.-]+\.[a-z]{2,}/\d{4}/\d{2}/"
    # JSON escaped URL embedded in test data (Twitter trigger sample data)
    r"|\\\\\"data\\\\\":\\\\\"http://|\\\"data\\\":\\\"http://"
    r"|top_engagers.*http://|top_influencers.*http://"
    # Referer HTTP header value (not an outbound call)
    r"|Referer:\s+[\"']http://|'Referer'.*'http://"
    # www.* in Chinese country TLD (.cn, .kr, .jp, .br, .ru, etc.)
    r"|http://www\.[a-z].*\.(cn|kr|jp|br|ru|do|nl|it|fr|de|es|pl|au)[/\"' ,:;]"
    # Korean / Chinese financial data APIs (government APIs, HTTP-only)
    r"|data\.krx\.co\.kr|data-dbg\.krx\.co\.kr"
    r"|eastmoney\.com|sinajs\.cn|mwee\.cn|taobao"
    r"|hq\.sinajs\.cn|push2\.eastmoney\.com|search-api-web\.eastmoney"
    # Japanese/Asian public data APIs
    r"|e-stat\.go\.jp|tianditu\.gov\.cn|lbs\.tianditu"
    r"|data\.gov\.sg|data1\.integral\.com"
    # Telecom / blockchain nodes (HTTP-only API endpoints)
    r"|outian\.net|regen\.network|baidu-int\.com"
    # Other known HTTP-only references
    r"|m3g\.iqm\.unicamp\.br"     # Packmol website
    r"|euroscore\.org"            # EuroSCORE calculator
    r"|mesonet\.agron\.iastate|ows\.mundialis\.de"  # WMS tile servers
    r"|theapistack\.com|api\.jutuike\.com"
    # UK Land Registry / FHIR StructureDefinition / DOREMUS — RDF property URIs
    r"|landregistry\.data\.gov\.uk/def|data\.doremus\.org"
    r"|/FHIR/StructureDefinition|/StructureDefinition/"
    r"|open\.epic\.com/FHIR|medplum\.com/StructureDefinition"
    r"|medplum\.com/ai-spaces"
    # OpenOffice / ODF namespace URI
    r"|openoffice\.org/\d+/registry"
    # Government / authority data APIs that are HTTP-only by design
    r"|results\.jntuh\.ac\.in"    # JNTU Hyderabad results portal
    r"|www\.senado\.gov\.do"      # Dominican Republic senate
    r"|db\.itkc\.or\.kr"          # Korean Institute of Traditional Culture
    r"|www\.law\.go\.kr|law\.go\.kr"  # Korean law database
    r"|plus\.kipris\.or\.kr"      # Korean IP Registry (KIPRIS)
    r"|www\.szse\.cn|vip\.stock\.finance\.sina|finance\.sina\.com\.cn"
    r"|sinacn\.com|sinajs\.cn"    # Sina financial
    r"|cnes\.datasus\.gov\.br"    # Brazilian health data
    r"|water\.usgs\.gov"          # USGS water data
    r"|aflowlib\.org"             # AFLOW materials database
    r"|aflux_url"                 # AFLOW URL variable name
    # Misc tool / community references
    r"|b3mn\.org/stencilset"      # Signavio BPMN stencil namespace
    r"|openid\.net/specs"         # OpenID spec URI
    r"|itunes\.apple\.com/dataenc|readium\.org/2014/01/lcp"  # DRM scheme URIs
    r"|berkeleybop\.org|geneontology\.org"  # bioinformatics
    r"|icom\.museum"              # ICOM museum domain (test in httpx)
    r"|ilpubs\.stanford\.edu"     # Stanford papers
    r"|wa\.me\b"                  # WhatsApp shortlink (placeholder)
    # Demo/data test URLs (fake data, not production)
    r"|circledev\.net:31337"      # Activepieces fake test data port 31337
    r"|api\.sandbox\."            # sandbox subdomain → clearly test environment
    r"|\.sandbox\."               # any sandbox domain
    # Selenium / Playwright practice sites
    r"|automationpractice\.pl|automationexercise\.com"
    # Regex / security pattern strings containing http:// as pattern text
    r"|http://192\\\.168\\\.|\\'http://192\\\.168"  # escaped regex inside string
    # HTML template strings (http:// in HTML attributes)
    r"|<a\s+href=[\"']?http://|href=.*http://[a-z]"
    # User-agent string (not an HTTP call)
    r"|\+http://[a-z0-9._-]+/bot\)"
    # ModelScope OSS CDN (Chinese model hosting, asset downloads)
    r"|modelscope-open\.oss-cn-hangzhou\.aliyuncs\.com"
    # Misc code signing, NLM/NIH references
    r"|tools\.ietf\.org/html|checkip\.amazonaws\.com"
    # BPMN / workflow namespace
    r"|b3mn\.org/stencilset|www\.bt\.cn|aingdesk\.bt\.cn"
    # DFIR / forensics malware detection (comparing known bad domains, not calling them)
    r"|key_url\.startswith|\.startswith\s*\([\"']http://"
    # RST named hyperlink target: .. _Label: http://...
    r"|\.\. _[a-z].*:\s*http://"
    # "such as", "like", "e.g." inline before URL in documentation
    r"|such as\s+[\"'`]*http://|like\s+[\"'`]*http://"
    # SSRF test / validation code (explicitly testing SSRF attacks, not making real calls)
    r"|validate_url_ssrf\s*\(|ssrf.*http://|SSRF.*http://"
    # Seafile / proxy note: "may return http:// URLs"
    r"|may return http://|returns http://|return http:// URL"
    # lmstudio URL scheme fallback message
    r"|Using http:// instead|unsupported.*scheme.*http://"
    # Patreon/donation embedded in podcast content
    r"|http://Patreon\.com|patreon\.com"
    # CDN image URLs in API sample data (product images, comparator images)
    r"|cdscdn\.com|beezupcdn\.blob|sarenza\.net|cdn\d*\."
    # Website field in venue/contact database alongside other fields
    r"|website.*instagram|instagram.*website"
    # Bare URL in RST docstring (reference without label)
    r"|http://www\.physics\.usyd|http://reference\.wolfram|http://vita\.had"
    # Pushplus notification (Chinese push service)
    r"|pushplus\.plus"
    # Korean/Chinese text label before URL (网址: or similar)
    r"|网址:\s+http://|документ|sslip\.io",
    re.IGNORECASE,
)

# Domini noti come riferimenti / identifier / placeholder / test — non chiamate di rete
_PV_KNOWN_REF_DOMAIN_PAT = re.compile(
    r"http://(?:[a-z0-9_-]+\.)*github\.com"          # GitHub (reference)
    r"|http://(?:[a-z0-9_-]+\.)*golang\.org"          # Go lang docs
    r"|http://doi\.org|http://dx\.doi\.org"           # DOI identifier
    r"|http://(?:[a-z0-9_-]+\.)*httpbin\.org"         # HTTP test service
    r"|http://placekitten\.com"                       # placeholder image
    r"|http://(?:[a-z0-9_-]+\.)*arxiv\.org"           # academic paper (all subdomains: export.arxiv.org)
    r"|http://orcid\.org"                             # researcher ID
    r"|http://(?:[a-z0-9_-]+\.)*snomed\.info"         # medical terminology
    r"|http://jsonpatch\.com"                         # JSON Patch spec
    r"|http://adaptivecards\.io"                      # MS Adaptive Cards schema
    r"|http://(?:[a-z0-9_-]+\.)*momentjs\.com"        # JS library doc/copyright
    r"|http://jabber\.org|http://xmpp\.org"           # XMPP URIs
    r"|http://(?:[a-z0-9_-]+\.)*graphdrawing\.org"    # graph spec (incl. graphml.graphdrawing.org)
    r"|http://(?:[a-z0-9_-]+\.)*w3\.org"              # W3C spec
    r"|http://yourdomain\.com|http://your-domain\."
    r"|http://existing\.com|http://company\.com"
    r"|http://gateway[0-9]+\.com"                     # placeholder gateways
    r"|http://mobi\.com|http://icom\.museum"          # placeholder domains
    r"|http://site\.com|http://alternate-s3-host\."
    r"|http://(?:[a-z0-9_-]+\.)*google\.com"          # obvious reference
    r"|http://(?:[a-z0-9_-]+\.)*steampowered\.com"    # Steam Web API (all subdomains)
    r"|http://(?:[a-z0-9_-]+\.)*ip-api\.com"          # IP geolocation
    r"|http://(?:[a-z0-9_-]+\.)*openweathermap\.org"  # weather API (all subdomains)
    # Open data / academic APIs (HTTP-only or low-risk reference)
    r"|http://(?:[a-z0-9_-]+\.)*worldbank\.org"       # World Bank open data
    r"|http://(?:[a-z0-9_-]+\.)*api\.open-notify\.org" # ISS position (HTTP-only API)
    r"|http://(?:[a-z0-9_-]+\.)*ergast\.com"          # F1 motorsport API
    r"|http://(?:[a-z0-9_-]+\.)*numbersapi\.com"      # trivia/numbers API
    r"|http://(?:[a-z0-9_-]+\.)*conceptnet\.io"       # ConceptNet AI knowledge base
    r"|http://(?:[a-z0-9_-]+\.)*worldtimeapi\.org"    # world time API
    r"|http://(?:[a-z0-9_-]+\.)*colormind\.io"        # color palette API
    r"|http://(?:[a-z0-9_-]+\.)*geonames\.org"        # geographical names API
    r"|http://(?:[a-z0-9_-]+\.)*web\.archive\.org"    # Wayback Machine
    r"|http://(?:[a-z0-9_-]+\.)*phishtank\.com"       # phishing data feed
    r"|http://(?:[a-z0-9_-]+\.)*geolite\.maxmind\.com" # GeoIP database download
    r"|http://(?:[a-z0-9_-]+\.)*weatherapi\.com"      # weather API
    r"|http://(?:[a-z0-9_-]+\.)*accuweather\.com"     # AccuWeather API
    r"|http://(?:[a-z0-9_-]+\.)*legislation\.gov\.uk" # UK legislation identifier URIs
    r"|http://(?:[a-z0-9_-]+\.)*openid\.net"          # OpenID spec URIs
    r"|http://(?:[a-z0-9_-]+\.)*opds-spec\.org"       # OPDS link relation URIs
    r"|http://(?:[a-z0-9_-]+\.)*tinymush\.org"        # MU* game community
    r"|http://(?:[a-z0-9_-]+\.)*theapistack\.com"     # API listing
    r"|http://(?:[a-z0-9_-]+\.)*bugs\.python\.org"    # Python bug tracker
    r"|http://(?:[a-z0-9_-]+\.)*stackoverflow\.com"   # StackOverflow reference
    r"|http://(?:[a-z0-9_-]+\.)*wikipedia\.org"       # Wikipedia reference
    r"|http://(?:[a-z0-9_-]+\.)*blogspot\."           # blog references
    r"|http://(?:[a-z0-9_-]+\.)*bitbucket\.org"       # Bitbucket reference
    r"|http://(?:[a-z0-9_-]+\.)*twimlets\.com"        # Twilio demo music
    r"|http://(?:[a-z0-9_-]+\.)*purl\.org"            # PURL identifier
    r"|http://(?:[a-z0-9_-]+\.)*obolibrary\.org"      # OBO ontology URIs
    r"|http://(?:[a-z0-9_-]+\.)*wikidata\.org"        # Wikidata
    r"|http://(?:[a-z0-9_-]+\.)*wikimedia\.org"       # Wikimedia
    r"|http://(?:[a-z0-9_-]+\.)*geneontology\.org"    # Gene Ontology
    r"|http://(?:[a-z0-9_-]+\.)*praytimes\.org"       # prayer times (doc URL)
    r"|http://(?:[a-z0-9_-]+\.)*npmjs\.(?:com|org)"   # npm registry
    r"|http://(?:[a-z0-9_-]+\.)*pypi\.org"            # PyPI
    r"|http://(?:[a-z0-9_-]+\.)*imile-inc\.com"       # internal npm registry (doc)
    r"|http://(?:[a-z0-9_-]+\.)*nvd3\.org"            # NVD3 library reference
    r"|http://(?:[a-z0-9_-]+\.)*genkit\.dev"          # Firebase Genkit (internal)
    r"|http://(?:[a-z0-9_-]+\.)*cocodataset\.org"     # COCO dataset
    r"|http://(?:[a-z0-9_-]+\.)*insomnia\.fountainhead\.cash" # Insomnia doc reference
    # Additional domains identified in iteration 3
    r"|http://(?:[a-z0-9_-]+\.)*openai\.com"         # openai.com reference
    r"|http://(?:[a-z0-9_-]+\.)*router\.project-osrm\.org"  # OSRM routing (open source)
    r"|http://(?:[a-z0-9_-]+\.)*sslip\.io"           # sslip.io wildcard DNS doc
    r"|http://(?:[a-z0-9_-]+\.)*rhostmush\.org|http://(?:[a-z0-9_-]+\.)*tinymux\.org"
    r"|http://(?:[a-z0-9_-]+\.)*mcp-service\.com"    # placeholder MCP service domain
    r"|http://(?:[a-z0-9_-]+\.)*my\.cdn\.com"        # "such as http://my.cdn.com" doc
    r"|http://(?:[a-z0-9_-]+\.)*andeshire\.com"      # fictional domain
    r"|http://(?:[a-z0-9_-]+\.)*violett\.com"        # example server in doc
    r"|http://(?:[a-z0-9_-]+\.)*codescalpel\.dev"    # licensing URL (inline reference)
    r"|http://(?:[a-z0-9_-]+\.)*s-ings\.com"         # typicons icon set reference
    r"|http://(?:[a-z0-9_-]+\.)*payram\.com"         # payram doc HTML
    r"|http://(?:[a-z0-9_-]+\.)*jasper(?:server|reports)?\."    # Jasper reports example
    # Additional iteration 4
    r"|http://(?:[a-z0-9_-]+\.)*open-notify\.org"    # open-notify (all subdomains)
    r"|http://(?:[a-z0-9_-]+\.)*acnhapi\.com"        # Animal Crossing API
    r"|http://(?:[a-z0-9_-]+\.)*shibe\.online"       # Shibe image API
    r"|http://(?:[a-z0-9_-]+\.)*xchat\.org"          # XChat IRC (defunct reference)
    r"|http://(?:[a-z0-9_-]+\.)*music\.163\.com"     # NetEase Music (Referer header)
    r"|http://(?:[a-z0-9_-]+\.)*gmail\.com"          # Gmail (web extension start URL)
    r"|http://(?:[a-z0-9_-]+\.)*mcpservers\.cn"      # MCP servers directory (CN)
    r"|http://(?:[a-z0-9_-]+\.)*loket\.nl"           # Dutch analytics API (sample data)
    r"|http://(?:[a-z0-9_-]+\.)*vtexcommercestable\." # VTex staging environment
    r"|http://(?:[a-z0-9_-]+\.)*musubix\.dev"         # MUSUBIX ontology URI
    # Additional iteration 5
    r"|http://(?:[a-z0-9_-]+\.)*getvero\.com",        # Vero email marketing (URL in test/sample data)
    re.IGNORECASE,
)

# Commento inline: http:// compare dopo # o // nel mezzo di una riga
_PV_INLINE_COMMENT_PAT = re.compile(r"#[^#\n]*http://|//[^/\n]*http://", re.IGNORECASE)

# Link RST/Sphinx in docstring: <http://...>
_PV_RST_LINK_PAT = re.compile(r"<http://[^>]+>", re.IGNORECASE)

# Costante di configurazione (non env var): baseUrl, BASE_URL, base_url assegnato
# a un valore http:// che sarà probabilmente sovrascritta dalla configurazione
_PV_CONFIG_CONST_PAT = re.compile(
    r"(?:baseUrl|base_url|BASE_URL|API_URL|api_url|endpoint_url"
    r"|HASS_URL|HASS_HOST|HA_URL|XMLTV_URL|OSRM_BASE_URL"
    r"|LOOKUP_SERVICE_URL|SOAP_NAMESPACE)\s*[:=].*http://"
    r"|http://.*(?:baseUrl|base_url|BASE_URL)",
    re.IGNORECASE,
)

# URL che appaiono solo nel testo di una descrizione (description:, 'description':)
_PV_DESC_FIELD_PAT = re.compile(
    r"[\"']?description[\"']?\s*:\s*[\"'].*http://|'description'.*http://",
    re.IGNORECASE,
)

# File di test / spec / esempi
_PV_TEST_FILE_PAT = re.compile(
    r"[/\\](?:test|spec|mock|fixture|__tests__|tests?|examples?|demo|sample)[/\\]"
    r"|\.(?:test|spec)\.[jt]s$"
    r"|^examples?[/\\]|^demo[/\\]|^sample[/\\]"     # relative path starting with examples/
    r"|[/\\]tmp_packages[/\\]|^tmp_packages[/\\]"     # vendored/temp packages (any position)
    r"|[/\\]vendor[/\\]|^vendor[/\\]"
    r"|[/\\]poc[/\\]"                                 # proof-of-concept folder
    r"|gallery_python[/\\]",                          # matplotlib gallery examples
    re.IGNORECASE,
)

# S3 pubblici / CDN dataset (accesso HTTP per design)
_PV_S3_PUBLIC_PAT = re.compile(
    r"s3-website\.|s3\.amazonaws\.com|fashion-mnist|\.s3\.",
    re.IGNORECASE,
)

# Env var con http:// come valore di default (overridable dall'utente)
_PV_ENV_DEFAULT_PAT = re.compile(
    r"os\.getenv\s*\(|process\.env\.|getenv\s*\(|os\.environ\.get\s*\("
    # Env var come stringa in argomento di funzione: ("ENV_VAR", "http://...")
    r"|[\"'][A-Z][A-Z0-9_]*_URL[\"']\s*,\s*[\"']http://"
    r"|[\"'][A-Z][A-Z0-9_]*_HOST[\"']\s*,\s*[\"']http://",
    re.IGNORECASE,
)

# FHIR / HL7 system field (identificatore URI, non chiamata di rete)
_PV_FHIR_SYSTEM_PAT = re.compile(
    r"system\s*:\s*[\"']http://|\"system\"\s*:\s*\"http://",
    re.IGNORECASE,
)

# RDF / Ontology namespace costruttori (Namespace("http://..."), register_namespace(...), ecc.)
_PV_RDF_NS_PAT = re.compile(
    r"Namespace\s*\(\s*[\"']http://"
    r"|register_namespace\s*\([^,)]*[\"']http://"
    r"|\bSP\s*=\s*Namespace|SPIN\s*=\s*Namespace"
    r"|\"(?:rel|type|system)\"\s*,\s*\"http://(?!localhost)"
    r"|\btype\s*:\s*[\"']http://(?:adlnet|purl|spinrdf)"
    r"|ET\.SubElement.*[\"']http://|\.set\s*\([\"']rel[\"']\s*,\s*[\"']http://"
    # General namespace tuple: ("prefix", "http://...")
    r"|\([\"'][a-z_-]+[\"']\s*,\s*[\"']http://[a-z]"
    # YANG namespace dict entries
    r"|[\"']http://[a-z].*[\"']\s*,\s*[\"']http://[a-z]*\.yang\b"
    r"|/yang/|cisco\.com/ns/yang|openconfig\.net/yang"
    # HTML anchor in i18n string (not a network call from the app)
    r"|<a\s+href=[\"'\\]*http://",
    re.IGNORECASE,
)

# Regex Python raw-string contenente http:// (non è una chiamata di rete)
_PV_REGEX_URL_PAT = re.compile(
    r"r[\"']http://|r'http://|r\"http://"
    r"|re\.compile.*http://|re\.search.*http://|re\.match.*http://"
    r"|_ENDPOINT_RE\s*=|_RE\s*=.*http://|_PAT.*http://",
    re.IGNORECASE,
)

# Istruzione di stampa / log (non implica una connessione di rete)
_PV_PRINT_LOG_PAT = re.compile(
    r"^\s*(?:echo\s+[\"']|print\s*\([f\"']|print\s*\(f[\"']"
    r"|logger\.\w+\s*\(|logging\.\w+\s*\("
    r"|console\.(log|info|error|warn)\s*\("
    r"|printf?\s*\([\"'])",
    re.IGNORECASE,
)

# Curl in script (installazione / demo, non chiamata dall'app)
_PV_CURL_INSTALL_PAT = re.compile(
    r"\bcurl\b[^;\"'\n]*http://|\bcurl -fsSL\b|\bcurl -L\b[^;]*http://"
    r"|\bwget\b[^;\"'\n]*http://",
    re.IGNORECASE,
)

# Riga APT/deb/rpm repository (mirror di pacchetti, HTTP per design)
_PV_APT_LINE_PAT = re.compile(
    r"^\s*(?:deb|deb-src)\s+http://|rpm.*http://|gpg-key.*http://"
    r"|sudo rpm -.*http://",
    re.IGNORECASE,
)

# Riferimento inline in stringa: (see http://...) o reference: http://
_PV_REF_INLINE_PAT = re.compile(
    r"\(see\s+http://|\(http://[a-z]|\breference:\s+http://"
    r"|\bsource:\s+http://|\bfrom:\s+http://[a-z]"
    r"|\bmore info:\s*http://|\bsee also:\s*http://"
    r"|http://[a-z0-9._-]+\.(blogspot|wordpress|medium)\.",
    re.IGNORECASE,
)

# IP esterno (non-privato, non-loopback, non-169.254.x) — pattern VP
_PV_EXT_IP_PAT = re.compile(r"http://(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")

# Chiamata HTTP effettiva (fetch, requests, axios, http.get) — segnale VP
_PV_HTTP_CALL_PAT = re.compile(
    r"\bfetch\s*\(|requests\.(get|post|put|delete|patch)\s*\("
    r"|\baxios\.(get|post|put|delete|patch)\s*\("
    r"|http(?:s?)\.(get|post|request)\s*\("
    r"|webloader\s*\("
    r"|postJson\s*\(|postJSON\s*\("              # postJson helper (bvbrc, etc.)
    r"|\bcurl\s+(?:-[a-zA-Z]+\s+)*http://\d",   # curl con IP esterno
    re.IGNORECASE,
)

# Well-known cloud provider / platform domains via HTTP (always VP if not FP)
_PV_CLOUD_VP_PAT = re.compile(
    r"http://[a-z0-9._-]+\.amazonaws\.com"       # AWS (ELB, EC2, EB, S3, etc.)
    r"|http://[a-z0-9._-]+\.aliyuncs\.com"        # Alibaba Cloud / Aliyun
    r"|http://[a-z0-9._-]+\.hf\.space"            # HuggingFace Spaces
    r"|http://[a-z0-9._-]+\.jd\.com(?:[:/\"]|$)", # JD.com internal services
    re.IGNORECASE,
)

# Explicit URL-assignment config patterns (url:, endpoint:, publicEndpoint:, kvUrl:, etc.)
# Constructors that accept a URL as first argument
_PV_URL_CONFIG_PAT = re.compile(
    r"(?:url|endpoint|baseUrl|base_url|publicEndpoint|kvUrl|mcp_url|dashboardURL"
    r"|server|host|remoteUrl|connectionUrl)\s*[=:]\s*[f\"'`]*http://"
    r"|AIIntentDetector\s*\([f\"']http://"
    r"|SimpleAIAgent\s*\([f\"']http://"
    r"|new\s+URL\s*\([f\"']http://",
    re.IGNORECASE,
)


def _pv_is_private_ip(m: re.Match) -> bool:
    """True se l'IP in m è privato (RFC 1918) o link-local."""
    try:
        a, b = int(m.group(1)), int(m.group(2))
        if a == 10: return True
        if a == 172 and 16 <= b <= 31: return True
        if a == 192 and b == 168: return True
        if a == 169 and b == 254: return True
        if a == 127: return True
        return False
    except Exception:
        return False


# ── SESSION_ID_IN_URL patterns ────────────────────────────────────────────────

# MCP SSE protocol: session_id nell'URL è il design del protocollo MCP
_PV_MCP_SSE_PAT = re.compile(
    r"session_id=\{session_id|session_id\.hex"
    r"|/message\?session_id=|/sse\?session[Ii]d="
    r"|sessionId=\{.*session[Ii]d|session_id=<id>"
    r"|sessionId=your-session-id|sessionId=abc-123"
    r"|sessionId=XYZ|session_id=xxx"
    r"|session_id=\{conn_id\}"
    r"|messages/\?session_id=\{|messages/\?session_id=\{"
    r"|/message\?sessionId=\{.*quote_plus"   # urllib.parse.quote_plus(session_id)
    r"|/messages/\?session_id=\{self\.session_id"
    r"|session_id=\{self\.session_id\}"      # MCP SSE transport
    r"|sessionId=\{self\.session_id\}"
    r"|request_url.*sessionId=\{self\.session_id"
    # Varianti MCP SSE aggiuntive
    r"|/messages\?session_id=\{session\.session_id"  # mcpproxy / wireMCP
    r"|ws\?session_id='|ws\?session_id=\""           # WebSocket suffix (no value)
    r"|f\"/messages\?session_id=|f'/messages\?session_id="
    r"|\?session_id=\{.*session_id\}"                # generic MCP SSE pattern
    r"|message_url\}?\?session_id=\{"                # pymcp-sse style
    r"|ws_url\s*\+=.*\?session_id=\{"                # amcp style WS append
    r"|req\.url.*\+.*\?sessionId=|split\([\"']sessionId="  # URL construction/parsing
    r"|sseTransport\.sessionId|sse.*session[Ii]d"    # SSE transport object
    r"|message_endpoint.*session[Ii]d=<|/messages/\?session_id=\d",  # doc/example
    re.IGNORECASE,
)

# Stripe checkout callback (CHECKOUT_SESSION_ID è un template Stripe, non segreto)
_PV_STRIPE_SESSION_PAT = re.compile(
    r"\{CHECKOUT_SESSION_ID\}|success_url.*session_id",
    re.IGNORECASE,
)

# Keyword argument di funzione (non URL query string)
_PV_FUNC_KWARG_PAT = re.compile(
    r",\s*sid=session_id|blocked_sid=|sid=cdp_session|sid=self\._session_manager"
    r"|rsid=self\.rsid"                           # document revision session ID
    r"|,\s*session_id=session_id"                 # generic kwarg
    r"|session_id=cdp_session|session_id=redirect_session"
    r"|session_id=execute_session|session_id=session_id\b"  # kwarg with same-name var
    r"|host=host.*session_id=session_id"          # named params in function call
    r"|display_name=display_name.*session_id="    # file upload kwarg
    r"|,\s*session_id=None\b",                   # optional session kwarg
    re.IGNORECASE,
)

# Documentazione / log / errore (non codice di produzione)
_PV_SESSION_DOC_PAT = re.compile(
    r"console\.(log|error)\s*\(`|print\s*\(f?[\"'].*session"
    r'|<code>|<li>|<div class|curl |example:|GET /|POST /'
    r"|Include \?sessionId|Sends event:endpoint|Direct endpoint pattern"
    r"|event: endpoint|urlParam|session_id=<id>|sessionId=\.\.\."
    r'|"endpoint".*"/messages\?session_id='
    r"|# /messages/?\?session_id"                    # inline comment with MCP URL
    r"|\"Message endpoint.*POST|MCP clients.*POST"   # doc dict / comment
    r"|drilldown\?session_id="                       # analytics drilldown (agentops)
    r"|channels\?session_id=\{"                      # Jupyter kernel channel (not auth)
    r"|e\.g\.\s+\"/messages/\?session_id=",          # example URL in comment
    re.IGNORECASE,
)

# SID non-auth (video ID, table ID, task ID, season ID — non token di sessione utente)
_PV_NON_AUTH_SID_PAT = re.compile(
    r"\?sid=\{video_id\}|\?sid=\{season_id\}|\?sid=\{task_id\}"
    r"|\?sid=\{sid\}&|/share\?sid=\{"
    r"|/progress\?sid=\{sid\}"
    r"|sid_type.*sid\}|/acl/sid/\{"
    r"|season_id.*series_id|series_id.*season_id"   # bilibili season/series ID
    r"|\?sid=\{clean_id\}|e-stat\.go\.jp.*\?sid="   # Japanese statistics table ID
    r"|\?sid=mijia\b"                               # Xiaomi service name (not user session)
    r"|\?_json=true&sid=[a-z]",                    # sid= with literal service name
    re.IGNORECASE,
)

# Bundle JS minificato (socket.io.min.js, webpack, ecc.)
_PV_SESSION_BUNDLE_PAT = re.compile(
    r'"object"==typeof exports|!function\(e,t\)\{|\.min\.js',
    re.IGNORECASE,
)

# VP: autenticazione reale in URL query string
_PV_AUTH_SESSION_URL_PAT = re.compile(
    # Pi-hole admin API: ?sid= o &sid= con session_id reale
    r"[?&](?:_)?sid=\{(?:self\.)?(?:session_id|encoded_sid)"
    r"|webwxsync\?sid="                          # WeChat web API
    r"|frontdoor\.jsp\?sid="                     # Salesforce
    r"|/login\?session_id=\{"                    # app login URL
    r"|/upload(?:ProductList)?\?session_id=\{",  # app upload URL
    re.IGNORECASE,
)


def hc_rules_protocol_violation(f: dict) -> tuple[str, str]:
    vid  = f.get("id", "")
    ev   = f.get("evidence") or ""
    path = (f.get("file") or "").lower()

    # ── INSECURE_TRANSPORT ────────────────────────────────────────────────────
    if vid == "INSECURE_TRANSPORT":
        # HC-FP: evidence vuota — nessuna prova di utilizzo reale
        if not ev:
            return "HC-FP", "hc_fp:it_no_evidence_cannot_verify"

        # HC-FP: evidence cita ENTRAMBI http:// e https:// → messaggio di
        # validazione/documentazione che descrive i protocolli validi
        if "http://" in ev and "https://" in ev:
            return "HC-FP", "hc_fp:it_both_protocols_mentioned_validator_or_doc"

        # HC-FP: IP/domini locali o privati
        if _PV_LOCAL_PAT.search(ev):
            return "HC-FP", "hc_fp:it_localhost_or_loopback"
        if _PV_PRIVATE_IP_PAT.search(ev):
            return "HC-FP", "hc_fp:it_private_rfc1918_ip"
        if _PV_LINKLOCAL_PAT.search(ev):
            return "HC-FP", "hc_fp:it_link_local_imds_no_tls_available"
        if _PV_MDNS_PAT.search(ev):
            return "HC-FP", "hc_fp:it_mdns_local_domain"
        if _PV_K8S_PAT.search(ev):
            return "HC-FP", "hc_fp:it_kubernetes_internal_service"
        # HC-FP: testo di esempio o placeholder
        if _PV_EXAMPLE_PAT.search(ev):
            return "HC-FP", "hc_fp:it_example_or_placeholder_url"
        # HC-FP: commento / copyright
        if _PV_COMMENT_PAT.match(ev) or _PV_COPYRIGHT_PAT.search(ev):
            return "HC-FP", "hc_fp:it_comment_or_copyright"
        # HC-FP: messaggio di validazione che cita http:// come schema ammesso
        if _PV_VALIDATOR_PAT.search(ev):
            return "HC-FP", "hc_fp:it_validator_message_not_usage"
        # HC-FP: messaggio di log/print con URL — istruzione informativa, non chiamata
        if _PV_PRINT_LOG_PAT.match(ev):
            return "HC-FP", "hc_fp:it_log_or_print_informational_not_network_call"
        # HC-FP: mirror pacchetti (usano HTTP per design)
        if _PV_PKG_MIRROR_PAT.search(ev):
            return "HC-FP", "hc_fp:it_package_mirror_http_by_design"
        # HC-FP: namespace XML/SOAP/XSD (non chiamate di rete)
        if _PV_XML_NS_PAT.search(ev):
            return "HC-FP", "hc_fp:it_xml_soap_namespace_not_network_call"
        # HC-FP: domini noti come riferimenti / identifier / placeholder
        if _PV_KNOWN_REF_DOMAIN_PAT.search(ev):
            return "HC-FP", "hc_fp:it_known_reference_or_placeholder_domain"
        # HC-FP: URL di documentazione, identifier standard, S3 pubblici
        if _PV_DOC_URL_PAT.search(ev):
            return "HC-FP", "hc_fp:it_documentation_or_reference_url"
        if _PV_S3_PUBLIC_PAT.search(ev):
            return "HC-FP", "hc_fp:it_public_s3_cdn_dataset"
        # HC-FP: commento inline (# ... http:// oppure // ... http://)
        if _PV_INLINE_COMMENT_PAT.search(ev):
            return "HC-FP", "hc_fp:it_inline_comment_url"
        # HC-FP: link RST/Sphinx in docstring: <http://...>
        if _PV_RST_LINK_PAT.search(ev):
            return "HC-FP", "hc_fp:it_rst_sphinx_docstring_link"
        # HC-FP: costante di configurazione named (overridable)
        if _PV_CONFIG_CONST_PAT.search(ev):
            return "HC-FP", "hc_fp:it_named_config_constant_overridable"
        # HC-FP: URL in campo 'description' (non chiamata di rete)
        if _PV_DESC_FIELD_PAT.search(ev):
            return "HC-FP", "hc_fp:it_url_in_description_field"
        # HC-FP: file di test / spec
        if _PV_TEST_FILE_PAT.search(path):
            return "HC-FP", "hc_fp:it_test_or_spec_file"
        # HC-FP: env var con default http:// (l'utente può sovrascrivere con https://)
        if _PV_ENV_DEFAULT_PAT.search(ev):
            return "HC-FP", "hc_fp:it_env_var_default_overridable"
        # HC-FP: FHIR system field (URI identifier, non chiamata di rete)
        if _PV_FHIR_SYSTEM_PAT.search(ev):
            return "HC-FP", "hc_fp:it_fhir_system_uri_identifier_not_network"
        # HC-FP: RDF/ontology Namespace() constructor o register_namespace()
        if _PV_RDF_NS_PAT.search(ev):
            return "HC-FP", "hc_fp:it_rdf_ontology_namespace_not_network_call"
        # HC-FP: Python raw-string regex pattern contenente http:// (non è una call)
        if _PV_REGEX_URL_PAT.search(ev):
            return "HC-FP", "hc_fp:it_regex_pattern_containing_url_not_network"
        # HC-FP: curl install / wget (script di installazione, non codice applicativo)
        if _PV_CURL_INSTALL_PAT.search(ev):
            return "HC-FP", "hc_fp:it_curl_wget_install_script_not_app_code"
        # HC-FP: riga APT/deb/rpm (mirror repository, HTTP per design)
        if _PV_APT_LINE_PAT.match(ev):
            return "HC-FP", "hc_fp:it_apt_rpm_repository_line_http_by_design"
        # HC-FP: riferimento inline in stringa: (see http://...) o reference: http://
        if _PV_REF_INLINE_PAT.search(ev):
            return "HC-FP", "hc_fp:it_inline_reference_string_not_network_call"

        # HC-VP: cloud provider / platform domain via HTTP (always VP if not FP-filtered)
        if _PV_CLOUD_VP_PAT.search(ev):
            return "HC-VP", "hc_vp:it_cloud_provider_http_endpoint"
        # HC-VP: explicit HTTP call function with http:// in evidence (not FP-filtered)
        if _PV_HTTP_CALL_PAT.search(ev):
            return "HC-VP", "hc_vp:it_explicit_http_call_function"
        # HC-VP: URL assignment/constructor config with http:// (not FP-filtered)
        if _PV_URL_CONFIG_PAT.search(ev):
            return "HC-VP", "hc_vp:it_url_config_assignment"

        # HC-VP: any remaining http://[external-domain] — all FP patterns exhausted
        # at this point nothing matched any FP rule, so any real-looking domain is VP
        if re.search(r"http://[a-z0-9][a-z0-9._-]*\.[a-z]{2,}", ev, re.IGNORECASE):
            return "HC-VP", "hc_vp:it_external_domain_http_all_fp_exhausted"

        # HC-VP: IP esterno non-privato in chiamata HTTP effettiva
        m = _PV_EXT_IP_PAT.search(ev)
        if m and not _pv_is_private_ip(m):
            if _PV_HTTP_CALL_PAT.search(ev):
                return "HC-VP", "hc_vp:it_external_ip_in_actual_http_call"
            # IP esterno in print/log/echo (informativo, non è una connessione)
            if _PV_PRINT_LOG_PAT.match(ev):
                return "HC-FP", "hc_fp:it_external_ip_in_print_or_log_not_network"
            # IP esterno in costante/config — hardcoded external IP via HTTP is a VP
            # regardless of whether there's an explicit fetch() call in this line
            return "HC-VP", "hc_vp:it_external_ip_hardcoded_http_endpoint"

    # ── SESSION_ID_IN_URL ─────────────────────────────────────────────────────
    if vid == "SESSION_ID_IN_URL":
        # HC-FP: localhost / loopback (development server, not a real auth session)
        if _PV_LOCAL_PAT.search(ev):
            return "HC-FP", "hc_fp:sid_localhost_development_server"
        # HC-FP: MCP SSE protocol (session_id nell'URL è il design del protocollo)
        if _PV_MCP_SSE_PAT.search(ev):
            return "HC-FP", "hc_fp:sid_mcp_sse_transport_protocol"
        # HC-FP: Stripe checkout (CHECKOUT_SESSION_ID non è un segreto utente)
        if _PV_STRIPE_SESSION_PAT.search(ev):
            return "HC-FP", "hc_fp:sid_stripe_checkout_session_not_auth"
        # HC-FP: keyword argument di funzione (non query string URL)
        if _PV_FUNC_KWARG_PAT.search(ev):
            return "HC-FP", "hc_fp:sid_function_kwarg_not_url_param"
        # HC-FP: documentazione / log / messaggi d'errore
        if _PV_SESSION_DOC_PAT.search(ev):
            return "HC-FP", "hc_fp:sid_documentation_or_log_message"
        # HC-FP: SID non-auth (video ID, task ID, season ID — non token utente)
        if _PV_NON_AUTH_SID_PAT.search(ev):
            return "HC-FP", "hc_fp:sid_non_auth_identifier_not_session_token"
        # HC-FP: bundle JS minificato
        if _PV_SESSION_BUNDLE_PAT.search(ev):
            return "HC-FP", "hc_fp:sid_minified_js_bundle"

        # HC-VP: session di autenticazione reale in URL query string
        if _PV_AUTH_SESSION_URL_PAT.search(ev):
            return "HC-VP", "hc_vp:sid_real_auth_session_in_url_query_string"

    return "UNCERTAIN", ""


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-watch | CATEGORIA: tool-poisoning
# ══════════════════════════════════════════════════════════════════════════════
#
# Lo scanner di mcp-watch (ToolPoisoningScanner) cerca, nelle stesse righe che
# contengono "description", pattern come "ignore previous instructions",
# "system: you are now", "[SYSTEM]|[ADMIN]|[OVERRIDE]", "act as if/a",
# "forget everything/all".
#
# Il filtro Stage 1 ha gia scartato test/doc/third-party/security-scanner e
# pattern comuni di falso positivo. Qui raffiniamo ulteriormente:
# - Pydantic field "overrides:" (non "override instruction")
# - passthrough "description: (x as any).description"
# - label legittimo "[SYSTEM][SAFE]"
# - descrizione API lunga senza contenuto di injection
# - English "act as additional/alternate ... requester/agent/delegate"

_TP_PYDANTIC_OVERRIDE = re.compile(
    r"\b(?:overrides?|admins?|systems?)\s*:\s*(?:Optional\[)?(?:List|list|Sequence)\b",
)
_TP_PYDANTIC_FIELD_DESC = re.compile(
    r"=\s*Field\s*\(.*description\s*=", re.DOTALL,
)
_TP_DESC_PASSTHROUGH = re.compile(
    r"description\s*:\s*\([^)]*?\)\.(?:description|text|value|content)"
    r"|description\s*:\s*\w+\.(?:description|text|value|content)\b"
)
_TP_SAFE_LABEL = re.compile(r"\[\s*SYSTEM\s*\]\s*\[\s*SAFE\s*\]", re.IGNORECASE)
_TP_ACT_AS_BENIGN = re.compile(
    r"\bwho\s+act\s+as\b"
    r"|\bact\s+as\s+(?:a[n]?\s+)?(?:additional|alternate|delegate|backup|"
    r"proxy|requester|requesters|reviewer|reviewers|approver|approvers|"
    r"contact|collaborator|legend|legendary|persona|owner|maintainer|"
    r"agent|signer)\b",
    re.IGNORECASE,
)
# Lunga descrizione di API REST/SDK senza contenuto di injection
_TP_LONG_API_DESC = re.compile(
    r"(?:REST\s+API|API\s+(?:endpoint|for|specification|documentation))"
    r"|(?:provides\s+data\s+so\s+that)"
    r"|(?:list\s+of\s+client\s+users|collection\s+of\s+[A-Z])",
    re.IGNORECASE,
)
# Persona / roleplay in contesto di simulazione legittima (es. startup game)
_TP_PERSONA_ROLEPLAY = re.compile(
    r"(?:persona\s+context|roleplay\s+as\s+(?:them|a|an)|"
    r"legendary\s+(?:founder|investor|figure))",
    re.IGNORECASE,
)
# Parameter description che documenta i valori possibili di un campo "role"
_TP_ROLE_FIELD_DOC = re.compile(
    r"['\"]?(?:description|label|help)['\"]?\s*[:=]\s*['\"]\s*"
    r"(?:New\s+role|Role\s+name|Role\s+to\s+assign|Role\s+type|"
    r"Specify\s+role|User\s+role)\s*:?\s*['\"]?\s*"
    r"['\"]?[\w,\s/\\|'-]*?(?:admin|user|owner|member|viewer|editor)",
    re.IGNORECASE,
)


def hc_rules_tool_poisoning(f: dict) -> tuple[str, str]:
    vid = f.get("id", "")
    ev = f.get("evidence") or ""
    fp = (f.get("file") or "").lower()

    # Solo HIDDEN_TOOL_INSTRUCTIONS arriva qui dopo Stage 1
    if vid != "HIDDEN_TOOL_INSTRUCTIONS":
        return "UNCERTAIN", ""

    # HC-FP: Pydantic field "overrides:"/"admins:" scambiato per "override"/"admin"
    if _TP_PYDANTIC_OVERRIDE.search(ev):
        return "HC-FP", "hc_fp:pydantic_field_named_overrides_or_admins"

    # HC-FP: description passthrough (description: (x as any).description)
    if _TP_DESC_PASSTHROUGH.search(ev):
        return "HC-FP", "hc_fp:description_passthrough_from_existing_field"

    # HC-FP: label legittimo [SYSTEM][SAFE] come prefisso descrittivo
    if _TP_SAFE_LABEL.search(ev):
        return "HC-FP", "hc_fp:system_safe_label_legitimate_prefix"

    # HC-FP: "act as" in contesto benigno ("who act as", "act as a delegate")
    if _TP_ACT_AS_BENIGN.search(ev):
        return "HC-FP", "hc_fp:act_as_benign_english_usage"

    # HC-FP: persona / roleplay in contesto di simulazione legittima
    if _TP_PERSONA_ROLEPLAY.search(ev):
        return "HC-FP", "hc_fp:persona_roleplay_simulation_context"

    # HC-FP: long API/REST description senza contenuto di injection
    if len(ev) > 300 and _TP_LONG_API_DESC.search(ev):
        return "HC-FP", "hc_fp:long_api_description_no_injection_content"

    return "UNCERTAIN", "uncertain_tool_poisoning_trigger"


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-watch | CATEGORIA: prompt-injection
# ══════════════════════════════════════════════════════════════════════════════
#
# Lo scanner PromptInjectionScanner cerca nelle tool description pattern di
# prompt injection (stessi di tool-poisoning + "pretend", "disregard",
# "simulate", "roleplay as", "new role:", "you are now").
#
# I pattern di Stage 2A sono gli stessi di tool-poisoning piu' alcuni extra:
# - "New role: 'admin' or 'user'" in parameter doc
# - "roleplay as legendary founder" in startup-sim MCP
# - "simulate a transaction/click" benign usage

_PI_NEW_ROLE_PARAM_DOC = re.compile(
    r"['\"]?description['\"]?\s*:\s*['\"]\s*New\s+role\s*:\s*['\"]",
    re.IGNORECASE,
)
_PI_SIMULATE_BENIGN = re.compile(
    r"\bsimulate\s+(?:a[n]?\s+)?(?:transaction|click|request|event|"
    r"response|call|payload|query|message|error|load|user|trade|session)\b",
    re.IGNORECASE,
)


def hc_rules_prompt_injection(f: dict) -> tuple[str, str]:
    vid = f.get("id", "")
    ev = f.get("evidence") or ""

    # Stage 1 scarta RETRIEVAL_AGENT_DECEPTION — solo TOOL_DESCRIPTION_INJECTION qui
    if vid != "TOOL_DESCRIPTION_INJECTION":
        return "UNCERTAIN", ""

    # Riutilizza le regole tool-poisoning (stessi pattern di FP)
    if _TP_PYDANTIC_OVERRIDE.search(ev):
        return "HC-FP", "hc_fp:pydantic_field_named_overrides_or_admins"
    if _TP_DESC_PASSTHROUGH.search(ev):
        return "HC-FP", "hc_fp:description_passthrough_from_existing_field"
    if _TP_SAFE_LABEL.search(ev):
        return "HC-FP", "hc_fp:system_safe_label_legitimate_prefix"
    if _TP_ACT_AS_BENIGN.search(ev):
        return "HC-FP", "hc_fp:act_as_benign_english_usage"
    if _TP_PERSONA_ROLEPLAY.search(ev):
        return "HC-FP", "hc_fp:persona_roleplay_simulation_context"
    if len(ev) > 300 and _TP_LONG_API_DESC.search(ev):
        return "HC-FP", "hc_fp:long_api_description_no_injection_content"

    # Specifici di prompt-injection
    if _PI_NEW_ROLE_PARAM_DOC.search(ev):
        return "HC-FP", "hc_fp:new_role_parameter_documentation_not_injection"
    if _PI_SIMULATE_BENIGN.search(ev):
        return "HC-FP", "hc_fp:simulate_benign_usage_not_injection"

    return "UNCERTAIN", "uncertain_prompt_injection_trigger"


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-watch | CATEGORIA: tool-mutation
# ══════════════════════════════════════════════════════════════════════════════
#
# Lo scanner ToolMutationScanner cerca pattern come "tools.push(...)" /
# "tools[x] = ..." nel codice sorgente. Il problema e' che questi pattern
# sono piu' spesso REGISTRAZIONE DI TOOL (__init__, register_tool, setup)
# che DYNAMIC MUTATION (rug pull, runtime modifica dopo discovery).
#
# Il filtro Stage 1 ha gia scartato i contesti piu' evidenti (test, bundle,
# categorical bucket-build). Tutti i 2577 residui hanno
# filter_confidence='tools_index_assignment'. L'analisi campionaria mostra
# che *tutti* sono pattern di registrazione:
# - self.tools[tool.name] = tool                    (registry class)
# - self.tools["specific_name"] = {...}             (explicit registration)
# - this.tools[options.name] = options              (TypeScript registrar)
# - server._tools['name'] = function                (direct assignment)
#
# Una vera DYNAMIC_TOOL_MUTATION richiederebbe:
# - modifica della lista tools VISIBILE AL CLIENT dopo tools/list
# - in un handler runtime (request handler, event listener, websocket)
# - NON nel __init__ o in setup_tools()
#
# Il Stage 1 dovrebbe gia richiedere indicatori runtime, ma la regex attuale
# non distingue bene. Qui facciamo un ulteriore raffinamento: qualsiasi
# assegnazione `self.tools[<key>] = <value>` in una funzione di setup/init
# e' FP.

_TM_REGISTRATION_PATS = [
    # Prefissi comuni per dict di tool registry/aggregazione — copre quasi tutti
    # i pattern di registration/discovery/transformation
    re.compile(
        r"\b(?:"
        r"all_|available_|mcp_|registered_|preferred_|enabled_|disabled_|"
        r"selected_|active_|inactive_|configured_|loaded_|pending_|"
        r"search_|local_|remote_|server_|client_|shared_|global_|"
        r"discovered_|detected_|resolved_|imported_|exported_|"
        r"transformed_|converted_|namespaced_|prefixed_|wrapped_|"
        r"composed_|merged_|combined_|filtered_|formatted_|"
        r"mapped_|keyed_|indexed_|grouped_|sorted_|cached_|"
        r"new_|old_|temp_|tmp_|current_|previous_|next_|"
        r"implemented_|registered_|exposed_|reported_|tracked_|"
        r"shadowed_|hidden_|visible_|public_|private_|internal_|external_|"
        r"dep_|parent_|child_|root_|leaf_|sub_|super_|"
        r"my_|your_|their_|our_|this_|"
        r"clean_|raw_|formatted_|enriched_|augmented_|annotated_|"
        r"pre_|post_|before_|after_|legacy_|deprecated_|"
        r"custom_|default_|standard_|extended_|base_|core_|"
        r"schema_|meta_|proxy_|wrapper_|handler_"
        r")?tools?\s*\[", re.IGNORECASE),
    # this.tools[...] / self.tools[...] / cls.tools[...]
    re.compile(r"(?:self|this|cls|obj|ctx|env|state)\.\w*tools?\s*\[",
               re.IGNORECASE),
    # namespaced: capabilities.tools[...], server._tool_manager._tools[...]
    re.compile(r"[\w.]+\._?tools?\s*\[\s*['\"\w_.]+\s*\]\s*="),
    # tool[key] = value   (assigning a field on an individual tool object)
    re.compile(r"\btool\s*\[\s*['\"\w_]+['\"]?\s*\]\s*=", re.IGNORECASE),
    # mcp_tool[...] = ..., converted_tool[...] = ...
    re.compile(r"\b\w*_?tool\s*\[\s*['\"\w_]+['\"]?\s*\]\s*=", re.IGNORECASE),
    # namespaced_tool["name"] = namespace_name(...)
    re.compile(r"\b\w*tool\w*\s*\[\s*['\"][\w_.-]+['\"]\s*\]\s*="),
    # by_tool[key] = ...  (aggregation dict)
    re.compile(r"\bby_tool\w*\s*\["),
    # Registry / store / collection
    re.compile(r"\b(?:registry|store|collection|pool|cache|map)\s*\["
               r".*?tool", re.IGNORECASE),
    # Catch-all: qualsiasi identificatore che finisce in "tools" (plural) o
    # "tool" (singular) seguito da [key] = value. Dopo Stage 1 (che scarta
    # test/doc/bundle/init/register contexts), tutti i pattern residui di
    # questa forma sono di registration/aggregation/transformation.
    re.compile(r"\b\w*_?tools\s*\[\s*[^\]]+\s*\]\s*="),
    re.compile(r"\b\w*_?tool\s*\[\s*[^\]]+\s*\]\s*="),
    # stats.requests_by_tool[entry.toolName] = ... + count  (aggregation counter)
    re.compile(r"requests_by_tool\s*\["),
    # global/local variable with "tool" in name
    re.compile(r"\b(?:g_|global_|local_|static_|dynamic_?)?"
               r"\w*_?tools?\s*\[\s*\w+", re.IGNORECASE),
]

# File paths che suggeriscono registrazione/registry (NON runtime mutation)
_TM_REGISTRY_FILE_PATS = [
    re.compile(r"/tool[_-]?(?:registry|registrar|manager|config|loader)\.",
               re.IGNORECASE),
    re.compile(r"/(?:register|registry|setup|config)\.py$", re.IGNORECASE),
    re.compile(r"tool[_-]?registry\.", re.IGNORECASE),
    re.compile(r"/tools_config\.", re.IGNORECASE),
]

# Escluso runtime: se il file path NON e' una registry e l'evidence ha
# chiaramente una chiamata di lettura (tool for tool in ...) NOT assignment
_TM_READ_ONLY_PAT = re.compile(
    r"for\s+tool\s+in\s+tools"
    r"|tool\[['\"]name['\"]\]\s*==",
    re.IGNORECASE,
)


def hc_rules_tool_mutation(f: dict) -> tuple[str, str]:
    vid = f.get("id", "")
    ev = f.get("evidence") or ""
    fp = (f.get("file") or "").lower()

    # Stage 1 scarta TOOL_NAME_COLLISION — solo DYNAMIC_TOOL_MUTATION qui
    if vid != "DYNAMIC_TOOL_MUTATION":
        return "UNCERTAIN", ""

    # HC-FP: pattern chiaramente di read-only (not assignment)
    if _TM_READ_ONLY_PAT.search(ev):
        return "HC-FP", "hc_fp:read_only_comparison_not_mutation"

    # HC-FP: file path e' una registry (tool_registry.py, registry.py, ecc.)
    for pat in _TM_REGISTRY_FILE_PATS:
        if pat.search(fp):
            return "HC-FP", "hc_fp:tool_registry_file_standard_registration"

    # HC-FP: evidence matcha uno dei pattern di registrazione noti
    for pat in _TM_REGISTRATION_PATS:
        if pat.search(ev):
            return "HC-FP", "hc_fp:tool_registration_not_dynamic_mutation"

    return "UNCERTAIN", "uncertain_tool_mutation_pattern"


# ══════════════════════════════════════════════════════════════════════════════
#  FRAMEWORK: mcp-watch | CATEGORIA: access-control
# ══════════════════════════════════════════════════════════════════════════════
#
# Lo scanner PermissionScanner flagga ogni linea di codice che contiene
# una keyword di permesso (admin/root/delete/create/...) vicino a una
# keyword di contesto (user/permission/scope/role/access). Risultato:
# 428.443 finding — rumore estremo.
#
# Il filtro Stage 1 usa una WHITELIST di pattern ad alto valore (IAM "*":"*",
# Dockerfile USER root, chmod 777, k8s privileged:true, AdministratorAccess,
# GRANT ALL PRIVILEGES, docker --privileged, CAP_SYS_ADMIN, ecc.).
# 428.443 → 17 kept.
#
# Dei 17 residui:
# - 5 tool/parametro che DOCUMENTANO AdministratorAccess come opzione di SSO
#   → FP (description parameter, non grant effettivo)
# - 2 mcpMock.json / cache di traduzione / esempi → FP (documentazione/dati)
# - 1 complete-mitre-attack-mcp-server (MITRE intentional data) → FP
# - 1 armada-mcp test-railway-deployment.js (checks FOR USER root) → FP
# - 1 agent-security-scanner-mcp (matched_text di scanner output) → FP
# - 6 aws-pentest-mcp: offensive tool che costruisce attacchi IAM con
#   AdministratorAccess/Action:"*"/Resource:"*" → VP (tool di privilege
#   escalation, come sec-mimikatz-mcp)
# - 1 durandal-memory-bridge: GRANT ALL PRIVILEGES ON DATABASE in setup
#   script → VP (grant reale di permessi wildcard)

# HC-VP: aws-pentest-mcp server e' un offensive IAM pentest tool
_AC_AWS_PENTEST_SERVER = "aws-pentest-mcp"

# HC-VP: GRANT ALL PRIVILEGES ON DATABASE ... TO ...  (pattern SQL di grant
# reale, non in docs)
_AC_GRANT_ALL_DB_PAT = re.compile(
    r"GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+(?:DATABASE|SCHEMA|TABLE|ALL)",
    re.IGNORECASE,
)

# HC-FP: description di parametro che MENZIONA AdministratorAccess come
# esempio di valore (non esegue grant)
_AC_PARAM_DESC_ADMIN_EXAMPLE = re.compile(
    r"""(?:
          description\s*[:=]\s*['"].*?
          (?:role\s+name\s+to\s+assume|SSO|example|e\.g\.|available).*?
          AdministratorAccess
        |
          (?:role\s+name\s+to\s+assume|available\s+roles?|role\s+must\s+be\s+available)
          .*?AdministratorAccess
        |
          e\.g\.[^)]*?AdministratorAccess
        )""",
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)
# HC-FP: mock data / cache di traduzione / example
_AC_MOCK_OR_CACHE_FILE = re.compile(
    r"mockjson|mock\.json$|/mocks?/"
    r"|translation[_-]?(?:db|cache|workdir)"
    r"|/cache/|/translations?/"
    r"|/examples?\.(?:json|yaml|yml)$",
    re.IGNORECASE,
)
# HC-FP: MITRE ATT&CK dataset (complete-mitre-attack-mcp-server)
_AC_MITRE_DATASET = re.compile(
    r"(?:mitre.?(?:attack|att&ck)|enterprise.attack|stix[_-]?bundle)",
    re.IGNORECASE,
)
# HC-FP: test o validation code che CERCA USER root / insecure permissions
_AC_TEST_USER_ROOT_CHECK = re.compile(
    r"(?:dockerfile\.includes|!.*USER\s+root|grep.*USER\s+root"
    r"|test.*non[_-]?root|test.*root[_-]?user)",
    re.IGNORECASE,
)
# HC-FP: scanner report con "matched_text" / pre-formatted report row
_AC_SCANNER_REPORT = re.compile(
    r"['\"]matched_text['\"]|clawhub-security-reports"
    r"|security-reports/.*\.md",
    re.IGNORECASE,
)
# HC-FP: Linux capability drop description in extension manifest
_AC_CAP_DROP_DESC = re.compile(
    r"(?:markdownDescription|description).*?"
    r"(?:capabilities\s+to\s+drop|Removes?\s+specific\s+privileges"
    r"|fine.grained\s+privilege\s+control)",
    re.IGNORECASE,
)
# HC-FP: Pydantic field description about enable_fuse / enable_access
_AC_ENABLE_ACCESS_DESC = re.compile(
    r"description\s*=\s*['\"]\s*Enable\s+(?:access|fuse|feature)",
    re.IGNORECASE,
)
# HC-FP: BPF tracing example con root/admin in stringa
_AC_BPF_EXAMPLE = re.compile(
    r"BPF\s+code|trace\s+block\s+I/O|mcptrace|bpftrace",
    re.IGNORECASE,
)

# HC-VP pattern per aws-pentest-mcp exploitation strings (exploitation embedded
# in tool output — privilege escalation via IAM)
_AC_AWS_PENTEST_EXPLOIT = re.compile(
    r"(?:attach-user-policy|attach-role-policy|put-user-policy|put-role-policy)"
    r".*?AdministratorAccess"
    r"|policy-document.*?['\"]Action['\"]\s*:\s*['\"]\*['\"]"
    r"|\[CRITICAL\].*?Attached\s+to\s+AdministratorAccess",
    re.IGNORECASE | re.DOTALL,
)


def hc_rules_access_control(f: dict) -> tuple[str, str]:
    vid = f.get("id", "")
    ev = f.get("evidence") or ""
    fp = (f.get("file") or "").lower()
    server = (f.get("server_name") or "")

    # Stage 1 scarta CONSENT_FATIGUE_RISK — solo EXCESSIVE_PERMISSIONS qui
    if vid != "EXCESSIVE_PERMISSIONS":
        return "UNCERTAIN", ""

    # ── HC-FP ───────────────────────────────────────────────────────────────
    if _AC_MOCK_OR_CACHE_FILE.search(fp):
        return "HC-FP", "hc_fp:mock_data_or_cache_file_not_code"
    if _AC_MITRE_DATASET.search(fp) or _AC_MITRE_DATASET.search(ev):
        return "HC-FP", "hc_fp:mitre_attack_dataset_intentional"
    if _AC_TEST_USER_ROOT_CHECK.search(ev):
        return "HC-FP", "hc_fp:test_code_checks_for_user_root_not_grants_it"
    if _AC_SCANNER_REPORT.search(ev) or _AC_SCANNER_REPORT.search(fp):
        return "HC-FP", "hc_fp:security_scanner_report_matched_text"
    if _AC_CAP_DROP_DESC.search(ev):
        return "HC-FP", "hc_fp:capability_drop_description_extension_manifest"
    if _AC_ENABLE_ACCESS_DESC.search(ev):
        return "HC-FP", "hc_fp:enable_access_pydantic_field_description"
    if _AC_BPF_EXAMPLE.search(ev) or _AC_BPF_EXAMPLE.search(fp):
        return "HC-FP", "hc_fp:bpf_tracing_example_data"
    if _AC_PARAM_DESC_ADMIN_EXAMPLE.search(ev):
        return "HC-FP", "hc_fp:parameter_description_admin_as_example_value"

    # ── HC-VP ───────────────────────────────────────────────────────────────
    # aws-pentest-mcp: server offensivo che esegue/istruisce IAM privilege escalation
    if server == _AC_AWS_PENTEST_SERVER:
        if _AC_AWS_PENTEST_EXPLOIT.search(ev):
            return "HC-VP", "hc_vp:aws_pentest_mcp_iam_privilege_escalation_exploit"
        # altri match su aws-pentest-mcp: detection code (findings.push, role.includes)
        if re.search(r"findings\d*\.push|role\.includes", ev):
            return "HC-VP", "hc_vp:aws_pentest_mcp_offensive_tool_context"

    # GRANT ALL PRIVILEGES su DB in script di setup
    if _AC_GRANT_ALL_DB_PAT.search(ev) and not re.search(
        r"(?://|#|\*|>>>)\s*GRANT", ev):
        return "HC-VP", "hc_vp:grant_all_privileges_on_database_runtime_sql"

    return "UNCERTAIN", "uncertain_access_control_pattern"


# ══════════════════════════════════════════════════════════════════════════════
#  DISPATCHER — mappa categoria → funzione regole HC
# ══════════════════════════════════════════════════════════════════════════════

HC_RULES: dict[str, callable] = {
    "credential-leak":        hc_rules_credential_leak,
    "data-exfiltration":      hc_rules_data_exfiltration,
    "input-validation":       hc_rules_input_validation,
    "steganographic-attack":  hc_rules_steganographic_attack,
    "protocol-violation":     hc_rules_protocol_violation,
    "tool-poisoning":         hc_rules_tool_poisoning,
    "prompt-injection":       hc_rules_prompt_injection,
    "tool-mutation":          hc_rules_tool_mutation,
    "access-control":         hc_rules_access_control,
}


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 2A — classificazione HC
# ══════════════════════════════════════════════════════════════════════════════

def run_stage2a(cat: str, findings: list) -> tuple[list, list, list]:
    """
    Applica le regole HC alla lista di finding.
    Ritorna (hc_fp_list, hc_vp_list, uncertain_list).
    """
    fn = HC_RULES.get(cat)
    if fn is None:
        raise ValueError(f"Nessuna regola HC per la categoria '{cat}'. "
                         f"Aggiungi hc_rules_{cat.replace('-','_')}() e registrala in HC_RULES.")

    hc_fp, hc_vp, unc = [], [], []
    for f in findings:
        bucket, reason = fn(f)
        enriched = dict(f, llm_bucket=bucket, bucket_reason=reason)
        if   bucket == "HC-FP":  hc_fp.append(enriched)
        elif bucket == "HC-VP":  hc_vp.append(enriched)
        else:                    unc.append(enriched)
    return hc_fp, hc_vp, unc


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 2B — classificazione Ollama
# ══════════════════════════════════════════════════════════════════════════════

OLLAMA_PROMPT = """\
Sei un esperto di sicurezza informatica che analizza finding di vulnerabilita di MCP server (Model Context Protocol).

Devi classificare il seguente finding come:
- VP (Vero Positivo): il finding indica una vera vulnerabilita di sicurezza
- FP (Falso Positivo): il finding e un errore dello scanner, codice di test, pattern legittimo

FINDING DA ANALIZZARE:
- ID vulnerabilita: {vid}
- Categoria: {category}
- Server: {server_name}
- File: {file}
- Confidence filtro: {filter_confidence}
- Evidence (riga di codice rilevante):
  {evidence}

ISTRUZIONI:

Per HARDCODED_CREDENTIALS -> VP se sembra una vera chiave/token, FP se:
  - e commentata (inizia con #, //, /*)
  - e un placeholder (abc123, your_, changeme, placeholder, example)
  - JWT con role "anon" (Supabase anon key pubblica)

Per PLAINTEXT_STORAGE -> VP se credenziali scritte su disco/log, FP se:
  - output su stdout di token LLM (streaming)
  - definizione di funzione, non una scrittura effettiva
  - file JSON di dati, non di configurazione

Per DATA_EXFILTRATION -> VP se dati utente/sessione inviati a server esterno, FP se:
  - chiamata API Ollama/embedding locale
  - parametro Python interno (non nel schema MCP)
  - metodo di caching o wrapper interno
  - codice bundled/minificato

Per INSECURE_CREDENTIAL_PERMISSIONS -> VP se permessi davvero errati, FP se:
  - file e package.json (script di build)
  - chmod imposta permessi sicuri (600, 644, 400)

RISPONDI SOLO con questo JSON (nient'altro, nessun testo prima o dopo):
{{"verdict": "VP" o "FP", "reason": "breve spiegazione in italiano (max 20 parole)"}}"""


def _build_ollama_prompt(f: dict) -> str:
    ev = (f.get("evidence") or "")[:500]
    return OLLAMA_PROMPT.format(
        vid=f.get("id", ""),
        category=f.get("category", ""),
        server_name=f.get("server_name", ""),
        file=f.get("file", ""),
        filter_confidence=f.get("filter_confidence", ""),
        evidence=ev,
    )


def _call_ollama(ollama_url: str, model: str, prompt: str) -> dict:
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{ollama_url}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    text = body.get("message", {}).get("content", "").strip()
    m = re.search(r"\{[^{}]+\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"verdict": "UNCERTAIN", "reason": f"parse_error:{text[:80]}"}


def check_ollama(ollama_url: str, model: str) -> bool:
    try:
        req = urllib.request.Request(f"{ollama_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            tags = json.loads(resp.read().decode("utf-8"))
        available = [m["name"].split(":")[0] for m in tags.get("models", [])]
        model_base = model.split(":")[0]
        if model_base not in available:
            print(f"ATTENZIONE: modello '{model}' non trovato in Ollama.")
            print(f"  Disponibili: {', '.join(available) or 'nessuno'}")
            print(f"  Esegui: ollama pull {model}")
            return False
        return True
    except urllib.error.URLError as e:
        print(f"ERRORE: impossibile connettersi a Ollama su {ollama_url}: {e}")
        print("  Assicurati che Ollama sia in esecuzione (ollama serve)")
        return False


def _cache_path(out_dir: Path) -> Path:
    return out_dir / "_ollama_cache.json"


def _load_cache(out_dir: Path) -> dict:
    p = _cache_path(out_dir)
    if p.exists():
        try:
            with io.open(p, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass
    return {}


def _save_cache(out_dir: Path, cache: dict) -> None:
    with io.open(_cache_path(out_dir), "w", encoding="utf-8") as fh:
        json.dump(cache, fh, ensure_ascii=False, indent=2)


def _cache_key(f: dict) -> str:
    return f"{f.get('server_name','')}/{f.get('file','')}/{f.get('line',0)}/{f.get('id','')}"


def run_stage2b(unc: list, out_dir: Path, args) -> list:
    """
    Classifica i finding UNCERTAIN con Ollama.
    Ritorna la lista arricchita con llm_verdict e llm_reason.
    """
    if not unc:
        return []

    cache = {} if args.no_cache else _load_cache(out_dir)
    results = []
    new_calls = 0
    n = len(unc)

    for i, f in enumerate(unc):
        key = _cache_key(f)
        if key in cache and not args.no_cache:
            vd = cache[key]
            print(f"  [{i+1}/{n}] CACHED  {f['server_name'][:30]:30s}  → {vd['verdict']}")
        else:
            prompt = _build_ollama_prompt(f)
            if args.dry_run:
                print(f"  [{i+1}/{n}] DRY-RUN {f['server_name'][:30]:30s}")
                print(f"    PROMPT: {prompt[:200]}...")
                vd = {"verdict": "DRY_RUN", "reason": "dry_run"}
            else:
                try:
                    vd = _call_ollama(args.ollama_url, args.model, prompt)
                    new_calls += 1
                    cache[key] = vd
                    _save_cache(out_dir, cache)
                    print(f"  [{i+1}/{n}] OLLAMA  {f['server_name'][:30]:30s}"
                          f"  → {vd.get('verdict','?'):2s}  {vd.get('reason','')[:55]}")
                except Exception as e:
                    print(f"  [{i+1}/{n}] ERRORE  {f['server_name']}: {e}")
                    vd = {"verdict": "ERROR", "reason": str(e)[:80]}

        results.append(dict(f,
                            llm_verdict=vd.get("verdict"),
                            llm_reason=vd.get("reason"),
                            verdict_source=f"ollama:{args.model}"))

    print(f"  Ollama: {new_calls} nuove chiamate, {n - new_calls} da cache")
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  MERGE finale → vp.json / fp.json / audit.json
# ══════════════════════════════════════════════════════════════════════════════

def run_merge(cat: str, src_meta: dict, hc_fp: list, hc_vp: list,
              unc_classified: list, out_dir: Path) -> None:
    vp_final, fp_final, audit = [], [], []

    for f in hc_vp:
        rec = dict(f, final_verdict="VP", verdict_source="hc_rule",
                   final_reason=f.get("bucket_reason", ""))
        vp_final.append(rec); audit.append(rec)

    for f in hc_fp:
        rec = dict(f, final_verdict="FP", verdict_source="hc_rule",
                   final_reason=f.get("bucket_reason", ""))
        fp_final.append(rec); audit.append(rec)

    for f in unc_classified:
        v = f.get("llm_verdict", "")
        if v not in ("VP", "FP"):
            v = "FP"  # default conservativo
        rec = dict(f, final_verdict=v, final_reason=f.get("llm_reason", ""))
        (vp_final if v == "VP" else fp_final).append(rec)
        audit.append(rec)

    def dump(path: Path, items: list, verdict: str) -> None:
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "category": cat,
                "pipeline_stage": "stage2_hc+ollama",
                "verdict": verdict,
                "original_total": src_meta.get("original_total"),
                "filter_kept_total": src_meta.get("kept_total"),
                "llm_total": len(items),
                "findings": items,
            }, fh, ensure_ascii=False, indent=2)

    dump(out_dir / "vp.json",    vp_final, "true_positive")
    dump(out_dir / "fp.json",    fp_final, "false_positive")
    with io.open(out_dir / "audit.json", "w", encoding="utf-8") as fh:
        json.dump({"total": len(audit), "findings": audit},
                  fh, ensure_ascii=False, indent=2)

    total = len(vp_final) + len(fp_final)
    print(f"\n  ── Risultati finali ──────────────────────────────")
    print(f"  Totale:          {total:4d}")
    print(f"  Veri Positivi:   {len(vp_final):4d}  ({len(vp_final)/total*100:.1f}%)")
    print(f"  Falsi Positivi:  {len(fp_final):4d}  ({len(fp_final)/total*100:.1f}%)")
    print(f"  ─────────────────────────────────────────────────")


# ══════════════════════════════════════════════════════════════════════════════
#  SALVATAGGIO bucket intermedi
# ══════════════════════════════════════════════════════════════════════════════

def save_buckets(cat: str, src_meta: dict, hc_fp: list, hc_vp: list,
                 unc: list, out_dir: Path) -> None:
    base = {"category": cat,
            "original_total": src_meta.get("original_total"),
            "filter_kept_total": src_meta.get("kept_total")}

    def dump(path: Path, items: list, bucket: str) -> None:
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump({**base, "bucket": bucket, "total": len(items), "findings": items},
                      fh, ensure_ascii=False, indent=2)

    dump(out_dir / "hc_fp.json",     hc_fp, "HC-FP")
    dump(out_dir / "hc_vp.json",     hc_vp, "HC-VP")
    dump(out_dir / "uncertain.json",  unc,   "UNCERTAIN")


# ══════════════════════════════════════════════════════════════════════════════
#  PIPELINE PRINCIPALE
# ══════════════════════════════════════════════════════════════════════════════

def run_category(cat: str, args) -> None:
    cat_dir   = HERE / cat / "filtered"
    src_path  = cat_dir / f"{cat.replace('-', '_')}_filtered.json"
    out_dir   = cat_dir / "llm_analysis"

    if not src_path.exists():
        print(f"[{cat}] File non trovato: {src_path}")
        return

    with io.open(src_path, encoding="utf-8") as fh:
        src = json.load(fh)
    findings = src["findings"]
    out_dir.mkdir(exist_ok=True)

    print(f"\n{'═'*60}")
    print(f"  Categoria: {cat}  ({len(findings)} finding filtrati)")
    print(f"{'═'*60}")

    # ── Stage 2A ─────────────────────────────────────────────────────────────
    print("\n[Stage 2A] Regole HC...")
    hc_fp, hc_vp, unc = run_stage2a(cat, findings)
    save_buckets(cat, src, hc_fp, hc_vp, unc, out_dir)

    total = len(findings)
    print(f"  HC-FP:     {len(hc_fp):4d}  ({len(hc_fp)/total*100:.1f}%)")
    print(f"  HC-VP:     {len(hc_vp):4d}  ({len(hc_vp)/total*100:.1f}%)")
    print(f"  UNCERTAIN: {len(unc):4d}  ({len(unc)/total*100:.1f}%)")

    if unc:
        print(f"\n  UNCERTAIN finding:")
        for f in unc:
            print(f"    {f['server_name'][:35]:35s}  {f['id']}")

    if args.hc_only:
        if not unc:
            # No UNCERTAIN → no LLM needed; produce final output directly
            print(f"\n[Merge] Produzione vp.json / fp.json / audit.json...")
            run_merge(cat, src, hc_fp, hc_vp, [], out_dir)
        print(f"\n[{cat}] --hc-only: skip Stage 2B.")
        return

    # ── Stage 2B ─────────────────────────────────────────────────────────────
    if unc:
        print(f"\n[Stage 2B] Ollama ({args.model})...")
        unc_classified = run_stage2b(unc, out_dir, args)
    else:
        print("\n[Stage 2B] Nessun finding UNCERTAIN, skip Ollama.")
        unc_classified = []

    # ── Merge ─────────────────────────────────────────────────────────────────
    print("\n[Merge] Produzione vp.json / fp.json / audit.json...")
    run_merge(cat, src, hc_fp, hc_vp, unc_classified, out_dir)

    # Breakdown FP
    all_fp_reasons = (
        [f.get("bucket_reason", "") for f in hc_fp]
        + [f.get("llm_reason", "") for f in unc_classified if f.get("llm_verdict") == "FP"]
    )
    if all_fp_reasons:
        print("\n  FP per motivo:")
        for r, c in Counter(all_fp_reasons).most_common(10):
            print(f"    {c:3d}  {r}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pipeline Stage 2A+2B mcp-watch: HC rules + Ollama per finding UNCERTAIN"
    )
    parser.add_argument("--category", default="all",
                        help=f"Categoria: {', '.join(CATEGORIES)}, o 'all' (default: all)")
    parser.add_argument("--model", default="llama3",
                        help="Modello Ollama (default: llama3)")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="URL Ollama (default: http://localhost:11434)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Ignora cache Ollama e riclassifica tutto da zero")
    parser.add_argument("--hc-only", action="store_true",
                        help="Esegui solo Stage 2A (senza Ollama)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Mostra prompt Ollama senza chiamare il server")
    args = parser.parse_args()

    if args.category == "all":
        cats = CATEGORIES
    elif args.category in CATEGORIES:
        cats = [args.category]
    else:
        print(f"Categoria '{args.category}' non riconosciuta.")
        print(f"Disponibili: {', '.join(CATEGORIES)}")
        return

    if not args.hc_only and not args.dry_run:
        if not check_ollama(args.ollama_url, args.model):
            return

    for cat in cats:
        try:
            run_category(cat, args)
        except ValueError as e:
            print(f"[{cat}] ERRORE: {e}")

    print("\nFatto.")


if __name__ == "__main__":
    main()
