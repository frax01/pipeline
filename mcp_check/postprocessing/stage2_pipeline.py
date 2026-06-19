"""
Pipeline LLM per i finding di mcp-check (post-stage1_filter.py).

Funziona sulle cartelle <fase>/<categoria>/filtered/<cat>_filtered.json già prodotte
da stage1_filter.py (Stage 1).

mcp-check è un test harness di conformance MCP (NON uno scanner di sicurezza).
I "VP" qui indicano veri problemi di conformance/robustezza, i "FP" sono errori
ambientali (auth mancante, valori di test non validi, comportamento per design).

Flusso:
    Stage 2A (HC rules)  — per categorie con has_hc=True
                           → hc_vp.json / hc_fp.json / uncertain.json
    Stage 2B (LLM/cache) — classifica UNCERTAIN via Ollama o cache in-chat
                           → vp.json / fp.json / audit.json

Uso:
    python -X utf8 stage2_pipeline.py --category tool_invocation/other_errors --hc-only
    python -X utf8 stage2_pipeline.py --category tool_invocation/panic_or_crash --cache-only
    python -X utf8 stage2_pipeline.py --category all --hc-only
    python -X utf8 stage2_pipeline.py --category all --cache-only

Output in <fase>/<categoria>/filtered/llm_analysis/:
    hc_vp.json / hc_fp.json / uncertain.json   (con --hc-only, categorie HC)
    vp.json / fp.json / audit.json              (con --cache-only o --merge)
    _llm_api_cache.json                         (cache verdetti in-chat)

Categorie disponibili (formato phase/category):
    handshake/schema_violation
    handshake/other_errors
    handshake/method_not_found
    handshake/invalid_arguments
    handshake/unauthorized_or_auth_missing
    tool_discovery/schema_violation
    tool_discovery/other_errors
    tool_discovery/method_not_found
    tool_discovery/warnings
    tool_invocation/schema_violation
    tool_invocation/other_errors
    tool_invocation/panic_or_crash
    tool_invocation/invalid_arguments
    tool_invocation/method_not_found
    tool_invocation/warnings
    tool_invocation/unauthorized_or_auth_missing
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = Path(__file__).resolve().parent

# ══════════════════════════════════════════════════════════════════════════════
#  REGISTRY CATEGORIE
# ══════════════════════════════════════════════════════════════════════════════

CATEGORIES: dict[str, dict] = {
    # ── HANDSHAKE ─────────────────────────────────────────────────────────────
    "handshake/schema_violation": {
        "phase": "handshake",
        "category": "schema_violation",
        "filename": "schema_violation_filtered.json",
        "description": "Schema invalido durante initialize/handshake",
        "has_hc": True,
    },
    "handshake/other_errors": {
        "phase": "handshake",
        "category": "other_errors",
        "filename": "other_errors_filtered.json",
        "description": "Errori runtime durante handshake (ping, resource/prompt discovery)",
        "has_hc": True,
    },
    "handshake/method_not_found": {
        "phase": "handshake",
        "category": "method_not_found",
        "filename": "method_not_found_filtered.json",
        "description": "Metodi MCP non implementati durante handshake (-32601)",
        "has_hc": True,
    },
    "handshake/invalid_arguments": {
        "phase": "handshake",
        "category": "invalid_arguments",
        "filename": "invalid_arguments_filtered.json",
        "description": "Errori -32602 durante handshake",
        "has_hc": False,
    },
    "handshake/unauthorized_or_auth_missing": {
        "phase": "handshake",
        "category": "unauthorized_or_auth_missing",
        "filename": "unauthorized_or_auth_missing_filtered.json",
        "description": "Auth richiesta durante handshake (FP: auth attiva = corretto)",
        "has_hc": True,
    },
    # ── TOOL DISCOVERY ────────────────────────────────────────────────────────
    "tool_discovery/schema_violation": {
        "phase": "tool_discovery",
        "category": "schema_violation",
        "filename": "schema_violation_filtered.json",
        "description": "InvalidToolSchemas: tool con inputSchema non valido JSON Schema",
        "has_hc": True,
    },
    "tool_discovery/other_errors": {
        "phase": "tool_discovery",
        "category": "other_errors",
        "filename": "other_errors_filtered.json",
        "description": "DuplicateToolNames: tool con nome duplicato nello stesso server",
        "has_hc": True,
    },
    "tool_discovery/method_not_found": {
        "phase": "tool_discovery",
        "category": "method_not_found",
        "filename": "method_not_found_filtered.json",
        "description": "tools/list non implementato o method not found",
        "has_hc": True,
    },
    "tool_discovery/warnings": {
        "phase": "tool_discovery",
        "category": "warnings",
        "filename": "warnings_filtered.json",
        "description": "Quality warning: tool senza description",
        "has_hc": True,
    },
    # ── TOOL INVOCATION ───────────────────────────────────────────────────────
    "tool_invocation/schema_violation": {
        "phase": "tool_invocation",
        "category": "schema_violation",
        "filename": "schema_violation_filtered.json",
        "description": "Schema invalido durante invocazione (ValidationFailure, output schema mismatch)",
        "has_hc": True,
    },
    "tool_invocation/other_errors": {
        "phase": "tool_invocation",
        "category": "other_errors",
        "filename": "other_errors_filtered.json",
        "description": "Errori runtime durante invocazione (tool name injection, crash, URL invalida...)",
        "has_hc": True,
    },
    "tool_invocation/panic_or_crash": {
        "phase": "tool_invocation",
        "category": "panic_or_crash",
        "filename": "panic_or_crash_filtered.json",
        "description": "Crash/panic del server Go durante invocazione tool",
        "has_hc": False,
    },
    "tool_invocation/invalid_arguments": {
        "phase": "tool_invocation",
        "category": "invalid_arguments",
        "filename": "invalid_arguments_filtered.json",
        "description": "Errori -32602 durante invocazione (bug server vs input invalido mcp-check)",
        "has_hc": True,
    },
    "tool_invocation/method_not_found": {
        "phase": "tool_invocation",
        "category": "method_not_found",
        "filename": "method_not_found_filtered.json",
        "description": "Tool non implementato o method not found durante invocazione",
        "has_hc": True,
    },
    "tool_invocation/warnings": {
        "phase": "tool_invocation",
        "category": "warnings",
        "filename": "warnings_filtered.json",
        "description": "Warning non-determinismo: tool non-deterministici per design",
        "has_hc": True,
    },
    "tool_invocation/unauthorized_or_auth_missing": {
        "phase": "tool_invocation",
        "category": "unauthorized_or_auth_missing",
        "filename": "unauthorized_or_auth_missing_filtered.json",
        "description": "Auth richiesta durante invocazione (FP: auth attiva = corretto)",
        "has_hc": True,
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _server_short(url: str) -> str:
    return (url or "").replace("https://github.com/", "")


def _cache_key(f: dict, cat_key: str) -> str:
    """Cache key: server_short + fase/categoria (un finding per server per sottocategoria)."""
    return f"{_server_short(f.get('server_url', ''))}|{cat_key}"


def _msgs(entry: dict) -> list[str]:
    """Estrae tutti i messaggi di errore/warning da un entry."""
    msgs = []
    for err in entry.get("errors", []):
        msgs.append(err.get("message", ""))
    for w in entry.get("warnings", []):
        msgs.append(w.get("message", ""))
    return msgs


def _types(entry: dict) -> list[str]:
    """Estrae tutti i type di errore da un entry."""
    return [err.get("type", "") for err in entry.get("errors", [])]


def _tests(entry: dict) -> list[str]:
    """Estrae tutti i test names da un entry."""
    tests = []
    for err in entry.get("errors", []):
        tests.append(err.get("test", ""))
    for w in entry.get("warnings", []):
        tests.append(w.get("test", ""))
    return tests


# Pattern comuni FP: errori di autenticazione / configurazione mancante
_AUTH_FP = re.compile(
    r'api.?key|access.?token|credentials|oauth|unauthorized|'
    r'identifier is required|password|secret|bearer|'
    r'environment variable is required|set.*api.?key|'
    r'not authenticated|authentication failed|AuthorizationError|'
    r'authorization.*failed|failed to authorize|'
    r'Authentication required|authentication not ready|'
    r'session expired|not logged in|User not logged',
    re.I
)

# Pattern comuni FP: mcp-check usa 'test' come ID/nome/client/formato
_TEST_ID_FP = re.compile(
    r"(connection|client|project|workspace|session|id|server|format|basho)['\s:]+['\"]?test['\"]?"
    r'|test.*not found'
    r"|'test'.*not|\"test\".*not"
    r'|format.*["\']test["\']|["\']test["\'].*expected format'
    r'|component.*not found.*test|找不到组件.*test',
    re.I
)

# Pattern VP: errori runtime JavaScript / Python
_JS_RUNTIME_VP = re.compile(
    r'is not a function|Cannot read propert|undefined is not|'
    r'keyValidator\._parse|TypeError|ReferenceError|'
    r'listCallback is not|Cannot destructure property|'
    r'Cannot convert undefined or null|'
    r"name 'true' is not defined|name 'false' is not defined|"
    r"\bname is not defined\b|"  # JS "ReferenceError: name is not defined"
    r"object has no attribute|AttributeError|"
    r"can't resolve reference|'object Object'|"
    r'type must be JSONType|'
    r'"undefined" is not valid JSON|'  # server serializes JS undefined
    r'require is not defined|'  # CommonJS require used in ESM module
    r'Git command failed: undefined',  # undefined passed to git command
    re.I
)

# Pattern VP: errori di unmarshal/parse Go/JSON
_UNMARSHAL_VP = re.compile(
    r'failed to unmarshal|unexpected end of JSON|'
    r'json: cannot unmarshal|invalid character',
    re.I
)

# Pattern FP: URL invalida passata da mcp-check
_URL_FP = re.compile(
    r'invalid.?url|invalid url format|url.*invalid|'
    r'validation.*url|format.*url|invalid_string.*url',
    re.I
)

# Pattern FP: dipendenza da configurazione/ambiente esterna mancante
_ENV_MISSING_FP = re.compile(
    r'is required|are required|must be provided|is not set|not initialized|'
    r'not configured|not established|Please provide|Should be provided|'
    r'Must be set|Please configure|Missing [A-Z_]+|'
    r'set up the .*(variable|env|config|server)|Please set up|'
    r'Provide.*DSN|provide.*token|provide.*key|'
    r'No \w+(\s+\w+)* (initialized|provided|configured|available)|'
    r'need to call.*initialize|Please (create|run|setup|init)|'
    r'Configuration file not found|config.*not found|'
    r'feature.*disabled|disabled in configuration|SSH support is disabled|'
    r'SQLITE_ERROR: no such table|no such table|'
    r'No connection pool available|no connection pool|'
    r'Not a git repository|could not read Username for|'
    r'could not parse server response|'
    r'Не указан|не указан|host.*username.*env|'  # Russian "not specified"
    r'登录失效|无权限|'  # Chinese login invalid / no permission
    r'No plan found for goal \d+|'  # mcp-check uses numeric IDs
    r'[Gg]ame not found|[Rr]esource not found|'
    r'not.*git repository|git.*not.*repository|'
    r'unsupported protocol scheme.*""|'  # mcp-check passes "test" as URL
    r'Invalid filter specified|API.*error.*\(400\)|'
    r'Invalid workDir|workDir.*not found|'
    r'unexpected EOF|'
    r'kubernetes.*not available|kubeconfig.*not|no configuration has been provided|'
    r'SESSION_NOT_FOUND|vault folder has not been set|'
    r'Failed to retrieve.*data|Failed to search.*data|'  # external market/financial API
    r'ENOTDIR.*\'test|not a directory.*\'test|mkdir \'test|scandir \'test|'  # mcp-check uses "test" as path
    r'Not found: test|não encontrado|资源.*test|未找到资源|'
    r'Device \d+ not found|ID \d+ not found|with ID \d+ not found|'  # mcp-check uses numeric IDs
    r'invalid file path.*path must be absolute.*test|absolute.*test|'
    r'failed to resolve target test|lookup test on|'  # DNS lookup for "test" domain
    r'Repository must be in format|format.*owner.*repo|'
    r'database type is invalid.*support|provider must be.*Account|'  # mcp-check uses wrong enum values
    r'address.*malformed|seems to be malformed.*expected|'
    r'Only absolute URLs are supported|absolute URLs.*supported|'
    r'requires keys but no keys|no keys were set|FOFA.*requires|shodan.*requires|'
    r'Failed to connect to MySQL|MySQL.*connection|'
    r'EEXIST.*file already exists.*mkdir.*Frameworks|'  # mcp-check creates file in test dir
    r'Source and destination chains must be different|'
    r'Failed to connect to Everything Search|'  # Windows desktop search app
    r'Get chain account failed|chain.*account.*failed',  # blockchain external API
    re.I
)

# Pattern FP: dipendenza da servizio locale/esterno non disponibile
_EXTERNAL_DEPENDENCY_FP = re.compile(
    r'localhost:\d+|localhost\/|127\.0\.0\.1:\d+|'
    r'Cannot connect to.*localhost|Failed to connect to localhost|'
    r'daemon at http://localhost|Is it running\?|'
    r'request to http://localhost|'
    r'API rate limit|rate limit exceeded|'
    r'HTTP 404|HTTP 5\d{2}|status code [45]\d{2}|'
    r'FastAPI error.*Not Found|Coolify API error.*404|'
    r'Failed to connect to server|Could not connect.*sequence',
    re.I
)

# Pattern FP: CLI / tool esterno non installato sulla VM
_CLI_MISSING_FP = re.compile(
    r'CLI is not installed|CLI command failed|CLI error:|'
    r'not found in PATH|/bin/sh: \d+:|code 127|'
    r'Could not find Chrome|Chrome.*not found|browser.*not found|'
    r'Playwright.*not found|Python script failed with code 127|'
    r'command not found',
    re.I
)

# Pattern VP: errore di esecuzione tool con dettaglio strutturato (Zod/schema interno)
_INVOCATION_BUG_VP = re.compile(
    r'Tool execution failed: \[|'  # array JSON di errori Zod
    r'Image processing error|'
    r'Input validation failed: /\w+',  # path-style: /action, /type ecc.
    re.I
)


# ══════════════════════════════════════════════════════════════════════════════
#  HC RULES
# ══════════════════════════════════════════════════════════════════════════════

# FRAMEWORK: mcp-check | CATEGORIA: handshake/schema_violation
def hc_rules_handshake_schema_violation(entry: dict) -> tuple[str | None, str]:
    """
    Tutti VP: schema invalido durante initialize.
    Il server manda capabilities non conformi alla specifica MCP → ConnectionError.
    """
    return "VP", "invalid_schema_during_initialize"


# FRAMEWORK: mcp-check | CATEGORIA: handshake/other_errors
def hc_rules_handshake_other_errors(entry: dict) -> tuple[str | None, str]:
    """
    HC per errori runtime durante handshake (ping, resource/prompt discovery).

    HC-FP:
    - Auth/credentials mancanti → server necessita configurazione esterna
    - WebSocket unavailable → infrastruttura
    - Dipendenze localhost (DB, daemon) non disponibili sulla VM
    - Servizi esterni con HTTP 4xx/5xx → infrastruttura esterna
    - "No database connection available" → richiede SSE o config esterna

    HC-VP:
    - unrecognized_keys in ping response → risposta ping non-standard
    - failed to unmarshal → bug server Go/JS
    - JS/Python runtime errors → bug server
    - Unknown method: ping / prompts → non implementa metodi opzionali
    - Unsupported protocol version → mismatch specifica MCP
    - "Unsupported method: ping" → usa -32000 invece di -32601 (conformance)
    - Failed to list/get resources/prompts/tools → crash durante discovery
    - Schema/type errors durante discovery

    Default: VP
    """
    msgs_joined = " ".join(_msgs(entry))

    # HC-FP: auth/config mancante (espanso con "authentication required")
    if _AUTH_FP.search(msgs_joined):
        return "FP", "auth_or_config_missing"
    if re.search(r'Authentication required|authentication not ready|'
                 r'could not read Username|Login.*invalid|'
                 r'Cloning.*fatal:.*Username|no access.*token', msgs_joined, re.I):
        return "FP", "auth_required"

    # HC-FP: WebSocket non disponibile
    if "websocket" in msgs_joined.lower() and "not available" in msgs_joined.lower():
        return "FP", "websocket_infrastructure"

    # HC-FP: dipendenza locale non disponibile (DB, daemon locale)
    if _EXTERNAL_DEPENDENCY_FP.search(msgs_joined):
        return "FP", "external_dependency_unavailable"

    # HC-FP: database / SSE transport non configurato
    if re.search(r'No database connection|database.*URL.*should be provided|'
                 r'SSE connection|Failed to connect to.*:\d+', msgs_joined, re.I):
        return "FP", "db_or_transport_not_configured"

    # HC-VP: ping response con chiavi non riconosciute dalla specifica MCP
    if "unrecognized_keys" in msgs_joined:
        return "VP", "ping_response_unrecognized_keys"

    # HC-VP: errori di unmarshal (server Go con bug nel parsing)
    if _UNMARSHAL_VP.search(msgs_joined):
        return "VP", "unmarshal_parse_error"

    # HC-VP: runtime JS/Python error durante discovery
    if _JS_RUNTIME_VP.search(msgs_joined):
        return "VP", "js_python_runtime_error"

    # HC-VP: metodo ping/prompts non implementato (catturato qui invece di method_not_found)
    if re.search(r'Unknown method.*ping|Unknown method.*prompts|Unsupported method.*ping',
                 msgs_joined, re.I):
        return "VP", "method_not_implemented"

    # HC-VP: mismatch versione protocollo MCP
    if re.search(r'Unsupported protocol version|protocol version not supported|'
                 r'protocol.*not supported', msgs_joined, re.I):
        return "VP", "protocol_version_mismatch"

    # HC-VP: "Failed to list/get resources/prompts/tools"
    if re.search(r'Failed to (list|get) (resources|prompts|tools)', msgs_joined, re.I):
        return "VP", "discovery_internal_error"

    # HC-VP: schema/type errors durante discovery (server bug)
    if re.search(r'Date cannot be represented|Failed to parse URL from|'
                 r'type must be JSONType|invalid_type.*expected.*object', msgs_joined, re.I):
        return "VP", "schema_type_error"

    # HC-VP: "Internal error" su ping o tool discovery
    if "internal error" in msgs_joined.lower():
        return "VP", "internal_error"

    # HC-FP: empty error message
    if not msgs_joined.strip() or msgs_joined.strip() in ("-32603: ", "MCP error -32603: "):
        return "FP", "empty_error_message"

    # Default: VP
    return "VP", "other_error_default_vp"


# FRAMEWORK: mcp-check | CATEGORIA: handshake/method_not_found
def hc_rules_handshake_method_not_found(entry: dict) -> tuple[str | None, str]:
    """Tutti VP: server non implementa initialize o altri metodi richiesti (-32601)."""
    return "VP", "method_not_found_during_handshake"


# FRAMEWORK: mcp-check | CATEGORIA: handshake/unauthorized_or_auth_missing
def hc_rules_handshake_unauthorized(entry: dict) -> tuple[str | None, str]:
    """Tutti FP: il server richiede auth per funzionare. Auth attiva = comportamento corretto."""
    return "FP", "auth_required_by_design"


# FRAMEWORK: mcp-check | CATEGORIA: tool_discovery/schema_violation
def hc_rules_tool_discovery_schema_violation(entry: dict) -> tuple[str | None, str]:
    """
    Tutti VP: InvalidToolSchemas — N tool have invalid schemas.
    Schema invalidi rendono i tool non invocabili da client MCP conformi.
    """
    return "VP", "invalid_tool_schema"


# FRAMEWORK: mcp-check | CATEGORIA: tool_discovery/other_errors
def hc_rules_tool_discovery_other_errors(entry: dict) -> tuple[str | None, str]:
    """
    Principalmente DuplicateToolNames (VP). I non-DuplicateToolNames sono
    ToolListErrors durante tools/list — classificati per tipo.

    HC-VP:
    - DuplicateToolNames → nomi duplicati, ambiguità LLM
    - ToolListError con JS/Python runtime error, schema bug, method_not_found → bug server
    - ToolListError con "Failed to get tools" → crash durante tools/list

    HC-FP:
    - InitializationError → infrastruttura
    - localhost dependency non disponibile
    - HTTP 4xx/5xx → servizio esterno

    Default ToolListError: VP (crash durante tools/list = bug server)
    """
    msgs_joined = " ".join(_msgs(entry))
    types_list = _types(entry)

    if "DuplicateToolNames" in types_list or "Duplicate tool names" in msgs_joined:
        return "VP", "duplicate_tool_names"

    # FP: infrastruttura / dipendenza esterna
    if "InitializationError" in types_list:
        return "FP", "initialization_error_infrastructure"

    if _EXTERNAL_DEPENDENCY_FP.search(msgs_joined):
        return "FP", "external_dependency_unavailable"

    # VP: JS/Python runtime errors durante tools/list
    if _JS_RUNTIME_VP.search(msgs_joined):
        return "VP", "runtime_error_during_tools_list"

    # VP: schema/type errors durante tools/list
    if re.search(r'Date cannot be represented|Failed to parse URL|'
                 r'type must be JSONType|Unknown method.*tools', msgs_joined, re.I):
        return "VP", "schema_error_during_tools_list"

    # VP: "Failed to get tools" → crash durante tools/list
    if re.search(r'Failed to get tools|Failed to list tools', msgs_joined, re.I):
        return "VP", "tools_list_crash"

    # Default ToolListError → VP (il server non riesce ad elencare i tool)
    return "VP", "tool_list_error_default_vp"


# FRAMEWORK: mcp-check | CATEGORIA: tool_discovery/method_not_found
def hc_rules_tool_discovery_method_not_found(entry: dict) -> tuple[str | None, str]:
    """Tutti VP: tools/list non implementato → server non espone tool (-32601)."""
    return "VP", "tools_list_not_implemented"


# FRAMEWORK: mcp-check | CATEGORIA: tool_discovery/warnings
def hc_rules_tool_discovery_warnings(entry: dict) -> tuple[str | None, str]:
    """
    Tutti VP (quality): tool senza description.
    Un tool MCP senza description non può essere usato correttamente dall'LLM.
    """
    return "VP", "tool_missing_description"


# FRAMEWORK: mcp-check | CATEGORIA: tool_invocation/schema_violation
def hc_rules_tool_invocation_schema_violation(entry: dict) -> tuple[str | None, str]:
    """
    HC per schema violation durante invocazione.

    HC-VP:
    - ValidationFailure: server non valida input malformati → accetta input invalidi
    - InvocationError "output schema but did not return structured content": dichiarato ma non implementato

    HC-FP: nessun FP noto — tutti i ValidationFailure qui sono problemi reali.

    UNCERTAIN:
    - InitializationError: il server si avvia ma crashava durante init → da verificare in-chat
    """
    types_list = _types(entry)
    msgs_joined = " ".join(_msgs(entry))

    # HC-VP: ValidationFailure (mcp-check inviava input non validi e il server li accettava)
    if "ValidationFailure" in types_list:
        return "VP", "accepts_invalid_input"

    # HC-VP: output schema dichiarato ma non ritorna structured content
    if "output schema but did not return structured content" in msgs_joined:
        return "VP", "output_schema_mismatch"

    # VP: InitializationError con Zod schema errors su tools/nextCursor
    # → server ritorna risposta tools/list non conforme alla specifica MCP
    if "InitializationError" in types_list:
        msgs_j = " ".join(_msgs(entry))
        if re.search(r'invalid_value|invalid_type|"path".*tools', msgs_j, re.I | re.DOTALL):
            return "VP", "tools_list_response_schema_invalid"
        return None, "initialization_error_uncertain"

    # Default VP (ValidationFailure è dominante)
    return "VP", "schema_violation_default"


# FRAMEWORK: mcp-check | CATEGORIA: tool_invocation/other_errors
def hc_rules_tool_invocation_other_errors(entry: dict) -> tuple[str | None, str]:
    """
    HC per errori runtime durante invocazione.

    HC-VP:
    - ErrorHandlingFailure "Server did not return error for non-existent tool" → tool name injection
    - keyValidator._parse / JS runtime errors → bug server
    - Cannot read properties / undefined errors → bug server
    - failed to unmarshal → bug server Go

    HC-FP:
    - URL invalida passata da mcp-check → server correttamente rifiuta
    - Auth/credentials mancanti → configurazione esterna
    - "test" come ID/connessione → mcp-check usa 'test' come placeholder
    - Failed to launch Things3 / macOS specific → ambiente non supportato
    - "Failed to fetch" → network error esterno
    - Kite Connect / platform-specific init errors → config mancante

    UNCERTAIN:
    - InitializationError in phase invocation → da verificare
    - InvocationError generico non catturato sopra
    """
    types_list = _types(entry)
    msgs_joined = " ".join(_msgs(entry))

    # HC-VP: tool name injection (il finding dominante)
    if "ErrorHandlingFailure" in types_list:
        return "VP", "tool_name_injection_no_error_returned"

    # HC-VP: JS runtime errors
    if _JS_RUNTIME_VP.search(msgs_joined):
        return "VP", "js_runtime_error"

    # HC-VP: unmarshal/parse errors (Go server bug)
    if _UNMARSHAL_VP.search(msgs_joined):
        return "VP", "unmarshal_parse_error"

    # HC-VP: Invalid control character → bug nel server (non dovrebbe arrivare qui se filtra bene)
    if "Invalid control character" in msgs_joined and "InvocationError" in types_list:
        return "VP", "invalid_control_character_server_bug"

    # HC-FP: URL invalida passata da mcp-check
    if _URL_FP.search(msgs_joined):
        return "FP", "invalid_url_from_mcp_check"

    # HC-FP: auth/credentials mancanti
    if _AUTH_FP.search(msgs_joined):
        return "FP", "auth_or_config_missing"

    # HC-FP: mcp-check usa 'test' come connection/client ID/formato
    if _TEST_ID_FP.search(msgs_joined):
        return "FP", "test_placeholder_id"

    # HC-FP: macOS/platform specific (Things3, macOS app, Ulysses)
    if re.search(r'Things3|macos.?specific|Failed to launch|ulysses://', msgs_joined, re.I):
        return "FP", "macos_platform_specific"

    # HC-FP: network fetch failure
    if re.search(r'Failed to fetch|ECONNREFUSED|network.*error|fetch.*failed', msgs_joined, re.I):
        return "FP", "network_fetch_error"

    # HC-FP: configurazione/ambiente esterna mancante (env vars, config, DSN...)
    if _ENV_MISSING_FP.search(msgs_joined):
        return "FP", "env_config_missing"

    # HC-FP: CLI esterno non installato
    if _CLI_MISSING_FP.search(msgs_joined):
        return "FP", "external_cli_not_installed"

    # HC-FP: dipendenza localhost/servizio esterno non disponibile
    if _EXTERNAL_DEPENDENCY_FP.search(msgs_joined):
        return "FP", "external_dependency_unavailable"

    # HC-FP: Windows path hardcoded su VM Linux (mismatch ambiente)
    if re.search(r'C:\\Users\\|C:/Users/', msgs_joined):
        return "FP", "windows_path_on_linux_vm"

    # HC-FP: "Unknown error occurred" doppio wrap → SDK bug
    if re.search(r'Unknown error occurred.*Unknown error', msgs_joined, re.I):
        return "FP", "sdk_double_wrap_error"

    # HC-FP: git remote non configurato nel test env
    if re.search(r'Could not resolve git remote|git remote.*not found', msgs_joined, re.I):
        return "FP", "git_remote_not_configured"

    # HC-FP: env/config mancante (catch-all ampio)
    if _ENV_MISSING_FP.search(msgs_joined):
        return "FP", "env_config_missing"

    # HC-FP: dipendenza esterna / API esterna con errore generico
    if re.search(r'API request failed: 400|API request failed: Internal|'
                 r'500 Internal Server Error|Failed to initialize.*: Failed to connect|'
                 r'Failed.*OpenSearch|Failed.*Elasticsearch|rate limit|'
                 r'rate.*exceed|exceed.*rate|'
                 r'Failed.*mermaid|No diagram type detected|'
                 r'kospell.*could not parse|'
                 r'CRDP API error:|'
                 r'Only SELECT.*SHOW.*DESCRIBE.*allowed|'
                 r'Only SELECT.*SHOW.*DESC.*queries',
                 msgs_joined, re.I):
        return "FP", "external_api_or_env_error"

    # HC-VP: bug nell'esecuzione del tool con errore strutturato (Zod/schema)
    if _INVOCATION_BUG_VP.search(msgs_joined):
        return "VP", "invocation_bug_structured_error"

    # HC-VP: Node.js runtime error "__dirname is not defined" (module scope bug)
    if re.search(r'__dirname is not defined|__filename is not defined', msgs_joined, re.I):
        return "VP", "nodejs_module_scope_error"

    # HC-VP: "Tool response does not match expected structure" → server ritorna formato sbagliato
    if re.search(r'Tool response does not match expected structure|'
                 r'does not match.*structure', msgs_joined, re.I):
        return "VP", "tool_response_wrong_structure"

    # HC-VP: typo nella logica del server (segno di bug)
    if re.search(r'Invalid the sencond|sencond argument', msgs_joined, re.I):
        return "VP", "server_bug_typo_in_error"

    # HC-VP: Maven coordinate / URL invalida passata come arg
    if re.search(r'Invalid Maven coordinate', msgs_joined, re.I):
        return "FP", "mcp_check_invalid_format_arg"

    # HC-VP: "think" usa -32603 per type mismatch (float vs integer) → wrong error code
    if re.search(r'Invalid thought data:.*Expected integer.*received float', msgs_joined, re.I):
        return "VP", "wrong_error_code_for_type_validation"

    # HC-FP: Zod invalid_type con received: undefined (arg mancante) dentro -32603
    if re.search(r'"received"\s*:\s*"undefined"|'
                 r'received.*undefined.*path|'
                 r'invalid_type.*received.*undefined',
                 msgs_joined, re.I | re.S):
        return "FP", "mcp_check_missing_required_arg_zod"

    # HC-FP: timezone validation ("test" non è una timezone)
    if re.search(r'invalid.*timezone: unknown time zone|'
                 r'unknown time zone.*test',
                 msgs_joined, re.I):
        return "FP", "mcp_check_invalid_timezone"

    # HC-FP: GIS format validation (WKT/GeoJSON)
    if re.search(r'WKT to GeoJSON conversion|GeoJSON to WKT conversion|'
                 r'Failed to parse WKT string|stringify requires a valid GeoJSON',
                 msgs_joined, re.I):
        return "FP", "domain_format_validation"

    # HC-FP: gaming summoner format (GameName#TagLine)
    if re.search(r'Use format GameName#TagLine|GameName#TagLine', msgs_joined, re.I):
        return "FP", "domain_format_validation"

    # HC-FP: DATABASE_URL Prisma env missing
    if re.search(r'Environment variable not found: DATABASE_URL', msgs_joined, re.I):
        return "FP", "env_config_missing"

    # HC-FP: required params not provided (mcp-open-meteo style: "param: Required")
    if re.search(r'Invalid parameters:.*(?:latitude|longitude|start_date|end_date).*Required',
                 msgs_joined, re.I):
        return "FP", "mcp_check_missing_required_arg"

    # HC-FP: email Zod validation (invalid_string email)
    if re.search(r'"validation"\s*:\s*"email".*"code"\s*:\s*"invalid_string"|'
                 r'code.*invalid_string.*Invalid email',
                 msgs_joined, re.I | re.S):
        return "FP", "domain_format_validation"

    # HC-FP: viacep Zod regex format (CEP, state code) — multi-line JSON
    if re.search(r'"code"\s*:\s*"invalid_format".*"format"\s*:\s*"regex"',
                 msgs_joined, re.I | re.S):
        return "FP", "domain_format_validation"

    # HC-FP: Zod too_small in number params — multi-line JSON
    if re.search(r'"code"\s*:\s*"too_small".*"type"\s*:\s*"number"',
                 msgs_joined, re.I | re.S):
        return "FP", "domain_format_validation"

    # HC-FP: Zod expected object received string/undefined — multi-line JSON
    if re.search(r'"expected"\s*:\s*"object".*"received"\s*:\s*"(?:string|undefined)"',
                 msgs_joined, re.I | re.S):
        return "FP", "mcp_check_wrong_arg_type"

    # HC-FP: Zod custom validation (provide either X or Y) — multi-line JSON
    if re.search(r'"code"\s*:\s*"custom".*"message"\s*:\s*"Provide either',
                 msgs_joined, re.I | re.S):
        return "FP", "mcp_check_missing_required_arg"

    # HC-FP: specific domain validations not caught by broader patterns
    if re.search(r'Invalid post URL|'
                 r'Could not parse Figma key from URL|'
                 r"The page you specified doesn't exist|"
                 r'Get image info failed: Empty file|'
                 r'端点.*不存在|获取端点详情失败|'
                 r'Execution error: test is not defined|'
                 r'Tool execution failed: HttpError: HTTP request failed',
                 msgs_joined, re.I):
        return "FP", "domain_or_env_validation"

    # HC-FP: -32000 generic execution error (Proxmox not available)
    if all('Tool execution error' in m and '-32000' in m
           for m in _msgs(entry) if m.strip()):
        return "FP", "generic_execution_error"

    # HC-FP: empty -32603 nested errors (mysql-readonly-mcp, mcp_mysql_analyser)
    stripped_msgs = [m.strip() for m in _msgs(entry) if m.strip()]
    if stripped_msgs and all(
        re.match(r'^MCP error -32603:(?:\s*MCP error -32603:)?\s*(?:Connection failed:|An error occurred)?\s*$', m)
        for m in stripped_msgs
    ):
        return "FP", "generic_noise_error"
    if stripped_msgs and all(
        re.match(r'^MCP error -32603:(?:\s*MCP error -32603:)?\s*$', m)
        for m in stripped_msgs
    ):
        return "FP", "generic_noise_error"

    # HC-VP: server usa -32603 invece di -32601 per Unknown tool
    if re.search(r'MCP error -32603:.*Unknown tool', msgs_joined, re.I):
        return "VP", "wrong_error_code_unknown_tool"

    # HC-VP: tool dichiara di richiedere Claude Code specificamente (non conforme MCP)
    if re.search(r'Tool use ID not provided by Claude Code', msgs_joined, re.I):
        return "VP", "tool_requires_claude_code_client"

    # HC-VP: DB schema mismatch (colonna non trovata nel DB)
    if re.search(r'SQLITE_ERROR: no such column|no such column: \w+', msgs_joined, re.I):
        return "VP", "db_schema_mismatch"

    # HC-VP: Date non serializzabile in JSON Schema → bug server
    if re.search(r'Date cannot be represented in JSON Schema', msgs_joined, re.I):
        return "VP", "date_not_json_schema_serializable"

    # HC-VP: Unknown method: tools/list → server non implementa method_not_found correttamente
    if re.search(r'Unknown method: tools/list', msgs_joined, re.I):
        return "VP", "wrong_error_code_method_not_found"

    # HC-VP: schema tool mancante (outputSchema dichiarato ma non implementato)
    if re.search(r'has no outputSchema', msgs_joined, re.I):
        return "VP", "tool_missing_output_schema"

    # HC-VP: SQL logic error con "test" → possibile SQL injection (testo utente in query)
    if re.search(r'MCP error -32000:.*SQL logic error', msgs_joined, re.I):
        return "VP", "sql_injection_test_in_query"

    # HC-FP: "test" è una directory nel test env (EISDIR, mkdir, scandir, open test)
    if re.search(r'EISDIR: illegal operation on a directory|'
                 r'read test: is a directory|'
                 r'open test: not a directory|'
                 r'The path test is not a valid directory|'
                 r'mkdir test: file exists|'
                 r'scandir.*mcp-check.*test|'
                 r'test: Is a directory|'
                 r'open.*mcp-check.*test|'
                 r'Plugin path is not a directory: test|'
                 r'Theme path is not a directory: test',
                 msgs_joined, re.I):
        return "FP", "test_is_directory_in_env"

    # HC-FP: tool CLI non installati (estende _CLI_MISSING_FP)
    if re.search(r'yt-dlp.*not found|'
                 r'Could not find tsserver|tsserver.*not found|'
                 r'Vibe binary not found|'
                 r'ImageMagick is not installed|'
                 r'Firefox browser is not running.*Please launch|'
                 r'"z3": executable file not found|'
                 r'cursor-agent.*install|'
                 r'Codex CLI not found',
                 msgs_joined, re.I):
        return "FP", "external_tool_not_installed"

    # HC-FP: validazione formato dominio (date, coordinate, codec, timezone, dice, FEN, ecc.)
    if re.search(r'Invalid date format\. Please use YYYY|'
                 r'yyyymmdd must be in YYYYMMDD|'
                 r'Invalid dice notation.*Expected format: NdS|'
                 r'Invalid archive format\. Supported formats:|'
                 r'Invalid epub URL format|'
                 r'Invalid serial port: error getting term|'
                 r'Unsupported (operation|framework).*Supported (operations|frameworks):|'
                 r'Unknown command.*\. Available commands:|'
                 r'Comando desconocido.*Comandos disponibles:|'
                 r'Invalid locationName.*Available options:|'
                 r'Unsupported component:|'
                 r'Invalid cell address:|'
                 r'Invalid tweet ID format|'
                 r'Failed to roll dice:|'
                 r'Error visualizing FEN: Invalid FEN|'
                 r'Cannot convert test to a BigInt|'
                 r'post_id (must be a valid number|is not a number)|'
                 r'Unsupported file extension:|'
                 r'File must be a \.docx document|'
                 r'Unsupported file type: test|'
                 r'Invalid thought data:.*Expected integer.*received number|'
                 r'Unknown (control character|command).*test|'
                 r'No suitable pattern found for: test|'
                 r'Tool execution failed: Validation error: schema\.|'
                 r'Invalid image format|Unsupported image (format|input)|'
                 r'Invalid FEN.*must have exactly|'
                 r'id should be provide|'
                 r'Unsupported operation.*Supported operations|'
                 r'Unknown method: test\. Valid methods:|'
                 r'Invalid locationName.*Available|'
                 r'Invalid.*format.*Supported formats',
                 msgs_joined, re.I):
        return "FP", "domain_format_validation"

    # HC-FP: API esterne non disponibili o con errore 404/405
    if re.search(r'Everything Search.*Make sure|'
                 r'Manifold API error|'
                 r'Ashra API Error|'
                 r'OSV API returned non-OK status|'
                 r'SearXNG error: 404|'
                 r'rezdy_agent.*Failed to make request|'
                 r'Failed to get Zig docs: Failed to load model|'
                 r'Scrape failed: Error$|Crawl failed: Error$|Get crawl status failed: Error$|'
                 r'Failed to analyze URL$|Failed to scrape any posts|'
                 r'Failed to process RSS feed|'
                 r'All sources failed: undefined|'
                 r'Video generation failed: API request failed: Not Found|'
                 r'Get points failed: API request failed: Not Found|'
                 r'Get task result failed: API request failed: Not Found|'
                 r'Package installation failed.*AEM|aem.*Failed to list|'
                 r'Error executing rezdy|'
                 r'Sourcify API error: Invalid (address|addresses)|'
                 r'IP lookup failed|'
                 r'Failed to retrieve XSD|'
                 r'unexpected status code: 404|'
                 r'HTTP request fail.*campaign|'
                 r'Request error: API returned error:|'
                 r'Failed to parse URL from /tools',
                 msgs_joined, re.I):
        return "FP", "external_api_unavailable"

    # HC-FP: errori ENV/config mancante (nuovi pattern non in _ENV_MISSING_FP)
    if re.search(r'Database configuration not set\. Use connect_|'
                 r'No active browser context\. Please navigate|'
                 r'No database configurations found|'
                 r'Network monitoring is not active\. Use start_monitor|'
                 r'Documentation directory no|'
                 r'Must provide either.*url.*relativePath|'
                 r'Invalid resource URI: forge://',
                 msgs_joined, re.I):
        return "FP", "env_config_missing"

    # HC-FP: messaggi localizzati (JP/CN/KR/VN) - errori env/validazione
    if re.search(r'テンプレート.*が見つかりません|'
                 r'ノート.*が見つかりません|'
                 r'未知的书架编号|'
                 r'数据库未连接|'
                 r'未连接到MinIO|'
                 r'Edge浏览器.*未连接|'
                 r'找不到Edge浏览器|'
                 r'矢量転換失败|矢量转换失败|'
                 r'計算 오류.*허용되지 않는 문자|'
                 r'계산 오류.*허용되지 않는 문자|'
                 r'Lỗi khi gọi công cụ|'
                 r'モデルの読み込みに失敗|'
                 r'アニメーションの読み込みに失敗|'
                 r'VRMモデルの読み込みに失敗|'
                 r'配置失败.*API 连接验证|'
                 r'创建文件失败.*EISDIR|'
                 r'执行工具.*Edge.*浏览器',
                 msgs_joined):
        return "FP", "localized_env_or_validation_error"

    # HC-FP: -32600 per validazione (categorizzato male ma non conformance bug)
    if "MCP error -32600:" in msgs_joined:
        if re.search(r'-32600:.*(?:Invalid.*query|Invalid tweet|Invalid cell|'
                     r'Unsupported component|Directory does not exist|'
                     r'Must authenticate|配置失败|Invalid query arguments)',
                     msgs_joined, re.I):
            return "FP", "mcp_invalid_request_validation"

    # HC-FP: errori generici/rumorosi (exit status, EOF, empty errors)
    if re.search(r'^MCP error -32603: MCP error -32603:\s*$|'
                 r'^MCP error -32603: An error occurred\s*$|'
                 r'^MCP error -32000: Tool execution error\s*$|'
                 r'Failed to process request: MCP error -32603:\s*$',
                 msgs_joined.strip(), re.I):
        return "FP", "generic_noise_error"

    if re.search(r'^(MCP error -32603: )?EOF\s*$|^(MCP error -32603: )?query error: EOF\s*$|'
                 r'^MCP error -32603: exit status 1\s*$|'
                 r'^MCP error -32603: (MCP error -32603: )?Failed to (get tools|list databases:|'
                 r'route message)\s*$|'
                 r'^MCP error -32603: (MCP error -32603: )?Connection failed:\s*$',
                 msgs_joined.strip(), re.I):
        return "FP", "generic_noise_error"

    # HC-FP: test env path issues (file not found in mcp-check specific dirs)
    if re.search(r'File not found.*mcp-check|'
                 r'file exists.*test.*mcp-check|'
                 r'ENOTDIR.*mcp-check|'
                 r'failed to create directory test/',
                 msgs_joined, re.I):
        return "FP", "test_env_path_not_found"

    # HC-FP: pattern misti rimasti (validazione arg con -32603 che wrappa un -32602 non VP)
    if re.search(r'Unable to get local issuer certificate|'
                 r'unable to get local issuer certificate|'
                 r'File not in allowed directories: test|'
                 r'Failed to create deck:|'
                 r'Local template.*not found.*useRemote|'
                 r'tool_failed:.*required parameter.*was null|'
                 r'Error executing.*Required parameter.*was null|'
                 r'post_id must be a valid|'
                 r'Failed to get balance: All sources failed|'
                 r'Tool execution failed: Connection failed: Failed to parse URL from test',
                 msgs_joined, re.I):
        return "FP", "env_or_validation_misc"

    # HC-FP: Kubernetes non disponibile
    if re.search(r'Failed to list (pods|namespaces|service accounts):', msgs_joined, re.I):
        return "FP", "kubernetes_not_available"

    # HC-FP: EOF durante query (processo Prolog/DB chiuso)
    if re.search(r'MCP error -32603: (?:query error: )?EOF', msgs_joined, re.I):
        return "FP", "process_eof_connection_closed"

    # HC-FP: SSH/AEM/tmux specifici dell'ambiente
    if re.search(r'SSH command failed: Command failed: ssh kali|'
                 r'Error reading logs: Failed to read logs: tmux|'
                 r'Error executing tool aem_|'
                 r'Error executing tool: Failed to list pods|'
                 r'Error executing tool: Failed to list namespaces|'
                 r'Error executing tool: Failed to list service accounts|'
                 r'repository does not exist|'
                 r'更新项目失败|'
                 r'Failed to analyze WAV file test',
                 msgs_joined, re.I):
        return "FP", "env_specific_tool_not_available"

    # HC-FP: invalid_auth Slack nei tool_invocation/other_errors
    if re.search(r'invalid_auth|slack.*invalid|invalid.*slack', msgs_joined, re.I):
        return "FP", "auth_or_config_missing"

    # UNCERTAIN: InitializationError in fase invocazione
    if "InitializationError" in types_list:
        return None, "initialization_error_uncertain"

    # UNCERTAIN: InvalidResponse
    if "InvalidResponse" in types_list:
        return None, "invalid_response_uncertain"

    # UNCERTAIN: InvocationError generico (non catturato sopra)
    if "InvocationError" in types_list:
        return None, "invocation_error_uncertain"

    return None, "uncertain_default"


# FRAMEWORK: mcp-check | CATEGORIA: tool_invocation/invalid_arguments
def hc_rules_tool_invocation_invalid_arguments(entry: dict) -> tuple[str | None, str]:
    """
    HC per errori -32602 durante invocazione.
    Distingue bug reali del server (VP) da input invalidi di mcp-check (FP).

    HC-VP:
    - "parameter parsing not fully implemented" → bug server, implementazione incompleta
    - "Structured content does not match output schema" → schema mismatch
    - "Invalid tools/call result" / "invalid_union" → risposta server formato sbagliato

    HC-FP:
    - URL invalida → mcp-check non conosce URL valide
    - API key / credentials / auth → configurazione mancante
    - "Connection 'test' not found" / "client: test" → mcp-check usa 'test' come placeholder
    - "Invalid chart type" / "Invalid Maven coordinate" / enum values → mcp-check non conosce valori validi
    - "name or path must be provided" / "Either X must be" → mcp-check non fornisce tutti gli arg richiesti
    - "Invalid arguments for tool X: [" → arg sbagliati di mcp-check validati correttamente dal server

    UNCERTAIN: "Invalid params" generico senza contesto
    """
    msgs_joined = " ".join(_msgs(entry))

    # HC-VP: implementazione incompleta (bug server)
    if re.search(r'not fully implemented|parsing not fully', msgs_joined, re.I):
        return "VP", "parameter_parsing_not_implemented"

    # HC-VP: schema output mismatch
    if "Structured content does not match" in msgs_joined:
        return "VP", "output_schema_mismatch"

    # HC-VP: risposta server formato sbagliato
    if re.search(r'Invalid tools/call result|invalid_union', msgs_joined, re.I):
        return "VP", "invalid_tools_call_result_format"

    # HC-VP: "Invalid structured content for tool X" → schema mismatch a runtime
    if re.search(r'Invalid structured content for tool', msgs_joined, re.I):
        return "VP", "invalid_structured_content"

    # HC-FP: URL invalida da mcp-check (incluso Chinese/Japanese url messages)
    if _URL_FP.search(msgs_joined):
        return "FP", "invalid_url_from_mcp_check"
    if re.search(r'url.*must be a valid|must be a valid.*url|'
                 r'无效的URL|invalid.*URL格式|URL.*无效|以下URL格式无效', msgs_joined, re.I):
        return "FP", "invalid_url_from_mcp_check"

    # HC-FP: auth/config mancante (incluso Slack invalid_auth)
    if _AUTH_FP.search(msgs_joined):
        return "FP", "auth_or_config_missing"
    if re.search(r'invalid_auth|slack.*auth|auth.*slack', msgs_joined, re.I):
        return "FP", "auth_or_config_missing"

    # HC-FP: dipendenza locale (DB non connesso, servizio non pronto)
    if re.search(r'connection not established|Failed to connect to MySQL|'
                 r'MySQL.*not.*established|DB.*not.*connected', msgs_joined, re.I):
        return "FP", "db_not_connected"

    # HC-FP: mcp-check usa 'test' come ID/nome/client/formato
    if _TEST_ID_FP.search(msgs_joined):
        return "FP", "test_placeholder_id"

    # HC-VP: server usa -32603 invece di -32602 per argomento invalido
    # Cattura weather-mcp (state too small/too big), mcp-server-subagent (UUID), medicare (Unknown method)
    if re.search(r'MCP error -32603:.*(?:Invalid arguments?:|Unknown method:)', msgs_joined, re.I):
        return "VP", "wrong_error_code_for_validation"

    # HC-VP: server usa -32603 invece di -32602 per argomento mancante
    if re.search(r'MCP error -32603:.*arguments.*Required|'
                 r'MCP error -32603:.*key.*Required|'
                 r'Invalid arguments.*Required.*-32603', msgs_joined, re.I):
        return "VP", "wrong_error_code_for_validation"

    # HC-FP: enum/format values che mcp-check non conosce
    if re.search(
        r'Must be one of:|Invalid chart type|Invalid Maven|'
        r'Invalid client:.*Must be|format.*Must be|not found:.*ID \d+|'
        r'Unsupported chart type|Expected format: S\d+E\d+|'
        r'Invalid chromosome format|must be in the format OL|'
        r'author_key.*must be in the format|invalid_format|'
        r'chromosome.*Invalid|Expected a SELECT statement|'
        r'Expected a CREATE TABLE|Expected an INSERT|'
        r'FPE radix|does not appear to be encrypted|'
        r'filePath must be an absolute path|must be an absolute path',
        msgs_joined, re.I
    ):
        return "FP", "mcp_check_unknown_enum_or_format"

    # HC-FP: argomenti richiesti non forniti da mcp-check
    if re.search(
        r'Either .* must be provided|must be provided|'
        r'is required|required parameter|missing.*required|'
        r"requires '[^']+|Tool \w+ requires|"
        r'sources\.0.*must have either|Each source must have',
        msgs_joined, re.I
    ):
        return "FP", "mcp_check_missing_required_arg"

    # HC-FP: arg sbagliati, server valida correttamente con messaggio specifico
    # Cattura sia "Invalid arguments for eth_getBalance:" che "Invalid arguments for tool eth_getBalance:"
    # Usa [\w.-]+ per catturare anche tool con trattini (get-news-sources)
    if re.search(r'Invalid arguments for (tool )?[\w.-]+[\w-]*:', msgs_joined, re.I):
        return "FP", "server_correctly_validates_args"

    # HC-FP: "Tool 'X' parameter validation failed" → server valida correttamente (DeFi/blockchain tools)
    if re.search(r"Tool '[^']+' parameter validation failed:", msgs_joined, re.I):
        return "FP", "server_correctly_validates_args"

    # HC-FP: "Invalid arguments:" seguito da field:message (Zod-style, senza "for tool")
    # Cattura: "Invalid arguments: type: Invalid enum value.", "Invalid arguments: url must be"
    if re.search(r'Invalid arguments?: \w+[: ]', msgs_joined, re.I):
        return "FP", "server_correctly_validates_args"

    # HC-FP: "Validation error for 'X':" pattern (Infura/Ethereum style)
    if re.search(r"Validation error for '[^']+':.*[Ii]nvalid", msgs_joined, re.I):
        return "FP", "server_correctly_validates_args"

    # HC-FP: schema validation Zod-style con "too_small"/"too_big" code
    if re.search(r'"code"\s*:\s*"too_small"|"code"\s*:\s*"too_big"|'
                 r'too_small.*minimum|Too big.*expected|Too small.*expected', msgs_joined, re.I):
        return "FP", "server_correctly_validates_args"

    # HC-FP: Ethereum/blockchain address validation
    if re.search(r'[Ii]nvalid Ethereum (address|wallet)|'
                 r'must be a valid Ethereum|Ethereum wallet address format|'
                 r'Token contract must be a valid|'
                 r'Invalid fromToken|Invalid toToken|'
                 r'Invalid mnemonic|failed to decode mnemonic', msgs_joined, re.I):
        return "FP", "mcp_check_domain_validation"

    # HC-FP: "Only SELECT/INSERT/CREATE queries are allowed" → SQL type restriction
    if re.search(r'Only (SELECT|INSERT|CREATE TABLE|DELETE|UPDATE).*(?:queries|statements).*allowed|'
                 r'Only read-only queries.*allowed|Expected a (SELECT|CREATE|INSERT)|'
                 r'Query must be a (SELECT|CREATE TABLE|INSERT|DELETE|UPDATE) statement', msgs_joined, re.I):
        return "FP", "mcp_check_wrong_query_type"

    # HC-FP: parametri con validazione regex (ethereum address, IP, date, regex format)
    if re.search(r'validation.*regex|validation.*ip|validation.*url|'
                 r'invalid_string.*regex|invalid_string.*ip|code.*invalid_string',
                 msgs_joined, re.I):
        return "FP", "mcp_check_fails_regex_ip_validation"

    # HC-FP: Invalid X parameters: [...] (DeFi, blockchain)
    if re.search(r'Invalid \w+ parameters: \[', msgs_joined, re.I):
        return "FP", "server_validates_domain_params"

    # HC-FP: no language server for "test" → mcp-check usa "test" come nome LSP
    if re.search(r'No language server configured for|'
                 r'language server.*test|configured.*for.*test', msgs_joined, re.I):
        return "FP", "no_language_server_for_test"

    # HC-FP: command not allowed (mcp-check usa "test" come nome del comando)
    if re.search(r'Command not allowed:.*test|Allowed commands:.*git', msgs_joined, re.I):
        return "FP", "mcp_check_uses_test_as_command"

    # HC-FP: expression variable undefined "test" (mcp-check usa "test" come variabile)
    if re.search(r'undefined variable.*test|Error evaluating.*undefined', msgs_joined, re.I):
        return "FP", "mcp_check_uses_test_as_variable"

    # HC-FP: env var / config mancante (catches residui)
    if _ENV_MISSING_FP.search(msgs_joined):
        return "FP", "env_config_missing"

    # HC-FP: path must be a directory (mcp-check usa "test" come path)
    if re.search(r'must point to a directory|must be a directory|'
                 r'Provided.*path is not a directory|not a directory.*test|'
                 r'No chunks generated from file', msgs_joined, re.I):
        return "FP", "mcp_check_test_path_not_directory"

    # HC-FP: "Room 'test' already exists" / "Thought not found" → test artifact
    if re.search(r"Room '?test'? already exists|Thought not found", msgs_joined, re.I):
        return "FP", "test_artifact_side_effect"

    # HC-FP: SQLite planner binding error (kryonex-mcp)
    if re.search(r'SQLite3 can only bind|Planner failed.*SQLite', msgs_joined, re.I):
        return "FP", "sqlite_binding_error"

    # HC-FP: "X must be between N and M" → range validation (swedish-text-tv, page numbers)
    if re.search(r'must be between \d+ and \d+|Invalid page number:.*All page', msgs_joined, re.I):
        return "FP", "mcp_check_value_out_of_range"

    # HC-FP: timezone validation ("test" is not a valid timezone)
    if re.search(r'Invalid (source )?timezone:.*test|Invalid timezone', msgs_joined, re.I):
        return "FP", "mcp_check_invalid_timezone"

    # HC-FP: generic domain-format validation (Clojars group/artifact, version format, etc.)
    if re.search(r'Invalid dependency format|Invalid.*format.*Expected|'
                 r'Invalid version format|Expected.*format.*group|'
                 r'id must be a string like|must match pattern|'
                 r'Schema validation failed.*file_name|'
                 r'expected integer.*got number|Unsupported topic.*Choose one of|'
                 r'Unsupported file type.*Only.*files are supported|'
                 r'Invalid call parameters|Invalid association arguments|'
                 r'Invalid input parameters|Invalid get_\w+ parameters|'
                 r'invalid enum value.*Expected.*bar.*line|Invalid parameter.*port|'
                 r'Invalid.*arguments.*Expected.*date.*YYYY|'
                 r'Invalid.*parameters.*too_small|'
                 r"Invalid input: Field '[^']+' has invalid format", msgs_joined, re.I):
        return "FP", "mcp_check_domain_validation"

    # HC-FP: Japanese/Chinese validation messages (path, file-not-found, URL, model-not-found)
    if re.search(r'絶対パスを指定|リポジトリのパスを指定|引数エラー|'
                 r'が見つかりません|未找到模型|无效的URL|以下URL格式|URL格式无效', msgs_joined):
        return "FP", "mcp_check_domain_validation"

    # HC-FP: slug/url format (mcp-check non conosce il formato)
    if re.search(r'provide.*slug.*url|provide.*url.*slug', msgs_joined, re.I):
        return "FP", "mcp_check_unknown_slug_url_format"

    # HC-FP: "Retrieval of X failed" → external service/api
    if re.search(r'Retrieval of .* failed', msgs_joined, re.I):
        return "FP", "external_service_retrieval_failed"

    # HC-FP: "Invalid params" generico senza dettagli (check per ogni messaggio individuale)
    msgs_list = _msgs(entry)
    if all(re.match(r'^MCP error -32602: (MCP error -32602: )?Invalid params?\s*$', m.strip(), re.I)
           for m in msgs_list if m.strip()):
        return "FP", "generic_invalid_params"

    # HC-FP: "Invalid arguments" generico (my-first-mcp-server, linea-mcp)
    if re.search(r'^MCP error -32602: (MCP error -32602: )?Invalid arguments?\s*$',
                 msgs_joined.strip(), re.I):
        return "FP", "generic_invalid_args"

    return None, "uncertain"


# FRAMEWORK: mcp-check | CATEGORIA: tool_invocation/method_not_found
def hc_rules_tool_invocation_method_not_found(entry: dict) -> tuple[str | None, str]:
    """
    Tutti VP: tool dichiarato ma non implementato (-32601).
    Include "Tool implementation pending" e "Tool not implemented in standalone version".
    """
    return "VP", "tool_not_implemented"


# Nomi di tool per-design non-deterministici (regex sul nome del test)
_NONDETERMINISTIC_BY_DESIGN = re.compile(
    r'(time|clock|date|now|timestamp|'
    r'uuid|guid|random|rand|dice|roll|'
    r'weather|forecast|'
    r'health.?check|heartbeat|'
    r'system.?info|sys.?info|'
    r'sequential.?thinking|think|'
    r'ping|latency|'
    r'auth|login|session|token|'
    r'search|lookup|query|fetch|'
    r'generate.?uuid|generate.?id|'
    r'create.?note|create.?task|create.?project|create.?todo|'
    r'create.?entit|create.?relation|create.?convers|'
    r'get.?current|get.?weather|get.?system|'
    r'get.?component.?demo)',
    re.I
)


# FRAMEWORK: mcp-check | CATEGORIA: tool_invocation/warnings
def hc_rules_tool_invocation_warnings(entry: dict) -> tuple[str | None, str]:
    """
    HC per warning di non-determinismo.

    Tutti i warning sono "Tool behavior appears non-deterministic with identical inputs".
    Per la stragrande maggioranza dei tool flaggati il non-determinismo è atteso:
    - Tool con stato temporale (time, clock, date)
    - Tool con random/uuid/dice
    - Tool che creano oggetti con ID auto-generati (create_note, create_task...)
    - Tool che interrogano API esterne (weather, search, fetch)
    - Tool con state side-effects (health_check con timestamp)

    HC-FP: tool-name match a pattern non-deterministici noti → FP per design
    Default: UNCERTAIN (tool sconosciuto che potrebbe dover essere deterministico)
    """
    tests_list = _tests(entry)
    tests_joined = " ".join(tests_list)

    # Estrae nome del tool dal test name: "tool-<nome>-deterministic-behavior"
    tool_names = []
    for t in tests_list:
        m = re.match(r"tool-(.+)-deterministic-behavior", t)
        if m:
            tool_names.append(m.group(1))

    if not tool_names:
        return None, "no_tool_name_extracted"

    # Tutti i tool in questo entry sono non-deterministici per design?
    all_by_design = all(_NONDETERMINISTIC_BY_DESIGN.search(name) for name in tool_names)

    if all_by_design:
        return "FP", f"non_deterministic_by_design:{','.join(tool_names[:3])}"

    # Default FP: qualsiasi tool MCP è non-deterministico in un test harness
    # (side effects, timestamp, external state, auto-IDs, AI output...)
    return "FP", f"non_deterministic_default:{','.join(tool_names[:3])}"


# FRAMEWORK: mcp-check | CATEGORIA: tool_invocation/unauthorized_or_auth_missing
def hc_rules_tool_invocation_unauthorized(entry: dict) -> tuple[str | None, str]:
    """Tutti FP: il server richiede auth per funzionare. Auth attiva = comportamento corretto."""
    return "FP", "auth_required_by_design"


HC_RULES: dict[str, object] = {
    "handshake/schema_violation":              hc_rules_handshake_schema_violation,
    "handshake/other_errors":                  hc_rules_handshake_other_errors,
    "handshake/method_not_found":              hc_rules_handshake_method_not_found,
    "handshake/unauthorized_or_auth_missing":  hc_rules_handshake_unauthorized,
    "tool_discovery/schema_violation":         hc_rules_tool_discovery_schema_violation,
    "tool_discovery/other_errors":             hc_rules_tool_discovery_other_errors,
    "tool_discovery/method_not_found":         hc_rules_tool_discovery_method_not_found,
    "tool_discovery/warnings":                 hc_rules_tool_discovery_warnings,
    "tool_invocation/schema_violation":        hc_rules_tool_invocation_schema_violation,
    "tool_invocation/other_errors":            hc_rules_tool_invocation_other_errors,
    "tool_invocation/invalid_arguments":       hc_rules_tool_invocation_invalid_arguments,
    "tool_invocation/method_not_found":        hc_rules_tool_invocation_method_not_found,
    "tool_invocation/warnings":                hc_rules_tool_invocation_warnings,
    "tool_invocation/unauthorized_or_auth_missing": hc_rules_tool_invocation_unauthorized,
}


# ══════════════════════════════════════════════════════════════════════════════
#  LOADING
# ══════════════════════════════════════════════════════════════════════════════

def _cat_path(cat_key: str) -> Path:
    info = CATEGORIES[cat_key]
    phase = info["phase"]
    cat = info["category"]
    fname = info["filename"]
    return HERE / phase / cat / "filtered" / fname


def load_findings(cat_key: str) -> tuple[list, dict]:
    info = CATEGORIES[cat_key]
    path = _cat_path(cat_key)
    if not path.exists():
        raise FileNotFoundError(f"File sorgente non trovato: {path}")
    with io.open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    # mcp-check usa "entries" (non "findings")
    entries = data.get("entries") or []
    meta = {
        "cat_key": cat_key,
        "description": info["description"],
        "has_hc": info.get("has_hc", False),
        "total_in_file": data.get("total", len(entries)),
        "total_loaded": len(entries),
    }
    return entries, meta


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

def _out_dir(cat_key: str) -> Path:
    info = CATEGORIES[cat_key]
    phase = info["phase"]
    cat = info["category"]
    d = HERE / phase / cat / "filtered" / "llm_analysis"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_json(path: Path, data: object) -> None:
    with io.open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print(f"  -> {path}")


def _load_cache(out_dir: Path) -> dict:
    p = out_dir / "_llm_api_cache.json"
    if p.exists():
        with io.open(p, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def _save_cache(out_dir: Path, cache: dict) -> None:
    p = out_dir / "_llm_api_cache.json"
    with io.open(p, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, ensure_ascii=False, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  LLM / OLLAMA (riferimento — in pratica si usa --cache-only con cache in-chat)
# ══════════════════════════════════════════════════════════════════════════════

OLLAMA_PROMPT = """\
Sei un esperto di sicurezza e conformance del protocollo MCP (Model Context Protocol).

mcp-check è un test harness di conformance. Il finding sotto indica un problema
durante il test. Classifica come VP (Vero Positivo = problema reale del server)
o FP (Falso Positivo = errore ambientale: auth mancante, input invalido di mcp-check,
comportamento per design).

FASE/CATEGORIA: {cat_key}
DESCRIZIONE:    {description}
SERVER:         {server}
TEST:           {tests}
TIPI ERRORE:    {types}
MESSAGGI:
---
{msgs_snippet}
---

RISPONDI SOLO con questo JSON (nessun altro testo):
{{"verdict": "VP" o "FP", "reason": "spiegazione in italiano max 20 parole"}}"""


def _call_ollama(
    entry: dict,
    cat_key: str,
    model: str,
    ollama_url: str,
    dry_run: bool,
) -> dict | None:
    info = CATEGORIES[cat_key]
    msgs_snippet = "\n".join(_msgs(entry))[:800]

    prompt = OLLAMA_PROMPT.format(
        cat_key=cat_key,
        description=info["description"],
        server=_server_short(entry.get("server_url", ""))[:60],
        tests=", ".join(_tests(entry))[:120],
        types=", ".join(_types(entry))[:80],
        msgs_snippet=msgs_snippet,
    )

    if dry_run:
        print(f"  [DRY-RUN] Prompt:\n{prompt[:400]}\n...")
        return None

    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0},
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            f"{ollama_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        text = body.get("response", "").strip()
        m = re.search(r'\{[^}]+\}', text, re.DOTALL)
        if m:
            result = json.loads(m.group())
            verdict = result.get("verdict", "").upper()
            if verdict in ("VP", "FP"):
                return {"verdict": verdict, "reason": result.get("reason", "")}
        return {"verdict": "FP", "reason": f"parse_error: {text[:60]}"}
    except Exception as e:
        return {"verdict": "FP", "reason": f"ollama_error: {str(e)[:60]}"}


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 2A — HC RULES
# ══════════════════════════════════════════════════════════════════════════════

def run_hc_only(cat_key: str, entries: list, meta: dict) -> None:
    hc_fn = HC_RULES.get(cat_key)
    if not hc_fn:
        print(f"  WARN: nessuna HC rule per '{cat_key}' — usa --cache-only")
        return

    out_dir = _out_dir(cat_key)
    hc_vp, hc_fp, uncertain = [], [], []
    reason_counter: Counter = Counter()

    for entry in entries:
        verdict, reason = hc_fn(entry)
        e = dict(entry, _hc_verdict=verdict, _hc_reason=reason)
        reason_counter[f"{verdict or 'UNCERTAIN'}:{reason}"] += 1
        if verdict == "VP":
            hc_vp.append(e)
        elif verdict == "FP":
            hc_fp.append(e)
        else:
            uncertain.append(e)

    print(f"  HC: {len(hc_vp)} VP, {len(hc_fp)} FP, {len(uncertain)} UNCERTAIN")
    print("  Top reasons:")
    for r, c in reason_counter.most_common(15):
        print(f"    {c:5d}  {r}")

    desc = meta["description"]
    _save_json(out_dir / "hc_vp.json",
               {"cat_key": cat_key, "description": desc, "verdict": "true_positive",
                "total": len(hc_vp), "entries": hc_vp})
    _save_json(out_dir / "hc_fp.json",
               {"cat_key": cat_key, "description": desc, "verdict": "false_positive",
                "total": len(hc_fp), "entries": hc_fp})
    _save_json(out_dir / "uncertain.json",
               {"cat_key": cat_key, "total": len(uncertain), "entries": uncertain})


# ══════════════════════════════════════════════════════════════════════════════
#  STAGE 2B — LLM / CACHE
# ══════════════════════════════════════════════════════════════════════════════

def run_llm_stage(
    cat_key: str,
    entries: list,
    meta: dict,
    *,
    cache_only: bool,
    model: str,
    ollama_url: str,
    no_cache: bool,
    dry_run: bool,
) -> None:
    out_dir = _out_dir(cat_key)
    has_hc = meta.get("has_hc", False)

    if has_hc:
        uncertain_path = out_dir / "uncertain.json"
        hc_vp_path = out_dir / "hc_vp.json"
        hc_fp_path = out_dir / "hc_fp.json"

        if not uncertain_path.exists():
            print(f"  WARN: uncertain.json non trovato — esegui --hc-only prima")
            to_classify = entries
            hc_vp_list, hc_fp_list = [], []
        else:
            with io.open(uncertain_path, encoding="utf-8") as fh:
                to_classify = json.load(fh).get("entries", [])
            hc_vp_list = (json.load(io.open(hc_vp_path, encoding="utf-8")).get("entries", [])
                          if hc_vp_path.exists() else [])
            hc_fp_list = (json.load(io.open(hc_fp_path, encoding="utf-8")).get("entries", [])
                          if hc_fp_path.exists() else [])
            print(f"  Da HC: {len(hc_vp_list)} VP, {len(hc_fp_list)} FP, {len(to_classify)} UNCERTAIN")
    else:
        to_classify = entries
        hc_vp_list, hc_fp_list = [], []

    cache = {} if no_cache else _load_cache(out_dir)

    vp_list = list(hc_vp_list)
    fp_list = list(hc_fp_list)
    audit_list = []
    n_cache_hit = 0
    n_new_calls = 0
    n_uncached = 0

    print(f"\n[Stage LLM] Classificazione ({len(to_classify)} finding)...")

    for idx, entry in enumerate(to_classify, 1):
        key = _cache_key(entry, cat_key)
        cached = cache.get(key)

        if cached and not no_cache:
            verdict = cached["verdict"]
            reason = cached["reason"]
            source = "CACHE"
            n_cache_hit += 1
        elif cache_only:
            verdict = "FP"
            reason = "uncached_default_fp"
            source = "UNCACHED"
            n_uncached += 1
        else:
            result = _call_ollama(entry, cat_key, model, ollama_url, dry_run)
            if result:
                verdict = result["verdict"]
                reason = result["reason"]
                cache[key] = {"verdict": verdict, "reason": reason}
                n_new_calls += 1
            else:
                verdict = "FP"
                reason = "dry_run_or_error"
                n_new_calls += 1
            source = "OLLAMA"

        label = f"[{idx:4d}/{len(to_classify)}]"
        server_s = _server_short(entry.get("server_url", ""))[:50]
        print(f"  {label} {source:8s} {server_s:<50} -> {verdict}")

        e = dict(entry,
                 llm_verdict=verdict,
                 llm_reason=reason,
                 verdict_source=source,
                 final_verdict=verdict,
                 final_reason=reason)
        if verdict == "VP":
            vp_list.append(e)
        else:
            fp_list.append(e)
        audit_list.append(e)

    # Aggiungi HC entries all'audit
    for entry in hc_vp_list:
        audit_list.append(dict(entry, final_verdict="VP",
                               final_reason=entry.get("_hc_reason", "hc_vp")))
    for entry in hc_fp_list:
        audit_list.append(dict(entry, final_verdict="FP",
                               final_reason=entry.get("_hc_reason", "hc_fp")))

    _save_cache(out_dir, cache)

    desc = meta["description"]
    _save_json(out_dir / "vp.json",
               {"cat_key": cat_key, "description": desc, "verdict": "true_positive",
                "total": len(vp_list), "entries": vp_list})
    _save_json(out_dir / "fp.json",
               {"cat_key": cat_key, "description": desc, "verdict": "false_positive",
                "total": len(fp_list), "entries": fp_list})
    _save_json(out_dir / "audit.json",
               {"cat_key": cat_key, "total": len(audit_list), "entries": audit_list})

    print(f"\n  Riepilogo: {n_cache_hit} da cache, {n_new_calls} nuove chiamate, "
          f"{n_uncached} non cachati")
    print(f"\n-- Risultati finali --")
    print(f"  Totale:          {len(audit_list)}")
    print(f"  Veri Positivi:   {len(vp_list):5d}  ({len(vp_list)/max(len(audit_list),1)*100:.1f}%)")
    print(f"  Falsi Positivi:  {len(fp_list):5d}  ({len(fp_list)/max(len(audit_list),1)*100:.1f}%)")

    if n_uncached:
        print(f"\n  ATTENZIONE: {n_uncached} finding non in cache → classificati FP (default).")
        print(f"  Aggiungili in: {out_dir / '_llm_api_cache.json'}")
        print(f"  e riesegui --cache-only.")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(description="Pipeline LLM per mcp-check")
    parser.add_argument("--category", default="all",
                        help="Categoria (es. tool_invocation/other_errors) o 'all'. Default: all")
    parser.add_argument("--model", default="llama3",
                        help="Modello Ollama (default: llama3)")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="URL Ollama (default: http://localhost:11434)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Ignora cache e riclassifica tutto")
    parser.add_argument("--cache-only", action="store_true",
                        help="Usa solo cache (non chiama Ollama)")
    parser.add_argument("--hc-only", action="store_true",
                        help="Solo Stage 2A (HC rules), non chiama LLM")
    parser.add_argument("--merge", action="store_true",
                        help="Stage 2A + 2B completo (HC + LLM/cache)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Mostra prompt senza chiamare Ollama")
    args = parser.parse_args()

    cats = list(CATEGORIES.keys()) if args.category == "all" else [args.category]

    for cat_key in cats:
        if cat_key not in CATEGORIES:
            print(f"Categoria '{cat_key}' non trovata.")
            print(f"Disponibili: {list(CATEGORIES.keys())}")
            continue

        info = CATEGORIES[cat_key]
        print(f"\n{'='*70}")
        print(f"  Categoria: {cat_key}")
        print(f"  Desc:      {info['description']}")
        print(f"  Has HC:    {info['has_hc']}")
        print(f"{'='*70}")

        try:
            entries, meta = load_findings(cat_key)
        except FileNotFoundError as e:
            print(f"  ERRORE: {e}")
            continue

        print(f"  Entry caricati: {len(entries)}")

        if args.hc_only:
            if meta["has_hc"]:
                run_hc_only(cat_key, entries, meta)
            else:
                print(f"  INFO: '{cat_key}' non ha HC rules — usa --cache-only")

        elif args.cache_only or args.dry_run:
            run_llm_stage(cat_key, entries, meta,
                          cache_only=True,
                          model=args.model,
                          ollama_url=args.ollama_url,
                          no_cache=args.no_cache,
                          dry_run=args.dry_run)

        elif args.merge:
            if meta["has_hc"]:
                unc_path = HERE / info["phase"] / info["category"] / "filtered" / "llm_analysis" / "uncertain.json"
                if not unc_path.exists():
                    print("  Eseguo HC rules prima del merge...")
                    run_hc_only(cat_key, entries, meta)
            run_llm_stage(cat_key, entries, meta,
                          cache_only=False,
                          model=args.model,
                          ollama_url=args.ollama_url,
                          no_cache=args.no_cache,
                          dry_run=args.dry_run)

        else:
            parser.print_help()
            print(f"\n  Specifica --hc-only, --cache-only, o --merge")


if __name__ == "__main__":
    main()
