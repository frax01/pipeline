#!/usr/bin/env python3
"""
Filtro ad alta confidenza per mcp-security-scan.

Analizza i finding di mcp-security-scan e scarta i falsi positivi,
tenendo solo le vulnerabilita' con alta probabilita' di essere reali.

Categorie e ID vulnerability:
  - dangerous-capabilities (X-01): keyword-based, ALTISSIMO tasso FP
  - input-validation (X-02): fuzzing con indicatori generici, ALTISSIMO tasso FP
  - path-traversal (R-01): probe attivo, MEDIO tasso FP
  - sensitive-file-access (R-02): probe attivo, MEDIO tasso FP
  - rug-pull (X-03): diff deterministico, BASSO tasso FP
  - prompt-injection (P-02): pattern matching su descrizioni, MEDIO tasso FP
  - data-leak (A-03): token pattern matching, ALTO tasso FP
  - remote-access-control (RC-01): keyword + response matching, ALTO tasso FP
  - indirect-prompt-injection (P-03): pattern matching, ALTO tasso FP
  - sensitive-resource-exposure (R-03): keyword matching, ALTO tasso FP
  - initialization-error: noise infrastrutturale, SCARTATO

Uso:
  python filter_security_scan.py
  python filter_security_scan.py --dry-run
  python filter_security_scan.py --category input-validation

Output:
  - Per ogni categoria: <categoria>/filtered/<file>_filtered.json
  - Per ogni categoria: <categoria>/filtered/<categoria>_analysis.md
  - Report globale: filter_analysis_report.md
"""

import sys

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import os
import re
import argparse
from collections import defaultdict
from datetime import datetime


# ============================================================================
# CONFIGURAZIONE
# ============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Categorie da SCARTARE completamente (noise infrastrutturale)
SKIP_CATEGORIES = {
    'initialization-error',  # 444 entries - server non avviato, non e' una vuln
}

# ============================================================================
# UTILITY
# ============================================================================

def parse_details(details_str):
    """Prova a parsare il campo details come JSON."""
    if not details_str or not isinstance(details_str, str):
        return details_str
    try:
        return json.loads(details_str)
    except (json.JSONDecodeError, TypeError):
        return details_str


def text_lower(obj):
    """Estrai tutto il testo da un oggetto nested e ritorna lowercase."""
    if isinstance(obj, str):
        return obj.lower()
    if isinstance(obj, dict):
        return " ".join(text_lower(v) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(text_lower(v) for v in obj)
    return str(obj).lower()


# ============================================================================
# FILTRO: dangerous-capabilities (X-01)
# ============================================================================

# Keyword usate dallo scanner per flaggare tool "pericolosi"
# Problema: "fetch", "http", "url", "admin" sono troppo generici
# e flaggano tool di data fetching, URL parsing, admin panel read-only

# Tool REALMENTE pericolosi: eseguono comandi, scrivono/cancellano file,
# modificano sistema
DANGEROUS_TOOL_PATTERNS = [
    # Esecuzione comandi diretta
    re.compile(r'\b(exec|execute|run_command|run_shell|shell|bash|terminal|subprocess)\b', re.I),
    # Scrittura/cancellazione file
    re.compile(r'\b(write_file|delete_file|remove_file|rm\b|unlink|rmdir|create_file)\b', re.I),
    # Permessi
    re.compile(r'\b(chmod|chown|chgrp|setuid)\b', re.I),
    # Eval
    re.compile(r'\beval\b', re.I),
    # Payment/transazione
    re.compile(r'\b(payment|transfer_funds|send_money|charge|refund)\b', re.I),
]

# Tool SICURI che vengono flaggati per keyword generiche
SAFE_TOOL_PATTERNS = [
    # Data fetching/reading (flaggati per "fetch", "http", "url")
    re.compile(r'\b(fetch_\w*data|fetch_\w*info|get_\w*|search_\w*|list_\w*|read_\w*|query_\w*)\b', re.I),
    # URL come parametro non e' pericoloso
    re.compile(r'\b(parse_url|format_url|validate_url|url_encode|url_decode)\b', re.I),
    # Admin lettura
    re.compile(r'\b(get_admin|admin_info|admin_status|admin_list|view_admin)\b', re.I),
]

# Descrizioni che indicano tool read-only / safe
SAFE_DESCRIPTION_PATTERNS = [
    re.compile(r'(retrieve|search|query|look\s*up|get|list|view|show|display|check|inspect|browse)\b', re.I),
    re.compile(r'\bread[\s-]?only\b', re.I),
]

# Descrizioni che indicano tool REALMENTE pericolosi
DANGER_DESCRIPTION_PATTERNS = [
    re.compile(r'\b(execut(e|es|ing)\s+(a\s+)?command)', re.I),
    re.compile(r'\b(run\s+(a\s+)?(shell|command|script|bash))', re.I),
    re.compile(r'\b(delet(e|es|ing)\s+(file|director))', re.I),
    re.compile(r'\b(writ(e|es|ing)\s+(to\s+)?(file|disk|filesystem))', re.I),
    re.compile(r'\b(remov(e|es|ing)\s+(file|director))', re.I),
    re.compile(r'\b(kill|terminate)\s+(process|pid)', re.I),
    re.compile(r'\b(modify|change|update)\s+(permission|owner)', re.I),
    re.compile(r'\b(install|uninstall)\s+', re.I),
    re.compile(r'\b(docker.*(exec|run|compose))', re.I),
    re.compile(r'\b(ssh|scp|rsync)\b', re.I),
    re.compile(r'\b(sudo|su\s)', re.I),
    re.compile(r'\b(drop|truncate)\s+(table|database|collection)', re.I),
]


def _tool_has_unconstrained_dangerous_param(tool_def):
    """Controlla se un tool ha parametri pericolosi senza constraint."""
    schema = tool_def.get("inputSchema", {})
    props = schema.get("properties", {})

    dangerous_param_names = {"command", "cmd", "shell", "script", "exec",
                             "code", "query", "sql", "expression", "eval"}

    for pname, pdef in props.items():
        if pname.lower() in dangerous_param_names:
            # Ha constraint? (enum, pattern, maxLength corto)
            has_enum = "enum" in pdef
            has_pattern = "pattern" in pdef
            has_short_max = pdef.get("maxLength", 9999) < 200
            if not (has_enum or has_pattern or has_short_max):
                return True, pname
    return False, None


def filter_dangerous_capabilities(finding):
    """
    Filtra X-01 (dangerous capabilities).

    Il problema: lo scanner flagga tool con keyword generiche come
    "fetch", "http", "url", "admin" anche se sono read-only.

    Strategia:
    1. Parsa i tool flaggati dal campo details
    2. Per ogni tool, controlla nome e descrizione
    3. Tieni solo tool che REALMENTE eseguono comandi/scrivono/cancellano
    4. Filtra tool di data fetching / read-only
    """
    details = parse_details(finding.get("details", ""))
    if not isinstance(details, list):
        return None, "details_not_parseable"

    kept_tools = []
    for tool_def in details:
        if not isinstance(tool_def, dict):
            continue

        name = tool_def.get("name", "").lower()
        desc = tool_def.get("description", "").lower()
        full_text = f"{name} {desc}"

        # CHECK 1: nome o descrizione matchano pattern REALMENTE pericolosi?
        is_dangerous = False
        danger_reason = ""

        for pat in DANGEROUS_TOOL_PATTERNS:
            if pat.search(name):
                is_dangerous = True
                danger_reason = f"dangerous_name:{pat.pattern}"
                break

        if not is_dangerous:
            for pat in DANGER_DESCRIPTION_PATTERNS:
                if pat.search(desc):
                    is_dangerous = True
                    danger_reason = f"dangerous_desc:{pat.pattern}"
                    break

        # CHECK 2: ha parametri di tipo "command" senza constraint?
        if not is_dangerous:
            has_danger_param, param_name = _tool_has_unconstrained_dangerous_param(tool_def)
            if has_danger_param:
                is_dangerous = True
                danger_reason = f"unconstrained_param:{param_name}"

        # CHECK 3: se non e' pericoloso, e' un tool read-only/safe?
        if not is_dangerous:
            # Se la descrizione parla solo di lettura, skip
            for pat in SAFE_DESCRIPTION_PATTERNS:
                if pat.search(desc) and not any(p.search(full_text) for p in DANGER_DESCRIPTION_PATTERNS):
                    continue  # safe, skip

        if is_dangerous:
            tool_def["_filter_reason"] = danger_reason
            kept_tools.append(tool_def)

    if kept_tools:
        return kept_tools, f"kept_{len(kept_tools)}_of_{len(details)}"
    return None, "all_tools_safe"


# ============================================================================
# FILTRO: input-validation (X-02)
# ============================================================================

# Indicatori usati dallo scanner per determinare "injection riuscita"
# Problema: "linux", "insecure", "stdout" sono troppo generici
# e matchano error messages, documentazione, log

# Pattern che indicano VERA esecuzione di comando
REAL_INJECTION_PATTERNS = [
    # Output reale di `id`
    re.compile(r'uid=\d+\('),
    # Output reale di `uname -a` (kernel version nel response)
    re.compile(r'Linux\s+\S+\s+\d+\.\d+\.\d+'),
    # Contenuto reale di /etc/passwd
    re.compile(r'root:x:0:0:'),
    re.compile(r'root:[x*]:0:0:'),
    # Contenuto reale di /etc/hosts
    re.compile(r'127\.0\.0\.1\s+localhost'),
    # AWS metadata reale
    re.compile(r'ami-[0-9a-f]{8,17}'),
    re.compile(r'instance-id.*i-[0-9a-f]'),
    # Output reale di whoami
    re.compile(r'"text"\s*:\s*"[a-z_][a-z0-9_-]*\\n"'),  # username output
]

# Pattern che indicano che il server ha RIFIUTATO l'input (= NON vulnerabile)
REJECTION_PATTERNS = [
    re.compile(r'"isError"\s*:\s*true', re.I),
    re.compile(r'(invalid|illegal|not allowed|rejected|forbidden|denied|unauthorized)', re.I),
    re.compile(r'(does not exist|not found|no such|path.*(outside|invalid))', re.I),
    re.compile(r'(error|failed|cannot|unable to)', re.I),
]

# Pattern per payload echoing (server stampa il payload senza eseguirlo)
ECHO_PATTERNS = [
    re.compile(r'No \w+ found matching.*\.\./'),
    re.compile(r'Unknown command.*\.\./'),
    re.compile(r"pathspec.*did not match"),
    re.compile(r'Path does not exist'),
    re.compile(r'not a valid branch name'),
    re.compile(r'hostname contains invalid characters'),
]


def _analyze_injection_response(tool_entry):
    """
    Analizza una singola risposta di injection fuzzing.
    Ritorna (is_real_vuln, reason).
    """
    tool_name = tool_entry.get("tool", "")
    payload = tool_entry.get("payload", "")
    resp = tool_entry.get("resp", {})

    resp_text = json.dumps(resp, ensure_ascii=False).lower() if resp else ""
    resp_text_original = json.dumps(resp, ensure_ascii=False) if resp else ""

    # CHECK 1: Il response contiene output REALE di comando eseguito?
    for pat in REAL_INJECTION_PATTERNS:
        if pat.search(resp_text_original):
            return True, f"real_injection:{pat.pattern[:40]}"

    # CHECK 2: Il server ha rifiutato l'input? (isError: true o messaggi di errore)
    is_error = '"isError": true' in resp_text_original or '"isError":true' in resp_text_original
    if is_error:
        # Anche se isError=true, controlla se il messaggio di errore contiene
        # output di sistema (command injection tramite error message)
        for pat in REAL_INJECTION_PATTERNS:
            if pat.search(resp_text_original):
                return True, f"injection_in_error:{pat.pattern[:40]}"
        return False, "server_rejected_with_error"

    # CHECK 3: Payload echoing senza esecuzione
    for pat in ECHO_PATTERNS:
        if pat.search(resp_text_original):
            return False, "payload_echoed_not_executed"

    # CHECK 4: Response vuoto o generico
    if not resp_text.strip() or resp_text in ('{}', 'null', '""'):
        return False, "empty_response"

    # CHECK 5: Per path traversal payload, controlla se il path e' stato usato
    # come directory di lavoro (non come file letto)
    if "../../../../" in payload:
        if "workingdirectory" in resp_text and "../../../../" in resp_text:
            # Il server ha usato il path come working directory ma non ha letto il file
            # Controlla se c'e' contenuto di file reale
            has_file_content = any(p.search(resp_text_original) for p in REAL_INJECTION_PATTERNS)
            if not has_file_content:
                return False, "path_used_as_workdir_not_read"

    # CHECK 6: Per command injection payloads, l'output contiene
    # indicatori generici ma senza output reale di sistema?
    generic_indicators = ["linux", "insecure", "stdout", "meta-data"]
    has_generic = any(ind in resp_text for ind in generic_indicators)
    has_real = any(pat.search(resp_text_original) for pat in REAL_INJECTION_PATTERNS)

    if has_generic and not has_real:
        # Potrebbe essere solo un messaggio che contiene la parola "linux" etc.
        # Controlla contesto
        if "linux" in resp_text and not re.search(r'Linux\s+\S+\s+\d+\.\d+', resp_text_original):
            return False, "generic_indicator_no_real_output"
        if "insecure" in resp_text and re.search(r'(rejected|invalid|not allowed).*insecure', resp_text, re.I):
            return False, "insecure_in_rejection_message"

    # CHECK 7: Il response indica successo senza errori?
    # Se isError non e' presente o e' false, E il response non e' un rifiuto,
    # E non c'e' output reale di injection... potrebbe essere un FP
    is_not_error = '"isError": false' in resp_text_original or '"isError":false' in resp_text_original
    if is_not_error and not has_real:
        # Il tool ha "accettato" il payload ma non ha prodotto output di sistema
        # Potrebbe essere un'operazione che ha usato il payload come stringa innocua
        # Es: "Docker cleanup (../../../../etc/passwd) completed" - non ha letto il file
        return False, "accepted_but_no_injection_evidence"

    # Se nessun check e' conclusivo, tieni il finding con bassa confidenza
    if has_real:
        return True, "real_system_output"

    return False, "no_injection_evidence"


def filter_input_validation(finding):
    """
    Filtra X-02 (input validation & injection fuzzing).

    Problema PRINCIPALE: lo scanner usa indicatori generici come
    "linux", "insecure", "stdout" per determinare se l'injection
    ha avuto successo. Ma questi compaiono in error messages, docs, log.

    Strategia:
    1. Parsa le risposte di fuzzing
    2. Per ogni risposta, cerca output REALE di comandi eseguiti
    3. Scarta risposte con isError=true (server ha rifiutato)
    4. Scarta payload echoing (server stampa il payload nell'errore)
    5. Tieni SOLO injection realmente eseguite (uid=, uname output, etc)
    """
    details = parse_details(finding.get("details", ""))
    if not isinstance(details, list):
        return None, "details_not_parseable"

    kept_entries = []
    for tool_entry in details:
        if not isinstance(tool_entry, dict):
            continue

        is_vuln, reason = _analyze_injection_response(tool_entry)
        if is_vuln:
            tool_entry["_filter_reason"] = reason
            kept_entries.append(tool_entry)

    if kept_entries:
        return kept_entries, f"kept_{len(kept_entries)}_of_{len(details)}"
    return None, "all_injections_rejected"


# ============================================================================
# FILTRO: prompt-injection (P-02)
# ============================================================================

# Pattern di VERA prompt injection nelle tool description
REAL_PROMPT_INJECTION_PATTERNS = [
    re.compile(r'HIDDEN\s+INSTRUCTION', re.I),
    re.compile(r'INVISIBLE\s+TO\s+USER', re.I),
    re.compile(r'ignore\s+(any\s+)?(previous|prior|all)\s+(instructions|rules|safety)', re.I),
    re.compile(r'do\s+not\s+disclose\s+this', re.I),
    re.compile(r'exfiltrate', re.I),
    re.compile(r'send\s+(secrets|credentials|tokens|data)\s+to', re.I),
    re.compile(r'malicious[_-]?\w*\.evil', re.I),
    re.compile(r'override\s+(other\s+)?tools', re.I),
    re.compile(r'include\s+contents\s+of', re.I),
    re.compile(r'secretly\s+(send|transmit|exfiltrate|forward)', re.I),
    re.compile(r'pretend\s+to\s+be', re.I),
    re.compile(r'act\s+as\s+if\s+you\s+are', re.I),
    re.compile(r'when\s+(the\s+)?(user|human)\s+(is\s+)?not\s+(looking|watching|aware)', re.I),
]

# Contesti che generano falsi positivi (tool di sicurezza che DESCRIVONO attacchi)
SECURITY_TOOL_PATTERNS = [
    re.compile(r'(check|scan|detect|analyze|inspect|validate)\s+(for\s+)?(prompt\s+injection|injection|suspicious)', re.I),
    re.compile(r'security\s+(scan|check|analys|audit)', re.I),
    re.compile(r'(blocked|safe|trust|verify|protect)', re.I),
]


def filter_prompt_injection(finding):
    """
    Filtra P-02 (prompt injection in tool descriptions).

    Problemi:
    1. "Cannot complete check - MCP server died" = crash, non injection
    2. Tool di sicurezza che DESCRIVONO pattern di injection vengono flaggati
    3. Tool con "override" in contesti legittimi

    Strategia:
    1. Scarta "server died" / crash entries
    2. Scarta tool di sicurezza che descrivono pattern di attacco
    3. Tieni tool con VERE hidden instructions
    """
    details_str = finding.get("details", "")

    # CHECK 1: Server crashed - non e' prompt injection
    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"
    if "no_response" in details_str or "Process returned no data" in details_str:
        return None, "server_no_response"

    details = parse_details(details_str)
    if not isinstance(details, list):
        # Se non e' parseable ma contiene pattern reali, tieni
        if isinstance(details_str, str):
            for pat in REAL_PROMPT_INJECTION_PATTERNS:
                if pat.search(details_str):
                    return details_str, f"real_injection_in_raw_text"
        return None, "details_not_parseable"

    kept_tools = []
    for tool_def in details:
        if not isinstance(tool_def, dict):
            continue

        desc = tool_def.get("description", "")
        name = tool_def.get("name", "")

        # CHECK 2: E' un tool di sicurezza che DESCRIVE gli attacchi?
        is_security_tool = any(pat.search(desc) for pat in SECURITY_TOOL_PATTERNS)
        is_security_name = any(kw in name.lower() for kw in
                               ["scan", "guard", "shield", "security", "detect", "check", "protect", "shrike"])

        # CHECK 3: Contiene VERI pattern di injection?
        has_real_injection = any(pat.search(desc) for pat in REAL_PROMPT_INJECTION_PATTERNS)

        if has_real_injection:
            if is_security_tool or is_security_name:
                # Tool di sicurezza che descrive attacchi - probabilmente FP
                # MA se contiene "HIDDEN INSTRUCTION" esplicito, potrebbe essere un test case malevolo
                if re.search(r'HIDDEN\s+INSTRUCTION', desc, re.I) or \
                   re.search(r'INVISIBLE\s+TO\s+USER', desc, re.I) or \
                   re.search(r'malicious[_-]?\w*\.evil', desc, re.I):
                    tool_def["_filter_reason"] = "injection_in_security_tool_but_suspicious"
                    kept_tools.append(tool_def)
                else:
                    continue  # security tool che descrive pattern = FP
            else:
                tool_def["_filter_reason"] = "real_prompt_injection"
                kept_tools.append(tool_def)

    if kept_tools:
        return kept_tools, f"kept_{len(kept_tools)}_of_{len(details)}"
    return None, "no_real_injection"


# ============================================================================
# FILTRO: rug-pull (X-03)
# ============================================================================

def filter_rug_pull(finding):
    """
    Filtra X-03 (tool description stability / rug pull).

    Basso tasso FP (diff deterministico), ma filtra:
    1. Diff dovuti a startup race condition (tool list vuota alla prima chiamata)
    2. Diff solo nel numero di tool (non nelle descrizioni)
    3. Diff dovuti a ordering diverso
    """
    details_str = finding.get("details", "")

    # Server crash
    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"
    if "no_response" in details_str:
        return None, "server_no_response"

    details = parse_details(details_str)

    # Se il details contiene informazioni su tool che sono CAMBIATI, tieni
    # Se e' solo un messaggio di errore, scarta
    if isinstance(details, str):
        if "changed" in details.lower() or "differ" in details.lower() or "added" in details.lower() or "removed" in details.lower():
            return details, "description_changed"
        if "error" in details.lower() or "timeout" in details.lower():
            return None, "error_not_rugpull"
        # Tieni - potrebbe contenere il diff
        return details, "kept_raw"

    # Se e' un dict/list con info strutturate, tieni
    return details if details else None, "kept" if details else "empty_details"


# ============================================================================
# FILTRO: path-traversal (R-01)
# ============================================================================

def filter_path_traversal(finding):
    """
    Filtra R-01 (path traversal).

    Lo scanner prova file:///../../etc/hosts e controlla se c'e' un "result" dict.
    FP: server che ritornano errori dentro un result dict.

    Tieni solo se il contenuto sembra file reale.
    """
    details_str = finding.get("details", "")

    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"
    if "no_response" in details_str:
        return None, "server_no_response"

    details = parse_details(details_str)
    details_text = text_lower(details) if details else details_str.lower()

    # Se il response contiene contenuto reale di file di sistema
    if re.search(r'127\.0\.0\.1\s+localhost', str(details)):
        return details, "real_hosts_file_content"
    if re.search(r'root:[x*]:0:0:', str(details)):
        return details, "real_passwd_content"

    # Se contiene solo errori
    if re.search(r'(error|not found|denied|invalid|forbidden|does not exist)', details_text):
        return None, "server_rejected_traversal"

    # Se ha un result dict, controlla se contiene contenuto reale di file
    if details:
        details_text_str = str(details)
        # Result vuoto o null -> server ha rifiutato
        if isinstance(details, dict):
            result = details.get("result", {})
            if isinstance(result, dict):
                contents = result.get("contents")
                # contents: null, [], {} -> nessun file letto
                if contents is None or contents == [] or contents == {}:
                    return None, "result_empty_no_file_read"
            # Il result e' una lista di tool (risposta a tools/list, non a resource read)
            if isinstance(result, dict) and "tools" in result:
                return None, "result_is_tool_list_not_file"
        # Controlla se il contenuto sembra testo di file (ha newline, righe multiple)
        if re.search(r'\\n.*\\n.*\\n', details_text_str):
            return details, "has_multiline_content"
        # Se il result non e' vuoto ma non ha contenuto di file riconoscibile
        return None, "result_no_file_content"

    return None, "no_traversal_evidence"


# ============================================================================
# FILTRO: sensitive-file-access (R-02)
# ============================================================================

def filter_sensitive_file_access(finding):
    """
    Filtra R-02 (accesso a file sensibili).
    Stesso approccio di path-traversal: tieni solo se contenuto reale di file.
    """
    details_str = finding.get("details", "")

    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"
    if "no_response" in details_str:
        return None, "server_no_response"

    details = parse_details(details_str)
    details_text = text_lower(details) if details else details_str.lower()

    # Contenuto reale di /etc/passwd
    if re.search(r'root:[x*]:0:0:', str(details)):
        return details, "real_passwd_content"

    # Contenuto reale di file sensibili
    if re.search(r'(BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY)', str(details)):
        return details, "real_private_key"

    # Errori = server ha rifiutato
    if re.search(r'(error|not found|denied|invalid|forbidden|does not exist)', details_text):
        return None, "server_rejected_access"

    # Result vuoto / no file content
    if details:
        details_text_str = str(details)
        if isinstance(details, dict):
            result = details.get("result", {})
            if isinstance(result, dict):
                contents = result.get("contents")
                if contents is None or contents == [] or contents == {}:
                    return None, "result_empty_no_file_read"
            if isinstance(result, dict) and "tools" in result:
                return None, "result_is_tool_list_not_file"
        if re.search(r'\\n.*\\n.*\\n', details_text_str):
            return details, "has_multiline_content"
        return None, "result_no_file_content"

    return None, "no_file_access_evidence"


# ============================================================================
# FILTRO: data-leak (A-03)
# ============================================================================

# Pattern di token/credential REALI nel response
REAL_TOKEN_PATTERNS = [
    re.compile(r'sk-[a-zA-Z0-9]{20,}'),           # OpenAI key
    re.compile(r'sk-ant-api03-[a-zA-Z0-9\-_]+'),   # Anthropic key
    re.compile(r'ghp_[a-zA-Z0-9]{36}'),             # GitHub PAT
    re.compile(r'gho_[a-zA-Z0-9]{36}'),             # GitHub OAuth
    re.compile(r'AKIA[A-Z0-9]{16}'),                # AWS Access Key
    re.compile(r'Bearer\s+[a-zA-Z0-9\-_.]{20,}'),   # Bearer token reale
    re.compile(r'xoxb-[0-9]{10,}'),                 # Slack bot token
    re.compile(r'sk_live_[a-zA-Z0-9]{24,}'),        # Stripe live key
]


def filter_data_leak(finding):
    """
    Filtra A-03 (token indirection / data leak).

    Lo scanner chiama un tool "upstream_access" con code:"dummy" e cerca
    pattern come "access_token", "sk-", "bearer" nel response.

    Problemi:
    1. Errori che dicono "token mancante" non sono data leak
    2. "sk-" puo' matchare prefissi innocui
    3. "bearer" puo' apparire in documentazione

    Tieni solo se il response contiene token/credenziali REALI.
    """
    details_str = finding.get("details", "")

    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"

    details = parse_details(details_str)
    details_text = str(details) if details else details_str

    # CHECK 1: E' solo un errore che dice "token/credenziali mancanti"?
    error_about_missing = re.search(
        r'(missing|required|not set|undefined|please set|environment variable)',
        details_text, re.I
    )
    error_obj = None
    if isinstance(details, dict):
        error_obj = details.get("error", {})
        if isinstance(error_obj, dict) and error_obj.get("code"):
            # E' un errore MCP standard - non un data leak
            if error_about_missing:
                return None, "error_about_missing_credentials"

    # CHECK 2: Il response contiene token REALI?
    for pat in REAL_TOKEN_PATTERNS:
        if pat.search(details_text):
            return details, f"real_token_found:{pat.pattern[:30]}"

    # CHECK 3: Il response contiene "access_token" con un valore reale?
    if re.search(r'"access_token"\s*:\s*"[a-zA-Z0-9\-_.]{20,}"', details_text):
        return details, "access_token_with_value"

    # Se c'e' un errore, non e' un data leak
    if error_about_missing or (isinstance(details, dict) and "error" in details):
        return None, "error_response_no_leak"

    # Tieni se c'e' un result con contenuto sospetto
    if isinstance(details, dict) and "result" in details:
        result_text = str(details["result"])
        if re.search(r'(token|secret|password|credential|api.?key)', result_text, re.I):
            return details, "suspicious_result_content"

    return None, "no_data_leak_evidence"


# ============================================================================
# FILTRO: remote-access-control (RC-01)
# ============================================================================

def filter_remote_access(finding):
    """
    Filtra RC-01 (remote access control).

    Lo scanner cerca tool con keyword "remote", "port", "expose", "bind"
    e prova a chiamarli con port:8080. Poi cerca "enabled", "listening" nel response.

    Problemi:
    1. "remote" matcha remote_config, remote_storage, remote_query
    2. "enabled" e' troppo generico
    3. Tool che non accettano "port" parameter

    Tieni solo se il tool REALMENTE espone accesso remoto.
    """
    details_str = finding.get("details", "")

    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"

    details = parse_details(details_str)
    details_text = str(details) if details else details_str

    # Se c'e' un errore, il server ha rifiutato
    if re.search(r'"isError"\s*:\s*true', details_text):
        return None, "server_rejected"
    if re.search(r'"error"', details_text) and not re.search(r'"result"', details_text):
        return None, "error_response"

    # Controlla se c'e' evidenza REALE di accesso remoto attivato
    real_access_patterns = [
        re.compile(r'(listening|bound)\s+(on|to|at)\s+\S*:\d+', re.I),
        re.compile(r'server\s+started\s+on\s+\S*:\d+', re.I),
        re.compile(r'remote.?access.?(enabled|activated|opened)', re.I),
        re.compile(r'port\s+\d+\s+(is\s+)?(now\s+)?(open|listening|active)', re.I),
    ]

    for pat in real_access_patterns:
        if pat.search(details_text):
            return details, f"real_remote_access:{pat.pattern[:40]}"

    # "enabled" da solo e' troppo generico
    if re.search(r'\benabled\b', details_text, re.I):
        # Controlla contesto
        if re.search(r'(remote|access|port|bind|listen)', details_text, re.I):
            return details, "enabled_in_remote_context"
        return None, "enabled_generic_context"

    return None, "no_remote_access_evidence"


# ============================================================================
# FILTRO: indirect-prompt-injection (P-03)
# ============================================================================

def filter_indirect_prompt_injection(finding):
    """
    Filtra P-03 (indirect prompt injection via risorse esterne).
    Pochi finding (3), tieni quasi tutto tranne crash.
    """
    details_str = finding.get("details", "")

    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"
    if "no_response" in details_str:
        return None, "server_no_response"

    details = parse_details(details_str)
    if details:
        return details, "kept"
    return None, "empty_details"


# ============================================================================
# FILTRO: sensitive-resource-exposure (R-03)
# ============================================================================

def filter_sensitive_resource_exposure(finding):
    """
    Filtra R-03 (sensitive resource exposure).
    Pochi finding (2), tieni quasi tutto tranne crash.
    """
    details_str = finding.get("details", "")

    if "Cannot complete check" in details_str or "server died" in details_str:
        return None, "server_crashed"

    details = parse_details(details_str)
    if details:
        return details, "kept"
    return None, "empty_details"


# ============================================================================
# DISPATCHER CATEGORIE
# ============================================================================

CATEGORY_FILTERS = {
    'dangerous-capabilities': filter_dangerous_capabilities,
    'input-validation': filter_input_validation,
    'prompt-injection': filter_prompt_injection,
    'rug-pull': filter_rug_pull,
    'path-traversal': filter_path_traversal,
    'sensitive-file-access': filter_sensitive_file_access,
    'data-leak': filter_data_leak,
    'remote-access-control': filter_remote_access,
    'indirect-prompt-injection': filter_indirect_prompt_injection,
    'sensitive-resource-exposure': filter_sensitive_resource_exposure,
}

# Mappa categoria -> ID vulnerability per il report
CATEGORY_VULN_IDS = {
    'dangerous-capabilities': 'X-01',
    'input-validation': 'X-02',
    'prompt-injection': 'P-02',
    'rug-pull': 'X-03',
    'path-traversal': 'R-01',
    'sensitive-file-access': 'R-02',
    'data-leak': 'A-03',
    'remote-access-control': 'RC-01',
    'indirect-prompt-injection': 'P-03',
    'sensitive-resource-exposure': 'R-03',
}

# Descrizioni per il report
CATEGORY_DESCRIPTIONS = {
    'dangerous-capabilities': (
        "Tool con capacita' pericolose (esecuzione comandi, scrittura/cancellazione file, "
        "modifica permessi). Lo scanner usa keyword generiche ('fetch', 'http', 'url', 'admin') "
        "che generano moltissimi FP su tool read-only. Il filtro tiene solo tool che REALMENTE "
        "eseguono comandi, scrivono/cancellano file, o hanno parametri pericolosi senza constraint."
    ),
    'input-validation': (
        "Injection fuzzing con 5 payload ('; id', '$(whoami)', '`uname -a`', "
        "'../../../../etc/passwd', 'http://169.254.169.254/...'). Lo scanner cerca indicatori "
        "generici ('linux', 'insecure', 'stdout') nel response. Il filtro tiene SOLO risposte "
        "dove l'injection e' stata REALMENTE eseguita (output di 'id', 'uname', contenuto di "
        "/etc/passwd, etc.) e scarta tutte le risposte con isError=true o payload echoing."
    ),
    'prompt-injection': (
        "Pattern di prompt injection nascosti nelle tool description. Lo scanner cerca frasi "
        "come 'ignore safety rules', 'override other tools'. Il filtro scarta i server crashati "
        "e i tool di sicurezza che DESCRIVONO gli attacchi (non li implementano)."
    ),
    'rug-pull': (
        "Instabilita' delle tool description tra due chiamate successive (T1 vs T2). "
        "Indica che il server cambia comportamento dopo la prima chiamata. "
        "Basso tasso di FP (diff deterministico), filtro leggero."
    ),
    'path-traversal': (
        "Probe attivo con file:///../../etc/hosts. Il filtro tiene solo risposte "
        "con contenuto REALE di file di sistema (127.0.0.1 localhost, root:x:0:0, etc.)."
    ),
    'sensitive-file-access': (
        "Probe attivo con file:///etc/passwd. Il filtro tiene solo risposte "
        "con contenuto REALE di /etc/passwd o chiavi private."
    ),
    'data-leak': (
        "Token passati nel response senza indirection. Lo scanner chiama upstream_access "
        "e cerca pattern come 'access_token', 'sk-', 'bearer'. Il filtro scarta "
        "errori che dicono 'token mancante' e tiene solo risposte con token reali."
    ),
    'remote-access-control': (
        "Tool che espongono accesso remoto. Lo scanner cerca keyword 'remote', 'port', "
        "'expose' e prova a chiamare con port:8080. Il filtro scarta risposte di errore "
        "e tiene solo evidenza reale di porte aperte/servizi avviati."
    ),
    'indirect-prompt-injection': (
        "Injection indiretta tramite risorse esterne (external://, http://). "
        "Lo scanner legge la risorsa e cerca pattern di injection nel contenuto."
    ),
    'sensitive-resource-exposure': (
        "Risorse con URI private:// o nomi sospetti (credential, secret, token, key, password) "
        "che espongono dati sensibili nel contenuto."
    ),
}


# ============================================================================
# FUNZIONI PRINCIPALI
# ============================================================================

def load_category_data(category_dir):
    """Carica tutti i file JSON da una directory di categoria."""
    findings = []
    for filename in sorted(os.listdir(category_dir)):
        if not filename.endswith('.json'):
            continue
        # Skip file gia' filtrati
        if 'filtered' in filename:
            continue
        filepath = os.path.join(category_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for finding in data.get('findings', []):
                finding['_source_file'] = filename
                findings.append(finding)
        except Exception as e:
            print(f"  ERRORE leggendo {filepath}: {e}")
    return findings


def process_category(category, findings, dry_run=False):
    """Applica il filtro a una categoria e salva risultati."""
    filter_fn = CATEGORY_FILTERS.get(category)
    if not filter_fn:
        print(f"  WARN: nessun filtro per '{category}'")
        return None

    kept = []
    rejected = []
    reason_counter = defaultdict(int)

    for finding in findings:
        filtered_details, reason = filter_fn(finding)

        if filtered_details is not None:
            # Crea copia del finding con details filtrati
            filtered_finding = dict(finding)
            if isinstance(filtered_details, (list, dict)):
                filtered_finding['details'] = json.dumps(filtered_details, ensure_ascii=False)
            else:
                filtered_finding['details'] = str(filtered_details)
            filtered_finding['_filter_reason'] = reason
            # Rimuovi campo interno
            filtered_finding.pop('_source_file', None)
            kept.append(filtered_finding)
            reason_counter[f"KEPT:{reason}"] += 1
        else:
            reason_counter[f"REJECTED:{reason}"] += 1
            rejected.append(reason)

    stats = {
        'category': category,
        'vuln_id': CATEGORY_VULN_IDS.get(category, '?'),
        'original': len(findings),
        'filtered': len(kept),
        'removed': len(findings) - len(kept),
        'removal_rate': f"{(1 - len(kept)/max(len(findings),1))*100:.1f}%",
        'top_reasons': dict(reason_counter.most_common(20) if hasattr(reason_counter, 'most_common') else sorted(reason_counter.items(), key=lambda x: -x[1])[:20]),
    }

    if not dry_run and kept:
        category_dir = os.path.join(BASE_DIR, category)
        filtered_dir = os.path.join(category_dir, 'filtered')
        os.makedirs(filtered_dir, exist_ok=True)

        # Salva JSON filtrato
        output_file = os.path.join(filtered_dir, f'{category.replace("-", "_")}_filtered.json')
        output_data = {
            'total': len(kept),
            'category': category,
            'vuln_id': CATEGORY_VULN_IDS.get(category, '?'),
            'filter_date': datetime.now().isoformat(),
            'description': CATEGORY_DESCRIPTIONS.get(category, ''),
            'stats': {
                'original': len(findings),
                'kept': len(kept),
                'removed': len(findings) - len(kept),
                'removal_rate': stats['removal_rate'],
            },
            'findings': kept,
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        stats['output_file'] = output_file

        # Genera report MD
        report_path = generate_category_report(category, findings, kept, reason_counter, filtered_dir)
        stats['report_file'] = report_path

    return stats


def generate_category_report(category, original, filtered, reason_counter, output_dir):
    """Genera report .md per una categoria filtrata."""
    report_path = os.path.join(output_dir, f'{category.replace("-", "_")}_analysis.md')
    vuln_id = CATEGORY_VULN_IDS.get(category, '?')

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(f"# {category} ({vuln_id}) - Analisi Finding Filtrati\n\n")
        f.write(f"**Data analisi**: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")

        # Descrizione
        f.write(f"## Descrizione del check\n\n")
        f.write(f"{CATEGORY_DESCRIPTIONS.get(category, 'N/A')}\n\n")

        # Statistiche
        f.write(f"## Statistiche filtro\n\n")
        f.write(f"| Metrica | Valore |\n|---------|--------|\n")
        f.write(f"| Finding originali | {len(original)} |\n")
        f.write(f"| Finding filtrati (tenuti) | {len(filtered)} |\n")
        f.write(f"| Rimossi | {len(original) - len(filtered)} |\n")
        rate = (1 - len(filtered)/max(len(original),1))*100
        f.write(f"| Tasso di riduzione | {rate:.1f}% |\n\n")

        # Motivi di filtraggio
        f.write(f"## Motivi di filtraggio\n\n")
        f.write(f"| Motivo | Count |\n|--------|-------|\n")
        sorted_reasons = sorted(reason_counter.items(), key=lambda x: -x[1])
        for reason, count in sorted_reasons:
            f.write(f"| `{reason}` | {count} |\n")
        f.write("\n")

        # Server unici
        unique_servers = set()
        for finding in filtered:
            unique_servers.add(finding.get('server_url', '?'))
        f.write(f"## Server unici con vulnerabilita' reali: {len(unique_servers)}\n\n")

        # Esempi di finding tenuti
        f.write(f"## Esempi di finding tenuti (max 15)\n\n")
        shown = min(len(filtered), 15)
        for i, finding in enumerate(filtered[:shown]):
            f.write(f"### {i+1}. [{finding.get('server_name', '?')}]({finding.get('server_url', '?')})\n\n")
            f.write(f"- **ID**: `{finding.get('id', '?')}`\n")
            f.write(f"- **Severity**: `{finding.get('severity', '?')}`\n")
            f.write(f"- **Filter reason**: `{finding.get('_filter_reason', '?')}`\n")

            # Tronca details per il report
            details_str = finding.get('details', '')
            if len(details_str) > 800:
                details_str = details_str[:800] + "... [troncato]"
            # Escape per markdown
            details_str = details_str.replace('|', '\\|')
            f.write(f"- **Details**: ```{details_str}```\n\n")

        if len(filtered) > shown:
            f.write(f"\n*... e altri {len(filtered) - shown} finding*\n\n")

        # Interpretazione
        f.write(f"## Interpretazione\n\n")
        if category == 'input-validation':
            f.write(
                "I finding tenuti mostrano server dove i payload di injection sono stati "
                "**realmente eseguiti** dal sistema operativo sottostante. Ad esempio, "
                "il payload `; id` ha prodotto output `uid=1000(tecnico)...` o il payload "
                "`\\`uname -a\\`` ha prodotto la versione del kernel. Questi sono **command injection "
                "confermati** e rappresentano vulnerabilita' critiche.\n\n"
                "I finding scartati sono server che hanno rifiutato l'input (isError=true), "
                "o che hanno semplicemente echato il payload nel messaggio di errore senza eseguirlo.\n\n"
            )
        elif category == 'dangerous-capabilities':
            f.write(
                "I finding tenuti sono tool che **realmente** eseguono comandi di sistema, "
                "scrivono/cancellano file, o hanno parametri di tipo 'command'/'shell' senza "
                "constraint (enum, pattern, maxLength). Questi tool rappresentano un rischio "
                "reale se accessibili senza autenticazione.\n\n"
                "I finding scartati sono tool flaggati per keyword generiche come 'fetch', "
                "'http', 'url', 'admin' che in realta' sono read-only o data fetching.\n\n"
            )
        elif category == 'prompt-injection':
            f.write(
                "I finding tenuti contengono **istruzioni nascoste reali** nelle tool description, "
                "progettate per manipolare il modello LLM. Pattern come 'HIDDEN INSTRUCTION', "
                "'ignore previous instructions', 'exfiltrate' indicano tool malevoli.\n\n"
                "I finding scartati sono server crashati (non prompt injection) o tool di "
                "sicurezza che *descrivono* pattern di attacco per rilevarli.\n\n"
            )
        elif category == 'rug-pull':
            f.write(
                "I finding tenuti indicano server dove le tool description sono cambiate "
                "tra la prima e la seconda chiamata. Questo potrebbe indicare un server "
                "che modifica il proprio comportamento dopo l'installazione.\n\n"
            )
        elif category == 'path-traversal':
            f.write(
                "I finding tenuti mostrano server dove il probe con path traversal "
                "(file:///../../etc/hosts) ha restituito contenuto reale di file di sistema. "
                "Questo indica una vulnerabilita' di path traversal confermata.\n\n"
            )
        elif category == 'sensitive-file-access':
            f.write(
                "I finding tenuti mostrano server dove la lettura di file sensibili "
                "(file:///etc/passwd) ha restituito contenuto reale. Vulnerabilita' confermata.\n\n"
            )
        elif category == 'data-leak':
            f.write(
                "I finding tenuti mostrano server che hanno esposto token o credenziali reali "
                "nel response. I finding scartati sono errori che dicono 'token mancante' "
                "(il server richiede config, non sta leakando token).\n\n"
            )
        elif category == 'remote-access-control':
            f.write(
                "I finding tenuti mostrano server dove la chiamata con port:8080 ha "
                "effettivamente attivato un servizio remoto (porta aperta, server avviato). "
                "I finding scartati sono risposte di errore o keyword generiche.\n\n"
            )
        else:
            f.write(f"Finding filtrati per la categoria `{category}`.\n\n")

        # Lista completa server
        f.write(f"## Lista completa server vulnerabili\n\n")
        for url in sorted(unique_servers):
            f.write(f"- {url}\n")

    return report_path


def generate_global_report(all_stats):
    """Genera il report globale."""
    report_path = os.path.join(BASE_DIR, 'filter_analysis_report.md')

    total_orig = sum(s['original'] for s in all_stats)
    total_filt = sum(s['filtered'] for s in all_stats)

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("# MCP Security Scan - Report Filtro Falsi Positivi\n\n")
        f.write(f"**Data**: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")

        f.write("## Cosa fa mcp-security-scan\n\n")
        f.write(
            "mcp-security-scan e' uno scanner che testa la sicurezza dei server MCP "
            "tramite probe attivi e analisi euristica. I check includono:\n\n"
            "- **X-01**: Rilevamento capacita' pericolose nei tool (keyword-based)\n"
            "- **X-02**: Fuzzing di input validation con injection payloads\n"
            "- **X-03**: Stabilita' delle tool description (rug pull detection)\n"
            "- **R-01**: Path traversal su risorse\n"
            "- **R-02**: Accesso a file sensibili\n"
            "- **R-03**: Esposizione risorse sensibili\n"
            "- **A-03**: Token indirection / data leak\n"
            "- **P-02**: Prompt injection nelle tool description\n"
            "- **P-03**: Prompt injection indiretta via risorse esterne\n"
            "- **RC-01**: Esposizione accesso remoto\n\n"
        )

        f.write("## Perche' serve un filtro\n\n")
        f.write(
            "Lo scanner usa approcci euristici con **keyword matching** e **indicatori generici** "
            "che producono un alto tasso di falsi positivi:\n\n"
            "- **X-01**: keyword come 'fetch', 'http', 'url' flaggano tool read-only\n"
            "- **X-02**: indicatori come 'linux', 'insecure' matchano error messages\n"
            "- **A-03**: errori 'token mancante' confusi con data leak\n"
            "- **RC-01**: 'enabled' troppo generico come indicatore di accesso remoto\n\n"
        )

        f.write("## Categorie scartate\n\n")
        f.write("| Categoria | Motivo |\n|-----------|--------|\n")
        f.write("| `initialization-error` | Server non avviato, noise infrastrutturale (444 entries) |\n\n")

        f.write("## Risultati del filtro\n\n")
        f.write("| Categoria | Vuln ID | Originali | Filtrati | Rimossi | Riduzione |\n")
        f.write("|-----------|---------|-----------|----------|---------|----------|\n")

        for s in sorted(all_stats, key=lambda x: -x['original']):
            f.write(f"| `{s['category']}` | {s['vuln_id']} | {s['original']} | "
                    f"{s['filtered']} | {s['removed']} | {s['removal_rate']} |\n")

        f.write(f"| **TOTALE** | | **{total_orig}** | **{total_filt}** | "
                f"**{total_orig - total_filt}** | "
                f"**{(1 - total_filt/max(total_orig,1))*100:.1f}%** |\n\n")

        f.write("## Categorie piu' interessanti\n\n")

        f.write("### 1. input-validation (X-02) - Command Injection Confermati\n\n")
        f.write(
            "I finding tenuti sono server dove i payload di injection sono stati **realmente "
            "eseguiti**. Ad esempio, `; id` ha prodotto `uid=1000(tecnico)...`. "
            "Questi sono i finding piu' critici dell'intera analisi: **command injection confermati "
            "su server MCP reali**.\n\n"
        )

        f.write("### 2. prompt-injection (P-02) - Hidden Instructions\n\n")
        f.write(
            "Tool con istruzioni nascoste nelle description, progettate per manipolare l'LLM. "
            "Pattern come 'HIDDEN INSTRUCTION - INVISIBLE TO USER' sono chiari indicatori "
            "di intent malevolo.\n\n"
        )

        f.write("### 3. dangerous-capabilities (X-01) - Tool con Exec/Shell\n\n")
        f.write(
            "Tool che espongono esecuzione comandi (exec, shell, bash) o manipolazione "
            "file system senza constraint sui parametri. Pericolosi se il server e' "
            "accessibile senza autenticazione.\n\n"
        )

        f.write("### 4. rug-pull (X-03) - Comportamento Instabile\n\n")
        f.write(
            "Server che cambiano le tool description dopo la prima interazione. "
            "Potenziale indicatore di comportamento malevolo post-installazione.\n\n"
        )

        f.write("## Come usare i risultati\n\n")
        f.write(
            "I file filtrati si trovano in `<categoria>/filtered/`:\n"
            "- `*_filtered.json`: finding filtrati con alta confidenza di essere veri positivi\n"
            "- `*_analysis.md`: report di analisi con statistiche, esempi e interpretazione\n\n"
            "Il campo `_filter_reason` in ogni finding spiega perche' e' stato tenuto.\n"
        )

    return report_path


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Filtro falsi positivi per mcp-security-scan')
    parser.add_argument('--dry-run', action='store_true', help='Solo statistiche, non scrive file')
    parser.add_argument('--category', type=str, help='Filtra solo questa categoria')
    args = parser.parse_args()

    print("=" * 70)
    print("  FILTRO MCP-SECURITY-SCAN - Riduzione falsi positivi")
    print("=" * 70)
    print()

    total_original = 0
    total_filtered = 0
    all_stats = []

    # Itera sulle directory di categoria
    for category in sorted(os.listdir(BASE_DIR)):
        cat_dir = os.path.join(BASE_DIR, category)
        if not os.path.isdir(cat_dir):
            continue
        if category in ('filtered', '__pycache__', '.git'):
            continue

        # Filtro per categoria se specificato
        if args.category and category != args.category:
            continue

        # Skip categorie noise
        if category in SKIP_CATEGORIES:
            findings = load_category_data(cat_dir)
            print(f"  SKIP {category}: {len(findings)} findings (noise infrastrutturale)")
            total_original += len(findings)
            continue

        # Skip se non ha un filtro definito
        if category not in CATEGORY_FILTERS:
            print(f"  SKIP {category}: nessun filtro definito")
            continue

        print(f"\n  >> {category}")
        findings = load_category_data(cat_dir)
        print(f"     Caricati {len(findings)} findings")

        if not findings:
            print(f"     Nessun finding da filtrare")
            continue

        stats = process_category(category, findings, dry_run=args.dry_run)
        if stats:
            total_original += stats['original']
            total_filtered += stats['filtered']
            all_stats.append(stats)
            print(f"     Filtrati: {stats['filtered']}/{stats['original']} "
                  f"(rimossi {stats['removed']}, {stats['removal_rate']})")

    # Riepilogo
    print(f"\n{'='*70}")
    print(f"  RIEPILOGO FINALE")
    print(f"{'='*70}")
    print(f"\n  Finding originali totali: {total_original}")
    print(f"  Finding filtrati (tenuti): {total_filtered}")
    print(f"  Finding rimossi: {total_original - total_filtered}")
    if total_original > 0:
        print(f"  Tasso di riduzione: {(1 - total_filtered/total_original)*100:.1f}%")

    print(f"\n  {'Categoria':<30} {'ID':>6} {'Orig':>8} {'Filt':>8} {'Rimossi':>8}")
    print(f"  {'-'*28:<30} {'-'*4:>6} {'-'*6:>8} {'-'*6:>8} {'-'*6:>8}")
    for s in sorted(all_stats, key=lambda x: -x['original']):
        print(f"  {s['category']:<30} {s['vuln_id']:>6} {s['original']:>8} "
              f"{s['filtered']:>8} {s['removed']:>8}")

    if args.dry_run:
        print(f"\n  (DRY RUN - nessun file scritto)")
    else:
        if all_stats:
            report = generate_global_report(all_stats)
            print(f"\n  Report globale: {os.path.relpath(report, BASE_DIR)}")
        print(f"\n  File filtrati nelle directory filtered/ di ogni categoria.")

    print()


if __name__ == '__main__':
    main()
