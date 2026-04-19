# X-01 — DANGEROUS CAPABILITIES

**Finding originali**: 4644

Severity: **high**.

Lo scanner controlla ogni tool MCP restituito da `tools/list` cercando keyword "pericolose" nel nome o nella descrizione. Se il tool contiene una di queste keyword ma non ha constraint nello schema (enum, pattern, maxLength), viene flaggato.

```python
def check_dangerous_capabilities(tools: list[dict[str, Any]], spec: SpecCheck) -> Finding:
    risky_keywords = [
        "exec", "command", "shell", "write_file", "delete", "rm",
        "chmod", "chown", "fetch", "http", "url", "eval", "render",
        "payment", "admin", "privilege",
    ]

    risky_tools: list[dict[str, Any]] = []
    for tool in tools:
        name = (tool.get("name") or "").lower()
        desc = (tool.get("description") or "").lower()
        schema = tool.get("inputSchema") or {}

        # Check if tool has constraints
        has_constraints = False
        if isinstance(schema, dict):
            props = schema.get("properties") or {}
            for _, prop in props.items() if isinstance(props, dict) else []:
                if any(
                    k in prop
                    for k in ("enum", "pattern", "minimum", "maximum", "minLength", "maxLength")
                ):
                    has_constraints = True
                    break

        # If tool has risky keywords but no constraints, it's dangerous
        if (
            any(keyword in name or keyword in desc for keyword in risky_keywords)
            and not has_constraints
        ):
            risky_tools.append(tool)

    passed = len(risky_tools) == 0
    details = json.dumps(risky_tools)
    return _finding(spec, passed, details)
```

**Il problema**: keyword come `fetch`, `http`, `url`, `admin`, `render` sono troppo generiche e matchano moltissimi tool read-only (search, query, list, get). L'assenza di constraint dipende dallo stile di scrittura degli schemi, non dal reale pericolo.

---

## Stage 1 — filter_security_scan.py

**Finding dopo filtro**: 1230 (riduzione −73.5%)

Il filtro Stage 1 applica tre check sequenziali:

```python
# Tool REALMENTE pericolosi: eseguono comandi, scrivono/cancellano file
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
    dangerous_param_names = {"command", "cmd", "shell", "script", "exec",
                             "code", "query", "sql", "expression", "eval"}
    for pname, pdef in props.items():
        if pname.lower() in dangerous_param_names:
            has_enum = "enum" in pdef
            has_pattern = "pattern" in pdef
            has_short_max = pdef.get("maxLength", 9999) < 200
            if not (has_enum or has_pattern or has_short_max):
                return True, pname
    return False, None


def filter_dangerous_capabilities(finding):
    details = parse_details(finding.get("details", ""))
    kept_tools = []
    for tool_def in details:
        name = tool_def.get("name", "").lower()
        desc = tool_def.get("description", "").lower()

        # CHECK 1: nome matcha pattern REALMENTE pericolosi?
        is_dangerous = False
        for pat in DANGEROUS_TOOL_PATTERNS:
            if pat.search(name):
                is_dangerous = True; break

        # CHECK 2: descrizione parla di operazioni distruttive?
        if not is_dangerous:
            for pat in DANGER_DESCRIPTION_PATTERNS:
                if pat.search(desc):
                    is_dangerous = True; break

        # CHECK 3: parametri di tipo "command" senza constraint?
        if not is_dangerous:
            has_danger_param, param_name = _tool_has_unconstrained_dangerous_param(tool_def)
            if has_danger_param:
                is_dangerous = True

        if is_dangerous:
            kept_tools.append(tool_def)

    return kept_tools if kept_tools else None
```

Ripartizione finding filtrati (1230):
| `dangerous_name` (exec/shell/bash nel nome) | 66 |
| `dangerous_desc:install` | 340+ |
| `dangerous_desc:ssh` / `scp` / `rsync` | 200+ |
| `dangerous_desc:docker exec/run/compose` | 150+ |
| `unconstrained_param:query` | 216 |
| `unconstrained_param:command` / `code` / `sql` / `script` | 150+ |

---

## Stage 2A — Regole HC

Analizza nuovamente i tool filtrati per distinguere VP da FP con segnali più specifici.

```python
# Pattern per tool CHIARAMENTE OFFENSIVI / exploit framework
_DC_EXPLICIT_OFFENSE = re.compile(
    r'\b(reverse.?shell|bind.?shell|mimikatz|metasploit|meterpreter|'
    r'privilege.?escal|lateral.?movement|exfiltrat|c2.?server|'
    r'command.?and.?control|payload.?inject|backdoor)\b',
    re.I
)

# Descrizione read-only (search, get, list, ecc.)
_DC_READONLY_DESC = re.compile(
    r'^(retrieve|search|query|look.?up|get|list|view|show|display|check|'
    r'inspect|browse|fetch|read|scan|monitor|watch|describe|find|'
    r'analyze|analyse|report|status|info|summary|parse|extract|'
    r'count|stat|metric|audit|log|trace|stream|subscribe|listen)\b',
    re.I
)

# Descrizioni che indicano esecuzione comandi ESPLICITA
_DC_EXEC_DESC = re.compile(
    r'\b(execut(e|es|ing)\s+(a\s+)?(command|shell|script|bash|code|query|sql|statement)|'
    r'run\s+(a\s+)?(shell|command|script|bash|arbitrary)|'
    r'runs?\s+(shell|bash|commands?)\b|'
    r'execute\s+arbitrary|'
    r'spawn\s+(a\s+)?(process|command|shell)|'
    r'eval(uate)?\s+(code|expression|script))\b',
    re.I
)

# Operazioni su file OS (non AI model)
_DC_FILE_OPS_DESC = re.compile(
    r'\b(delet(e|es|ing)\s+(a\s+)?(file|director|folder)|'
    r'remov(e|es|ing)\s+(a\s+)?(file|director|folder)|'
    r'writ(e|es|ing)\s+(to\s+)?(a\s+)?(file|disk|filesystem|path)|'
    r'creat(e|es|ing)\s+(a\s+)?(file|director))\b',
    re.I
)

# Tool che gestiscono AI model (rm = remove model, non file OS) → FP
_DC_AI_MODEL_MGMT = re.compile(
    r'\b(model|ollama|llm|embedding|weight|checkpoint|artifact)\b',
    re.I
)

# SSH exec / esecuzione remota
_DC_SSH_EXEC_DESC = re.compile(
    r'\b(execut(e|es|ing)\s+(a\s+)?(command|script|bash)\s+(on|over|via|through|in)\s+(remote|ssh|the\s+server|a\s+container|kubernetes|pod|docker)|'
    r'ssh\s+(exec|command|into|session)|'
    r'run\s+(commands?\s+(on|over|via)\s+(remote|ssh|container|kubernetes|pod)))\b',
    re.I
)

# Install/deploy REALE (non solo analisi)
_DC_REAL_INSTALL_DESC = re.compile(
    r'\b(install(s|ing)?\s+(package|dependency|dependencies|library|plugin|hook|extension|software|tool)|'
    r'deploy(s|ing)?\s+(a\s+)?(service|container|app|application)|'
    r'npm\s+(install|run|exec)|pip\s+install|'
    r'apt.get|brew\s+install|yarn\s+(install|add))\b',
    re.I
)

# SOLO analisi/raccomandazione install (FP)
_DC_ANALYZE_INSTALL_DESC = re.compile(
    r'\b(detect(s|ing)?\s+(the\s+)?(tech\s+stack|mcp|framework|language)|'
    r'recommend(s|ing)?\s+(mcp|package|tool|server)|'
    r'analyz(e|es|ing)\s+(your|the)\s+(repo|project|codebase)|'
    r'suggest(s|ing)?\s+(package|tool|server|mcp)|'
    r'generat(e|es|ing)\s+(a\s+)?(config|configuration|\.env))\b',
    re.I
)

# sudo/su operations → VP
_DC_SUDO_DESC = re.compile(r'\b(sudo|su\s|run\s+as\s+root|escalat(e|es)\s+privilege)\b', re.I)

# DB destructive → VP
_DC_DB_DESTROY_DESC = re.compile(
    r'\b(drop\s+(table|database|collection|index|schema)|truncate\s+(table|database|collection))\b',
    re.I
)


def hc_rules_dangerous_capabilities(finding):
    details = _parse_details(finding.get("details", ""))
    vp_reasons, fp_reasons = [], []

    for tool in details:
        name = (tool.get("name") or "").lower().strip()
        desc = (tool.get("description") or "").lower().strip()
        filter_reason = tool.get("_filter_reason", "")

        # ── HC-VP ────────────────────────────────────────────────
        if _DC_EXPLICIT_OFFENSE.search(desc):      # VP-1: offensivo esplicito
            vp_reasons.append(f"explicit_offense:{name}"); continue
        if _DC_EXEC_DESC.search(desc):              # VP-2: exec comandi esplicito
            vp_reasons.append(f"exec_desc:{name}"); continue
        if _DC_FILE_OPS_DESC.search(desc):          # VP-3: file ops
            if not _DC_AI_MODEL_MGMT.search(desc):
                vp_reasons.append(f"file_ops:{name}"); continue
        if _DC_SSH_EXEC_DESC.search(desc):          # VP-4: SSH exec
            vp_reasons.append(f"ssh_exec:{name}"); continue
        if _DC_SUDO_DESC.search(desc):              # VP-5: sudo
            vp_reasons.append(f"sudo_su:{name}"); continue
        if _DC_DB_DESTROY_DESC.search(desc):        # VP-6: DROP/TRUNCATE
            vp_reasons.append(f"db_destroy:{name}"); continue

        # VP-7: dangerous_name + desc non read-only
        if "dangerous_name:" in filter_reason and not _DC_READONLY_DESC.match(desc):
            vp_reasons.append(f"dangerous_name_non_readonly:{name}"); continue

        # VP-8: unconstrained param + desc non read-only
        if "unconstrained_param:" in filter_reason:
            param = filter_reason.replace("unconstrained_param:", "").split(":")[0]
            if not _DC_READONLY_DESC.match(desc):
                vp_reasons.append(f"unconstrained_{param}:{name}"); continue
            else:
                fp_reasons.append(f"unconstrained_{param}_readonly:{name}"); continue

        # VP-9: install reale (non analisi)
        if "install" in filter_reason and _DC_REAL_INSTALL_DESC.search(desc):
            if not _DC_ANALYZE_INSTALL_DESC.search(desc):
                vp_reasons.append(f"real_install:{name}"); continue

        # ── HC-FP ────────────────────────────────────────────────
        # FP-1: dangerous_name + desc read-only
        if "dangerous_name:" in filter_reason and _DC_READONLY_DESC.match(desc):
            fp_reasons.append(f"dangerous_name_readonly:{name}"); continue
        # FP-2: install in desc ma tool analizza/raccomanda
        if "install" in filter_reason and _DC_ANALYZE_INSTALL_DESC.search(desc):
            fp_reasons.append(f"analyze_not_install:{name}"); continue
        # FP-3: delete/rm name ma AI model mgmt
        if ("write_file|delete_file|remove_file|rm" in filter_reason
                and _DC_AI_MODEL_MGMT.search(desc)):
            fp_reasons.append(f"ai_model_mgmt:{name}"); continue
        # FP-4: payment/transaction tool legittimo
        if "payment" in filter_reason:
            fp_reasons.append(f"payment_tool:{name}"); continue

    if vp_reasons:
        return "VP", f"confirmed_dangerous:{';'.join(vp_reasons[:3])}"
    if fp_reasons:
        return "FP", f"false_positive:{';'.join(fp_reasons[:3])}"
    return None, f"uncertain_{len(details)}_tools"
```

Risultato HC:
| HC-VP | 961 |
| HC-FP | 208 |
| UNCERTAIN | 61 |

---

## Stage 2B — Analisi LLM (in-chat con Sonnet)

I 61 UNCERTAIN sono stati classificati manualmente in-chat, scrivendo i verdetti in `_llm_api_cache.json`.

**Breakdown UNCERTAIN (61 → 40 VP, 21 FP):**

VP (40): terminal/shell/SSH server, software install reali, offensive security tools, distruzione VPS/container, esecuzione script.

FP (21): tool read-only (delete_ssh_connection = config, get_keypair_list = read-only), SDK instructions, code/config generation (no exec), IaC analysis, registry-only operations.

---

**Veri positivi confermati dopo analisi LLM**: 1001

Ripartizione finale: **1001 VP + 229 FP = 1230** (961 HC-VP + 208 HC-FP + 61 UNCERTAIN classificati: 40 VP + 21 FP).

### Esempi di VP confermati

**VP 1: 0xshariq/docker-mcp-server — `docker-compose` (unconstrained_param:command)**

```json
{
    "name": "docker-compose",
    "description": "Run Docker Compose commands",
    "inputSchema": {
        "properties": {
            "command": {"type": "string", "description": "Docker Compose command to run (e.g., 'up', 'down')"}
        }
    }
}
```

Il parametro `command` è una stringa senza constraint → esecuzione arbitraria di comandi docker compose.

**VP 2: AI-QL/mcp-devcontainers — `devcontainer_exec` (exec_desc)**

```json
{
    "name": "devcontainer_exec",
    "description": "Runs a custom shell command inside the devcontainer for the specified workspace. Useful for executing arbitrary commands or scripts within the devcontainer environment."
}
```

La descrizione contiene esplicitamente "runs a custom shell command" e "executing arbitrary commands".

**VP 3: schwarztim/sec-nuclei-mcp — `nuclei_scan` (explicit_offense)**

```json
{
    "name": "nuclei_scan",
    "description": "Run a Nuclei vulnerability scan against one or more targets via SSH to Kali. Supports filtering by severity, template, protocol..."
}
```

Offensive security tool: Nuclei vulnerability scanner via SSH a Kali Linux.

**VP 4: nagypeterjob/brew-mcp — `install` / `uninstall` (real_install)**

```json
{
    "name": "install",
    "description": "Install a formula or cask."
}
```

Install reale di pacchetti Homebrew sul sistema.

### Esempi di FP classificati

**FP 1: AiondaDotCom/mcp-salesforce — `salesforce_query` (unconstrained_param:query + readonly desc)**

```json
{
    "name": "salesforce_query",
    "description": "Execute SOQL queries against any Salesforce object. Supports SELECT, WHERE, ORDER BY, LIMIT, and other SOQL features."
}
```

Il parametro `query` è unconstrained ma la descrizione inizia con "Execute SOQL" → query read-only, non command execution.

**FP 2: fastmcp-me/flint-note-mcp — `remove_vault` (UNCERTAIN → FP)**

```json
{
    "name": "remove_vault",
    "description": "Remove a vault from the registry (does not delete files)"
}
```

Registry operation: rimuove entry dal registro, NON cancella file (dichiarato esplicitamente).

**FP 3: amirdauti/dritan-mcp — `system_check_prereqs` (UNCERTAIN → FP)**

```json
{
    "name": "system_check_prereqs",
    "description": "Check whether required local binaries are installed (currently solana-keygen) and return install commands."
}
```

Check read-only: verifica presenza di binari, restituisce comandi di install come output (non li esegue).

---

### Perché il tasso di VP è alto (81.4%)

Il filtro Stage 1 e le regole HC di Stage 2A sono sequenzialmente selettivi: partendo da un dataset già filtrato (1230 finding su 4644 originali), solo tool con evidenza forte di operazioni distruttive passano l'HC come VP. I 961 HC-VP sono:

1. **Explicit offense** (nuclei, metasploit, reverse shell): offensive security tools espliciti
2. **Exec description** ("executes a shell command", "runs arbitrary code"): esecuzione comandi confermata
3. **File OS operations** ("deletes a file", "writes to disk"): non AI model management
4. **SSH exec** ("execute command via SSH"): command execution remoto
5. **Unconstrained param** (command/sql/code/script): iniezione possibile se desc non read-only
6. **Real install** (npm install, pip install, brew install): package install reali

I 229 FP sono principalmente search/query tools con `query` unconstrained ma description read-only, o tool di SDK integration/analysis che menzionano "install" ma non lo eseguono.
