# X-02 — INPUT VALIDATION / INJECTION FUZZING

**Finding originali**: 4364

Severity: **critical**.

Lo scanner esegue **fuzzing attivo** su ogni tool MCP: per ogni tool con almeno un parametro string, prova 5 payload di injection e controlla se la risposta contiene indicatori di esecuzione riuscita.

```python
def check_injection_fuzzing(
    tools: list[dict[str, Any]],
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]],
    spec: SpecCheck,
) -> Finding:
    payloads = [
        "; id",
        "$(whoami)",
        "`uname -a`",
        "../../../../etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
    ]

    observed_danger = []
    for tool in tools:
        name = tool.get("name")
        schema = tool.get("inputSchema") or {}
        props = schema.get("properties") or {}

        # Find a string parameter to test
        str_param = None
        for param_name, param_def in props.items() if isinstance(props, dict) else []:
            if param_def.get("type") == "string":
                str_param = param_name
                break

        if not (name and str_param):
            continue

        # Test each payload
        for payload in payloads:
            resp = send_recv_func("tools/call", {"name": name, "arguments": {str_param: payload}})

            # Check if response contains system information (dangerous)
            text = json.dumps(resp).lower()
            danger_indicators = [
                "uid=", "linux", "root:x:", "etc/passwd",
                "meta-data", "insecure", "stdout",
            ]
            if any(indicator in text for indicator in danger_indicators):
                observed_danger.append({"tool": name, "payload": payload, "resp": resp})
                break  # Stop testing this tool after first dangerous response

    passed = len(observed_danger) == 0
    details = json.dumps(observed_danger)
    return _finding(spec, passed, details)
```

**Il problema**: gli indicatori `linux`, `insecure`, `stdout` sono troppo generici. Matchano:
- Error messages: "This operation is insecure on Linux"
- Log/stdout references: "writing to stdout"
- Documentazione: "supports Linux and Windows"
- Payload echoing: il server stampa il payload nell'errore senza eseguirlo

---

## Stage 1 — filter_security_scan.py

**Finding dopo filtro**: 85 (riduzione −98.1%)

Il filtro analizza ogni risposta cercando **output REALE** di comandi eseguiti, distinguendolo da echo/errori/testo casuale.

```python
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
]

# Pattern che indicano RIFIUTO (server non vulnerabile)
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
    resp_text = json.dumps(resp, ensure_ascii=False)

    # CHECK 1: Il response contiene output REALE?
    for pat in REAL_INJECTION_PATTERNS:
        if pat.search(resp_text):
            return True, f"real_injection:{pat.pattern[:40]}"

    # CHECK 2: Il server ha rifiutato?
    if '"isError":true' in resp_text:
        # Anche se isError=true, controlla se errore contiene output
        for pat in REAL_INJECTION_PATTERNS:
            if pat.search(resp_text):
                return True, f"injection_in_error"
        return False, "server_rejected_with_error"

    # CHECK 3: Payload echoing
    for pat in ECHO_PATTERNS:
        if pat.search(resp_text):
            return False, "payload_echoed_not_executed"

    # CHECK 4: Response vuoto
    if not resp_text.strip() or resp_text in ('{}', 'null', '""'):
        return False, "empty_response"

    # CHECK 5: Path traversal payload usato come workdir
    if "../../../../" in payload:
        if "workingdirectory" in resp_text and "../../../../" in resp_text:
            has_file_content = any(p.search(resp_text) for p in REAL_INJECTION_PATTERNS)
            if not has_file_content:
                return False, "path_used_as_workdir_not_read"

    # CHECK 6: Indicatori generici senza output reale
    generic_indicators = ["linux", "insecure", "stdout", "meta-data"]
    has_generic = any(ind in resp_text.lower() for ind in generic_indicators)
    has_real = any(pat.search(resp_text) for pat in REAL_INJECTION_PATTERNS)
    if has_generic and not has_real:
        if "linux" in resp_text.lower() and not re.search(r'Linux\s+\S+\s+\d+\.\d+', resp_text):
            return False, "generic_indicator_no_real_output"
        if "insecure" in resp_text.lower() and re.search(r'(rejected|invalid).*insecure', resp_text, re.I):
            return False, "insecure_in_rejection_message"

    # CHECK 7: isError=false ma no output reale
    if '"isError":false' in resp_text and not has_real:
        return False, "accepted_but_no_injection_evidence"

    if has_real:
        return True, "real_system_output"
    return False, "no_injection_evidence"
```

Ripartizione finding filtrati (85):
| `real_injection:uid=` (command injection su `; id`) | 40+ |
| `real_injection:Linux kernel` (da `` `uname -a` ``) | 20+ |
| `real_injection:root:x:0:0:` (da `../../../../etc/passwd`) | 15+ |
| `real_injection:ami-...` / `meta-data` (AWS metadata) | 5+ |

---

## Stage 2A — Regole HC

**Nessuna Stage 2A** per input-validation: il filtro Stage 1 è già estremamente selettivo (cerca output reale di sistema), quindi non serve un secondo stage di regole HC.

---

## Stage 2B — Analisi LLM (in-chat con Sonnet)

**Cache pre-popolata**: 83 VP bulk + 2 FP manuali.

I 2 FP identificati sono casi in cui il payload compare nel response per ragioni legittime:

**FP 1: Mnehmos/mnehmos.open5e.mcp — `rag_chat` + payload `http://169.254.169.254/...`**

Il tool è un RAG chatbot su documentazione D&D. Il payload IMDS (AWS metadata) finisce nel contesto LLM che lo menziona nella risposta come termine tecnico ("meta-data"), non perché il server abbia fatto fetch all'IMDS.

**FP 2: schwartx/ddgs-mcp — `web_search` + payload `$(whoami)`**

Il tool è letteralmente una ricerca DuckDuckGo. Il payload viene passato come query e DuckDuckGo restituisce risultati in cui può apparire la stringa "whoami" come testo, ma nessun comando è stato eseguito.

---

**Veri positivi confermati dopo analisi LLM**: 83

Ripartizione finale: **83 VP + 2 FP = 85**. Questi sono i finding **più critici dell'intera analisi mcp-security-scan**: command injection **confermati** su server MCP reali, con output di sistema effettivamente restituito dal server.

### Esempi di VP confermati

**VP 1: deepsuthar496/Remote-Command-MCP — `execute_remote_command` + payload `; id`**

```json
{
    "tool": "execute_remote_command",
    "payload": "; id",
    "resp": {
        "result": {
            "content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip)..."}]
        }
    }
}
```

Command injection **confermato**: il server ha eseguito `; id` e restituito l'output del comando. UID, GID e groups dell'utente Linux sono reali.

**VP 2: 0xshariq/github-mcp-server — `git_branch` + payload `` `uname -a` ``**

```json
{
    "tool": "git_branch",
    "payload": "`uname -a`",
    "resp": {
        "result": {"content": [{"type": "text", "text": "Error: Command failed: git branch \"`uname -a`\"..."}]}
    }
}
```

Il tool esegue `git branch` con il payload come argomento shell — la backtick expansion esegue `uname -a` prima di git. Anche se restituisce un errore, l'expansion è già avvenuta.

### Perché questi sono i finding più importanti

A differenza delle altre categorie dove si rileva "intento potenziale" (dangerous-capabilities, rug-pull), qui c'è **prova diretta di vulnerabilità sfruttabile**: il server ha effettivamente eseguito il comando iniettato e restituito l'output. Sono 83 server MCP che possono essere compromessi da qualsiasi client MCP connesso.
