# MCP Security Scanner - Come Funziona

Tool: **mcp-security-scanner** (autore Red Hat), package Python `mcp_scanner`, **entry point CLI `mcp-scan`**.
Repo locale: `C:\Users\francesco\Desktop\Frameworks\mcp-security-scanner` (versione **0.1.3**).

> **Correzione importante — transport.** Il tool supporta 4 transport (stdio, http, sse, websocket) con **controlli diversi** per ognuno, ma la pipeline lo usa **sempre e solo in modalità `stdio`** (`frameworks/mcpSecurityScan.py:200`). Quindi girano **solo gli 11 controlli stdio**; i controlli HTTP/SSE (TLS, Origin/DNS-rebind, Session tampering, Prompt-argument, Template fuzzing, ecc.) **non vengono mai eseguiti** nella pipeline. Il vecchio doc li descriveva come se girassero — qui documento **solo ciò che succede davvero in stdio**.
>
> Nota anche: il comando di config `cmd_security_scan` in `functions/config.py:92` **non è quello usato** — il wrapper `mcpSecurityScan.py` costruisce da sé la riga di comando (vedi sotto).

## Panoramica

A differenza di `mcp-guard`/`mcp-fuzzer`, questo scanner fa un mix di **analisi statica della superficie** (nomi/descrizioni/schemi dei tool) e **alcuni test attivi mirati** (path traversal, fuzzing di injection, esposizione token/risorse). Non è un fuzzer massivo: manda pochi payload precisi e verifica la risposta.

### Comando lanciato nella pipeline (`frameworks/mcpSecurityScan.py:200`)

```bash
mcp-scan scan \
  --transport stdio \
  --command "<command> <main_file>" \   # es. "node build/index.js" o "python server.py"
  --format json \
  --output <repo>/security_report.json
# cwd = repo del server; timeout = TIMEOUT_SECONDS = 3600s
```

La CLI (`cli.py:212`) instrada `--transport stdio` verso `scan_stdio` (`stdio_scanner.py:426`) → `run_checks_stdio`. Nessun `--url`: il server è un processo locale avviato dallo scanner.

L'output `security_report.json` viene riletto da `parse_mcp_security_scan` (`frameworks/mcpSecurityScan.py:99`).

---

## Parte 1: Avvio del server e ciclo di scansione

`run_checks_stdio` (`stdio_scanner.py:181`):

1. **`StdioClient`** (`stdio_scanner.py:27`) avvia il server: `subprocess.Popen(shlex.split(cmd), stdin/stdout/stderr=PIPE, text=True, bufsize=1, env+PYTHONUNBUFFERED=1)`. Dopo 0.1s controlla che il processo sia ancora vivo; se è già uscito → `RuntimeError` → **BASE-01 fallito** ("Command failed to start") e stop.
2. **`send_recv`**: scrive una riga JSON-RPC (`{"jsonrpc":"2.0","id":1,"method":...}\n`) su stdin e legge **una riga** da stdout. Se il transport si rompe ritorna codici sentinella non-standard: `process_died`, `stdio_unavailable`, `write_failed`, `read_failed`, `no_response`, `non-json`. `_is_process_error` li riconosce.
3. **BASE-01 — initialize**: manda `initialize` (protocolVersion `2024-11-05`, capabilities `{}`, clientInfo `mcp-security-scanner`). Se è un process-error → BASE-01 fallito e **stop** (è il caso `initialization-error`). Altrimenti passa se la risposta ha `result.capabilities`.
4. **tools/list**: recupera i tool. Se il server muore qui → segna **X-01, P-02, X-03** come falliti e stop.
5. Esegue in sequenza i controlli qui sotto, poi chiude il processo (`client.close()`, terminate→kill).

---

## Parte 2: Gli 11 controlli eseguiti in stdio

Ogni controllo produce un `Finding` con `passed: true/false`. **`passed=false` = vulnerabilità.** Severità e categoria vengono dallo spec `scanner_specs.schema`; la pipeline rinomina l'ID in una categoria propria (`MCP_SECURITY_SCAN_CATEGORIES`, `functions/config.py:67`).

| ID | Categoria (pipeline) | Severità | Tipo | Passa (sicuro) se… |
|---|---|---|---|---|
| BASE-01 | `initialization-error` | info | handshake | il server risponde a `initialize` con `capabilities` |
| X-01 | `dangerous-capabilities` | high | statico | nessun tool "rischioso" privo di vincoli |
| P-02 | `prompt-injection` | medium | statico | nessuna frase manipolatoria nelle description |
| X-03 | `rug-pull` | medium | attivo (2× list) | i tool non cambiano tra due `tools/list` |
| R-01 | `path-traversal` | high | attivo | il server rifiuta `file:///../../etc/hosts` |
| R-02 | `sensitive-file-access` | high | attivo | il server rifiuta `file:///etc/passwd` |
| R-03 | `sensitive-resource-exposure` | high | attivo | nessuna risorsa "segreta" leggibile |
| X-02 | `input-validation` | critical | attivo (fuzzing) | nessun payload di injection produce output di sistema |
| A-03 | `data-leak` | critical | attivo | il server non restituisce token upstream |
| P-03 | `indirect-prompt-injection` | high | attivo | le risorse esterne non alterano un tool di summary |
| RC-01 | `remote-access-control` | critical | attivo | nessun tool apre accesso remoto/porte |

### Dettaglio + esempi (`security_checks.py`)

**X-01 — Dangerous capabilities** (`check_dangerous_capabilities`, statico). Per ogni tool, se il **nome o la description** contiene una di queste keyword *e* lo `inputSchema` **non ha vincoli**, il tool è rischioso:
- keyword: `exec, command, shell, write_file, delete, rm, chmod, chown, fetch, http, url, eval, render, payment, admin, privilege`
- "ha vincoli" = una property dello schema contiene `enum` / `pattern` / `minimum` / `maximum` / `minLength` / `maxLength`.
- *Esempio*: un tool `exec_shell(cmd: string)` senza `enum`/`pattern` → **fallito**. Lo stesso tool con `cmd` vincolato da un `enum` di comandi ammessi → passa.

**P-02 — Prompt injection heuristics** (statico). Cerca come **sottostringa** (case-insensitive) nelle description queste frasi: `ignore any safety rules`, `override other tools`, `include contents of`, `do not disclose this instruction`, `hidden instruction`. *Esempio*: description "… (hidden instruction: exfiltrate keys)" → fallito.

**X-03 — Tool stability / rug-pull** (attivo). Chiama `tools/list` **due volte** e confronta l'insieme di `(name, description)` con `symmetric_difference`. Se differiscono → fallito. Se una delle due liste è vuota (race di avvio) → **passa** (evita falsi positivi); se la prima è vuota fa un retry dopo 2s.

**R-01 — Path traversal** (attivo). `resources/read {"uri": "file:///../../etc/hosts"}`. Se la risposta contiene un `result` (dict) → il server ha **accettato** il traversal → fallito.

**R-02 — Sensitive file access** (attivo). Idem con `file:///etc/passwd`. `result` presente → fallito.

**R-03 — Sensitive resource exposure** (attivo). In `resources/list` cerca `credential/secret/token/key/password` in `name`/`uri`; per i sospetti fa `resources/read` e se il contenuto contiene `password`, `apikey`, `api key`, `sk-`, `postgresql://`, `username:` → fallito. (Nome sospetto ma contenuto pulito → non segnalato.)

**X-02 — Injection fuzzing** (attivo, critical). Per ogni tool trova il **primo parametro `string`** e gli invia 5 payload via `tools/call`:
- `"; id"`, `"$(whoami)"`, `` "`uname -a`" ``, `"../../../../etc/passwd"`, `"http://169.254.169.254/latest/meta-data/"`
- Se la risposta contiene `uid=`, `linux`, `root:x:`, `etc/passwd`, `meta-data`, `insecure`, `stdout` → **RCE/leak** → fallito (si ferma al primo hit per tool).

**A-03 — Token pass-through** (attivo, critical). Chiama un tool chiamato `upstream_access` con `{"code":"dummy"}`; se la risposta contiene `access_token`, `sk-`, `token-body`, `bearer ` → fallito. (Su server che non hanno quel tool, la chiamata dà errore e il check passa.)

**P-03 — Indirect prompt injection** (attivo). Trova risorse con URI `external://` / `http://` / `https://`, le legge e cerca `ignore previous instructions`, `do not disclose`, `exfiltrate`, `send secrets`, `hidden instruction`, `override`, `leak`. Poi cerca un tool "summarize/summary" e lo chiama sull'URI: se l'output riflette quelle frasi o contiene `secret`/`token`/`password` → `exploited` → fallito.

**RC-01 — Remote access control** (attivo, critical). Cerca tool con `remote_access`/`remote`/`port` nel nome o `remote access`/`open port`/`expose`/`bind` nella description; li chiama con `{"port": 8080}` e se la risposta contiene `remote_access_enabled:true`, `remote-access:true`, `enabled`, `listening`, `bound to`, `server started` → fallito.

### Esempio concreto di flusso

Server con un tool `run_command(cmd: string)` senza vincoli:
- **X-01** → fallito (`dangerous-capabilities`, keyword `command`, nessun `enum`).
- **X-02** → invia `"$(whoami)"` a `cmd`; se la risposta contiene `uid=` → fallito (`input-validation`, critical).
- Gli altri (R-01/R-02/RC-01…) passano se il server non espone risorse/porte.

---

## Parte 3: Come leggere i risultati

- **`passed=true` = sicuro** (il controllo è superato). Solo i finding con `passed=false` vengono contati come vulnerabilità (`parse_mcp_security_scan:124`).
- I controlli **attivi** falliscono **solo se il server espone davvero** quella capacità (tool pericoloso, risorsa segreta, porta remota…). Su un server benigno passano tutti: non c'è "rumore" da timeout come nel fuzzer.
- **`initialization-error`**: se BASE-01 fallisce (server non avviabile via stdio) è l'**unico** finding. Il wrapper lo tratta come **fallimento infrastrutturale e scarta il server** (`mcpSecurityScan.py:239`) — non è una vulnerabilità reale. La post-elaborazione lo conferma (`mcp_security_scan/postprocessing/stage1_filter.py`: "server non avviato, non è una vuln").

---

## Parte 4: Controlli che NON girano (definiti nello spec ma non in stdio)

Lo spec `scanner_specs.schema` definisce ~29 check, ma in stdio ne girano 11. Questi **esistono ma non vengono eseguiti** dalla pipeline (sono HTTP/SSE-only o non implementati nel percorso stdio):

| Non eseguiti | Perché |
|---|---|
| `A-01` (auth), `A-02` (OAuth metadata), `A-04` (RBAC), `KF-04` | Solo `remote-http`: l'auth non si applica a un processo locale (stdio). |
| `T-01` (Origin/DNS-rebind), `T-02` (TLS/HSTS), `T-03` (session id) | Solo HTTP/SSE: non c'è un layer di rete in stdio. |
| `P-01` (prompt argument validation), `R-04` (template fuzzing), `R-05` (private://), `X-04` (rate limit), `S-01` (sampling), `L-01` (audit log), `SC-01/02` (supply-chain), `KF-01/02/03` | Non chiamati in `run_checks_stdio` (definiti nello spec ma senza implementazione nel percorso stdio). |

> Quindi la sezione "Controlli HTTP" del vecchio doc (T-01/T-02/T-03/P-01/R-04) descriveva test che **nella pipeline non vengono mai eseguiti**. E `A-01` (unauthenticated access) è **saltato** in stdio, non "agnostico".

---

## Parte 5: Pipeline e output

### Flusso

1. `run_security_scan.py` itera sui server; per ognuno clona il repo, rileva linguaggio, costruisce il comando di avvio.
2. `execute_mcp_security_scan` (`frameworks/mcpSecurityScan.py:179`) costruisce `server_command` (`node <file>` / `python <file>` / `<command> <file>`) e lancia `mcp-scan scan --transport stdio --command "<server_command>" --format json --output <repo>/security_report.json`. Timeout 3600s; alla fine uccide sempre i processi-server orfani (`_kill_server_processes`).
3. Se `security_report.json` non esiste → `failure`. Se l'unica categoria è `initialization-error` → server scartato.
4. `parse_mcp_security_scan` conta i finding **falliti** come vulnerabilità, per categoria e severità.

### Struttura del report (`Report` → `findings[]`)

```json
{
  "target": "stdio:node build/index.js",
  "findings": [
    {
      "id": "X-02",
      "title": "Input validation & injection fuzzing",
      "category": "tools",
      "severity": "critical",
      "passed": false,
      "details": "[{\"tool\": \"run_command\", \"payload\": \"$(whoami)\", \"resp\": {\"result\": {\"content\": [{\"type\":\"text\",\"text\":\"uid=0(root) ...\"}]}}}]",
      "remediation": ["Apply allowlists, strict parsers, sandboxing; disable raw shells ..."],
      "references": ["API input validation best practices"]
    }
  ]
}
```

Output della pipeline (`parse_mcp_security_scan`):
```json
{
  "mcp-security-scan": {
    "status": "completed",
    "total-vulnerabilities": 2,
    "categories": {"dangerous-capabilities": 1, "input-validation": 1},
    "categories_passed": {"path-traversal": 1, "rug-pull": 1, ...},
    "percentage_of_vulnerability": {"dangerous-capabilities": 50.0, "input-validation": 50.0},
    "findings": {"total": 11, "passed": 9, "failed": 2, "percentage_passed": 81.82},
    "severity": {"counts": {"critical": 1, "high": 1}, "percentage_of_severity": {...}},
    "failed_findings": [ /* id, category, severity, title, details, remediation, references */ ]
  }
}
```

La mappa ID→categoria (`functions/config.py:67`) è esattamente l'elenco degli 11 controlli stdio: qualsiasi ID fuori mappa diventerebbe `"unknown"` — segnale che è comparso un check non previsto.
