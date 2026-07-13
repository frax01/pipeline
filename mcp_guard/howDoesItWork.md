# MCP Guard - Come Funziona

Tool: **mcp-guard** (`UniversalMCPScanner`), un unico script Python `mcp_scanner.py` (~6000 righe).
Repo locale: `C:\Users\francesco\Desktop\Frameworks\mcp-guard\mcp_scanner.py`

## Panoramica

Per ogni server MCP, lo scanner esegue **due fasi in sequenza** (`scan_mcp_server`, `mcp_scanner.py:210`, chiamato con `scan_type='both'`):

1. **Fase 1 — Static Analysis** (`_perform_static_code_analysis`, `mcp_scanner.py:3291`): ispeziona i file sorgenti del repo con una libreria di regex, **senza eseguirli**.
2. **Fase 2 — Dynamic Live Fuzzing** (`analyze_server_fuzzing`, `mcp_scanner.py:2705`): **avvia il server MCP in locale** e gli invia payload reali (fuzzing dei tool + fuzzing del protocollo JSON-RPC), analizzando ogni risposta.

> **Nota sul refactor.** La vecchia "Fase 3" è stata rimossa/unita alla Fase 2. Diversi blocchi del sorgente **non sono più nel percorso attivo** e vanno considerati legacy: `analyze_server()` e il **dependency scanning** (`_run_npm_audit`, `_run_bandit`, `_run_gosec`), i rilevatori "contextual" dei segreti, l'intera classe `UniversalDynamicAnalyzer`, e i fallback di analisi statica "arricchita" — questi ultimi sono **volutamente commentati** (`mcp_scanner.py:2765-2776`) perché producevano risultati fabbricati. Anche i limiti di risorse CPU/RAM e il file `mcp_guard_crash.log` **non** fanno parte del flusso di produzione. Questo documento descrive **solo ciò che gira davvero**.

### Comando lanciato nella pipeline

`frameworks/mcpGuard.py:142` (`execute_mcp_guard`) lancia lo scanner come subprocess:

```bash
python mcp_scanner.py <server_url> <repo_path> <command> <elem>
#        └ cmd_guard (functions/config.py:91)
# scan_type = 'both' è hardcoded in main() (mcp_scanner.py:5713)
# timeout complessivo = TIMEOUT_SECONDS = 3600s (functions/config.py:65)
```

Lo scanner scrive un report `mcp_security_scan_<nome>_<timestamp>.json` nella cartella di mcp-guard; la pipeline lo rilegge con `parse_mcp_guard` (`frameworks/mcpGuard.py:77`) e distribuisce ogni vulnerabilità in `static/`, `dynamic/`, `fuzzing/`, `protocol/` (vedi Parte 4).

---

## Parte 1: Static Analysis (Fase 1)

### Come funziona

`_perform_static_code_analysis` (`mcp_scanner.py:3291`) fa un `os.walk` del repo e per ogni file sorgente applica una lista di **regex compilate**.

- **Estensioni analizzate**: `.py`, `.js`, `.ts`, `.go`, `.mjs`, `.cjs`.
- **Cartelle saltate** (`skip_dirs`): `.git`, `node_modules`, `__pycache__`, `venv`, `.venv`, `dist`, `build`, `.next`, `vendor`, `test`, `tests`, `__tests__`, `spec`, `examples`, `docs`, `migrations`, `alembic`, `fixtures`, `seeds`, `scripts`, `benchmarks`, `coverage` (+ tutte quelle che iniziano con `.`).
- **File > 500 KB saltati** (probabile bundle/minified).
- **Dedup** per `(file, riga, cwe)`; per ogni match salva uno snippet della riga (max 150 caratteri).

### Logica anti-falsi-positivi

Ogni regex non cerca solo il **sink pericoloso** (es. `os.system(...)`), ma richiede anche un **segno di input dinamico** sullo stesso punto: f-string (`f"..."`), `.format(`, `%`, concatenazione `+ var`, template literal JS (`` ` `` / `${...}`). Una chiamata con soli argomenti costanti **non** fa match. Alcune regex hanno un filtro di lingua (`languages`), altre valgono per tutti i linguaggi.

### La libreria di pattern (`_get_static_patterns`, `mcp_scanner.py:3104`)

14 pattern che coprono ~9 classi di vulnerabilità:

| # | Titolo | CWE | Severità | Lingue | Esempio che fa match |
|---|---|---|---|---|---|
| 1 | Command Injection — subprocess/os | CWE-78 | critical | `.py` | `os.system(f"convert {user_file}")` |
| 2 | Command Injection — child_process.exec | CWE-78 | critical | `.js/.ts` | `child_process.execSync(\`rm ${path}\`)` |
| 3 | Command Injection — exec.Command | CWE-78 | critical | `.go` | `exec.Command("sh","-c","ls "+arg)` |
| 4 | Code Injection — eval | CWE-94 | critical | `.py` | `eval(f"{expr}")` |
| 5 | Code Injection — eval | CWE-94 | critical | `.js/.ts` | ``eval(`${code}`)`` |
| 6 | Path Traversal — os.path.join/Path | CWE-22 | high | `.py` | `open(os.path.join(base, f"{name}"))` |
| 7 | Path Traversal — path.join/resolve | CWE-22 | high | `.js/.ts` | `path.join(root, \`${sub}\`)` |
| 8 | Path Traversal — filepath.Join | CWE-22 | high | `.go` | `filepath.Join(base, name+ext)` |
| 9 | Hardcoded Credential | CWE-798 | high | tutte | `api_key = "sk-1a2b3c4d5e6f7g8h"` |
| 10 | SQL Injection — query dinamica | CWE-89 | high | tutte | `cursor.execute(f"SELECT * FROM u WHERE id={id}")` |
| 11 | Insecure Deserialization — pickle | CWE-502 | high | `.py` | `pickle.loads(data)` |
| 12 | SSRF — URL da input utente | CWE-918 | high | tutte | `requests.get(f"http://{host}/api")` |
| 13 | Prompt Injection nella tool description | CWE-1024 | critical | tutte | `description = "... IGNORE PREVIOUS instructions ..."` |
| 14 | Dangerous Tool Handler | CWE-20 | high | tutte | handler `def run(...)` che entro ~200 char chiama `subprocess`/`os.system` |

Il pattern **13** è specifico MCP: cerca, dentro un campo `description`/`tool_description`, frasi tipiche di prompt-injection (`<IMPORTANT`, `IGNORE PREVIOUS`, `you must`, `you should always`, `do not tell`) — cioè una tool description che tenta di manipolare l'LLM invece di descrivere la funzione.

### Scoring

La severità è fissa per pattern e mappa su punteggi fissi (`mcp_scanner.py:3356`):

| Severità | CVSS | AIVSS |
|---|---|---|
| critical | 9.0 | 7.0 |
| high | 7.5 | 5.0 |
| medium | 5.0 | 3.0 |
| altro | 3.0 | 2.0 |

Ogni finding statico ha `type="static"`, `confidence="medium"`, il path/riga reali e lo snippet nella `description`; `exploit_payload` e `server_response` restano **vuoti** (non si inventano payload).

### Esempio concreto (statico)

File `server.py` con:
```python
@tool()
def read_file(path):
    return open(os.path.join(BASE_DIR, f"{path}")).read()
```
→ il pattern **6** fa match sulla riga (`os.path.join(...` con f-string). Finding: `Path Traversal — unsanitised input in path construction`, `CWE-22`, `high`, `file_path="server.py"`, `line_number=3`, snippet nella description, CVSS 7.5.

---

## Parte 2: Dynamic Live Fuzzing (Fase 2)

### Avvio del server

`_start_mcp_server_process` (`mcp_scanner.py:3958`) fa `subprocess.Popen("<command> <elem>", shell=True, stdin/stdout/stderr=PIPE, text=True, cwd=repo_path)`. Su Linux usa `start_new_session=True` per poter poi killare **l'intero process tree** con `killpg` (senza, i figli node/python restano attaccati alle pipe e mandano `asyncio.run()` in deadlock — vedi il blocco di cleanup a `mcp_scanner.py:2789`).

Dopo l'avvio: attende **5s** (per gestire il download uvx/npx alla prima esecuzione) e testa la reattività con un `ping` (`_test_server_responsiveness`, `mcp_scanner.py:4004`).

- Se il server **non risponde** → ritorna `None`, **niente fuzzing** (`_server_started = False`, si ritorna una lista vuota; i vecchi fallback statici "arricchiti" sono disabilitati).
- Se il transport è `http` → percorso separato `_run_http_dynamic_fuzzing` (server HTTP avviato e interrogato via `requests`). Altrimenti si usa **stdio**.

A livello di modulo (`mcp_scanner.py:14`) lo scanner imposta `signal.SIGPIPE → SIG_IGN` su Linux, così non muore se il server figlio chiude la pipe mentre gli scrive.

### Il flusso di fuzzing live (`_perform_live_fuzzing`, `mcp_scanner.py:2831`)

1. **Handshake `initialize`**:
   ```json
   {"jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{"protocolVersion":"2024-11-05",
              "capabilities":{"tools":{"listChanged":true},
                              "resources":{"subscribe":true,"listChanged":true}},
              "clientInfo":{"name":"mcp-guard-fuzzer","version":"1.0"}}}
   ```
2. **Discovery** con `tools/list`: legge i tool reali del server (`{"tools":[...]}` o lista diretta).
3. **Payload mirati sui tool** (`_generate_targeted_fuzzing_payloads`, `mcp_scanner.py:2943`): per **ogni tool scoperto** inietta ciascuno dei **18 vettori d'attacco** nel **primo parametro di tipo string**; gli altri parametri `required` ricevono default sicuri (`number→1`, `boolean→true`, `array→[]`, altro→`"test"`). Se **nessun tool** è stato scoperto, usa nomi generici di fallback (`run`, `execute`, `read_file`, `query`, `fetch`, `eval`) × 18 vettori.
4. **Payload su risorse/prompt** (4 payload): `resources/list`, `resources/read` con `file://../../etc/passwd`, `resources/read` con `file:///etc/shadow`, `prompts/list`.
5. **Payload di protocollo** (`_generate_protocol_payloads`, `mcp_scanner.py:3039`, 20 payload).

Invio: ogni payload con timeout **13s** (`PER_PAYLOAD_TIMEOUT`); se il processo muore o si accumulano **10 timeout consecutivi** il fuzzing si interrompe. Ogni risposta passa a `_analyze_real_response` (Parte 3).

### I 18 vettori di injection (tool fuzzing)

| Categoria | Payload |
|---|---|
| Path traversal | `../../../etc/passwd`, `....//....//etc/shadow`, `/etc/passwd`, `C:\Windows\System32\config\SAM` |
| Command injection | `whoami; cat /etc/passwd`, `$(id)`, `` `cat /etc/passwd` ``, `test && ls -la /`, `test \|\| id` |
| Code injection | `__import__('os').system('id')`, `require('child_process').execSync('id').toString()`, `eval('1+1')` |
| SQL injection | `' OR 1=1; --`, `'; DROP TABLE users; --`, `1 UNION SELECT * FROM information_schema.tables; --` |
| SSRF | `http://169.254.169.254/latest/meta-data/`, `http://localhost:6379/`, `file:///etc/passwd` |

Esempio di payload generato per un tool `search(query: string)`:
```json
{"jsonrpc":"2.0","id":42,"method":"tools/call",
 "params":{"name":"search","arguments":{"query":"../../../etc/passwd"}}}
```

### I 20 payload di protocollo (protocol fuzzing)

Testano la robustezza del parser JSON-RPC:

| Gruppo | Esempi |
|---|---|
| Versione JSON-RPC invalida | `"jsonrpc":"1.0"`, `"3.0"`, `""` (con `tools/list`) |
| Campi obbligatori mancanti | manca `jsonrpc`; manca `id`; manca `method` |
| Tipi di campo sbagliati | `id:"string_id"`, `method:12345`, `params:"not_an_object"`, `params:[1,2,3]`, `params:{"name":null}` |
| ID limite | `id:-1`, `id:0`, `id:99999999999` |
| Method vuoto/speciale | `method:""`, `"   "`, `"tools/\x00list"`, `"tools/../../../etc/passwd"` |
| Payload gigante (DoS) | `arguments:{"data":"A"*100000}` (100 KB) |
| Oggetto nidificato (stack overflow) | `params` nidificato 100 livelli |

### Trasporto (I/O stdio)

`_send_real_mcp_message` (`mcp_scanner.py:4112`) scrive `json.dumps(payload)+"\n"` sullo stdin (write con timeout 2s) e legge la risposta con `_read_mcp_response` (timeout 10s, `mcp_scanner.py:4151`), che accumula righe finché non trova un JSON-RPC valido (`_is_valid_jsonrpc_response`: deve avere `jsonrpc:"2.0"` e `result` **o** `error`). Se qualcosa va storto ritorna un dict sentinella: `{"error":"write_timeout"}`, `{"error":"communication_failed"}`, `{"error":"broken_pipe"}`, `{"error":"server_terminated"}`, `{"error":"no_response","timeout":true}`, oppure `{"raw_response":[...],"parsed":false}`.

---

## Parte 3: Come vengono giudicate le risposte (la logica chiave)

Tutta l'intelligenza sta in `_analyze_real_response` (`mcp_scanner.py:4257`). **Questo è il punto più importante da capire**, e la filosofia è opposta a quella di un fuzzer classico.

### Cosa NON viene segnalato (filtri anti-falsi-positivi)

- **Nessuna risposta / timeout** → **non** è una vulnerabilità (il server può essere lento o occupato). Ritorna `None`. → conteggiato come falso positivo filtrato (`_filtered_count`).
- **`server_terminated`** → di norma **non** segnalato, tranne se il method contiene indicatori di path traversal (`../`, `/etc/`, `c:\`) o è un method non-standard sospetto.
- **Echo-awareness**: se un indicatore trovato nella risposta (es. `/etc/passwd`) **compare già nel payload che abbiamo inviato**, è considerato semplice **echo** dell'input, **non** prova di exploit.
- **`isError` del tool**: se la `result.content[].text` contiene un JSON con `{"isError": true}`, i frammenti del payload restituiti sono considerati echo e **non** exploit.

### Cosa VIENE segnalato (i segnali reali)

| Condizione sulla risposta | Vulnerabilità | Severità |
|---|---|---|
| `tools/call` result contiene **contenuto reale di file** non presente nel payload (`root:x:`, `daemon:x:`, `bin:x:`, `root:$`, `[autorun]`, `[boot loader]`, `/proc/version`, …) | Path traversal returned sensitive file content | **critical** |
| result contiene **output di shell** (`uid=`, `gid=`, `groups=`, `drwx`, `-rw-`, `total `) | Command injection returned shell output | **critical** |
| result contiene **tracce di esecuzione codice** (`<module>`, `traceback`, `__main__`, `SyntaxError`, `eval()`, …) | Code injection was executed | **critical** |
| `error` message contiene **path di sistema nuovi** (`/etc/`, `/proc/`, `/var/`, `c:\`) non nel payload | Path traversal info disclosure in error | **high** |
| `error` message contiene **stack/debug** (`traceback`, `stack trace`, `file "`, `internal error`, …) | Debug information disclosure | **medium** |
| `error` message contiene **marcatori shell** (`sh:`, `bash:`, `cmd:`, `powershell`) | Command execution attempt detected | **high** |
| result (method non di discovery) contiene **pattern di credenziali** (`password=`, `api_key:`, `-----BEGIN RSA`, `AKIA`, …) | Sensitive information disclosed | **medium** |
| risposta con `result` a un payload con `jsonrpc != "2.0"` | Server accepts invalid JSON-RPC version | **low** |
| risposta con `result` a un payload **senza `id`** | Server accepts requests without ID | **low** |
| risposta non-JSON (`raw_response`, `parsed:false`) | Non-JSON response to JSON-RPC request | **low** |

### Filtro finale di qualità

Prima di emettere un finding (`mcp_scanner.py:4503`) lo scanner:
- **scarta** qualsiasi cosa contenga `timeout` / `resource exhaustion` / `dos vulnerability`;
- **tiene** i finding ad alto impatto (`injection`, `traversal`, `disclosure`, `execution`, `critical`, `sensitive`, `credential`, `admin`);
- tiene le violazioni di protocollo solo se **specifiche** (descrizione > 30 caratteri).
Se non sopravvive nulla → `None` (falso positivo filtrato).

### Conversione a Vulnerability (`_convert_to_vulnerability`, `mcp_scanner.py:4531`)

Il finding sopravvissuto diventa un oggetto `Vulnerability` con `type` = categoria (`fuzzing` o `protocol`), severità→CWE (`critical→CWE-94`, `high→CWE-22`, altro→`CWE-20`), `exploit_payload` = il payload esatto inviato, `server_response` = la risposta del server, `confidence="high"`, e scoring CVSS/AIVSS (dal `VulnerabilityScorer`, o fallback CVSS 6.0 / AIVSS 4.0).

### Come leggere i risultati

| Situazione | Significato |
|---|---|
| 0 vulnerabilità dinamiche + server avviato | **Buono** — il server ha retto tutti i payload senza rivelare contenuti/eseguire comandi. È l'esito sano. |
| Server non avviato (`_server_started=False`) | **Non testabile** dinamicamente — nessun finding di fuzzing (non è di per sé una vulnerabilità). |
| Finding `critical` (traversal/command/code) | **Vero exploit riprodotto**: il payload ha restituito contenuto di file reale / output di shell / esecuzione codice. `exploit_payload` + `server_response` permettono di riprodurlo. |
| Molti timeout | **Rumore**, filtrato di proposito: qui i timeout **non** contano come DoS/vulnerabilità (differenza chiave rispetto al fuzzer). |

> In sintesi: mentre il fuzzer `mcp-fuzzer` conta i crash/exception, **mcp-guard cerca la prova dell'exploit nella risposta** (contenuto sensibile, output di comando, disclosure) ed è aggressivo nel filtrare tutto ciò che è solo instabilità/eco.

---

## Parte 4: Output e pipeline

### Struttura del report JSON

`scan_mcp_server` produce (`mcp_scanner.py:232`):

```json
{
  "server_info": { "server_type": "python", "name": "...", "transport_type": "stdio", ... },
  "scan_type": "both",
  "vulnerabilities": [ /* oggetti Vulnerability, sia static che fuzzing/protocol */ ],
  "summary": {
    "total": 3,
    "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0},
    "by_type": {"static": 1, "fuzzing": 1, "protocol": 1, ...},
    "cvss_v4.0_metrics": {"average_score": 8.0, "highest_score": 9.0, ...},
    "aivss_metrics": {...},
    "risk_assessment": {"overall_risk": "CRITICAL", "business_impact": "SEVERE", "exploitability": "HIGH"},
    "filtering_stats": {"total_raw_findings": 12, "filtered_false_positives": 9, "real_vulnerabilities": 3, "filter_effectiveness": "75.0%"}
  },
  "analyses_completed": {"static": true, "fuzzing": true, "protocol": true}
}
```

Esempio di singola vulnerabilità dinamica:
```json
{
  "id": "dynamic-1737045-8421",
  "type": "fuzzing",
  "severity": "critical",
  "title": "Path Traversal Vulnerability",
  "cwe_id": "CWE-22",
  "file_path": "server.py",
  "exploit_payload": "{'jsonrpc': '2.0', 'id': 42, 'method': 'tools/call', 'params': {'name': 'read', 'arguments': {'path': '../../../etc/passwd'}}}",
  "server_response": "{'result': {'content': [{'type': 'text', 'text': 'root:x:0:0:root:/root:/bin/bash\\n...'}]}}",
  "confidence": "high"
}
```

`risk_assessment` è derivato dal punteggio massimo (`mcp_scanner.py:445`): ≥9.0 → CRITICAL, ≥7.0 → HIGH, ≥4.0 → MEDIUM, >0 → LOW.

### Flusso della pipeline

1. `run_guard.py` itera sui server dal file Excel; per ognuno clona il repo, rileva linguaggio, costruisce la config (`prepare_server` / `prepare_npx_server`).
2. Chiama `execute_mcp_guard` (`frameworks/mcpGuard.py:142`), che lancia `python mcp_scanner.py <url> <repo> <command> <elem>` come subprocess (timeout 3600s) e, alla fine, uccide i processi-server orfani (`_kill_server_processes`).
3. `parse_mcp_guard` (`frameworks/mcpGuard.py:77`) legge il JSON, raggruppa le vulnerabilità per `title` (categoria), conta severità/CWE e calcola le percentuali.
4. `save_vulnerability_entry` (`run_guard.py:112`) salva ogni vulnerabilità in `mcp_guard/<analysis_type>/<category>/<title>.json`, dove `analysis_type` ∈ {`static`, `dynamic`, `fuzzing`, `protocol`}.

### File di output

```
mcp_guard/
  mcp_guard_stats.json      # progresso e statistiche aggregate
  mcp_guard_servers.json    # esito/failure_reason per ogni server
  static/                   # finding della Fase 1 (per categoria)
    command-injection.../...json
    path-traversal.../...json
  fuzzing/                  # finding tool-fuzzing della Fase 2
  protocol/                 # finding protocol-fuzzing della Fase 2
  dynamic/                  # eventuali finding dinamici generici
```

Ogni file raccoglie le occorrenze di quella vulnerabilità su tutti i server: `server_url`, `server_name`, `language`, `severity`, `file`, `description`, `payload`, `response`, `remediation`.
