c'è un'altra differenza importante. Confronto i due avvii:

Real fuzzing (_start_mcp_server_process):

await asyncio.sleep(2) + _test_server_responsiveness che manda un ping e aspetta fino a 3 secondi extra → totale ~5 secondi
Se il timeout scade ma il processo è vivo → successo comunque (return process.poll() is None)
Robustness fuzzing (_start_mcp_server):

time.sleep(2) + solo process.poll() is None → totale solo 2 secondi
Nessun test di responsiveness
Un server che impiega 2-4 secondi per inizializzare: passa il check poll() (processo vivo), ma quando robustness inizia subito a inviare payload via stdin, il server non è ancora pronto → i write su stdin falliscono o non rispondono, e i payload vanno sprecati.

Inoltre, durante il fuzzing robustness (_perform_jsonrpc_fuzzing), se il server muore, process.stdin.write() lancia BrokenPipeError, il continue passa al prossimo payload, ma lo stesso identico errore si ripete su ogni payload — il loop continua inutilmente su un server morto.

Tutto ok. Riassumo i 3 fix applicati:

1. HTTP servers skippati nel robustness fuzzing (fix principale)
UniversalDynamicAnalyzer.analyze_server skippava completamente i server HTTP (_server_started = False, return), mentre real_fuzzing li gestiva tramite _run_http_dynamic_fuzzing. Ora il robustness fa la stessa cosa con _run_http_robustness_fuzzing.

2. Startup troppo corto nel robustness fuzzing
_start_mcp_server aspettava solo 2 secondi e faceva process.poll() is None — nessun test reale. _start_mcp_server_process (real_fuzzing) aspettava 2s + mandava un ping + aspettava fino a 3 secondi extra di risposta. Ora _start_mcp_server fa lo stesso: manda un ping, aspetta fino a 3s per la risposta, e se il processo è ancora vivo lo considera pronto (stessa logica del real_fuzzing).

3. Loop di fuzzing inutile su server morto
_perform_jsonrpc_fuzzing faceva continue su ogni BrokenPipeError, iterando inutilmente su tutti i payload rimanenti. Ora:

Controlla process.poll() prima di ogni payload
Tiene un contatore di failure consecutive
Dopo 3 failure di fila (BrokenPipeError/OSError), esce dal loop

## 3. mcp_guard - Implementazione e fix

### 3.1 `uvx mcp-guard` non trovato su PyPI
**File**: `functions/config.py` (riga 67)
**Problema**: Il comando era `cmd_guard = [UVX, "mcp-guard", str(CONFIG)]`, ma `mcp-guard` non e' un pacchetto pubblicato su PyPI — e' un tool locale in `~/Desktop/Frameworks/mcp-guard/`. `uvx` cercava di scaricarlo dal registry e falliva.
**Fix**: Cambiato in `cmd_guard = [sys.executable, str(MCP_GUARD_DIR / "mcp_scanner.py")]`. Ora lancia direttamente `python mcp_scanner.py <url> <repo_path> <command> <elem>`.

### 3.2 `update_framework_tests_errors` non definita
**File**: `functions/stats.py` (riga 615)
**Problema**: La funzione `update_framework_tests_errors` veniva chiamata per mcp-guard ma non era mai stata implementata.
**Fix**: Rimossa la chiamata a `update_framework_tests_errors`. Le altre funzioni di stats (`update_analysis_types`, `update_framework_categories`, `update_framework_severity`) gestiscono gia' tutti i dati necessari.

### 3.3 Server startup diverso tra real_fuzzing e robustness_fuzzing
**File**: `mcp_scanner.py` (classe `UniversalDynamicAnalyzer`)
**Problema**: I due fuzzing avviavano i server in modo diverso:
- `real_fuzzing` (UniversalStaticAnalyzer): avvio **async** con `await asyncio.sleep()` + test di responsiveness con ping JSON-RPC e `asyncio.wait_for` (3s timeout)
- `robustness_fuzzing` (UniversalDynamicAnalyzer): avvio **sync** con `time.sleep()` + semplice check `process.poll()` senza test di responsiveness

Questo causava numeri diversi: il robustness_fuzzing non riusciva ad avviare alcuni server che il real_fuzzing avviava correttamente.

**Fix**:
- Sostituito `_start_mcp_server` (sync) con `_start_mcp_server_async` (async), identico a `_start_mcp_server_process` di UniversalStaticAnalyzer
- `analyze_server()` ora usa `asyncio.run()` per chiamare il metodo async, come fa `analyze_server_fuzzing()`
- Entrambi i metodi usano: stessa `Popen`, stessa `asyncio.sleep`, stesso `_test_server_responsiveness` con ping JSON-RPC

### 3.4 Timeout troppo breve per server `uvx`
**File**: `mcp_scanner.py` (entrambi `_start_mcp_server_process` e `_start_mcp_server_async`)
**Problema**: Il tempo di attesa iniziale era 2 secondi. Per server avviati con `uvx`, la prima esecuzione richiede il download del pacchetto, che puo' superare i 2s. Il primo analyzer falliva, il secondo riusciva perche' `uvx` aveva gia' la cache.
**Fix**: Aumentato `asyncio.sleep` da 2 a 5 secondi in entrambi i metodi. Timeout totale: 5s sleep + 3s responsiveness = 8s.

### 3.5 Conteggio `robustness_fuzzing` in `analyses_completed`
**File**: `mcp_scanner.py` (in `scan_mcp_server`, riga ~292)
**Problema**: Originariamente `robustness_fuzzing` veniva contato come completato solo se `_server_started == True`. Questo e' il comportamento corretto e coerente con `real_fuzzing` (che conta `real_fuzzing` se il server parte, `dynamic` se non parte).
**Stato**: Mantenuto il check `_server_started` — i numeri di real_fuzzing e robustness_fuzzing ora coincidono perche' entrambi usano lo stesso metodo di avvio.

### 3.6 `OSError: [Errno 22] Invalid argument` sui pipe dei processi
**File**: `mcp_scanner.py` (`_cleanup_scanner_resources` e `_stop_mcp_server`)
**Problema**: I pipe (stdin/stdout/stderr) dei processi server venivano chiusi solo se il processo era ancora in vita (`process.poll() is None`). Se il server moriva durante il fuzzing, i pipe restavano aperti e il garbage collector di Python generava `OSError: [Errno 22] Invalid argument` quando provava a chiuderli.
**Fix**: I pipe ora vengono chiusi **sempre** (sia per processi vivi che morti), prima di qualsiasi tentativo di terminate/kill.

### 3.7 Server HTTP skippati nel robustness_fuzzing
**File**: `mcp_scanner.py` (in `analyze_server`)
**Problema**: I server HTTP venivano saltati con un log "Skipping stdio-based dynamic analysis for HTTP server" e `_server_started = False`.
**Fix**: Ora i server HTTP vengono analizzati con `_run_http_robustness_fuzzing()`, coerentemente con il real_fuzzing che usa `_run_http_dynamic_fuzzing()`.