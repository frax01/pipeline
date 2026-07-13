# MCP Fuzzer - Come Funziona

Tool usato: **mcp-server-fuzzer** v0.3.1 (PyPI: `mcp-fuzzer`)
Repo: https://github.com/agent-hellboy/mcp-server-fuzzer

## Panoramica

Il fuzzer testa ogni MCP server in **due modalita**:

1. **Tool fuzzing** — chiama i tool del server (es. `enhance_prompt`) con input fuzzati per trovare crash, eccezioni e vulnerabilita nella logica applicativa.
2. **Protocol fuzzing** — invia richieste JSON-RPC raw al protocollo MCP per testare la robustezza del layer di comunicazione.

Comando usato nella pipeline (`frameworks/fuzzing.py:297-327`):

```bash
mcp-fuzzer \
  --mode all \                    # sia tool che protocol
  --phase both \                  # realistic + aggressive per i tool
  --protocol stdio \              # comunicazione via stdin/stdout
  --endpoint "<command>" \        # comando per avviare il server
  --runs 10 \                     # 10 run per fase (= 20 totali per tool)
  --runs-per-type 10 \            # 10 run per ogni protocol type
  --timeout 60 \
  --enable-safety-system \        # blocca input pericolosi reali
  --fs-root /tmp/safe \           # sandbox filesystem
  --no-network \                  # blocca accesso rete
  --output-format json
```

---

## Parte 1: Tool Fuzzing

### Fasi

Con `--phase both` e `--runs 10`, ogni tool riceve **20 run totali**:

- **10 run realistic**: input realistici che un utente vero potrebbe mandare
- **10 run aggressive**: payload di attacco (SQL injection, XSS, path traversal, ecc.)

### Come genera gli input

Il fuzzer legge lo schema del tool dal server (`tools/list`), poi genera input basati sul tipo di ogni parametro.

#### Fase Realistic (`schema_parser.py:_handle_string_type`)

Usa 3 strategie scelte random:

| Strategia | Cosa genera | Esempio |
|---|---|---|
| `boundary` | Stringhe ai limiti di lunghezza (min, max, meta, min+1, max-1) | `""`, `"abcdefghijklm..."` |
| `sample` | Sceglie da `REALISTIC_SAMPLES` (nomi, email, URL, query, path, id) | `"John"`, `"admin@localhost"`, `"example"` |
| `random_text` | Parole random concatenate fino alla lunghezza target | `"check file create update"`, `"test query"` |

Codice: `interesting_values.py:get_realistic_boundary_string()`

#### Fase Aggressive (`schema_parser.py:_handle_string_type`)

Sceglie random tra **12 strategie di attacco**:

| Strategia | Cosa testa | Esempio payload |
|---|---|---|
| `sql` | SQL injection | `' OR '1'='1`, `'; DROP TABLE--`, `' UNION SELECT NULL--` |
| `nosql` | NoSQL injection | `{"$gt": ""}`, `{"$ne": null}` |
| `xss` | Cross-site scripting | `<script>alert(1)</script>`, `<img onerror=alert(1)>` |
| `path` | Path traversal | `../../etc/passwd`, `/etc/shadow` |
| `command` | Command injection | `; echo test`, `$(whoami)`, `\| cat /etc/passwd` |
| `ssrf` | Server-side request forgery | `http://169.254.169.254/`, `http://127.0.0.1` |
| `unicode` | Trucchi unicode | Caratteri RTL override, BOM, zero-width |
| `type_confusion` | Confusione di tipo | `"true"`, `"null"`, `"[]"`, `"0"` |
| `encoding` | Bypass encoding | `%00`, `%2e%2e%2f`, `\x00` |
| `empty_edge` | Edge case vuoti | `""`, `" "`, `"\t"`, `"\n"`, `"\x00"` |
| `overflow` | Buffer overflow | `"AAAA..."` (fino a 1000 caratteri) |
| `mixed` | Caratteri random misti | Mix di ascii, digits, punteggiatura |

Codice: `schema_parser.py:_handle_string_type()`, `interesting_values.py:get_payload_within_length()`

### Safety System

Con `--enable-safety-system`, il fuzzer blocca payload che potrebbero fare danni reali:
- Blocca URL e script (`<script>`, `http://`)
- Sanitizza path del filesystem alla sandbox (`--fs-root /tmp/safe`)
- Blocca comandi shell pericolosi

Questo spiega perche alcuni payload XSS vengono troncati (es. `"<sv"` invece di `"<script>alert(1)</script>"`).

### Output per i tool

Per ogni tool, il report JSON contiene:

```json
{
  "name": "enhance_prompt",
  "runs": 20,
  "successful": 2,
  "exceptions": 18,
  "safety_blocked": 0,
  "success_rate": 10.0,
  "exception_details": [
    {
      "type": "str",
      "message": "Failed to receive message from stdio transport",
      "arguments": {"prompt": "test query"}
    }
  ]
}
```

- `successful`: il server ha risposto senza errori
- `exceptions`: il server ha crashato o non ha risposto
- `arguments`: l'input esatto che ha causato l'eccezione (utile per riprodurre il bug)

Nel contesto del fuzzing "successful" non vuol dire "l'attacco è riuscito". Vuol dire il contrario: il server ha ricevuto un input strano/malevolo e ha retto — ha risposto con un risultato JSON-RPC valido senza morire. Quindi è l'esito sano, quello che vuoi vedere.

Il senso è quello di un crash test, non di un test funzionale:

Non ti interessa se la risposta del server è "giusta" nel merito.
Ti interessa solo se il server è rimasto in piedi.
successful = è rimasto in piedi

Quindi la lettura è:

Campo	          Buono o cattivo?
successful alto	Buono — server robusto, non crasha sotto input ostile
exceptions = "Server returned error"	Buono — il server rifiuta l'input in modo pulito
exceptions = "Failed to receive..." su tutti i run	Di solito rumore (problema di avvio/transport), non un bug
exceptions = "Failed to receive..." su un input specifico mentre gli altri passano	Cattivo — potenziale crash da investigare

---

## Parte 2: Protocol Fuzzing

### Cosa fa

A differenza del tool fuzzing (che testa i tool del server), il protocol fuzzing testa il **protocollo MCP stesso** — come il server gestisce le richieste JSON-RPC standard.

Il fuzzer invia 10 richieste per ognuno dei **17 protocol type** definiti nella spec MCP, tutti nella fase `realistic` (`--protocol-phase realistic` e' hardcoded nel fuzzer).

### I 17 Protocol Types

#### 1. InitializeRequest — `"initialize"`
Handshake iniziale. Il client invia la sua versione del protocollo e le capabilities, il server risponde con le proprie. Deve avvenire come prima richiesta.

```json
{"jsonrpc": "2.0", "method": "initialize",
 "params": {"protocolVersion": "2024-11-05",
            "capabilities": {"roots": {}, "sampling": {}},
            "clientInfo": {"name": "mcp-fuzzer", "version": "0.3.1"}},
 "id": 123}
```

**Cosa cerca:** Il server crasha con versioni del protocollo malformate? Accetta capabilities inventate?

#### 2. PingRequest — `"ping"`
Health check. Il server DEVE rispondere con `{}`.

```json
{"jsonrpc": "2.0", "method": "ping", "params": {}, "id": 123}
```

**Cosa cerca:** Il server e' vivo e conforme alla spec?

#### 3. ProgressNotification — `"notifications/progress"`
Notifica (nessun `id`, nessuna risposta attesa). Il client avvisa il server del progresso di un'operazione lunga.

**Cosa cerca:** Il server crasha su notifiche inattese? Nelle notifiche il successo e' garantito (non serve risposta).

#### 4. CancelNotification — `"notifications/cancelled"`
Notifica di cancellazione di un'operazione in corso. Stessa logica delle notifiche — successo garantito se il server non crasha.

#### 5. ListResourcesRequest — `"resources/list"`
Chiede l'elenco di tutte le risorse esposte dal server (file, database, API). Nessun parametro richiesto.

```json
{"jsonrpc": "2.0", "method": "resources/list", "params": {}, "id": 123}
```

**Cosa cerca:** Il server che non ha risorse risponde con un errore pulito o crasha?

#### 6. ReadResourceRequest — `"resources/read"`
Chiede di leggere il contenuto di una specifica risorsa tramite URI.

```json
{"jsonrpc": "2.0", "method": "resources/read",
 "params": {"uri": "file:///tmp/test.txt"}, "id": 123}
```

**Cosa cerca:** Test critico per **path traversal**. Nella fase aggressive prova `file:///etc/passwd`, `../../etc/shadow`, UNC path Windows.

#### 7. ListResourceTemplatesRequest — `"resources/templates/list"`
Chiede l'elenco dei template di risorse — URI parametrizzati (es. `file:///{path}`, `db:///{table}/{id}`).

**Cosa cerca:** Il server espone template che rivelano struttura interna (path filesystem, nomi tabelle)?

#### 8. SubscribeRequest — `"resources/subscribe"`
Il client si iscrive agli aggiornamenti di una risorsa. Quando cambia, il server inviera' notifiche.

```json
{"jsonrpc": "2.0", "method": "resources/subscribe",
 "params": {"uri": "resource://server/updates"}, "id": 123}
```

**Cosa cerca:** Si possono iscrivere a risorse interne non accessibili?

#### 9. UnsubscribeRequest — `"resources/unsubscribe"`
Cancella l'iscrizione a una risorsa. Inverso di Subscribe, stessa struttura.

#### 10. ListPromptsRequest — `"prompts/list"`
Chiede l'elenco dei prompt template esposti dal server. Nessun parametro richiesto.

**Cosa cerca:** Il server gestisce correttamente la richiesta se non ha prompt?

#### 11. GetPromptRequest — `"prompts/get"`
Chiede uno specifico prompt template per nome.

```json
{"jsonrpc": "2.0", "method": "prompts/get",
 "params": {"name": "summarize"}, "id": 123}
```

**Cosa cerca:** Il nome viene usato in query DB/filesystem senza sanitizzazione? Nella fase aggressive prova nomi come `' OR '1'='1`.

#### 12. ListRootsRequest — `"roots/list"`
Chiede al client l'elenco delle root directory accessibili. Nella spec MCP va nella direzione inversa (server -> client), ma il fuzzer la invia al server per testare la reazione.

**Cosa cerca:** Il server leaka path del filesystem locale?

#### 13. SetLevelRequest — `"logging/setLevel"`
Chiede al server di cambiare il livello di logging.

```json
{"jsonrpc": "2.0", "method": "logging/setLevel",
 "params": {"level": "debug"}, "id": 123}
```

**Cosa cerca:** Il livello viene passato senza validazione? Un server che usa `eval()` potrebbe essere vulnerabile.

#### 14. CompleteRequest — `"completion/complete"`
Chiede autocompletamento per un argomento di un prompt o risorsa.

```json
{"jsonrpc": "2.0", "method": "completion/complete",
 "params": {"ref": {"type": "ref/prompt", "name": "test"},
            "argument": {"name": "query", "value": "test"}},
 "id": 123}
```

**Cosa cerca:** Il `name` del ref viene usato per cercare su filesystem/DB?

#### 15. CreateMessageRequest — `"sampling/createMessage"`
Chiede al client di campionare un LLM. Come ListRoots, va in direzione inversa (server -> client).

```json
{"jsonrpc": "2.0", "method": "sampling/createMessage",
 "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "hello"}}],
            "maxTokens": 100},
 "id": 123}
```

**Cosa cerca:** `maxTokens` validato? Il testo viene passato a un LLM senza sanitizzazione (prompt injection)?

#### 16. ElicitRequest — `"elicitation/create"`
Il server chiede al client di raccogliere input dall'utente tramite un form strutturato (schema JSON).

```json
{"jsonrpc": "2.0", "method": "elicitation/create",
 "params": {"message": "Please provide input",
            "requestedSchema": {"type": "object", "properties": {"value": {"type": "string"}}}},
 "id": 123}
```

**Cosa cerca:** Lo schema viene renderizzato lato client senza sanitizzazione?

#### 17. GenericJSONRPCRequest — metodo random
Non corrisponde a un tipo MCP reale. Invia metodi random (`"tools/call"`, `"custom/method"`, `"unknown/method"`) con payload generici.

**Cosa cerca:** Come reagisce il server a metodi sconosciuti? Crasha o gestisce l'errore?

### Micro-mutazioni automatiche

Il layer di mutation del fuzzer aggiunge piccole variazioni sopra i payload generati:
- Campi extra iniettati: `"fuzz_te": -1`, `"fuzz_gp": false`, `"fuzz_qa": "<script>alert(1)</script>"`
- Caratteri aggiunti al method name: `"resources/list?"`, `"roots/list!"`
- ID duplicati o con tipi sbagliati

Queste mutazioni testano la robustezza del parser JSON-RPC del server.

### Variabilita' dei parametri nella fase realistic

Alcuni tipi hanno parametri che variano tra le 10 run, altri sono fissi:

| Varia | Protocol Types |
|---|---|
| Si | `ReadResourceRequest` (3 URI), `GetPromptRequest` (4 nomi), `SetLevelRequest` (4 livelli) |
| No | Tutti gli altri — inviano gli stessi params 10 volte. La variazione e' solo nell'`id` e nelle micro-mutazioni |

Per i tipi senza parametri (`ListResourcesRequest`, `ListPromptsRequest`, `PingRequest`, ecc.) non c'e' nulla da variare nella fase realistic. La differenza tra le run e' solo il random `id` e le micro-mutazioni.

### Output per il protocol

Per ogni protocol type, il report contiene:

```json
{
  "type": "ReadResourceRequest",
  "runs": 10,
  "successful": 0,
  "errors": 10,
  "success_rate": 0.0,
  "error_details": [
    {
      "fuzz_data": {
        "jsonrpc": "2.0",
        "method": "resources/read",
        "params": {"uri": "file:///tmp/test.txt"},
        "id": 220736
      },
      "run": 0
    }
  ]
}
```

- `successful`: il server ha risposto correttamente
- `errors`: il server ha rifiutato o non ha risposto
- `fuzz_data`: il payload JSON-RPC esatto inviato al server
- `error_details`: presente solo quando ci sono errori (aggiunto con nostra modifica a `reports/output/protocol.py`)

### Come interpretare i risultati

| Risultato | Significato |
|---|---|
| 100% success su Initialize + Ping | Il server e' vivo e conforme alla base MCP |
| 100% success su Notifications | Normale — le notifiche non richiedono risposta |
| 0% su funzionalita' non implementate | Atteso — il server rifiuta operazioni che non supporta |
| Eccezione/crash su qualsiasi tipo | **Possibile vulnerabilita'** — il server non dovrebbe mai crashare |

---

## Parte 3: Pipeline di esecuzione

### Flusso completo

1. `run_fuzzing.py` itera sui server MCP dal file Excel
2. Per ogni server, clona il repo, detecta linguaggio, trova entrypoint
3. Chiama `execute_mcp_fuzzing()` (`frameworks/fuzzing.py:266`)
4. Che lancia `mcp-fuzzer` come subprocess con i parametri configurati
5. Il fuzzer:
   - Avvia il server MCP via stdio
   - Chiama `tools/list` per scoprire i tool disponibili
   - Esegue 20 run per tool (10 realistic + 10 aggressive)
   - Esegue 10 run per ognuno dei 17 protocol type
   - Salva il report JSON in `reports/sessions/<session-id>/`
6. `parse_fuzzing_report_json()` legge il report e estrae i dati strutturati
7. `update_output_files()` salva i risultati nelle cartelle `exceptions/` e `protocol/`

### File di output

```
fuzzing/
  fuzzing_stats.json      # Progresso e statistiche aggregate
  fuzzing_servers.json    # Risultato per ogni server
  exceptions/             # File raggruppati per tipo di eccezione
    Failed_to_receive_message_from_stdio_transport.json
    Server_returned_error.json
    ...
  protocol/               # Risultati protocol per tipo
    InitializeRequest.json
    ReadResourceRequest.json
    ...
```

---

## Parte 4: Bug Fix Applicati (v0.3.1)

I fix sono nei file installati del pacchetto (`site-packages/mcp_fuzzer/`), NON nel source locale.

### Fix 1: Input realistic sempre vuoti
**File:** `fuzz_engine/mutators/strategies/interesting_values.py`
**Funzione:** `get_realistic_boundary_string()`
**Bug:** `run_index` era sempre 0, selezionava sempre `boundaries[0] = min_length = 0` -> stringa vuota.
**Fix:** Riscritto con 3 strategie (boundary, sample, random_text) e `random.choice()`.

### Fix 2: Payload aggressivi sempre uguali
**File:** `fuzz_engine/mutators/strategies/interesting_values.py`
**Funzione:** `get_payload_within_length()`
**Bug:** Ritornava sempre il PRIMO payload che entra nel limite di lunghezza.
**Fix:** `random.choice(fitting)` tra tutti i payload che entrano nel limite.

### Fix 3: Poche strategie aggressive
**File:** `fuzz_engine/mutators/strategies/schema_parser.py`
**Funzione:** `_handle_string_type()`
**Bug:** Solo 5 strategie (sql, xss, path, unicode, mixed). XSS bloccato dal safety system.
**Fix:** Espanso a 12 strategie (aggiunto nosql, command, ssrf, type_confusion, encoding, empty_edge, overflow).

### Fix 4: Protocol types tutti falliti ("Unknown protocol type")
**File:** `fuzz_engine/mutators/strategies/spec_protocol.py`
**Funzione:** `get_spec_protocol_fuzzer_method()`
**Bug:** Lo schema JSON MCP (git submodule) non era incluso nel pacchetto PyPI. Senza schema, tutti i 16 tipi (tranne `GenericJSONRPCRequest`) fallivano con `ValueError`.
**Fix:** Aggiunto fallback hardcoded con `_PROTOCOL_METHOD_MAP`, `_PROTOCOL_PARAMS_REALISTIC` e `_PROTOCOL_PARAMS_AGGRESSIVE` che genera payload corretti senza dipendere dal file schema.

### Fix 5: Protocol report senza payload
**File:** `reports/output/protocol.py`
**Funzione:** `_format_protocol_results()`
**Bug:** Il report per i protocol types mostrava solo conteggi (runs, errors), senza i payload inviati.
**Fix:** Aggiunto campo `error_details` con `fuzz_data`, `server_error`, `exception` per ogni run fallito — come gia' esisteva per i tool (`exception_details`).

### File modificati (da copiare sulle VM)

```
# Fix 1-2: Input generation
site-packages/mcp_fuzzer/fuzz_engine/mutators/strategies/interesting_values.py

# Fix 3: Aggressive strategies
site-packages/mcp_fuzzer/fuzz_engine/mutators/strategies/schema_parser.py

# Fix 4-5: Protocol fallback + report details
site-packages/mcp_fuzzer/fuzz_engine/mutators/strategies/spec_protocol.py
site-packages/mcp_fuzzer/reports/output/protocol.py
```
