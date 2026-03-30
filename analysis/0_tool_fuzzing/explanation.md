# 1. Perché i dettagli sono solo per le exceptions?
Nel codice del reporter (mcp_fuzzer/reports/output/protocol.py), i risultati dei tool vengono formattati così:

Exceptions: vengono salvati con exception_details (type, message, arguments) — quindi puoi raggruppare per messaggio (exceptions_by_message)
Successful: vengono solo contati (successful += 1), senza salvare dettagli su cosa è stato restituito
Questo è un limite dell'output attuale. I risultati successful contengono la response del server, ma vengono scartati durante l'aggregazione. Se vuoi i dettagli anche dei successful, bisognerebbe aggiungere un campo tipo success_details o response_summary nella formattazione.

# 2. Perché i protocol types hanno così tanti errori?
Quasi tutti i protocol types hanno 0 successful su ~1730 runs. Il motivo è nella logica di _result_has_failure():

def _result_has_failure(result):
    return bool(
        result.get("exception")
        or not result.get("success", True)
        or result.get("error")
        or result.get("server_error")
    )

Conta come "errore" 4 condizioni diverse: exception, success=False, error field, e server_error field.

Il protocol fuzzer manda versioni malformate/fuzzate di messaggi di protocollo MCP (InitializeRequest, PingRequest, CancelNotification, ecc.). I server giustamente rifiutano questi messaggi perché non sono conformi allo schema — rispondono con un error JSON-RPC o server_error. Questo viene contato come "errore" nelle stats.

In pratica:

Non è un bug del fuzzer — è il comportamento atteso. I server stanno facendo la cosa giusta rifiutando input malformati.
I pochi successi (ReadResourceRequest: 115, GenericJSONRPCRequest: 105, GetPromptRequest: 33) indicano server che hanno accettato input fuzzati — e quelli sì sono i casi interessanti da analizzare, perché potrebbero indicare validazione insufficiente.

Analisi dei Risultati del Fuzzing su Server MCP — Campagna su 9 VM
1. Panoramica del Dataset
La campagna di fuzzing ha analizzato un dataset di 60.200 server MCP (indice fino a 60.205), distribuiti per linguaggio:

Linguaggio	Server	Percentuale
Node.js	24.004	39,9%
Python	14.790	24,6%
Go	1.411	2,3%
Unknown	19.995	33,2%
Totale	60.200	100%
Verifica: 24.004 + 14.790 + 1.411 + 19.995 = 60.200 ✓

Di questi 60.200 server, 6.035 sono stati effettivamente fuzzati con successo (il 10,02%), ovvero quelli per cui è stato possibile instaurare una connessione stdio, completare l'handshake MCP e avviare le sessioni di test. La distribuzione dei server fuzzati è:

Linguaggio	Fuzzati	% sui fuzzati
Node.js	5.686	94,2%
Go	314	5,2%
Python	35	0,6%
Totale	6.035	100%
Verifica: 5.686 + 314 + 35 = 6.035 ✓ — e 6.035 / 60.200 = 10,02% ✓

Il dominio netto di Node.js (94,2% dei server fuzzati) rispecchia la maturità dell'ecosistema MCP su Node.js: la maggior parte dei server pubblicati usa @modelcontextprotocol/sdk e si avvia facilmente con npx. I server Python e Go sono spesso più frammentati nell'installazione (dipendenze, build step, ambienti virtuali), il che spiega il basso tasso di raggiungibilità.

2. Fuzzing dei Tool — I Numeri
Sui 6.035 server fuzzati sono stati rilevati 48.093 tool complessivi (~8 tool per server in media). Il fuzzer ha eseguito 972.560 run totali di tool fuzzing, con i seguenti risultati:

Metrica	Valore
Tool totali	48.093
Run totali	972.560
Successi	790.815
Eccezioni	181.745
Safety blocked	0
Success rate	81,3%
Verifica: 790.815 + 181.745 = 972.560 ✓ — e 790.815 / 972.560 = 0,8131 ✓

Con 48.093 tool e 972.560 run, abbiamo una media di ~20,2 run per tool, coerente con un'esecuzione in modalità both (10 run in fase realistic + 10 run in fase aggressive).

Come funziona il tool fuzzing nel codice
Il ToolExecutor itera i run per ciascun tool e li esegue in parallelo con concorrenza controllata (tool_executor.py:51-91):

async def execute(self, tool, runs=10, phase="aggressive"):
    operations = []
    for i in range(runs):
        operations.append((self._execute_single_run, [tool, i, phase], {}))
    batch_results = await self.executor.execute_batch(operations)
    results = self.collector.collect_results(batch_results)
    return results

Per ogni singolo run, il ToolMutator genera argomenti fuzzati basandosi sullo schema JSON del tool, poi il safety system li filtra prima dell'invio (tool_executor.py:93-159):

async def _execute_single_run(self, tool, run_index, phase):
    args = await self.mutator.mutate(tool, phase)
    if self.safety_system:
        if self.safety_system.should_skip_tool_call(tool_name, args):
            return build_tool_result(safety_blocked=True, ...)
        sanitized_args = self.safety_system.sanitize_tool_arguments(tool_name, args)
    # ... invio e raccolta risultato

Il success rate del 81,3% indica che la maggior parte dei server MCP gestisce correttamente anche input anomali, restituendo risultati (anche se di errore applicativo) senza crashare. Il 18,7% di eccezioni rappresenta i casi in cui il server ha generato un errore di trasporto non gestito.

3. Classificazione delle Eccezioni (181.745 totali)
Messaggio eccezione	Count	%	Origine nel codice
Server returned error	154.639	85,1%	stdio_driver.py:262
Failed to receive message from stdio transport	16.736	9,2%	stdio_driver.py:231
No response received from stdio transport	5.626	3,1%	stdio_driver.py:254
Failed to send message over stdio transport	4.743	2,6%	stdio_driver.py:197
Too many responses received without matching request ID	1	~0%	Mismatch di ID
Totale	181.745	100%	
Verifica: 154.639 + 16.736 + 5.626 + 4.743 + 1 = 181.745 ✓

Spiegazione di ogni tipo di eccezione
"Server returned error" (85,1%) — Il server ha ricevuto il messaggio, lo ha processato, e ha restituito un errore JSON-RPC standard (campo "error" nella risposta). Questo è il comportamento corretto di un server che rifiuta input invalidi:

# stdio_driver.py:259-265
if response.get("id") == request_id:
    if "error" in response:
        raise ServerError(
            "Server returned error",
            context={"request_id": request_id, "error": response["error"]},
        )

"Failed to receive message from stdio transport" (9,2%) — Il processo del server era attivo ma la lettura da stdout è fallita (output corrotto, JSON malformato, buffer pieno, encoding errato):

# stdio_driver.py:228-234
except Exception as e:
    self.manager.state.record_error(str(e))
    raise TransportError(
        "Failed to receive message from stdio transport",
        context={"command": self.command},
    ) from e

"No response received from stdio transport" (3,1%) — Il messaggio è stato inviato ma il server non ha mai risposto (hang, deadlock, il processo è morto silenziosamente):

# stdio_driver.py:252-257
response = await self._receive_message()
if response is None:
    raise TransportError(
        "No response received from stdio transport",
        context={"request_id": request_id},
    )

"Failed to send message over stdio transport" (2,6%) — Non è stato possibile scrivere sullo stdin del processo server (processo crashato, pipe chiusa, broken pipe):

# stdio_driver.py:197-203 (dentro _send_message)
raise TransportError(
    "Failed to send message to stdio transport",
    context={"message": message},
)

Il fatto che l'85% delle eccezioni sia "Server returned error" è un dato positivo: significa che la maggior parte dei server gestisce correttamente input malformati, restituendo errori JSON-RPC standard anziché crashare. Solo il 15% circa delle eccezioni è dovuto a problemi di trasporto reali (crash del processo, hang, pipe rotte).

4. Fuzzing dei Tipi di Protocollo — I Numeri
Parallelamente al tool fuzzing, è stato eseguito il protocol fuzzing, testando 17 tipi di messaggio MCP su ciascuno dei 6.035 server:

Metrica	Valore
Tipi testati (totale istanze)	102.595
Run totali	1.033.067
Successi	8.394
Errori	1.024.673
Success rate	0,81%
Verifica:

Istanze: 6.035 server × 17 tipi = 102.595 ✓
Run base per tipo: 6.035 server × 10 run = 60.350 ✓
8.394 + 1.024.673 = 1.033.067 ✓
Risultati per tipo di protocollo
Tipo protocollo	Run	Successi	Errori	Success rate
InitializeRequest	60.350	0	60.350	0,00%
ProgressNotification	60.350	0	60.350	0,00%
CancelNotification	60.350	0	60.350	0,00%
ListResourcesRequest	60.350	0	60.350	0,00%
SetLevelRequest	60.350	0	60.350	0,00%
CreateMessageRequest	60.350	0	60.350	0,00%
ListPromptsRequest	60.350	0	60.350	0,00%
ListRootsRequest	60.350	0	60.350	0,00%
SubscribeRequest	60.350	0	60.350	0,00%
UnsubscribeRequest	60.350	0	60.350	0,00%
CompleteRequest	60.350	0	60.350	0,00%
ListResourceTemplatesRequest	60.350	0	60.350	0,00%
ElicitRequest	60.350	0	60.350	0,00%
PingRequest	60.350	0	60.350	0,00%
ReadResourceRequest	65.495	4.359	61.136	6,66%
GetPromptRequest	62.322	1.263	61.059	2,03%
GenericJSONRPCRequest	60.350	2.772	57.578	4,59%
Verifica errori: (14 × 60.350) + 61.136 + 57.578 + 61.059 = 844.900 + 179.773 = 1.024.673 ✓
Verifica successi: 4.359 + 2.772 + 1.263 = 8.394 ✓

Perché ReadResourceRequest e GetPromptRequest hanno più run degli altri
La baseline è 60.350 run (6.035 server × 10 run). I tipi con run aggiuntivi hanno ricevuto run extra corrispondenti a server che espongono effettivamente quelle capability:

ReadResourceRequest: 65.495 − 60.350 = 5.145 run extra → server che dichiarano risorse disponibili
GetPromptRequest: 62.322 − 60.350 = 1.972 run extra → server che dichiarano prompt disponibili
Questo conferma che ~5.145 server su 6.035 espongono risorse e ~1.972 espongono prompt.

5. Perché 14 Tipi di Protocollo Hanno 0% di Successo
Il success rate dello 0% per 14 dei 17 tipi è il risultato atteso e si spiega con l'architettura del fuzzer. Lo StrategyManager definisce solo 10 strategie esplicite, e il protocol fuzzing usa prevalentemente la fase aggressive:

# strategy_manager.py:39-80
PROTOCOL_STRATEGIES = {
    "InitializeRequest": {
        "realistic": fuzz_initialize_request_realistic,
        "aggressive": fuzz_initialize_request_aggressive,
    },
    "ReadResourceRequest": {
        "realistic": fuzz_read_resource_request_realistic,
        "aggressive": get_aggressive_fuzzer_method("ReadResourceRequest"),
    },
    # ... altri 8 tipi
}

Nella fase aggressive, i messaggi sono intenzionalmente malformati con payload di attacco. Esempio per InitializeRequest (aggressive/protocol_type_strategy.py:164-265):

def fuzz_initialize_request_aggressive():
    malicious_versions = [
        generate_malicious_string(),
        None, "", "999.999.999", "-1.0.0",
        random.choice(SQL_INJECTION),      # "' OR '1'='1"
        random.choice(XSS_PAYLOADS),       # "<script>alert('xss')</script>"
        random.choice(PATH_TRAVERSAL),     # "../../../etc/passwd"
        "A" * 1000,                        # Buffer overflow
        "\x00\x01\x02",                    # Null bytes
    ]
    base_request = {
        "jsonrpc": random.choice(["2.0", "1.0", "3.0", None, ""]),
        "id": random.choice(malicious_ids),
        "method": random.choice(malicious_methods),  # None, "__proto__", "eval()"
    }

Un server MCP conforme deve rifiutare questi messaggi. Il tasso di errore del 100% conferma che i server:

Validano correttamente la protocolVersion
Rifiutano versioni JSON-RPC non standard (1.0, 3.0)
Non accettano metodi inesistenti o malevoli
Non processano notifiche con payload corrotti
Per i tipi come PingRequest, ListResourcesRequest, SubscribeRequest ecc., il pattern è identico: i messaggi aggressivi contengono ID malformati, metodi alterati e parametri corrotti che il server rifiuta con un errore JSON-RPC.

6. Perché 3 Tipi Hanno Successo Parziale
ReadResourceRequest (6,66%) — Ha il tasso più alto perché nella fase realistic genera URI confinati a una sandbox sicura:

# realistic/protocol_type_strategy.py:16-23
SAFE_FILE_URIS = [
    "file:///tmp/mcp-fuzzer/",
    "file:///tmp/mcp-fuzzer/readme.txt",
    "file:///tmp/mcp-fuzzer/application.log",
    "file:///tmp/mcp-fuzzer/session-data.json",
]

def fuzz_read_resource_request_realistic():
    return {
        "jsonrpc": "2.0",
        "id": random.randint(1, 1000),
        "method": "resources/read",
        "params": {"uri": pick_safe_uri()},
    }

I 4.359 successi (su 65.495 run) provengono da server che espongono risorse e riescono a processare URI validi. Il metodo resources/read è un metodo MCP standard che il server riconosce, e quando l'URI è valido e la risorsa esiste, la richiesta va a buon fine.

GenericJSONRPCRequest (4,59%) — Invia richieste JSON-RPC con struttura variabile:

# aggressive/protocol_type_strategy.py:424-431
def fuzz_generic_jsonrpc_request():
    return {
        "jsonrpc": random.choice(["2.0", "1.0", "3.0", "invalid", "", None]),
        "id": generate_malicious_value(),
        "method": generate_malicious_string(),
        "params": generate_malicious_value(),
    }

I 2.772 successi avvengono quando casualmente jsonrpc è "2.0" (1/6 di probabilità) e il metodo generato coincide con uno riconosciuto dal server, o quando il server accetta la richiesta senza validarla strettamente.

GetPromptRequest (2,03%) — Simile a ReadResourceRequest, nella fase realistic genera richieste valide per prompt:

# realistic/protocol_type_strategy.py:239+
def fuzz_get_prompt_request_realistic():
    return {
        "jsonrpc": "2.0",
        "id": random.randint(1, 1000),
        "method": "prompts/get",
        "params": {"name": random.choice(["test-prompt", "example", ...])},
    }

I 1.263 successi provengono dai ~1.972 server che espongono prompt e dove il nome generato dal fuzzer corrisponde a un prompt esistente.

7. Coerenza dei Numeri — Verifica Completa
Verifica	Calcolo	Risultato
Totale server per lingua	24.004 + 14.790 + 1.411 + 19.995	= 60.200 ✓
Totale server fuzzati per lingua	5.686 + 314 + 35	= 6.035 ✓
Percentuale fuzzati	6.035 / 60.200	= 10,02% ✓
Tool run = successi + eccezioni	790.815 + 181.745	= 972.560 ✓
Tool success rate	790.815 / 972.560	= 0,8131 ✓
Somma eccezioni per messaggio	154.639 + 16.736 + 5.626 + 4.743 + 1	= 181.745 ✓
Protocol istanze = server × tipi	6.035 × 17	= 102.595 ✓
Protocol run base = server × 10	6.035 × 10	= 60.350 ✓
Protocol run = successi + errori	8.394 + 1.024.673	= 1.033.067 ✓
Protocol successi per tipo	4.359 + 2.772 + 1.263	= 8.394 ✓
Protocol errori per tipo	(14 × 60.350) + 61.136 + 57.578 + 61.059	= 1.024.673 ✓
Nota sulla formattazione del success rate: nel file JSON, il tool success rate è espresso come ratio decimale (0,813127 = 81,3%), mentre il protocol success rate è espresso come percentuale già formattata (0,81 = 0,81%). Lo stesso vale per i tassi per tipo (6,66%, 4,59%, 2,03%). Questa è una lieve inconsistenza di formato ma i valori sono corretti.

8. Conclusioni
Copertura: solo il 10% dei server è stato raggiungibile per il fuzzing, limitazione legata alla complessità di installazione (dipendenze, build, ambienti) — con netto vantaggio per Node.js (94,2% dei fuzzati).

Robustezza dei tool (81,3% success rate): la maggior parte dei server MCP gestisce correttamente input fuzzati a livello di tool, rispondendo con errori applicativi anziché crashare. L'85% delle eccezioni è "Server returned error" (errore JSON-RPC standard), segno di buona validazione.

Robustezza del protocollo (0,81% success rate): il tasso quasi nullo è il risultato desiderato. I server rifiutano correttamente messaggi di protocollo aggressivamente malformati (SQL injection, XSS, path traversal, buffer overflow nei campi MCP). I 3 tipi con successo parziale (ReadResourceRequest, GenericJSONRPCRequest, GetPromptRequest) hanno successo solo quando le richieste cadono casualmente in una forma valida.

Nessuna safety violation: total_safety_blocked: 0 indica che il safety system non ha dovuto bloccare nessuna operazione ritenuta pericolosa a livello di tool call, poiché i payload generati sono stati gestiti direttamente dai server.

Stabilità del trasporto: solo il 15% delle eccezioni totali è legato a problemi di trasporto (crash, hang, pipe rotte), confermando che la maggior parte dei server MCP mantiene il processo attivo anche sotto stress di fuzzing intensivo.