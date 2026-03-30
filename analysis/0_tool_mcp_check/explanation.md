Analisi dei risultati mcp-check: test di conformance su 60.205 MCP server
1. Metodologia e dataset
L'analisi e stata condotta utilizzando mcp-check (v1.0.6) su un dataset di 60.205 repository/server MCP, distribuiti su 9 VM Linux (utente tecnico) per parallelizzare il workload. I risultati delle singole VM sono stati successivamente mergiati in un unico file di statistiche aggregate.

mcp-check esegue per default 3 suite di test su ogni server, come definito nella configurazione di default (src/core/config.ts):

const DEFAULT_CONFIG: ResolvedCheckConfig = {
  suites: ['handshake', 'tool-discovery', 'tool-invocation'],
  timeouts: {
    connectMs: 5000,
    invokeMs: 15000,
    shutdownMs: 3000,
    streamMs: 30000,
  },
  // ...
};

Ogni server viene avviato via stdio transport (il piu comune per server npm/pip), e sottoposto a:

Handshake: connessione, negoziazione capabilities, ping, discovery
Tool Discovery: enumerazione tool, validazione JSON Schema, controllo descrizioni
Tool Invocation: invocazione con input validi, input invalidi, tool inesistenti, determinismo, error handling
2. Numeri di alto livello - Verifica
2.1 Distribuzione per linguaggio (dataset completo)
Linguaggio	Server	%
Node.js	23.278	38,67%
Python	20.602	34,22%
Go	1.749	2,91%
Docker	1.125	1,87%
Unknown	13.451	22,34%
Totale	60.205	100%
Verifica: 23.278 + 20.602 + 1.749 + 1.125 + 13.451 = 60.205 ✓

2.2 Raggiungibilita: chi e stato testato?
Categoria	Server	%
Testati con successo (mcp-check)	34.404	57,14%
Falliti prima del test	25.801	42,86%
Totale	60.205	100%
Verifica: 34.404 + 25.801 = 60.205 ✓

Dei 34.404 server testati, la distribuzione per linguaggio e:

Linguaggio	Testati	Su totale	Tasso testabilita
Node.js	20.303	23.278	87,22%
Python	13.017	20.602	63,18%
Go	1.084	1.749	61,98%
Verifica testati: 20.303 + 13.017 + 1.084 = 34.404 ✓

I server Docker (1.125) e Unknown (13.451) hanno tasso di testabilita 0%: Docker richiede un container attivo, e i server "unknown" non sono stati identificati come eseguibili via stdio.

Server non testati per linguaggio: (23.278 - 20.303) + (20.602 - 13.017) + (1.749 - 1.084) + 1.125 + 13.451 = 2.975 + 7.585 + 665 + 1.125 + 13.451 = 25.801 ✓

2.3 Motivi di fallimento pre-test
Causa	Count	% su falliti
execution_timeout	22.778	88,28%
preparation_failed	2.992	11,60%
prepare_timeout	31	0,12%
Totale	25.801	100%
Verifica: 22.778 + 2.992 + 31 = 25.801 ✓

L'88% dei server non testabili e andato in timeout di esecuzione: il processo non ha risposto entro i limiti previsti. Questi sono tipicamente server che richiedono infrastrutture esterne (database, API, container Docker) per avviarsi, oppure che hanno errori di installazione delle dipendenze (npm install / pip install falliti).

3. Risultati dei test - Verifica
3.1 Sommario globale
Esito	Count	%
Passed	114.995	52,83%
Failed	100.926	46,37%
Warnings	1.638	0,75%
Skipped	97	0,04%
Totale test	217.656	100%
Verifica: 114.995 + 100.926 + 1.638 + 97 = 217.656 ✓
Success rate: 114.995 / 217.656 = 52,83% ✓

3.2 Risultati per suite
Suite	Passed	Failed	Warnings	Skipped	Totale	Pass rate
Handshake	32.343	27.463	0	0	59.806	54,08%
Tool Discovery	36.527	27.193	372	0	64.092	56,99%
Tool Invocation	46.125	46.270	1.266	97	93.758	49,20%
Totale	114.995	100.926	1.638	97	217.656	
Verifiche incrociate:

Passed: 32.343 + 36.527 + 46.125 = 114.995 ✓
Failed: 27.463 + 27.193 + 46.270 = 100.926 ✓
Warnings: 0 + 372 + 1.266 = 1.638 ✓
Skipped: 0 + 0 + 97 = 97 ✓
Totale: 59.806 + 64.092 + 93.758 = 217.656 ✓
4. Analisi degli errori per categoria
4.1 Problemi di connessione/trasporto (~80.000 errori)
Questo e il problema dominante dell'ecosistema. I due errori principali:

Errore	Count
Transport not connected	53.733
Failed to establish connection: Transport not connected	24.424
Failed to establish connection: MCP error -32001: Request timed out	1.972
Failed to establish connection: MCP error -32000: Connection closed	415
MCP error -32000: Connection closed	104
Expected timeout error but got: MCP error -32000: Connection closed	66
MCP error -32001: Request timed out	45
Perche succede: Il server viene avviato via StdioTransport (src/transports/stdio.ts), che spawna un processo figlio e comunica tramite stdin/stdout con messaggi JSON-RPC. Se il processo crasha, si blocca, o chiude lo stream prima che il test finisca, il transport risulta disconnesso. Il codice in src/transports/base.ts gestisce lo stato della connessione:

// src/transports/base.ts - gestione stato connessione
abstract class BaseTransport {
  protected _state: ConnectionState = 'disconnected';
  
  async connectWithRetry(target: Target, maxRetries: number): Promise<void> {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        await this.connect(target);
        return;
      } catch (error) {
        if (attempt === maxRetries) throw error;
        await this.delay(Math.pow(2, attempt) * 1000); // exponential backoff
      }
    }
  }
}

L'errore viene poi catturato nella handshake suite (src/suites/handshake.ts):

// src/suites/handshake.ts - cattura errori di connessione
} catch (error: any) {
  cases.push({
    name: 'connection-establishment',
    status: 'failed',
    durationMs: Date.now() - connectStart,
    error: {
      type: 'ConnectionError',
      message: `Failed to establish connection: ${error.message}`,
    },
  });
}

Cause principali:

Server che richiedono servizi esterni (DB, API) non disponibili nelle VM
Dipendenze non installate o incompatibili
Server che crashano durante l'inizializzazione
Timeout di connessione (default 5 secondi) troppo breve per server lenti
4.2 Validazione input assente (12.277 errori)
"Tool accepted invalid input without error": 12.277

Questo e il secondo errore piu significativo per gravita (non per volume). Il test in src/suites/tool-invocation.ts genera deliberatamente input invalidi e verifica che il server li rifiuti:

// src/suites/tool-invocation.ts - test input validation
if (tool.inputSchema) {
  const invalidInput = this.generateInvalidInput(tool);
  try {
    await client.callTool(toolName, invalidInput);
    // Se arriviamo qui, il tool NON ha rifiutato l'input invalido
    cases.push({
      name: `tool-${toolName}-input-validation`,
      status: 'failed',
      durationMs: Date.now() - invalidStart,
      error: {
        type: 'ValidationFailure',
        message: 'Tool accepted invalid input without error',
      },
    });
  } catch {
    // OK: il tool ha correttamente rifiutato l'input
    cases.push({ name: `tool-${toolName}-input-validation`, status: 'passed', ... });
  }
}

Perche succede: 12.277 tool su migliaia di server non validano gli input secondo il proprio inputSchema. Accettano qualsiasi dato senza sollevare errori. Questo significa che:

Molti server MCP definiscono un JSON Schema per i propri tool ma poi non lo applicano a runtime
E un problema di sicurezza: un LLM potrebbe inviare dati malformati che vengono accettati silenziosamente
I framework MCP (specialmente quelli Python) spesso non implementano validazione automatica
4.3 Gestione tool inesistenti (3.502 errori)
"Server did not return error for non-existent tool": 3.502

Il test invoca un tool con nome inventato e verifica che il server risponda con un errore:

// src/suites/tool-invocation.ts - test tool inesistente
const nonExistentToolName = '__mcp_check_nonexistent_tool__';
try {
  await client.callTool(nonExistentToolName, {});
  // Se arriviamo qui, il server non ha restituito errore
  cases.push({
    name: 'error-handling-nonexistent-tool',
    status: 'failed',
    error: {
      type: 'ErrorHandlingFailure',
      message: 'Server did not return error for non-existent tool',
    },
  });
} catch {
  // OK: il server ha correttamente restituito un errore
  cases.push({ name: 'error-handling-nonexistent-tool', status: 'passed', ... });
}

Perche succede: 3.502 server non gestiscono correttamente le chiamate a tool inesistenti. Invece di rispondere con un errore MCP -32601 (Method not found), restituiscono una risposta vuota, generica, o addirittura tentano di eseguire qualcosa. Secondo la specifica MCP, il server DEVE restituire un errore per tool sconosciuti.

4.4 Problemi di protocollo: Method not found
"Ping failed: MCP error -32601: Method not found: ping": 32
"Ping failed: MCP error -32601: Method not found": 28
"Ping failed: MCP error -32601: Method 'ping' not found": 2
"Resource discovery failed: MCP error -32601: Method not found": 180
"Tool discovery failed: MCP error -32601: Method not found": 11

Perche succede: Questi server non implementano metodi previsti dalla specifica MCP:

ping non supportato (~62 server): il metodo ping e parte della specifica MCP base, ma alcuni server non lo implementano
Resource discovery non supportato (180 server): il server dichiara di supportare risorse nelle capabilities ma non implementa resources/list
Tool discovery non supportato (11 server): non implementano tools/list pur dichiarando supporto tools
4.5 Schema invalidi dei tool
"1 tools have invalid schemas": 104
"2 tools have invalid schemas": 35
"3 tools have invalid schemas": 22
"4 tools have invalid schemas": 8
...fino a "36 tools have invalid schemas": 1

Il test di validazione schema in src/suites/tool-discovery.ts verifica che ogni tool abbia un inputSchema conforme a JSON Schema (tipo "object"):

// src/suites/tool-discovery.ts - validazione schema
const schemaErrors = tools.filter(tool => {
  if (!tool.inputSchema) return true;
  if (tool.inputSchema.type !== 'object') return true;
  return false;
}).length;

if (schemaErrors > 0) {
  cases.push({
    name: 'tool-schema-validation',
    status: 'failed',
    error: {
      type: 'InvalidToolSchemas',
      message: `${schemaErrors} tools have invalid schemas`,
    },
  });
}

Perche succede: Molti server definiscono inputSchema con tipo diverso da "object" (es. "string", "array", o omettono il campo type), violando la specifica MCP che richiede inputSchema.type = "object".

4.6 Credenziali e API key mancanti
Centinaia di errori specifici per server, tutti con la stessa causa: il server richiede variabili d'ambiente o API key che non sono configurate nelle VM di test. Esempi:

"MCP error -32603: ALGOLIA_APP_ID and ALGOLIA_WRITE_API_KEY environment variables are required": 2
"MCP error -32600: FASTMAIL_API_TOKEN environment variable is required": 3
"MCP error -32603: GYAZO_ACCESS_TOKEN environment variable is required": 3
"MCP error -32603: Missing Jira configuration. Please set JIRA_BASE_URL...": 3
"MCP error -32603: RAINDROP_TOKEN is not set": 3
"MCP error -32603: Authentication Failed: Requires authentication": 13

Perche succede: Questi sono server MCP che wrappano API di terze parti (Algolia, Jira, GitHub, Gyazo, ecc.). Senza le credenziali, i tool rispondono con errori -32603 (Internal Error) o -32600 (Invalid Request). Il pattern tipico e che la connessione e l'handshake funzionano, la tool discovery funziona, ma la tool invocation fallisce perche il tool tenta effettivamente di chiamare l'API esterna.

Il codice MCP Error -32603 corrisponde a InternalError nella specifica JSON-RPC 2.0, mentre -32602 e InvalidParams e -32600 e InvalidRequest.

4.7 Errori specifici di piattaforma
Dato che le VM sono Linux, diversi server pensati per macOS o Windows falliscono:

"osascript: not found" (server macOS con AppleScript): ~15 occorrenze
"spawn powershell.exe ENOENT" (server Windows): 2 occorrenze  
"Playwright/Puppeteer browser not installed": ~30 occorrenze
"docker: not found": ~5 occorrenze
"Flutter SDK not found in PATH": 2 occorrenze
"kubectl ENOENT": ~3 occorrenze

5. Analisi dei warnings
5.1 Comportamento non deterministico (1.266 warnings)
"Tool behavior appears non-deterministic with identical inputs": 1.266

Questo warning viene dalla suite tool-invocation, che esegue lo stesso tool con gli stessi input piu volte e confronta i risultati:

// src/suites/tool-invocation.ts - test determinismo
// Il test invoca lo stesso tool con input identici e confronta le risposte
// Se le risposte differiscono, viene emesso un warning
warnings: [
  'Tool behavior appears non-deterministic with identical inputs',
],

Perche succede: 1.266 tool producono risultati diversi con input identici. Questo e normale per tool che:

Restituiscono dati in tempo reale (meteo, stock, news)
Includono timestamp nella risposta
Generano ID casuali
Dipendono da stato esterno
Non e necessariamente un bug, ma e un segnale di attenzione per gli LLM che potrebbero aspettarsi risposte consistenti.

5.2 Tool senza descrizione (372 warnings)
"1 tools lack descriptions": 120 server
"2 tools lack descriptions": 46 server
"3 tools lack descriptions": 29 server
...fino a "313 tools lack descriptions": 1 server

Il codice in src/suites/tool-discovery.ts verifica che ogni tool abbia una description:

// src/suites/tool-discovery.ts - controllo descrizioni
const toolsWithoutDescription = tools.filter(t => !t.description);
if (toolsWithoutDescription.length > 0) {
  // Registra warning
  warnings: [
    `${toolsWithoutDescription.length} tools lack descriptions`,
  ],
}

Somma di tutti i warning "tools lack descriptions": 120 + 46 + 29 + 25 + 19 + 18 + 14 + ... = 372 ✓ (corrisponde esattamente ai 372 warnings della suite tool-discovery)

Perche e grave: La description del tool e il meccanismo principale con cui un LLM decide quale tool usare. Senza descrizione, il tool e sostanzialmente invisibile al modello.

Verifica totale warnings: 1.266 (tool-invocation) + 372 (tool-discovery) = 1.638 ✓

6. Verifica incrociata finale
Metrica	Calcolata	Dichiarata	Match
Totale server	23.278+20.602+1.749+1.125+13.451	60.205	✓
Server testati	20.303+13.017+1.084	34.404	✓
% testati	34.404/60.205	57,14%	✓
Server non testati	60.205-34.404	25.801	✓
% non testati	25.801/60.205	42,86%	✓
Failure reasons total	22.778+2.992+31	25.801	✓
Totale test	59.806+64.092+93.758	217.656	✓
Totale passed	32.343+36.527+46.125	114.995	✓
Totale failed	27.463+27.193+46.270	100.926	✓
Totale warnings	0+372+1.266	1.638	✓
Totale skipped	0+0+97	97	✓
Success rate	114.995/217.656	52,83%	✓
Tutti i numeri tornano. Non ci sono incongruenze nei dati aggregati.

7. Sintesi e interpretazione
Lo stato dell'ecosistema MCP in numeri
Il 42,86% dei server MCP non e nemmeno avviabile in un ambiente standard. Quasi la meta dell'ecosistema e composta da server che non possono essere testati senza infrastrutture specifiche (database, API key, container Docker, servizi cloud).

Dei server avviabili, solo il 52,83% dei test passa. L'ecosistema MCP ha un serio problema di qualita: quasi la meta dei test case fallisce.

Il problema n.1 e la stabilita delle connessioni. Con oltre 78.000 errori legati a "Transport not connected", molti server crashano o chiudono la connessione durante i test. Questo suggerisce fragilita nella gestione del ciclo di vita del processo.

Il problema n.2 e la mancanza di validazione input. 12.277 tool accettano dati invalidi senza errore, esponendo potenziali vulnerabilita quando un LLM invia input malformati.

Node.js ha il miglior tasso di testabilita (87,22%) rispetto a Python (63,18%) e Go (61,98%). Questo riflette la maturita dell'SDK MCP per Node.js (@modelcontextprotocol/sdk) e la maggiore standardizzazione del packaging npm.

Python ha il peggior delta di testabilita: 7.585 server Python (il 36,82%) non sono avviabili, probabilmente a causa di problemi di dipendenze (versioni Python incompatibili, pacchetti mancanti, virtual environment non gestiti).

L'ecosistema e fortemente dipendente da servizi esterni: centinaia di errori diversi relativi a API key mancanti dimostrano che una larga parte dei server MCP e un thin wrapper su API di terze parti, inutilizzabile senza credenziali.