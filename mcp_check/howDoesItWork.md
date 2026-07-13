# MCP Check: How It Works

Questo strumento utilizza un approccio strutturato a **"suite di test"** (Test Suites) per eseguire controlli di qualità, resilienza e aderenza al protocollo ufficiale MCP. Ogni suite si concentra su un aspetto specifico delle prestazioni o dell'affidabilità del server.

Le suite registrate sono **esattamente 6** (`src/suites/index.ts`); ognuna implementa `TestSuitePlugin` ed è composta da più **case** (sotto-test). La sezione **Test eseguiti** di ogni suite elenca *tutti* i case presenti nel sorgente, così da coprire ogni test possibile. La funzione di *chaos engineering* (`src/chaos/`) è una feature separata di fault-injection, non una test suite, e non è documentata qui.

Ecco la spiegazione dettagliata per ogni suite, mantenendo l'intera densità informativa originale.

---

## 1. HandshakeTestSuite
* **Cos'è**: Valida l'inizializzazione del protocollo MCP, assicurandosi che la fase di "handshake" (connessione iniziale e negoziazione delle capacità) avvenga correttamente rispettando gli standard dell'SDK ufficiale.
* **Esempio di Match**: Verifica che il server accetti la connessione, risponda tempestivamente a un comando di ping, e riesca a elencare correttamente i tools, le resources e i prompts supportati.
* **Test eseguiti** (6 case, `src/suites/handshake.ts`):
    1. **`connection-establishment`**: stabilisce la connessione (prova prima il transport SDK, con fallback a un adapter custom per trasporti come TCP) e misura `connectionTimeMs`.
    2. **`server-capabilities-validation`**: incrocia le capabilities restituite con `config.expectations` tramite `validateServerCapabilities`.
    3. **`ping-test`**: chiama `client.ping()` misurando `Date.now() - pingStart`.
    4. **`tool-discovery`**: `client.listTools()` (solo se il server dichiara la capability `tools`).
    5. **`resource-discovery`**: `client.listResources()` (solo se dichiara `resources`).
    6. **`prompt-discovery`**: `client.listPrompts()` (solo se dichiara `prompts`).
* **Esempio concreto** (`ping-test` + `server-capabilities-validation`): il server risponde al ping in 12 ms → case `ping-test` = `passed` con `responseTimeMs: 12`. Se però la config richiede `requireTools: true` ma il server non espone la capability `tools`, il case `server-capabilities-validation` = `failed` con errore `CapabilitiesMismatch: "Server does not support tools but they are required"`.

## 2. LargePayloadTestSuite
* **Cos'è**: Testa la resilienza del server MCP sotto sforzo quando è costretto a gestire grandi quantità di dati (payload pesanti), prevenendo crash o colli di bottiglia legati alla memoria.
* **Esempio di Match**: Il server non deve andare in crash se riceve una stringa in input lunga centinaia di kilobyte, se genera un output JSON enorme o se viene richiamato ripetutamente consumando RAM in modo anomalo (memory leak).
* **Test eseguiti** (5 case, `src/suites/large-payload.ts`):
    1. **`testLargeInputPayload`**: cerca il primo tool con un parametro di tipo "string" e invia via `callTool` stringhe generate con `'x'.repeat(size)` per ogni size in `[1024, 10240, 102400]` byte (configurabile via `testParameters.payloadSizes`); registra `largestSuccessfulBytes`.
    2. **`testLargeOutputPayload`**: cerca un tool il cui nome contiene `large`/`payload`/`data`/`json` (altrimenti usa `tools[0]`), lo invoca e misura la dimensione della risposta con `responseSizeBytes = JSON.stringify(result).length`.
    3. **`testLargeJsonStructure`**: per un tool con parametro `array`/`object`, crea un array di 100 elementi (`{id, name, data: 'x'.repeat(100)}`) oppure un oggetto con 50 chiavi profondamente nidificate e lo passa al server.
    4. **`testMemoryStability`**: profila `process.memoryUsage().heapUsed` all'inizio e alla fine di N cicli di richieste (default 10, richiamando opzionalmente `global.gc()` per forzare la pulizia). Emette `warning` se la crescita supera la soglia (default 10 MB, `memoryGrowthThresholdMB`).
    5. **`testResourceContentSize`**: legge fino a 5 resources (`readResource`) e somma i byte letti (`totalBytesRead`), segnalando le letture fallite.
* **Esempio concreto** (`testLargeInputPayload`): manda al primo tool con input string tre payload da 1 KB, 10 KB e 100 KB (`'x'.repeat(102400)`). Se il server regge fino a 10 KB ma fallisce a 100 KB, il case è `warning` con `largestSuccessfulBytes: 10240` e warning `"Only handled payloads up to 10240 bytes successfully"`.

## 3. StreamingTestSuite
* **Cos'è**: Verifica le capacità del server di sopportare elaborazioni in parallelo (concorrenza), richieste rapide e flussi di dati (streaming).
* **Esempio di Match**: Gestire con successo 5 chiamate dello stesso tool lanciate nel medesimo istante senza generare errori interni.
* **Test eseguiti** (4 case, `src/suites/streaming.ts`):
    1. **`testRapidRequests`**: invia una raffica di `client.ping()` in un ciclo for (default 10, `testParameters.rapidRequestCount`) e le attende contemporaneamente con `Promise.all(requests)`; calcola `averageResponseTime`.
    2. **`testLongRunningOperations`**: invoca `tools[0]` con `{ test: 'long-running-simulation' }` per simulare un'operazione lunga e ne misura `operationTime`.
    3. **`testConcurrentCalls`**: istanzia 5 `client.callTool()` passando `{ concurrent: true, callId: i }` nello stesso momento, valutando poi per quanti l'esito non contiene errori (`successCount = results.filter((r) => !r.isError).length`).
    4. **`testResourceStreaming`**: chiama `readResource(resource.uri)` sul primo resource valutando il tempo speso (`readTime`) e i frammenti ricevuti (`contentCount`); `skipped` se il server non supporta resources.
* **Esempio concreto** (`testConcurrentCalls`): lancia simultaneamente 5 chiamate allo stesso tool con `{ concurrent: true }`. Se tutte e 5 tornano senza `isError` → `passed`; se anche una sola fallisce → `failed` con messaggio `"4 out of 5 concurrent calls failed"`.

## 4. TimeoutTestSuite
* **Cos'è**: Controlla che il server non rimanga bloccato in operazioni a ciclo infinito e gestisca correttamente le situazioni in cui il tempo limite scade.
* **Esempio di Match**: Un'operazione lenta di rete che dura troppo deve essere interrotta dal server in modo sicuro. Il server non deve rimanere paralizzato per connessioni abortite e deve sapersi "riprendere" per servire le chiamate successive.
* **Test eseguiti** (5 case, `src/suites/timeout.ts`):
    1. **`testConnectionTimeout`**: utilizza `Promise.race()` mettendo in competizione la connessione al server `client.connectFromTarget()` con un `setTimeout()` (pari a `connectMs + 1000`) che genera un'eccezione se si supera il tempo limite.
    2. **`testInvocationTimeout`**: cerca specificamente tool che contengono le stringhe "slow" o "delay" nel nome (altrimenti usa `tools[0]`) e ne invoca l'esecuzione, registrando un `warning` se l'esecuzione supera il parametro `invokeMs` (default 10 secondi).
    3. **`testConcurrentTimeouts`**: invoca fino a 3 tool diversi (`testParameters.concurrentRequestCount`) contemporaneamente con `Promise.allSettled` e conta quante richieste risultano `fulfilled`.
    4. **`testTimeoutRecovery`**: esegue una prima richiesta, attende volutamente 100 ms, ed esegue una seconda richiesta per assicurarsi che il socket/servizio sia di nuovo disponibile (`secondRequestSucceeded`).
    5. **`testProgressiveTimeout`**: esegue fino a 5 invocazioni ripetute misurando min/max/media dei tempi di risposta e la `varianceMs`; imposta il flag `consistent` se la varianza resta sotto 2× la media.
* **Esempio concreto** (`testTimeoutRecovery`): invoca un tool, aspetta 100 ms, poi lo re-invoca. Se la seconda chiamata riesce (`secondRequestSucceeded: true`) il server ha "recuperato" correttamente → `passed`; altrimenti → `warning` con `"Server may have issues recovering after requests"`.

## 5. ToolDiscoveryTestSuite
* **Cos'è**: Si occupa di ispezionare tutti i tool dichiarati e certifica che le informazioni strutturali fornite all'intelligenza artificiale siano impeccabili, coerenti e senza conflitti.
* **Esempio di Match**: Il test solleva errori in presenza di tool con lo stesso nome, tool che non hanno il campo `description` compilato o, ancor più grave, tool i cui parametri input non rispettano il formato valido JSON Schema richiesto.
* **Test eseguiti** (5 case, `src/suites/tool-discovery.ts`): lo scanner integra la libreria **Ajv** configurandola in modo custom e compila un rigoroso meta-schema formale (`JSON_SCHEMA_META`).
    1. **`tool-enumeration`**: `client.listTools()`, conta i tool e misura `responseTimeMs`.
    2. **`required-tools-validation`**: confronta i tool dichiarati obbligatori in `expectations.tools` (con `required: true`) con quelli effettivamente trovati; `failed`/`MissingRequiredTools` se ne mancano.
    3. **`tool-schema-validation`**: sottopone il nodo `inputSchema` di ogni tool al controllo semantico `schemaValidator(tool.inputSchema)`, più controlli di integrità logica: che i campi citati in `required` esistano dentro `properties`, e che restrizioni come `maxLength`/`minLength`, `maximum`/`minimum`, `maxItems`/`minItems` non siano in conflitto matematico (oltre a regex valide ed enum non vuoti).
    4. **`unique-tool-names`**: applica `findDuplicates` sui nomi; `DuplicateToolNames` se ci sono collisioni.
    5. **`tool-description-quality`**: emette un `warning` per i tool privi del campo `description`.
* **Esempio concreto** (`tool-schema-validation`): un tool con un parametro string che dichiara `minLength: 5` e `maxLength: 3` viene bocciato — il case diventa `failed` (`InvalidToolSchemas`) con il dettaglio `Property "campo": minLength (5) > maxLength (3)`.

## 6. ToolInvocationTestSuite
* **Cos'è**: Si tratta di un test di esecuzione reale e profondo (un vero e proprio "fuzzing"). Lo scanner formula input fittizi basati sugli schemi JSON dichiarati dai tool e li lancia attivamente al server, monitorando la risposta.
* **Esempio di Match**: Manda un intero o valori illogici laddove il server richiedeva una email o un enum specifico. Controlla che le funzioni dichiarate siano "deterministiche" (se chiamo la stessa funzione due volte con le stesse variabili, mi deve restituire esattamente lo stesso risultato).
* **Selezione dei tool**: lo scanner testa i tool dichiarati attesi in `expectations.tools` più un massimo di 3 tool scoperti non attesi (`testParameters.maxUnexpectedTools`). *Nota: in questa versione del sorgente non esiste un filtro `readOnly`/anti-mutazione — ogni tool selezionato viene effettivamente invocato, anche con payload grandi o invalidi.*
* **Test eseguiti** (`src/suites/tool-invocation.ts`) — per **ogni tool** selezionato vengono eseguiti 3 case, più 2 case globali:
    1. **`tool-<name>-basic-invocation`**: `generateBasicInput` costruisce ricorsivamente un payload lecito (solo i campi `required`, con valori validi per tipo/`format` — es. `format: "email"` → `'test@example.com'`), invoca il tool e valida la risposta con `validateToolResponse` (deve avere un array `content` e ogni elemento un campo `type`).
    2. **`tool-<name>-input-validation`** (fuzzing): `generateInvalidValueForProperty` invia volutamente valori illegali — `'!@#$%^&*()_+[]{}|;:,.<>?'` per campi vincolati da `pattern`, `INVALID_ENUM_VALUE_<timestamp>` per gli `enum`, tipi sbagliati per number/boolean/array. Il case è `passed` se il server **rifiuta** l'input (solleva un errore), `failed` se lo **accetta senza errore** (`"Tool accepted invalid input without error"`).
    3. **`tool-<name>-deterministic-behavior`**: esegue `client.callTool(toolName, deterministicInput)` due volte di seguito ed esegue una `compareResults` sulle due stringhe JSON dei risultati. Se i payload non combaciano al 100%, emette un `warning` di instabilità deterministica.
    4. **`timeout-handling`** (`testTimeouts`, globale): invoca `tools[0]` con un timeout ridotto (`min(invokeMs, 5000)`); un errore di timeout è considerato `passed` (comportamento atteso), un altro errore è `failed`.
    5. **`error-handling-nonexistent-tool`** (`testErrorHandling`, globale): chiama un tool inesistente (`non-existent-tool-<timestamp>`) e si aspetta un errore; `failed` se il server non lo restituisce.
* **Esempio concreto** (`tool-<name>-input-validation`): per un campo `email` l'input valido è `test@example.com`; la variante invalida, per un campo con `pattern`, è `'!@#$%^&*()_+[]{}|;:,.<>?'` e per un `enum` è `INVALID_ENUM_VALUE_<timestamp>`. Il case è `passed` se il server rifiuta l'input sollevando un errore, `failed` se lo accetta senza segnalare nulla.
