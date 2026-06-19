# MCP Check: How It Works

Questo strumento utilizza un approccio strutturato a **"suite di test"** (Test Suites) per eseguire controlli di qualità, resilienza e aderenza al protocollo ufficiale MCP. Ogni suite si concentra su un aspetto specifico delle prestazioni o dell'affidabilità del server.

Ecco la spiegazione dettagliata per ogni suite di test trovata nei file sorgenti, mantenendo l'intera densità informativa originale.

---

## 1. HandshakeTestSuite
* **Cos'è**: Valida l'inizializzazione del protocollo MCP, assicurandosi che la fase di "handshake" (connessione iniziale e negoziazione delle capacità) avvenga correttamente rispettando gli standard dell'SDK ufficiale.
* **Esempio di Match**: Verifica che il server accetti la connessione, risponda tempestivamente a un comando di ping, e riesca a elencare correttamente i tools, le resources e i prompts supportati.
* **Dettaglio Tecnico**: Lo scanner istanzia un `MCPTestClient` e tenta una connessione tramite il trasporto configurato. Invia richieste SDK standard come `client.ping()`, `client.listTools()` e `client.listResources()` misurandone il tempo di risposta (`Date.now() - pingStart`). Valida poi l'oggetto restituito incrociandolo con la configurazione attesa (`validateServerCapabilities`).

## 2. LargePayloadTestSuite
* **Cos'è**: Testa la resilienza del server MCP sotto sforzo quando è costretto a gestire grandi quantità di dati (payload pesanti), prevenendo crash o colli di bottiglia legati alla memoria.
* **Esempio di Match**: Il server non deve andare in crash se riceve una stringa in input lunga centinaia di kilobyte, se genera un output JSON enorme o se viene richiamato ripetutamente consumando RAM in modo anomalo (memory leak).
* **Dettaglio Tecnico**: Lo scanner esegue varie routine:
    * **In testLargeInputPayload**: cerca un parametro di tipo "string" e invia via `callTool` stringhe generate con `'x'.repeat(size)` arrivando fino a 102.400 byte.
    * **In testLargeJsonStructure**: crea array di 100 elementi o oggetti profondamente nidificati e li passa al server.
    * **In testMemoryStability**: fa una profilazione richiamando l'API `process.memoryUsage().heapUsed` all'inizio e alla fine di cicli ripetuti di richieste (richiamando opzionalmente `global.gc()` per forzare la pulizia in memoria). Fallisce se la crescita in megabyte supera la soglia specificata.

## 3. StreamingTestSuite
* **Cos'è**: Verifica le capacità del server di sopportare elaborazioni in parallelo (concorrenza), richieste rapide e flussi di dati (streaming).
* **Esempio di Match**: Gestire con successo 5 chiamate dello stesso tool lanciate nel medesimo istante senza generare errori interni.
* **Dettaglio Tecnico**:
    * **La funzione testRapidRequests**: invia una raffica di chiamate `client.ping()` in un ciclo for e le attende contemporaneamente tramite `Promise.all(requests)`.
    * **La funzione testConcurrentCalls**: istanzia molteplici `client.callTool()` passando la variabile `{ concurrent: true }` nello stesso momento, valutando poi per quanti di essi l'esito non contiene errori (`successCount = results.filter((r) => !r.isError).length`).
    * **La funzione testResourceStreaming**: chiama `readResource(resource.uri)` valutando il tempo speso e i frammenti inviati in risposta.

## 4. TimeoutTestSuite
* **Cos'è**: Controlla che il server non rimanga bloccato in operazioni a ciclo infinito e gestisca correttamente le situazioni in cui il tempo limite scade.
* **Esempio di Match**: Un'operazione lenta di rete che dura troppo deve essere interrotta dal server in modo sicuro. Il server non deve rimanere paralizzato per connessioni abortite e deve sapersi "riprendere" per servire le chiamate successive.
* **Dettaglio Tecnico**:
    * **In testConnectionTimeout**: utilizza `Promise.race()` mettendo in competizione la connessione al server `client.connectFromTarget()` con un `setTimeout()` che genera un'eccezione se si supera il tempo limite.
    * **In testInvocationTimeout**: il test cerca specificamente tool che contengono le stringhe "slow" o "delay" nel nome e ne invoca l'esecuzione, registrando un fallimento o warning se l'esecuzione supera il parametro `invokeTimeout` (es. 10 secondi).
    * **In testTimeoutRecovery**: simula un'eccezione, attende volutamente 100ms, ed esegue una seconda richiesta per assicurarsi che il socket/servizio sia di nuovo disponibile (`secondRequestSucceeded`).

## 5. ToolDiscoveryTestSuite
* **Cos'è**: Si occupa di ispezionare tutti i tool dichiarati e certifica che le informazioni strutturali fornite all'intelligenza artificiale siano impeccabili, coerenti e senza conflitti.
* **Esempio di Match**: Il test solleva errori in presenza di tool con lo stesso nome, tool che non hanno il campo `description` compilato o, ancor più grave, tool i cui parametri input non rispettano il formato valido JSON Schema richiesto.
* **Dettaglio Tecnico**: Lo scanner integra la libreria **Ajv** configurandola in modo custom e compila un rigoroso meta-schema formale (`JSON_SCHEMA_META`).
    * **Interroga la lista tool** con `client.listTools()`. Sottopone il nodo `inputSchema` di ogni tool al controllo semantico `schemaValidator(tool.inputSchema)`. Esegue anche controlli di integrità logica (es. assicura che tutti i campi citati nell'array `required` esistano effettivamente dentro `properties`).
    * **Chiama una logica custom** iterando su stringhe, numeri e array per assicurarsi che restrizioni come `maxLength` non siano in conflitto matematico con `minLength`.

## 6. ToolInvocationTestSuite
* **Cos'è**: Si tratta di un test di esecuzione reale e profondo (un vero e proprio "fuzzing"). Lo scanner formula input fittizi basati sugli schemi JSON dichiarati dai tool e li lancia attivamente al server, monitorando la risposta.
* **Esempio di Match**: Manda un intero o valori illogici laddove il server richiedeva una email o un enum specifico. Controlla che le funzioni dichiarate siano "deterministiche" (se chiamo la stessa funzione due volte con le stesse variabili, mi deve restituire esattamente lo stesso risultato).
* **Dettaglio Tecnico**: Lo scanner salta preventivamente i tool considerati "mutanti" (`isReadOnly: false`) per evitare danni.
    * **Generazione Input Corretto**: Analizza ricorsivamente le proprietà del JSON schema per costruire programmaticamente un payload lecito (se l'input atteso ha format "email", il mock genera `'test@example.com'`).
    * **Fuzzing (Invalid Input)**: La funzione `generateInvalidValueForProperty` invia volutamente caratteri speciali `!@#$%^&*()_+[]{}|;:,.<>?` a campi ristretti da regex o `INVALID_ENUM_VALUE`. Verifica che per questi attacchi il server non vada in crash, ma attivi la flag MCP `isError: true` o inserisca una riga di testo tipo "error" nella risposta.
    * **Test Deterministico**: Esegue `client.callTool(toolName, deterministicInput)` per due volte di seguito ed esegue una `compareResults` sulle due stringhe JSON dei risultati. Se i payload non combaciano al 100%, emette un warning di instabilità deterministica.
