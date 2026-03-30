# MCP Check — Spiegazione dei grafici

**MCP Check** e un tool di conformance testing per il protocollo MCP. NON e uno scanner di sicurezza — testa la qualita dell'implementazione: handshake, discovery dei tool, validazione degli input, gestione degli errori, performance sotto carico, timeout e payload grandi.

Server analizzati: **34.404** su 60.205 (57.14%)
Test totali eseguiti: **217.656** (media 6.33 test per server)
Success rate complessivo: **52.83%**

---

## 01_languages.png — Distribuzione dei linguaggi

**Cosa mostra**: Linguaggi dei 34.404 server che MCP Check e riuscito ad avviare e testare.

**Interpretazione**: Node.js (20.303) e Python (13.017) dominano, con Go (1.084) in minoranza. Rispetto al dataset completo, mancano Docker (1.125) e unknown (13.451) — MCP Check richiede che il server si avvii e risponda al protocollo MCP, quindi i server senza un entry point chiaro o con dipendenze non risolvibili vengono esclusi. Il 42.86% di server non avviabili e il fattore principale della bassa copertura.

---

## 02_suite_results.png — Risultati per suite di test

**Cosa mostra**: Conteggio di test passed/failed/warnings per ciascuna delle 3 suite principali.

**Le 3 suite**:
- **Handshake (32.343 passed / 27.463 failed)**: Testa la connessione iniziale, la risposta a `initialize`, le capability dichiarate e il ping. I 27.463 failed sono principalmente server che non si avviano o non rispondono all'handshake MCP — non sono vulnerabilita ma problemi di deployment
- **Tool Discovery (36.527 passed / 27.193 failed)**: Testa l'enumerazione dei tool, la validita degli schema JSON, l'unicita dei nomi e la qualita delle descrizioni. I failed includono schema invalidi (35+104+22 server con schema tool non conformi) e server non connessi
- **Tool Invocation (46.125 passed / 46.270 failed)**: La suite piu critica — testa l'invocazione dei tool con input validi, invalidi e inesistenti, e verifica il determinismo. I 46.270 failed includono 12.277 tool che accettano input invalidi e 3.502 che non gestiscono tool inesistenti

**Perche tool-invocation ha quasi 50/50**: Questa suite include test volutamente negativi (input invalido, tool inesistente) che molti server falliscono perche non implementano validazione.

---

## 03_test_results_pie.png — Risultati complessivi

**Cosa mostra**: Distribuzione globale di tutti i 217.656 test eseguiti.

- **Passed (114.995, 52.83%)**: Test superati con successo
- **Failed (100.926, 46.37%)**: Test falliti — include sia problemi di connessione (server non avviati) che problemi di implementazione (input validation mancante)
- **Warnings (1.638, 0.75%)**: Problemi minori (es. tool con descrizioni vuote ma schema validi)
- **Skipped (97, 0.04%)**: Test non applicabili (es. resource-streaming su server senza risorse)

**Il 52.83% di success rate e basso**: Ma e inflazionato dal numero di server che non si avviano. Se consideriamo solo i server funzionanti, il success rate sale significativamente.

---

## 04_top_errors.png — Top 12 tipi di errore

**Cosa mostra**: I messaggi di errore piu frequenti durante i test.

**Errori principali e significato**:
- **Transport not connected (53.733)**: Il server non ha stabilito la connessione MCP — spesso perche non si e avviato. Questo singolo errore rappresenta oltre la meta di tutti i fallimenti
- **Failed to establish connection: Transport not connected (24.424)**: Variante dello stesso problema — il client non riesce a connettersi
- **Tool accepted invalid input without error (12.277)**: **Questo e il finding piu importante dal punto di vista della sicurezza.** 12.277 tool accettano input con tipo sbagliato (es. numero invece di stringa) o valori enum invalidi senza restituire errore. Questo indica assenza di validazione
- **Server did not return error for non-existent tool (3.502)**: 3.502 server non restituiscono errore quando si invoca un tool che non esiste — violazione della specifica MCP
- **Failed to establish connection: MCP error -32001: Request timed out (1.972)**: Server che si connettono ma non rispondono entro il timeout

**Punto chiave**: I primi 2 errori (78.157 totali) sono problemi infrastrutturali, non di implementazione. I finding significativi sono il 3° e il 4°.

---

## 05_success_rate.png — Barra del success rate

**Cosa mostra**: Visualizzazione sintetica del success rate globale (52.83%).

**Contesto**: Questo numero va letto insieme alla distribuzione degli errori. Se sottraiamo gli errori "Transport not connected" (problemi di avvio, non di implementazione), il success rate effettivo dei server funzionanti e significativamente piu alto. MCP Check e l'unico tool che fornisce un dato oggettivo pass/fail — non fa interpretazioni soggettive.
