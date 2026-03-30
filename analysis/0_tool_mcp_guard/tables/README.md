# MCP Guard — Spiegazione dei grafici

**MCP Guard** e uno scanner Python a 3 livelli: analisi statica del codice sorgente (regex su pattern pericolosi), analisi dinamica simulata (genera finding basandosi sul codice senza avviare il server), e real fuzzing (avvia il server e invia payload malevoli). Assegna severity con CVSS v4.0 e AIVSS (AI Vulnerability Scoring System).

Server analizzati: **56.407** su 60.205 (93.69%)
Vulnerabilita totali trovate: **561.632** (media 9.96 per server)

---

## 01_languages.png — Distribuzione dei linguaggi

**Cosa mostra**: Distribuzione dei linguaggi di programmazione dei 56.407 server analizzati.

**Interpretazione**: Node.js (23.330) e Python (21.017) dominano il dataset, con Go (1.736), Docker (1.198) e unknown (9.126) in minoranza. La categoria "unknown" include server il cui linguaggio non e stato rilevato automaticamente dal parser. Questa distribuzione riflette l'ecosistema MCP reale, dove la maggior parte dei server sono implementati in TypeScript/JavaScript o Python.

---

## 02_severity.png — Distribuzione delle severity

**Cosa mostra**: Conteggio delle vulnerabilita per livello di severity (critical, high, medium, low).

**Interpretazione dei numeri**:
- **Medium (279.875, 49.8%)**: La maggioranza — include missing input validation, insecure endpoints, debug exposure
- **Critical (174.352, 31%)**: Numero molto alto, gonfiato dai 115.706 "command injection" dell'analisi dinamica simulata che NON avvia il server
- **High (106.715, 19%)**: Include path traversal, authorization bypass, hardcoded credentials
- **Low (690, 0.12%)**: Quasi assente

**Problema**: La distribuzione con 31% critical e anomala per uno scanner di sicurezza — in un assessment realistico ci si aspetterebbe una piramide inversa (molti low/medium, pochi high/critical). Questo conferma che l'analisi dinamica simulata gonfia le severity.

---

## 03_top_categories.png — Top 15 categorie di vulnerabilita

**Cosa mostra**: Le 15 categorie piu frequenti espresse in percentuale sul totale, aggregando tutte le fasi di analisi.

**Categorie principali e loro significato**:
- **Command Injection (20.6%)**: MCP Guard ha cercato tool con parametri che vengono passati a `subprocess.run()`, `os.system()`, `exec()`. Il 20.6% include sia finding reali (real fuzzing) sia simulati (dynamic). Non distingue tra i due nel conteggio aggregato
- **Insecure Endpoint/SSRF (13.4%)**: Server che fanno bind su `http://localhost:XXXX` — rilevato via analisi statica. E un rischio reale ma la severity dipende dal contesto di deployment
- **Missing Input Validation (8.3%)**: Pattern statico — qualsiasi handler MCP senza validazione esplicita dei parametri
- **Hardcoded Credentials (7.3%)**: Analisi statica trova stringhe che assomigliano a API key o password nel codice. Alto tasso di falsi positivi (variabili di esempio, placeholder)
- **Path Traversal (6.9%)**: Trovato sia staticamente (uso di `path.join` senza sanitizzazione) sia con fuzzing reale (`../../../../etc/passwd`)

---

## 04_analysis_types.png — Server per tipo di analisi

**Cosa mostra**: Quanti server sono stati analizzati da ciascuna fase.

- **Static (56.407, 100%)**: Tutti i server — analisi del codice sorgente con regex
- **Dynamic/Simulated (45.178, 80%)**: Analisi "dinamica" che in realta NON avvia il server ma simula cosa succederebbe basandosi sul codice. E la fonte principale di falsi positivi
- **Real Fuzzing (11.229, 19.9%)**: Server effettivamente avviati e testati con payload malevoli. Questi finding hanno la confidenza piu alta
- **Robustness Fuzzing (9.094, 16.1%)**: Sottocategoria del fuzzing che testa la resilienza (payload grandi, resource exhaustion)

**Punto chiave per la tesi**: Solo il ~20% dei server e stato testato con fuzzing reale. L'80% dei finding "dinamici" sono in realta simulazioni — questo e il limite strutturale principale di MCP Guard.

---

## 05_static.png — Top categorie dell'analisi statica

**Cosa mostra**: Le 10 categorie piu frequenti trovate dall'analisi statica (regex su codice sorgente).

**Interpretazione**:
- **mcp-tool-missing-input-validation (46.370)**: Quasi ogni server viene flaggato — il detector cerca handler `tools/call` senza validazione esplicita, ma molti server usano la validazione built-in dello schema JSON
- **unsafe-mcp-resource-access (33.142)**: Qualsiasi uso di `resources/read` senza controllo di accesso esplicito
- **unsafe-mcp-json-rpc-message-handling (30.551)**: Handler JSON-RPC senza sanitizzazione dei messaggi
- **mcp-handler-missing-authentication (20.097)**: Server senza autenticazione — corretto nella maggior parte dei casi dato che MCP su stdio non richiede auth

Questi numeri sono alti perche i pattern regex sono generici e non considerano il contesto.

---

## 06_dynamic_simulated.png — Top categorie dell'analisi dinamica simulata

**Cosa mostra**: Le categorie trovate dall'analisi "dinamica" che NON avvia realmente il server.

**Perche e problematico**:
- **Command Injection (115.706)**: Il numero piu alto. Il detector simula cosa succederebbe se un payload di injection venisse inviato a un tool che usa `exec()` o `subprocess` — ma non verifica che il payload raggiunga effettivamente quella funzione
- **Insecure Endpoint/SSRF (74.988)**: Qualsiasi endpoint HTTP trovato nel codice viene flaggato come potenziale SSRF
- **Hardcoded Credentials (41.077)**: Stringhe che matchano pattern di credenziali

Questi finding hanno bassa confidenza perche sono inferiti dal codice, non verificati a runtime.

---

## 07_real_fuzzing.png — Top categorie del fuzzing reale

**Cosa mostra**: Categorie trovate avviando effettivamente il server e inviando payload malevoli.

**Questi sono i finding piu affidabili di MCP Guard**:
- **Path Traversal (15.562)**: Il server ha accettato `../../../../etc/passwd` come input e ha risposto senza errore — vulnerabilita verificata
- **Command Injection (14.832)**: Il server ha accettato payload come `; id` o `$(whoami)` — verificato a runtime
- **Timeout/DoS (8.773)**: Il server ha rallentato o non ha risposto durante l'elaborazione di payload malevoli
- **Authorization Bypass (5.952)**: Tool protetti accessibili senza credenziali
- **Code Injection (4.190)**: Il server ha accettato payload `eval()` — verificato

A differenza dell'analisi dinamica simulata, questi numeri hanno alta confidenza perche il comportamento e stato osservato a runtime.

---

## 08_failure_reasons.png — Motivi di fallimento

**Cosa mostra**: Perche il 6.31% dei server (3.797) non e stato analizzato.

- **execution_timeout (1.764)**: Il server si e avviato ma non ha risposto entro il timeout
- **clone_failed (1.478)**: Impossibile clonare il repository (rimosso, privato, errore di rete)
- **config_build_failed (358)**: Impossibile costruire la configurazione di lancio
- **prepare_timeout (161)**: Timeout durante la preparazione (npm install, pip install)

Questi numeri sono ragionevoli e indicano un'infrastruttura di test funzionante.
