# Fuzzing (MCP Fuzzer) — Spiegazione dei grafici

**MCP Fuzzer** e un fuzzer Python che avvia ogni server MCP e invia input mutati ai tool in due fasi: (1) realistic — input plausibili con variazioni casuali; (2) aggressive — payload malevoli (SQL injection, XSS, path traversal, buffer overflow). Esegue anche protocol fuzzing inviando messaggi MCP malformati (InitializeRequest con campi mancanti, ProgressNotification con payload invalidi, ecc.). Conta successi ed eccezioni senza classificare vulnerabilita di sicurezza.

Server analizzati: **6.035** su 60.205 (10.02%)
Tool totali fuzzati: **48.093**
Run totali di fuzzing: **972.560** (tool) + **1.033.067** (protocol) = **2.005.627**
Success rate tool fuzzing: **81.3%**
Safety blocked: **0**

---

## 01_languages.png — Distribuzione dei linguaggi

**Cosa mostra**: Linguaggi dei 6.035 server fuzzati.

**Interpretazione**: Node.js (5.686, 94.2%) domina massicciamente, con Go (314) e Python (35) quasi assenti. La copertura bassissima (10%) e dovuta al requisito piu stringente di tutti i tool: il fuzzer deve avviare il server, connettersi via MCP, enumerare i tool E invocarli ripetutamente con input mutati. I server Python tendono ad avere piu dipendenze esterne non risolvibili, il che spiega la loro quasi totale assenza.

---

## 02_tool_fuzzing_results.png — Risultati del fuzzing sui tool

**Cosa mostra**: Dei 972.560 run di fuzzing (invocazioni di tool con input mutati), quanti hanno avuto successo vs eccezione.

- **Successful (790.815, 81.3%)**: Il tool ha risposto senza errore all'input mutato. Questo puo significare sia che il tool e robusto sia che accetta qualsiasi input senza validazione
- **Exceptions (181.745, 18.7%)**: Il tool ha restituito un errore o e crashato

**Ambiguita del success rate**: Un success rate dell'81.3% NON e necessariamente positivo. Se il tool accetta `../../../../etc/passwd` come path senza errore, conta come "successo" — ma in realta indica assenza di validazione. Il fuzzer non distingue tra "robustezza" e "assenza di validazione".

---

## 03_exception_types.png — Tipi di eccezione

**Cosa mostra**: Distribuzione delle 181.745 eccezioni per tipo.

- **Server returned error (154.639, 85.1%)**: Il server ha risposto con un errore JSON-RPC. Questo e il comportamento CORRETTO — il server ha ricevuto input invalido e lo ha rifiutato. Non e una vulnerabilita
- **Failed to receive message from stdio transport (16.736, 9.2%)**: Il server ha chiuso la connessione senza rispondere — possibile crash o timeout
- **No response received from stdio transport (5.626, 3.1%)**: Il server non ha risposto entro il timeout — possibile DoS o loop infinito
- **Failed to send message over stdio transport (4.743, 2.6%)**: Errore di comunicazione — il server potrebbe essere crashato
- **Too many responses (1)**: Il server ha inviato risposte multiple per una singola richiesta — bug di implementazione

**Punto chiave**: L'85% delle "eccezioni" sono in realta risposte d'errore corrette. Le eccezioni preoccupanti sono le 22.362 (12.3%) dove il server non ha risposto o ha chiuso la connessione — possibili crash o DoS.

---

## 04_protocol_success_rates.png — Success rate per tipo di messaggio protocollo

**Cosa mostra**: Per ciascuno dei 17 tipi di messaggi MCP malformati inviati, la percentuale di successo (il server ha risposto positivamente al messaggio malformato).

**Interpretazione critica**:
- **0% success per 14/17 tipi**: InitializeRequest, ProgressNotification, CancelNotification, ListResourcesRequest, SetLevelRequest, CreateMessageRequest, ListPromptsRequest, ListRootsRequest, SubscribeRequest, UnsubscribeRequest, CompleteRequest, ListResourceTemplatesRequest, ElicitRequest, PingRequest — tutti i server hanno correttamente rifiutato i messaggi malformati. Questo e il risultato ATTESO e POSITIVO
- **ReadResourceRequest (6.66%)**: 4.359 server hanno risposto positivamente a una richiesta di lettura risorsa malformata — possibile mancanza di validazione
- **GenericJSONRPCRequest (4.59%)**: 2.772 server hanno risposto a richieste JSON-RPC generiche non standard — possibile handler troppo permissivo
- **GetPromptRequest (2.03%)**: 1.263 server hanno risposto a richieste prompt malformate

**Il 0% success rate NON e un problema**: E il risultato corretto. I server rifiutano messaggi malformati come dovrebbero. Presentare il 0% come "fallimento" (come fa il tool) e fuorviante — e in realta un successo di sicurezza.

---

## 05_summary_table.png — Tabella riassuntiva

**Cosa mostra**: Metriche chiave aggregate.

| Metrica | Valore | Significato |
|---|---|---|
| Total Servers | 6.035 | Solo il 10% del dataset — bassa copertura |
| Total Tools | 48.093 | ~8 tool per server in media |
| Total Fuzzing Runs | 972.560 | ~161 invocazioni per server |
| Tool Fuzzing Success Rate | 81.3% | Ambiguo — successo = risposta senza errore |
| Protocol Fuzzing Success Rate | 0.81% | Correttamente basso — i server rifiutano messaggi malformati |
| Safety Blocked | 0 | Il safety system non ha MAI agito — indica che non e implementato o e disabilitato |

**Conclusione**: Il fuzzer e utile come stress test (trova crash e timeout) ma non come scanner di vulnerabilita. Non classifica i finding per tipo o severity, non distingue tra "input accettato perche valido" e "input accettato perche non validato", e il safety system a 0 suggerisce che non aggiunge analisi di sicurezza oltre al conteggio di successi/errori.
