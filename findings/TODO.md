1. Ricontrollare tutti i finding per vedere vp e fp, siamo sicuri che siano tutti vp quelli che ho trovato? Non c'è un modo per ricontrollare ulteriormente ed essere molto stringenti nell'analisi? Mi sembra che ci siano forse troppi vp o che alcune volte questi vp siano un pò lasciati al caso. Forse può essere utile campionare un pò i dati
2. Come vedi nella cartella C:\Users\francesco\Desktop\pipeline\findings mancano le cartelle per mcp-guard e mcp-fuzzing, le puoi fare? Sai come farle? Forse puoi prendere spunto dalle cartelle degli altri framework
4. Mi riguardi tutte le sezioni del file e vedi se tornano tutti i numeri e tutte le cose che ho scritto?
5. Sapresti darmi le fonti di tutte le regole che hai creato? Devo documentarci la mia tesi e soprattutto devo presentarle al prof
8. Mi spieghi meglio tutta la parte del protocol fuzzing?
Sia questa parte:

#### Appendice B: tool_fuzzing/protocol-fuzzing (1 categoria su 17 sub-protocol)

Pipeline: 103.394 raw (6.082 server × 17 protocol type) → Stage 1 (filter intermedio per success_rate 5-95%) → 3.511 filtrati → Stage 2A → Stage 2B → **1.562 VP / 1.949 FP**.

Probe runtime: invia richieste JSON-RPC malformate per ogni protocol type MCP.

| Sub-protocol type | Note |
|-------------------|------|
| InitializeRequest | server processa init malformato (security relevant) |
| ReadResourceRequest | server accetta resource read malformato |
| GenericJSONRPCRequest | server processa metodo arbitrario |
| CreateMessageRequest | server processa LLM call malformato |
| altri 13 protocol type | informational (ListPrompts, Ping, ecc.) |

| Filtered | VP | FP |
|---------:|---:|---:|
| 3.511 | 1.562 | 1.949 |

che questa parte:

### 6.2 Schema povero del fuzzing (`tool_fuzzing`)

Il campo `success_details` nei dati raw è quasi sempre vuoto. Vediamo solo il counter "successful=N" senza il payload effettivamente accettato. Il segnale per protocol-fuzzing è quindi debole: i VP sono "potenziali" e non confermati.

## Appendice B — `tool_fuzzing/protocol-fuzzing` (compliance JSON-RPC)

`tool_fuzzing/protocol-fuzzing` invia 6.082 server × 17 tipi di richieste JSON-RPC malformate (Initialize, ReadResource, GetPrompt, ListResources, CreateMessage, ecc.) e misura quanti server processano la richiesta invalida.

### B.1 Numeri

**Veri Positivi totali**: 1.562
**Server unici interessati**: ~1.300

### B.2 Categorie analizzate

| Categoria | VP | Note |
|-----------|---:|------|
| `protocol-fuzzing` (17 protocol type aggregati) | 1.562 | Server processa con successo richieste JSON-RPC malformate su metodi MCP standard. Il counter `successful=N` indica accettazione, ma il payload effettivo non è disponibile (`success_details` array vuoto) |

### B.3 Perché in Appendice (non Core)

A differenza di `mcp-watch/protocol-violation` (transport security, session ID in URL, server processa version invalida — security MCP) e `mcp-guard/protocol-*` (probe specifici su missing-id e invalid-version), `tool_fuzzing/protocol-fuzzing` testa la **conformità generale** del server al protocollo JSON-RPC su tutti i 17 metodi MCP

### B.4 Limiti del segnale

Il campo `success_details` nei dati raw è quasi sempre vuoto. Il VP è "potenziale" e non confermato: vediamo solo il counter "successful=N", non il payload effettivamente accettato dal server. Questo limite, combinato con la natura di compliance test, motiva la collocazione in Appendice piuttosto che nel Core.

Anche qui non sto capendo bene cosa dice e soprattutto la parte del success_details=N

9. è possibile in qualche modo come viene detto in questa sezione

## 6. Limiti dell'Analisi

### 6.1 SAST regex-only (`mcp-guard`, `mcp-watch`)

Pattern matching senza analisi del data flow. Un pattern sintattico VP non sempre corrisponde a una vulnerabilità reale.

**Esempio**: `cursor.execute(f"... {t}")` viene marcato come VP, ma se la variabile `t` proviene da una query precedente su `sqlite_master` (sorgente fidata), si tratta di un Falso Positivo nascosto. Distinguere questi casi richiederebbe AST parsing e data-flow tracking.

**Stima dei FP residui sui VP statici**:

| Categoria | VP raw | FP rate stimato | VP reali stimati |
|-----------|-------:|----------------:|-----------------:|
| sql-injection | 2.382 | 30-50% | 1.190-1.670 |
| dangerous-capabilities | 1.991 | 15-20% | 1.590-1.690 |
| credential-leak | 1.552 | 10-15% | 1.320-1.400 |
| path-traversal | 1.296 | 5-10% | 1.165-1.230 |
| ssrf | 717 | 5-10% | 645-680 |
| input-validation | 208 | 10-20% | 165-185 |
| altre statiche | ~600 | 5-15% | 510-570 |

Arrivare ad avere un numero preciso di vp e fp e non solo una stima?
10. Ma perchè nella parte core del fuzzing in C:\Users\francesco\Desktop\pipeline\THREAT_ANALYSIS_REPORT.md viene messo solo il server crash (che poi è solo 1) e nient'altro? Sono tutti fp gli altri? Infatti perchè nel fuzzing queste 4 categorie sono praticamente tutti fp? Mi rifai un recap fatto bene (qui in chat) di come funziona il fuzzing e di come lo abbiamo suddiviso in tutte queste analisi?

## 4. Categorie output (4)

Mapping 22 file raw → 4 categorie: 

| # | Categoria | Source files | Filt entries |
|---|-----------|--------------|-------------:|
| 1 | `server-error-fuzzing` | exceptions/Server_returned_error.json | 10.944 |
| 2 | `transport-failure-fuzzing` | 3 file exceptions: Failed_to_send + Failed_to_receive + No_response | 3.385 |
| 3 | `server-crash-fuzzing` | exceptions/'int'_object_has_no_attribute_'get'.json | 1 |
| 4 | `protocol-fuzzing` | 17 file protocol/* (merged) | 3.511 |

**Riduzione Stage 1**: 118.756 → 17.841 (-85%)

---

## 5. Risultati finali (post spot-check fix)

**Pipeline: 118.756 raw → 17.841 filtered → 1.563 VP / 16.278 FP / 0 UNC**

| Categoria | Filt | VP | FP | VP% |
|-----------|-----:|---:|---:|----:|
| server-error-fuzzing | 10.944 | 0 | 10.944 | 0% |
| transport-failure-fuzzing | 3.385 | 0 | 3.385 | 0% |
| server-crash-fuzzing | 1 | 1 | 0 | 100% |
| protocol-fuzzing | 3.511 | 1.562 | 1.949 | 44.5% |
| **TOTALE** | **17.841** | **1.563** | **16.278** | **8.8%** |

Il file lo trovi in C:\Users\francesco\Desktop\pipeline\analysisAllData\0_tool_fuzzing\ANALYSIS_GUIDE.md
11. Mi fai una tabella di copertura dei vari framework sulla lista di tutti i server che sto analizzando?


###

Conitnuare il filtro e salvare tutti i dati, in particolare salvare anche le varie regole dei vari stage che avrà generato in più nelle analisis che ha fatto