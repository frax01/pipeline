# Cross-Tool Comparison Charts

Questi 4 grafici mettono a confronto tutti e 7 i tool di analisi eseguiti sullo stesso dataset di **60.205 server MCP** raccolti dal registry pubblico. Servono a evidenziare le differenze strutturali tra gli scanner in termini di copertura, volume di finding, sensibilita e affidabilita.

---

## 00_cross_tool_coverage.png — Copertura server per tool

**Cosa mostra**: Percentuale e numero assoluto di server che ogni tool e riuscito ad analizzare con successo sui 60.205 totali.

**Perche i numeri variano cosi tanto**: Ogni tool ha requisiti diversi per poter analizzare un server:
- **MCP Guard (93.7%)** e **MCP Security Scan (91.3%)** hanno la copertura piu alta perche eseguono anche analisi statica del codice sorgente — non hanno bisogno di avviare il server
- **MCP Watch (78%)** clona il repo e scansiona i file sorgente con regex, quindi funziona sulla maggior parte dei server con codice accessibile
- **MCP Check (57.1%)** deve avviare il server e stabilire una connessione MCP — il 42.9% dei server non si avvia (dipendenze mancanti, configurazione, servizi esterni richiesti)
- **MCP Shield (19%)** e **MCP Scan/Snyk (17.8%)** devono avviare il server E enumerare i tool via protocollo MCP — pipeline piu fragile
- **Fuzzing (10%)** e il piu restrittivo: deve avviare il server, connettersi, enumerare i tool E invocarli con input mutati

**Implicazione**: Un tool con alta copertura non e necessariamente migliore — MCP Guard e MCP Watch hanno alta copertura proprio perche fanno analisi superficiale (regex su codice), mentre Snyk ha bassa copertura perche fa analisi profonda (avvia il server e interroga un backend LLM).

---

## 00_cross_tool_vulnerabilities.png — Volume totale di issue per tool

**Cosa mostra**: Numero totale di issue/finding riportati da ogni tool, in scala logaritmica per gestire la varianza estrema (da 5.352 a 9.911.265).

**Interpretazione dei numeri**:
- **MCP Watch (9.9M)**: Il numero piu alto di 3 ordini di grandezza rispetto a Snyk. Questo non significa che ha trovato piu vulnerabilita reali — i suoi pattern regex sono cosi generici che `import { X } from "../utils/Y"` viene contato come path traversal, e `public` come keyword TypeScript diventa "public output" in un toxic flow. ~95% sono falsi positivi stimati
- **MCP Guard (561K)**: Numero gonfiato dall'analisi "dinamica simulata" che non avvia realmente il server ma genera finding basandosi su pattern nel codice. 115.706 "command injection" sono simulati, non verificati
- **Fuzzing (181K)**: Conta eccezioni (errori del server durante fuzzing), NON vulnerabilita classificate. Un'eccezione puo essere sia un crash reale che un corretto rifiuto di input invalido
- **MCP Check (100K)**: Conta test falliti (conformita al protocollo), non vulnerabilita di sicurezza. Include "Transport not connected" (53.733) che sono server che non si avviano
- **MCP Security Scan (61.8K)**: 88% sono "initialization-error" (info) — correttamente non classificati come vulnerabilita. I finding reali sono ~7.300
- **MCP Shield (6.8K)** e **MCP Scan/Snyk (5.3K)**: I numeri piu contenuti e realistici

**Nota a pie di pagina**: MCP Check conta failed tests e Fuzzing conta exceptions — non sono direttamente comparabili con le vulnerabilita degli altri tool.

---

## 00_cross_tool_avg_vulns.png — Media issue per server

**Cosa mostra**: Rapporto tra issue totali e server analizzati, sempre in scala logaritmica.

**Perche questa metrica e importante**: Normalizza il volume rispetto alla copertura. Un tool che analizza pochi server ma trova molti issue per server e piu "rumoroso" di uno che analizza molti server trovandone pochi.

- **MCP Watch (210.96/server)**: Ogni server genera in media 211 finding — chiaramente insostenibile per un analista. Un singolo file TypeScript puo generare decine di finding per pattern generici
- **Fuzzing (30.12/server)**: Ogni server testato genera ~30 eccezioni durante il fuzzing, il che e ragionevole dato che il fuzzer invia centinaia di input mutati per server
- **MCP Guard (9.96/server)**: ~10 finding per server, gonfiato dall'analisi statica e dinamica simulata
- **MCP Check (2.93/server)**: ~3 test falliti per server in media, ragionevole per un test di conformita
- **MCP Security Scan (1.12/server)**: ~1 finding per server, ma include gli initialization error
- **MCP Shield (0.60/server)**: Meno di 1 tool vulnerabile per server in media
- **MCP Scan/Snyk (0.50/server)**: Il rapporto piu basso — solo 1 finding ogni 2 server

---

## 00_cross_tool_false_positives.png — Stima del tasso di falsi positivi

**Cosa mostra**: Stima qualitativa della percentuale di finding che sono falsi positivi, basata sull'analisi manuale dei risultati e della metodologia di ogni tool.

**Come sono state calcolate le stime** (da analisi manuale documentata in `toolExplained.md`):
- **MCP Check (7.5%)**: I test sono oggettivi (pass/fail), quindi quasi nessun falso positivo. Il 7.5% tiene conto di server che falliscono per ragioni ambientali (dipendenze mancanti sul runner) non per bug reali
- **MCP Scan/Snyk (20%)**: I W001 "dangerous words" generano falsi positivi quando parole come "important" o "critical" sono usate in contesti legittimi. Gli E001 (prompt injection via LLM) sono piu affidabili
- **MCP Security Scan (27.5%)**: L'injection fuzzing (X-02) puo avere falsi positivi quando il server risponde con parole come "linux" o "stdout" in contesti innocui
- **MCP Shield (65%)**: Il detector "sensitive-file-access" (75% dei finding) e troppo aggressivo — qualsiasi tool che menziona "reads", "content", "file" viene flaggato
- **MCP Guard (75%)**: L'analisi "dinamica simulata" genera finding senza avviare il server — il problema strutturale principale
- **MCP Watch (95%)**: Pattern regex cosi generici che praticamente ogni file sorgente genera decine di finding
- **Fuzzing (N/A)**: Non classifica vulnerabilita, quindi il concetto di falso positivo non si applica

**La linea rossa al 50%**: Soglia indicativa — tool sopra il 50% generano piu rumore che segnale, rendendo l'output poco utile senza un pesante lavoro di triage manuale.
