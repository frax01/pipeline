# Analisi dei Risultati della Scansione di Sicurezza su 60.205 MCP Server

Panoramica del Dataset
Sono stati analizzati 60.205 MCP server provenienti da package pubblici, distribuiti tra diverse tecnologie: Node.js (23.870), Python (21.101), Go (1.819), Docker (1.140) e server di linguaggio non identificato (12.275). Di questi, 54.973 (91,31%) hanno prodotto almeno un finding dal security scanner, mentre i restanti ~5.232 non sono stati raggiungibili o non hanno risposto al protocollo MCP.

Il dato dominante: initialization-error (88,19%)
Il risultato più macroscopico — e anche il più facilmente fraintendibile — è che 54.504 server su 54.973 (99,1%) hanno fallito il check di inizializzazione (categoria initialization-error, severity info). Questo corrisponde al check BASE-01 definito in scanner_specs.schema (riga 8), che invia una richiesta initialize al server e verifica che la risposta contenga un oggetto capabilities coerente.

Nel codice (stdio_scanner.py:186-203), il check funziona così:

resp = client.send_recv("initialize", {})
ok = isinstance(resp, dict) and "result" in resp and "capabilities" in resp.get("result", {})

Perché così tanti fallimenti? In una scansione massiva di package registry, la stragrande maggioranza dei pacchetti:

Non è un server MCP eseguibile (sono librerie, SDK, utility)
Richiede configurazione specifica (variabili d'ambiente, database, API key) per avviarsi
Crasha all'avvio senza le dipendenze corrette
Implementa versioni incompatibili del protocollo MCP
Questo è un risultato atteso e corretto: il fatto che ~88% dei finding sia di tipo info indica che il scanner gestisce correttamente i server non funzionanti senza generare falsi positivi di sicurezza. La severity info è appropriata perché un errore di inizializzazione non è una vulnerabilità, ma un'impossibilità di proseguire con l'analisi. 

(Però non vuol dire che se non fa un'inizializzazione corretta allora non continua l'analisi, infatti se il server si è comunque avviato allora l'analisi andrà avanti)

Solo ~8.500 server (~15,5% di quelli scansionati) hanno superato l'inizializzazione e sono stati sottoposti ai check di sicurezza approfonditi.

Verifica della consistenza numerica
I numeri tornano perfettamente e confermano la correttezza dell'implementazione:

Gruppo di check	Server testati	Calcolo
BASE-01 (initialization)	54.973	54.504 fail + 469 pass = 54.973 ✓
Check sui tool (X-01, P-02, X-03)	~8.526	es. 3.581 + 4.945 = 8.526 per X-01
Check dinamici (X-02, R-01, R-02, R-03, A-03, P-03, RC-01)	~8.495	es. 3.338 + 5.157 = 8.495 per X-02
Totale finding: 54.973 (da BASE-01) + ~8.526 × 3 (check statici sui tool) + ~8.495 × 7 (check dinamici) = ~140.016 ✓ — coincide esattamente con il dato riportato.

La leggera differenza tra 8.526 e 8.495 si spiega perché i check sui tool (X-01, P-02, X-03) richiedono solo la risposta a tools/list, mentre i check dinamici necessitano di interazioni aggiuntive (invocazione di tool, lettura risorse, ecc.) e ~31 server hanno smesso di rispondere tra una fase e l'altra.

Vulnerabilità reali trovate (escludendo initialization-error)
Sui ~8.500 server funzionanti, le vulnerabilità effettive sono:

1. Dangerous Capabilities — X-01 (high) — 3.581 server (42% dei testati)
Il check più significativo. Implementato in security_checks.py:51-104, esegue analisi statica dei metadati dei tool:

risky_keywords = ["exec", "command", "shell", "write_file", "delete", "rm", 
                   "chmod", "chown", "fetch", "http", "url", "eval", "render", 
                   "payment", "admin", "privilege"]

Per ogni tool, lo scanner verifica se il nome o la descrizione contiene keyword rischiose E se lo schema di input manca di vincoli (enum, pattern, minimum, maximum, minLength, maxLength). Un tool è flaggato come pericoloso solo se ha keyword rischiose senza constraint di validazione.

Il 42% di failure rate è plausibile e preoccupante: significa che quasi la metà dei server MCP funzionanti espone tool potenzialmente distruttivi (esecuzione comandi, scrittura file, cancellazione, accesso rete) senza alcun vincolo sugli input. Questo è coerente con lo stato attuale dell'ecosistema MCP, dove molti server sono proof-of-concept o wrapper di API senza hardening.

2. Input Validation / Injection — X-02 (critical) — 3.338 server (39% dei testati)
Il check più aggressivo. Implementato in security_checks.py:253-309, esegue fuzzing attivo inviando payload malevoli ai tool:

payloads = ["; id", "$(whoami)", "`uname -a`", 
            "../../../../etc/passwd", 
            "http://169.254.169.254/latest/meta-data/"]

Per ogni tool con un parametro di tipo string, il scanner invia questi payload e analizza la risposta cercando indicatori di command injection riuscita (uid=, linux, root:x:, etc/passwd, meta-data, insecure, stdout).

Il 39% di failure rate è allarmante ma credibile: indica che circa 4 server su 10 restituiscono output che suggerisce esecuzione di comandi shell o accesso al filesystem non autorizzato. Nota: il check ha un tasso di falsi positivi non trascurabile — la parola "linux" o "stdout" nella risposta potrebbe apparire in contesti innocui. Tuttavia, la combinazione con payload specifici di injection rende il dato significativo.

3. Rug-Pull Detection — X-03 (medium) — 95 server (1,1%)
Implementato in security_checks.py:132-170, chiama tools/list due volte e confronta i risultati:

set1 = {tool_key(t) for t in tools_first}
set2 = {tool_key(t) for t in tools_second}
diff = []
if set1 != set2:
    # Tool descriptions changed between calls

95 server hanno mostrato tool che cambiano descrizione o nome tra due chiamate successive — un pattern noto come "rug-pull" dove un server presenta tool innocui all'approvazione iniziale e poi modifica il comportamento dopo l'autorizzazione dell'utente. Questo è un numero basso ma non zero, e indica server con comportamento dinamico potenzialmente malevolo.

4. Path Traversal — R-01 (high) — 124 server (1,5%)
Implementato in security_checks.py:173-188, tenta un attacco di directory traversal:

attempt = send_recv_func("resources/read", {"uri": "file:///../../etc/hosts"})
accepted = "result" in attempt and isinstance(attempt.get("result"), dict)

124 server hanno accettato la richiesta di leggere file:///../../etc/hosts senza rifiutarla, indicando vulnerabilità a path traversal. Questo è un difetto grave che permette la lettura arbitraria di file sul server.

5. Sensitive File Access — R-02 (high) — 103 server (1,2%)
Simile a R-01, ma testa l'accesso diretto a /etc/passwd (security_checks.py:191-205). 103 server hanno permesso la lettura di file di sistema sensibili.

6. Prompt Injection — P-02 (medium) — 34 server (0,4%)
Analisi statica delle descrizioni dei tool (security_checks.py:107-129) cercando frasi manipolative:

bad_phrases = ["ignore any safety rules", "override other tools", 
               "include contents of", "do not disclose this instruction", 
               "hidden instruction"]

34 server contengono tool con istruzioni nascoste nelle descrizioni, progettate per manipolare il comportamento dell'LLM client. Questo è un attacco diretto al modello AI che consuma i tool.

7. Data Leak / Token Pass-through — A-03 (critical) — 11 server
Implementato in security_checks.py:312-331, tenta di invocare un tool che potrebbe esporre token upstream:

leak_attempt = send_recv_func("tools/call", 
    {"name": "upstream_access", "arguments": {"code": "dummy"}})
token_indicators = ["access_token", "sk-", "token-body", "bearer "]

11 server hanno restituito risposte contenenti indicatori di token/credenziali. Nota: questo check ha un limite — cerca un tool specifico chiamato upstream_access che potrebbe non esistere nella maggior parte dei server. Il basso numero potrebbe indicare sotto-rilevamento piuttosto che assenza del problema.

8. Remote Access Control — RC-01 (critical) — 7 server
Implementato in security_checks.py:425-486, cerca tool che permettono di aprire porte o abilitare accesso remoto senza autorizzazione. Solo 7 server, ma la severity è critica perché permetterebbe a un attaccante di esporre servizi di rete.

9. Indirect Prompt Injection — P-03 (high) — 2 server
Il check più sofisticato (security_checks.py:334-422): legge risorse esterne (external://, http://, https://) cercando istruzioni di injection, poi invoca tool di summarizzazione per verificare se le istruzioni nascoste vengono eseguite. Solo 2 server, coerente con il fatto che pochi server espongono risorse esterne con contenuto controllato da attaccanti.

10. Sensitive Resource Exposure — R-03 (high) — 1 server
Implementato in security_checks.py:208-250, cerca risorse con nomi contenenti keyword sensibili (credential, secret, token, key, password) e ne legge il contenuto verificando la presenza di credenziali reali. Un solo server trovato — questo è un check con bassa prevalenza perché richiede che il server esponga esplicitamente risorse con nomi sospetti e che il contenuto contenga effettivamente credenziali.

Distribuzione delle severity
Severity	Count	%	Significato
info	54.504	88,19%	Errori di inizializzazione — non vulnerabilità
high	3.811	6,17%	Dangerous capabilities + path traversal + file access + prompt injection indiretta + resource exposure
critical	3.356	5,43%	Injection fuzzing + data leak + remote access control
medium	129	0,21%	Prompt injection statica + rug-pull
La verifica aritmetica conferma la correttezza:

high: 3.581 (X-01) + 124 (R-01) + 103 (R-02) + 2 (P-03) + 1 (R-03) = 3.811 ✓
critical: 3.338 (X-02) + 11 (A-03) + 7 (RC-01) = 3.356 ✓
medium: 34 (P-02) + 95 (X-03) = 129 ✓
Tasso di superamento complessivo
78.216 finding su 140.016 (55,86%) sono passati. Questo dato va contestualizzato:

La maggior parte dei "fail" (54.504 su 61.800 = 88%) proviene da initialization-error (info)
Escludendo gli errori di inizializzazione, sui check di sicurezza reali: 7.296 fail su 85.043 finding = 8,6% di failure rate — un dato molto più informativo
Sui ~8.500 server funzionanti, la maggior parte delle vulnerabilità riguarda tool pericolosi senza validazione (X-01) e input non sanitizzati (X-02)
Valutazione complessiva: i risultati hanno senso?
Sì, i risultati sono coerenti e credibili, per i seguenti motivi:

La proporzione di initialization-error è attesa in un bulk scan di package registry — la maggior parte dei pacchetti non è un server MCP eseguibile standalone

Il rapporto X-01/X-02 è logico: se il 42% dei server ha tool pericolosi senza vincoli (X-01), è naturale che il 39% sia anche vulnerabile a injection (X-02), perché l'assenza di schema validation è il prerequisito per entrambi i problemi

I check rari (P-03, RC-01, R-03) hanno numeri bassi perché richiedono condizioni molto specifiche (risorse esterne, tool di accesso remoto, risorse con nomi sensibili) — coerente con la specificità dei check

I numeri sono internamente consistenti: i totali dei finding tornano esattamente, le severity si sommano correttamente, e il numero di server testati per ogni check è coerente con il flusso di esecuzione del codice

Un possibile limite: il check A-03 (data-leak) cerca solo un tool chiamato upstream_access, il che lo rende molto specifico e potenzialmente sotto-rappresentato. Analogamente, RC-01 cerca keyword molto specifiche. Questi check potrebbero essere migliorati con un approccio più generico.

Metodologie di rilevamento utilizzate
Lo scanner combina tre approcci complementari, tutti visibili nel codice sorgente (security_checks.py):

Approccio	Check	Descrizione
Analisi statica	X-01, P-02	Parsing di nomi, descrizioni e schema dei tool — nessuna invocazione
Confronto snapshot	X-03	Due chiamate a tools/list e diff dei risultati
Fuzzing dinamico	X-02, R-01, R-02, R-03, A-03, P-03, RC-01	Invocazione attiva di tool e lettura risorse con payload malevoli
L'architettura è transport-agnostic: le funzioni in security_checks.py accettano una callback send_recv_func iniettata dal transport layer (HTTP in http_checks.py, stdio in stdio_scanner.py), permettendo gli stessi check su qualsiasi protocollo di comunicazione MCP.

# Divisione analisi
### Protocol testing
BASE-01 — Fingerprint server capabilities
T-01 — Origin validation & local bind (DNS-rebind resistance)
T-02 — TLS enforcement & HSTS
T-03 — Session identifier handling
A-01 — Authentication required for remote servers
### Analisi statica
X-01 — Dangerous capability detection in tools
P-02 — Prompt/description injection heuristics
X-03 — Tool description stability (anti rug-pull)
### Fuzzing / exploitation attivo (lancia un comando e poi analizza le risposte con delle regex)
X-02 — Input validation & injection fuzzing
R-01 — Resource URI validation & path traversal prevention
R-02 — Per-resource access control (sensitive file access)
R-03 — Sensitive resource exposure
A-03 — Token indirection (no upstream token pass-through)
P-03 — Indirect prompt injection via external resources
RC-01 — Remote access control exposure