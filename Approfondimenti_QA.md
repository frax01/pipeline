# Approfondimenti per il Q&A

Due concetti che potrebbero chiederti in sede di discussione. Per ognuno: prima la **risposta breve** (quella che dici a voce), poi l'**approfondimento** se vogliono i dettagli.

---

## 1. Stage 2A — le regole di dominio: come erano fatte e cosa guardavano

### Risposta breve
«Lo Stage 2A è un insieme di regole *ad alta confidenza*, una per categoria di vulnerabilità. Ogni regola non guarda solo lo snippet di codice, ma **triangola tre segnali**: lo snippet, l'**identità del server** (nome, linguaggio, path del file) e il verdetto interno del framework. Le ho costruite empiricamente, leggendo a mano un campione dei finding grezzi categoria per categoria e codificando in regole le strutture ricorrenti dei falsi positivi e dei veri positivi certi. Ogni finding viene marcato come *falso positivo certo*, *vero positivo certo*, oppure *incerto* — e gli incerti passano all'LLM nello Stage 2B.»

### In dettaglio

**I tre segnali che ogni regola incrocia:**
1. **Lo snippet** — la riga di codice segnalata (l'"evidence"): c'è davvero un input non controllato che arriva a un *sink* pericoloso (exec, spawn, query, ecc.)?
2. **L'identità del server** — nome, linguaggio, path del file. Serve a capire il *contesto*: è un file di test o di terze parti? è un server honeypot (volutamente vulnerabile)? è un server il cui *scopo dichiarato* è proprio quell'operazione?
3. **Il verdetto interno del framework** — ad esempio il risk score che alcuni scanner (come mcp-shield) producono già da soli.

**Come sono state costruite — processo empirico e iterativo:**
1. Faccio girare lo scanner → ottengo i finding grezzi di una categoria.
2. Leggo a mano un campione → capisco *perché* lo scanner sbaglia (la struttura ricorrente dei falsi positivi) e quali sono i veri positivi inequivocabili.
3. Codifico ogni pattern ricorrente (sia FP che VP) in una regola; ciò che resta genuinamente ambiguo lo lascio **UNCERTAIN**.
4. Ri-eseguo, ri-ispeziono, raffino.

**L'output di ogni regola è una di tre etichette:**
- **HC-FP** — falso positivo certo (es. match dentro un file di test/vendor, bundle minificato, codice commentato, placeholder, server honeypot, chiamata SDK che *sembra* un sink ma non lo è).
- **HC-VP** — vero positivo certo (es. una chiave che ha il formato reale di un provider: `sk-…`, `AKIA…`, `ghp_…`).
- **UNCERTAIN** — non decido io, lo passo all'LLM (Stage 2B).

Le regole sono **conservative**: marcano HC solo quando sono certe, altrimenti lasciano UNCERTAIN. Quindi non gonfiano i risultati.

**L'esempio della slide (f-string / `execute_sql`) mappato ai tre segnali:**
Uno scanner segnala `cursor.execute(f"... {table}")` come **SQL injection**, perché una variabile viene concatenata dentro una query. La regola di dominio guarda:
- **snippet:** sì, c'è un'f-string che costruisce una query;
- **identità del server:** è un server *database* il cui compito dichiarato è eseguire SQL (espone un tool tipo `execute_sql`, o il nome/descrizione lo dicono);
- **verdetto:** coerente.

→ Conclusione: **HC-FP**. Eseguire SQL arbitrario *è la funzione voluta* di quel server, non una vulnerabilità. Lo **stesso identico snippet** in un server che *non* è un runner SQL, dove `table` arriva da un argomento non attendibile del tool, sarebbe invece un vero positivo. È esattamente il **contesto** che un semplice regex (Stage 1) non vede e che lo Stage 2A aggiunge tramite l'identità del server.

**Esempio di pseudo-regola (categoria credential-leak):**
```python
def hc_rules_credential_leak(f):
    name = f["server_name"]
    ev   = f["evidence"]
    # server volutamente vulnerabili / honeypot → falso positivo certo
    if name in _CL_INTENTIONAL_VULN:
        return "HC-FP", "intentional_vuln"
    # chiave con formato reale di un provider (sk-, AKIA, ghp_) → vero positivo certo
    if re.search(r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_\w{30,}", ev):
        return "HC-VP", "provider_key"
    return "UNCERTAIN", ""   # → lo decide l'LLM allo Stage 2B
```

### La domanda scomoda (probabile): "regole fatte a mano sugli stessi dati non rischiano overfitting/bias?"
Risposta: «Sì, è il rischio intrinseco delle euristiche. Proprio per questo la loro affidabilità **non è assunta ma misurata in modo indipendente** dall'audit manuale contro il codice sorgente reale, che è un ground truth *esterno* alle regole — ed è esattamente ciò che produce il 64,8% di precisione. Inoltre le regole sono conservative: decidono solo i casi su cui sono sicure, tutto il resto lo lasciano all'LLM.»

---

## 2. Cos'è la recall (e perché misuro la precision ma non la recall)

### Risposta breve
«La **precision** risponde a: *di tutto ciò che gli strumenti segnalano, quanto è realmente una vulnerabilità?* La **recall** risponde alla domanda opposta: *di tutte le vulnerabilità reali che esistono, quante ne hanno effettivamente trovate?* Io misuro la precision — il 64,8% — perché per la recall servirebbe conoscere il numero *totale* delle vulnerabilità presenti, incluse quelle che nessuno strumento ha segnalato; e questo richiederebbe un benchmark etichettato di tutte le vulnerabilità MCP, che non esiste, o l'audit manuale di tutti i 69.000 server, che è impraticabile.»

### In dettaglio

Ogni finding può cadere in una di quattro caselle (matrice di confusione):

| | È una vera vulnerabilità | NON è una vulnerabilità |
|---|---|---|
| **Lo strumento la segnala** | True Positive (TP) | False Positive (FP) |
| **Lo strumento NON la segnala** | False Negative (FN) | True Negative (TN) |

- **Precision** = TP / (TP + FP) → *"quando lo strumento dice «vulnerabilità», quanto spesso ha ragione?"* Guarda solo le cose **segnalate**.
- **Recall** = TP / (TP + FN) → *"di tutte le vulnerabilità che ci sono davvero, quante ne ho catturate?"* Include anche i **FN**, cioè le vulnerabilità **mancate**.

**Analogia della rete da pesca:**
- *Precision* = quanto è pulito il pescato (quanti pesci veri rispetto alla spazzatura tirata su).
- *Recall* = quanta parte di tutti i pesci del mare sei riuscito a prendere (quanti te ne sono sfuggiti).

**Perché nella tesi misuro la precision ma non la recall:**
Per calcolare la precision mi basta prendere i finding **segnalati** e verificare a mano se sono veri o falsi (TP vs FP) — ed è quello che ho fatto con l'audit sui 1.579 finding. Per la recall invece mi servirebbero i **False Negative**: cioè le vulnerabilità reali che *nessuno strumento ha segnalato*. Ma non puoi contare ciò che non hai trovato senza:
- un **benchmark pubblico etichettato** di tutte le vulnerabilità MCP (non esiste), **oppure**
- l'**audit manuale esaustivo di ogni server** (69.000 server → impraticabile).

**Cosa implica per i risultati:**
- Il 64,8% e i ~18.100 riguardano la **qualità di ciò che gli strumenti segnalano**, non la loro **copertura**.
- Le vulnerabilità reali nell'ecosistema potrebbero essere **di più** di quelle trovate: quello che gli strumenti mancano (i FN) resta fuori dalla misura.
- Per questo nelle *Limitations* dico "precision, not recall": è un limite noto e **intrinseco al campo** (manca un ground truth), non un difetto del metodo.
- Il *proxy-based LLM fuzzing* proposto nei Future Works aiuta sul lato **sfruttabilità a runtime**, ma non risolve del tutto la recall.
