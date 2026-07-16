## 1. Credential leak non è statico? Perchè si trova nella tabella dinamica? (slide 11)
Il credential leak è statico ma ad alta precisione perché non è un pattern generico: matcha i formati esatti delle chiavi dei provider — lo stesso metodo di gitleaks — quindi un match è quasi sempre un segreto reale.

Perchè le altre sono classificate come dinamiche?
- Untrusted content (mcp-scan): non cerca un pattern, capisce che quel tool recupera contenuto da una fonte esterna e lo passa al modello. Quando lo segnala, il significato è chiaro → quasi nessun falso positivo.
- Sensitive info disclosure (mcp-guard e mcp-server-fuzzer): Invoca davvero il tool e ispeziona la risposta a runtime: se nella risposta compaiono variabili d'ambiente, root:x:, /etc/passwd… la fuga è osservata, non ipotizzata. O c'è o non c'è → 100%.
- Prompt injection (mcp-shield): legge e interpreta la docstring per trovare istruzioni nascoste ("nascondi i passaggi all'utente", "manda le email a…"). Alta, ma sotto il 100% perché qualche descrizione borderline può sembrare injection senza esserlo.

Quindi poi la precisione dipende dalla tecnica di rilevamento.

## 2. Cos'è la recall (e perché misuro la precision ma non la recall)

«La **precision** risponde a: *di tutto ciò che gli strumenti segnalano, quanto è realmente una vulnerabilità?* La **recall** risponde alla domanda opposta: *di tutte le vulnerabilità reali che esistono, quante ne hanno effettivamente trovate?* Io misuro la precision — il 64,8% — perché per la recall servirebbe conoscere il numero *totale* delle vulnerabilità presenti, incluse quelle che nessuno strumento ha segnalato; e questo richiederebbe un benchmark etichettato di tutte le vulnerabilità MCP, che non esiste, o l'audit manuale di tutti i 69.000 server, che è impraticabile.»

- **Precision** = TP / (TP + FP) → *"quando lo strumento dice «vulnerabilità», quanto spesso ha ragione?"* Guarda solo le cose **segnalate**.
- **Recall** = TP / (TP + FN) → *"di tutte le vulnerabilità che ci sono davvero, quante ne ho catturate?"* Include anche i **FN**, cioè le vulnerabilità **mancate**.

**Analogia della rete da pesca:**
- *Precision* = quanto è pulito il pescato (quanti pesci veri rispetto alla spazzatura tirata su).
- *Recall* = quanta parte di tutti i pesci del mare sei riuscito a prendere (quanti te ne sono sfuggiti).

**Perché nella tesi misuro la precision ma non la recall:**
Per calcolare la precision mi basta prendere i finding **segnalati** e verificare a mano se sono veri o falsi (TP vs FP) — ed è quello che ho fatto con l'audit sui 1.579 finding. Per la recall invece mi servirebbero i **False Negative**: cioè le vulnerabilità reali che *nessuno strumento ha segnalato*. Ma non puoi contare ciò che non hai trovato senza:
- un **benchmark pubblico etichettato** di tutte le vulnerabilità MCP (non esiste), **oppure**
- l'**audit manuale esaustivo di ogni server** (69.000 server → impraticabile).

## 3. Stage 2A — le regole di dominio: come erano fatte e cosa guardavano

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

### Chiarificazione su Stage1 e 2A
Nello Stage 1 la firma sk-/AKIA/ghp_ serve a non scartare un candidato — è un filtro: "questa stringa ha il formato di un segreto, tienila nel pool".
Nello Stage 2A la stessa firma serve a emettere il verdetto: "questo è un vero positivo certo (HC-VP)".

### Come sono costruiti questi 2 stage?
Le regole sono concretamente regex, liste di valori noti e funzioni Python. Le ho costruite leggendo campioni dell'output grezzo, raggruppando i finding per pattern e codificando ogni pattern in una regola, con round iterativi di raffinamento. Lo Stage 1 poggia su standard pubblici — i formati delle chiavi, le convenzioni sui file di test, l'entropia — quindi è in parte auto-giustificato; lo Stage 2A è invece dominio empirico costruito leggendo il codice reale dei server, ed è per questo che la sua affidabilità la misuro con l'audit manuale

Stadio	Cosa decide a runtime	Come nascono le regole
Stage 1	regex/liste deterministiche (keep/drop)	fatte a mano da te: standard esterni + convenzioni + entropia + lettura campione
Stage 2A	regole di dominio deterministiche (HC-VP/HC-FP/UNCERTAIN)	fatte a mano da te: leggendo il codice reale dei server, una regola per categoria

Domanda mia:
però sia nello stage 1 che 2a va visto il codice per capirlo giusto? Nell'1 di meno magari perchè basta vedere lo snippet di codice quando le regole possono non coprire tutto mentre per il 2a bisogna vedere bene tutto il triangolo di segnali giusto?

Risposta:
Quando COSTRUISCI le regole (offline, sei tu): qui hai ragione.

Stage 1: ti basta guardare lo snippet + il path del campione. Raramente devi aprire tutto il repo — la stringa e la posizione del file bastano per capire "è un placeholder / è un test / ha il formato di una chiave".
Stage 2A: devi aprire il codice reale del server e capirne lo scopo. È qui che serve il "triangolo" (snippet + identità del server + verdetto del framework): per stabilire l'identità/scopo del server hai dovuto leggerlo. Ispezione più profonda.
Quindi: entrambi guardano il codice in fase di costruzione, ma lo Stage 2A più a fondo. ✅ Corretto.

Quando la pipeline GIRA (runtime, sui 69k server): qui nessuno dei due "guarda il codice per capirlo". Sono entrambi codice deterministico che legge dei campi già estratti dal finding:

lo Stage 1 legge evidence + path e applica le regex;
lo Stage 2A legge i tre campi del triangolo (snippet, metadati del server, verdetto) e applica gli if.
Il "triangolo" a runtime non è un umano che ispeziona tre cose: sono tre campi di dato che la regola controlla automaticamente. Nessuna comprensione, solo pattern-matching.

Il processo è empirico e iterativo, sempre lo stesso:
1. Faccio girare lo scanner → ottengo i finding grezzi (JSON: server, file, riga, evidence, categoria).
2. Apro un campione (50-100 finding di una categoria) e li leggo.
3. Li raggruppo per pattern visivo (cluster): "questi 40 sono tutti dentro node_modules/", "questi 15 sono your_api_key", "questi 20 sono chiavi AIzaSy vere".
4. Per ogni cluster decido keep/drop e codifico il perché in una regola: il cluster "test file" → una regex sul path; il cluster "placeholder" → una regex sulla stringa; il cluster "honeypot" → aggiungo quei nomi a una lista.
5. Ri-eseguo, guardo il residuo, aggiungo regole. (È qui che nascono i "round" di tightening: ogni giro stringo le regole sui FP rimasti — es. ho ristretto _CMD_FUZZ_SHELL_OUTPUT a contenuti shell reali come uid=0(root) invece del semplice echo di /etc/passwd.)

### Qualcos'altro, l'entropia:
L'entropia di Shannon è una misura di quanto una stringa è "casuale"/imprevedibile, espressa in bit per carattere. Serve a distinguere un segreto vero (che è casuale) da un placeholder (che è una parola leggibile), senza sapere il formato.

Cos'è, in intuizione:

Stringa casuale → tanti caratteri diversi, nessuna struttura → entropia alta. Es. aB3xK9mQ7pL2vR8t ≈ 4 bit/car.
Stringa prevedibile (parola, ripetizione, template) → entropia bassa. Es. your_api_key , changeme , XXXXXXXX ≈ 2-3 bit/car.
La formula è H = −Σ p(c)·log₂ p(c), dove p(c) è la frequenza di ogni carattere nella stringa. In pratica: quante "sorprese" ti dà in media ogni carattere.

Dove la usi (nel tuo Stage 1):
Solo nel rilevamento credenziali, e solo per il caso generico api_key = "..." che non matcha una firma di provider. Il ragionamento è:

se la stringa ha un formato noto (ghp_, AKIA, sk-ant-) → la decidi con la firma, l'entropia non serve;
se non ha un formato riconoscibile — è solo una stringa qualunque assegnata a una variabile tipo api_key/password — dalla forma non capisci se è un segreto vero o un placeholder. Allora calcoli l'entropia del valore:
< 3.5 bit/car → non abbastanza casuale → probabilmente placeholder/parola → scarti (falso positivo).
≥ 3.5 → sembra un segreto casuale reale → tieni.
Perché serve: le firme catturano solo le chiavi dai formati noti. Ma moltissimi segreti sono generici — una stringa random esadecimale o base64 senza prefisso riconoscibile. L'entropia è il modo indipendente dal formato per dire "questa sembra un segreto casuale" contro "questa è testo leggibile". È lo stesso trucco che usano i secret-scanner come trufflehog.

Esempi rapidi:

Valore	Entropia	Verdetto Stage 1
f3a9c2b7e1d84a0f... (hex random)	alta (~4)	keep
Kx9$mQ2vLp7Zt	alta	keep
your_api_key	bassa	drop
changeme	bassa	drop
XXXXXXXXXXXX	quasi zero	drop
Per il prof, in una frase:

"L'entropia di Shannon misura quanto una stringa è casuale, in bit per carattere. La uso nello Stage 1 sul caso credenziali generico, quando non c'è una firma di provider: se il valore ha entropia sotto 3.5 lo scarto come placeholder, sopra lo tengo come probabile segreto reale. È il modo indipendente dal formato per distinguere un segreto casuale da una parola leggibile."

## 4. Perchè per il credential leak abbiamo auditato tutti i 1342 finding?
- Credential leak → verifica economica e locale. Ogni finding è una stringa candidata in un file, una riga. Per decidere basta guardare quel punto: è una chiave vera o un placeholder / un token di esempio / una chiave pubblica? Non devi capire l'intero server né seguire il data-flow. Quindi controllarli tutti è fattibile in tempo ragionevole → ottieni la precisione esatta della classe (1.258 veri su 1.342 = 94%).
- Altre categorie → verifica costosa. Per un SQL injection, un command injection, una dangerous capability… devi leggere il codice, capire cosa fa il server e tracciare se l'input controllato dall'attaccante arriva davvero al sink senza sanitizzazione. Sono minuti per finding. Quindi campioni ~15 per categoria e stimi la precisione della classe statisticamente.

QUindi li ho classificati per pattern, non uno a uno. Un credential leak è una decisione locale — guardo il formato della stringa e il file: sk-, AIzaSy, ghp_ in un .env committato è vero; una anon key di Supabase o una config Firebase è pubblica per design; una sequenza tipo your_api_key è un placeholder. Raggruppo per formato e propago il verdetto




-----

- External attacker della slide 4 e 6 sono praticamente uguali, non è una ripetizione?
- Posso togliere dalla slide 10 le 18.100 estimated vulnerabilities?
- Forse togliere la slide di data collection e dirla velocemente quando introduco la pipeline?