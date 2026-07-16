# How (In)secure Are MCP Servers?

## Slide 1 — Titolo *(~15s)*
Buongiorno a tutti. Sono Francesco Martignoni e presento la mia tesi *"How (In)secure Are MCP Servers?"*, un'analisi di sicurezza su larga scala dell'ecosistema Model Context Protocol.

## Slide 2 — Model Context Protocol *(~70s)*
Il Model Context Protocol è uno standard introdotto da Anthropic a fine 2024, che serve a collegare un modello linguistico (LLM) a servizi esterni, come un file system, un database, una API... Questo espande le capacità degli LLM, ma ne amplia anche la superficie di attacco.

L'architettura ha tre componenti: 
- l'**host**, l'applicazione con cui parla l'utente e l'unico che comunica con l'LLM; 
- il **client**, uno per server, con una sessione dedicata; 
- e il **server**, il programma che espone la capacità esterna e può avere **3 tipi di primitive**:
    - i **tool**, azioni che l'LLM decide di invocare autonomamente durante il ragionamento. Ad esempio un utente può chiedere di creare un file sul Desktop con del contenuto specifico e il modello chiamerà il server *filesystem*, che svolgerà il compito assegnato, 
    - le **resource**, dati allegati alla conversazione per dare più contesto; 
    - e i **prompt**, scorciatoie pre-impostate per l'utente.

Ci sono infine due meccanismi di trasporto: `stdio` per i server locali e `HTTP/SSE` per quelli remoti.

## Slide 3 — Main Contributions *(~35s)*
Il contributo dello studio è triplice. 
- Primo, abbiamo analizzato un dataset su larga scala con oltre 69K server raccolti. 
- Secondo, **SAMS** (Security Analysis of MCP Servers), una pipeline che combina sette framework di sicurezza, con una fase successiva di post-processing e una validazione finale manuale. 
- Terzo, i risultati empirici trovati, con cui vediamo che la maggior parte dei problemi dell'ecosistema MCP sono errori classici di programmazione, non attacchi nuovi specifici degli LLM (sebbene largamente presenti).

## Slide 4 — Goals *(~40s)*
L'obiettivo del lavoro è studiare e misurare quanto siano diffuse le vulnerabilità nell'intero ecosistema MCP, e fornire raccomandazioni pratiche per prevenirle.
In particolare, i problemi di sicurezza nascono da tre origini. Due sono dentro il server: 
- le **misconfiguration**, che sono debolezze involontarie come un errore dello sviluppatore o codice insicuro; 
- e gli **exploit**, codice malevolo inserito di proposito per danneggiare l'utente. 

- La terza arriva da fuori: l'**attaccante esterno**, che inietta contenuto dannoso in una fonte che il server poi recupera e passa al modello.

## Slide 5 — Research Questions *(~25s)*
Da qui, ecco le tre domande di ricerca. 
- La prima: in cui ci chiediamo quanto siano affidabili gli attuali framework di analisi di sicurezza per MCP? 
- La seconda: quali classi di vulnerabilità sono più diffuse nell'ecosistema? 
- La terza: quali raccomandazioni pratiche possono ridurre questi rischi?

## Slide 6 — Attacker Models & Threat Scenarios *(~100s)*
Per formalizzare l'analisi ho definito tre modelli di attaccante: 
- il primo: lo *sviluppatore malevolo*, che pubblica un server creato appositamente per danneggiare l'utente; 
- poi l'*utente malevolo*, che abusa delle debolezze di un server legittimo; 
- il terzo: l'*attaccante esterno*, che inietta contenuto su una fonte esterna che il server poi passa all'LLM.

Ho definito poi **nove scenari di minaccia**.
- Il *tool poisoning*: la descrizione di un tool manipola l'LLM a compiere un'azione dannosa. 
- La *data exfiltration*: un server malevolo trasmette attivamente dati sensibili verso un attaccante grazie al suo codice sorgente. 
- Il *credential leak*: credenziali in chiaro nel codice sorgente. 
- L'*access control*: il server si concede permessi troppo ampi, violando il minimo privilegio. 
- L'*improper input validation*: argomenti del tool passati a un'operazione sensibile senza controlli. 
- La *sensitive info disclosure*: un tool restituisce dati che dovrebbero restare lato server, come variabili d'ambiente. 
- Il *protocol non-compliance*: il server devia dalle specifiche del protocollo, non implementato correttamente. 
- La *dangerous capability*: un tool espone un'operazione intrinsecamente pericolosa, come l'esecuzione di comandi shell. 
- E l'*untrusted content*: un tool recupera contenuto esterno non attendibile e lo passa al modello, aprendo un canale di injection indiretta.

## Slide 7 — SAMS: a Pipeline for MCP Security Analysis *(~35s)*
Per l'analisi ho sviluppato **SAMS**, una pipeline composta da quattro fasi. 
- La **Collection**, che raccoglie 69.104 server unici. 
- L'**Analysis** che passa i server ai sette framework, che li analizzano con tecniche complementari. 
- Il **Post-processing** che filtra i milioni di finding in tre step. 
- E la **Validation** è una verifica manuale del codice sorgente, che serve a misurare l'affidabilità del metodo.

## Slide 8 — Data Collection *(~25s)*
In particolare, nella fase di Collection, un web crawler recupera più di 148K server da 18 registry pubblici diversi. Da qui normalizzo gli URL, calcolo un hash del contenuto, elimino i duplicati e arrivo alla lista finale di 69.104 server unici.

## Slide 9 — Framework Selection *(~60s)*
I sette framework sono stati scelti a partire da 26 strumenti proposti nello stato dell'arte e, come potete vedere in alto nella tabella, li ho sistematizzati per tecnica di analisi:
- analisi statica del codice, 
- analisi semantica via LLM, 
- test del protocollo e dei tool, 
- e fuzzing dinamico (una tecnica che serve a trovare "punti deboli" facendo correre al server dei pericoli controllati con input inaspettati)

e poi ne ho selezionati sette per una copertura complementare e completa.

Un punto importante: non li ho solo usati, in alcuni casi li ho dovuti adattare o re-implementare. 
Per esempio *mcp-guard*, nella versione originale, per il fuzzing inventava le vulnerabilità invece di testarle davvero, quindi l'ho riscritto con una logica migliore; e *mcp-shield* usava un LLM che ho sostituito con un modello locale sia per costo, privacy e riproducibilità.

## Slide 10 — Three-Stage Post-Processing *(~80s)*
Dopo aver esposto tutta la sequenza della nostra pipeline, ecco che i sette scanner producono più di 3 milioni di finding grezzi, ma la maggior parte è rumore: vanno filtrati prima di poterli interpretare. 
Lo faccio in tre stage di post-processing diversi.
1. Lo **Stage 1** è un filtro regex che elimina il rumore ovvio — per esempio un `api_key` che è solo un placeholder — e scendiamo a più di 73.000 findings.
2. Lo **Stage 2A** applica regole di dominio che guardano lo snippet di codice e l'identità del server (nome, linguaggio e file_path) — per esempio una query costruita con un'f-string non è una vulnerabilità se il compito di quel server è proprio eseguire SQL — e arriviamo a circa 23.000.
3. Lo **Stage 2B** passa i casi ambigui a un LLM locale, che ne capisce il significato — per esempio una anon key pubblica di Supabase, che sembra un segreto ma è pubblica per definizione.

Alla fine restano 27.958 high-confidence findings. E anticipando la validazione manuale, le vulnerabilità reali stimate sono circa 18.100.

## Slide 11 — Manual Audit Validation: Framework Reliability (RQ1) *(~55s)*
Per rispondere alla prima domanda, come dicevo, ho validato la pipeline con un audit manuale del codice sorgente, ispezionando più di 1500 finding. 
Il risultato è una precisione pesata del 64,8%: quindi i framework sono utili, ma comunque rumorosi.
Cosa vuol dire "pesata": è il tasso di conferma di ogni categoria, pesato per quanti finding ha nel dataset — quindi circa 18.100 finding reali sui 27K high-confidence.

Il dato interessante è che la precisione è disomogenea. Le categorie dinamiche e semantiche confermano tra l'80 e il 100%, perché guardano il comportamento a runtime o il significato. Le categorie statiche a regex confermano molto meno, perché non vedono il contesto né il data-flow.

## Slide 12 — Some misconfigurations and intentionally malicious examples *(~50s)*
Per rendere concreti questi scenari, ecco tre esempi.
- Il primo è intenzionalmente malevolo, un exploit: una descrizione di tool avvelenata. Un semplice tool `add` nasconde nella docstring un'istruzione — manda tutte le email all'attaccante e non dirlo all'utente. Il modello può interpretarla come parte del comportamento del tool.
- Il secondo è una misconfiguration: un tool onesto, `execute_command`, che esegue un comando di shell arbitrario sull'host — la capacità è dichiarata, ma è pericolosa se concessa a qualsiasi chiamante, incluso un LLM manipolato.
- Il terzo, anch'esso una misconfiguration, è un credential leak: uno sviluppatore che pubblica il server con una API key in chiaro.

## Slide 13 — Vulnerability Distribution (RQ2) *(~45s)*
Per la seconda domanda ho aggregato i 27K finding nei nove scenari. 
La cosa più importante è separare due cose diverse.
Il numero più grande, 15.436, è protocol non-compliance: sono problemi di robustezza e di qualità, quindi server che non seguono correttamente le specifiche e sono implementati male.
Le vere vulnerabilità di sicurezza invece sono 12.522, concentrate soprattutto nelle prime categorie, dall'improper input validation all'untrusted content.
Il messaggio chiave è che gli attacchi specifici degli LLM, come il tool poisoning, così presenti in letteratura, nella pratica sono molto rari.

## Slide 14 — Developer Recommendations (RQ3) *(~55s)*
Per la terza domanda, ecco cinque raccomandazioni concrete.
- Primo: validare gli argomenti dei tool nel codice, non tramite l'LLM. 
- Secondo: non esporre accesso illimitato a shell, file system o rete, questo rientra nelle categoria delle dangerous capabilities. 
- Terzo: togliere i segreti dell'utente dal codice sorgente prima di pubblicare. 
- Quarto: trattare il contenuto recuperato da sorgenti esterne come dato, non come istruzioni, un modello potrebbe essere istruito a comportamenti malevoli. 
- E quinto, per chi installa: isolare i server locali in sandbox e usare solo server fidati e controllati.

Il punto è che quasi tutte queste sono secure coding classico applicato a una superficie nuova — pratiche che gli sviluppatori già conoscono.

## Slide 15 — Limitations *(~50s)*
Alcuni limiti, importanti per interpretare i risultati e il lavoro svolto.
- Analizzo solo i server pubblici e open-source, non abbiamo analizzato quelli privati.
- Il dataset è uno snapshot di un ecosistema in rapida evoluzione, quindi non abbiamo studiato come i server cambiamo nel tempo.
- Parte dei risultati è stimata da un campione, non abbiamo potuto validare a mano tutto il dataset degli high-confidence findings.
- Protocol non-compliance e vulnerabilità sfruttabili vanno letti separatamente, come ho mostrato.  
- La classificazione con l'LLM può introdurre incertezza.
- Infine, per i dati analizzati manualmente abbiamo misurato la precisione, non il recall, quindi quanti findings sono reali, anche perchè non esiste un benchmark etichettato di vulnerabilità MCP.

## Slide 16 — Conclusions & Future Works *(~50s)*
In conclusione, tre take-away. 
- I server MCP espongono una superficie di attacco ampia e in rapida crescita, inoltre con centinaia o migliaia di server nuovi che escono ogni mese. 
- La maggior parte dei problemi sono errori classici di sicurezza del software, non attacchi specifici degli LLM (sebbene molto presenti). 
- E i framework di analisi aiutano, ma vanno validati e analizzati per essere resi affidabili.

Come lavori futuri propongo:
- un fuzzing degli LLM in stile proxy, per testare la sfruttabilità reale a runtime, catturando input e output dei tool che invece un'analisi statica non può rilevare, 
- e un monitoraggio continuo, ri-eseguendo la pipeline per vedere come cambiano i server nel tempo.

## Slide 17 — References
*(Slide di backup — non parlata. Avanza velocemente o lasciala per le domande.)*

## Slide 18 — Chiusura *(~10s)*
Grazie per l'attenzione. Resto a disposizione per eventuali domande.
