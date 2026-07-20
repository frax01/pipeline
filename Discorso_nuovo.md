# How (In)secure Are MCP Servers?

## Slide 1 — Titolo *(~15s)*
Buongiorno a tutti. Sono Francesco Martignoni e presento la mia tesi, che è un'analisi di sicurezza su larga scala dell'ecosistema Model Context Protocol.

## Slide 2 — Model Context Protocol *(~55s)*
Il Model Context Protocol è uno standard introdotto da Anthropic a fine 2024, che serve a collegare un modello linguistico (LLM) a servizi esterni, come un file system, un database, una API... Questo espande le capacità degli LLM, ma ne amplia anche la superficie di attacco.

L'architettura ha tre componenti: 
- l'**host**, l'applicazione con cui parla l'utente e l'unico che comunica con l'LLM; 
- il **client**, uno per server, con una sessione dedicata; 
- e il **server**, il programma che espone la capacità esterna e può avere **3 tipi di primitive**:
    - i **tool**, azioni che l'LLM decide di invocare autonomamente durante il ragionamento. 
    - le **resource**, dati allegati alla conversazione per dare più contesto; 
    - e i **prompt**, scorciatoie pre-impostate per l'utente.

Ci sono due meccanismi di trasporto: `stdio` per i server locali e `HTTP/SSE` per quelli remoti.

## Slide 3 - Execution Flow *(~60s)*
Vediamo un esempio di un flusso di esecuzione in cui un utente chiede di creare un file report.txt sul Desktop.
1. Il primo passo è l'utente che manda il prompt all'applicazione AI.
2. L'host comunica all'LLM la richiesta insieme alla lista di ciò che i server mettono a disposizione (in questo caso filesystem e web). Il modello decide da solo quale server e tool usare: sceglie write_file del filesystem, e ne costruisce gli argomenti, path con il percorso di report.txt nel Desktop e content con il contenuto di report.
3. L'host instrada la chiamata al server attraverso il client dedicato,
4. il server esegue la chiamata creando il file

Notate che ogni server espone tre primitive — tool, resource e prompt — ma il modello può invocarne solo una: i tool. Resource e prompt le chiama l'utente.

Il punto chiave, anche per la sicurezza, è che è il modello a scegliere quale tool chiamare e a produrne gli argomenti.

## Slide 4 — Attacker Models & Threat Scenarios *(~55)*
Per formalizzare l'analisi ho definito 3 modelli di attaccante e 9 scenari di minaccia e il loro collegamento mostra che tipi di problemi di sicurezza possono nascere. 
- il primo: lo *sviluppatore malevolo*, che pubblica un server creato appositamente per danneggiare l'utente. Questo avviene con codice malevolo o backdoor come ad esempio nel **tool poisoning:** dove la descrizione di un tool manipola l'LLM a compiere un'azione dannosa.
- poi l'*utente malevolo*, che abusa delle debolezze involontarie di un server legittimo, come un errore dello sviluppatore o codice insicuro, ad esempio la **credential leak:** credenziali in chiaro nel codice sorgente.
- il terzo: l'*attaccante esterno*, che inietta contenuto su una fonte esterna che un tool di un server recupera e passa all'LLM, aprendo un canale di iniezione indiretta.

## SLide 5 - Attackers Along the Execution Flow *(~40)*
Riprendiamo lo stesso flusso di prima, ora con gli attaccanti. Ognuno colpisce in un punto diverso. 
- L'utente malevolo agisce all'ingresso: manda input che l'LLM trasforma in argomenti, e sfrutta una debolezza del server — è il caso della validazione impropria dell'input o di una capacità pericolosa. 
- Lo sviluppatore malevolo è il server stesso: una descrizione di tool avvelenata guida la scelta del modello, oppure il suo codice che esfiltra dati. 
- L'attaccante esterno invece non tocca il flusso diretto: avvelena una fonte esterna che il server recupera, e il contenuto malevolo rientra e arriva all'LLM.

## Slide 6 — Goal & Research Questions *(~35s)*
L'obiettivo del lavoro è studiare e misurare quanto siano diffuse le vulnerabilità nell'intero ecosistema MCP, e fornire raccomandazioni pratiche per prevenirle.

Da qui, ecco le tre domande di ricerca, che sono il filo conduttore del lavoro. 
- La prima: in cui ci chiediamo quanto siano affidabili gli attuali framework esistenti di analisi di sicurezza per MCP? 
- La seconda: quali classi di vulnerabilità sono più diffuse nell'ecosistema? 
- La terza: quali raccomandazioni pratiche possono ridurre questi rischi?

## Slide 7 — Main Contributions *(~35s)*
Il contributo dello studio è triplice. 
- Primo, abbiamo analizzato un dataset su larga scala con oltre 69K server. 
- Secondo, **SAMS**, una pipeline che combina sette framework di sicurezza, con una fase successiva di post-elaborazione e una validazione finale manuale. 
- Terzo, i risultati empirici trovati, con cui vediamo che la maggior parte dei problemi dell'ecosistema MCP sono classici errori di programmazione, non attacchi nuovi specifici degli LLM (sebbene largamente presenti).

## Slide 8 — SAMS: a Pipeline for MCP Security Analysis *(~35s)*
Per l'analisi ho sviluppato **SAMS**, una pipeline composta da quattro fasi. 
- La **Collezione**, che raccoglie 69.104 server unici. 
- L'**Analisi** che passa questi server ai sette framework, che li analizzano con tecniche complementari. 
- Il **Post-elaborazione** che filtra i milioni di dati trovati in tre step. 
- E la **Validazione** è una verifica manuale del codice sorgente, che serve a misurare l'affidabilità del metodo.

## Slide 9 — Data Collection *(~25s)*
In particolare, nella fase di Collezione, un programma recupera più di 148K server da 18 fonti pubbliche diverse. Da qui normalizzo gli URL, calcolo un hash del contenuto, elimino i duplicati e arrivo alla lista finale di 69.104 server unici.

## Slide 10 — Framework Selection *(~80s)*
I sette framework sono stati scelti a partire da 26 strumenti proposti nello stato dell'arte e, come potete vedere in alto nella tabella, li ho sistematizzati per tecnica di analisi:
- analisi statica del codice, 
- analisi semantica via LLM, 
- test del protocollo e dei tool, 
- e fuzzing dinamico

e poi ne ho selezionati sette per una copertura complementare e completa.

Un punto importante: non li ho solo usati, in alcuni casi li ho dovuti adattare o re-implementare. 
Per esempio *mcp-guard*, nella versione originale, per il fuzzing inventava le vulnerabilità invece di testarle davvero, quindi l'ho riscritto con una logica migliore; e *mcp-shield* usava un LLM che ho sostituito con un modello locale sia per costo, privacy e riproducibilità.

E poi un confronto con lo stato dell'arte: il lavoro più vicino analizza 67.000 server, ma con solo i tool Python.
Tutti gli altri lavori studiano tra i 1.300 e 8.000 server, un ordine di grandezza diverso rispetto al nostro che, oltre ai 69K server, usa sette framework di analisi, quattro tecniche complementari e più linguaggi.

## Slide 11 — Three-Stage Post-Processing *(~80s)*
Dopo aver esposto tutta la sequenza della nostra pipeline, ecco che i sette scanner producono più di 3 milioni di dati, ma la maggior parte è rumore: vanno filtrati prima di poterli interpretare. 
Lo faccio in tre stage di post-elaborazione.
1. Lo **Stage 1** è un filtro con espressioni regolari che prende i 3 milioni di dati ed elimina il rumore ovvio — per esempio un `api_key` che è solo un placeholder — e scendiamo a circa di 73.000 dati.
2. Lo **Stage 2A** applica regole di dominio che guardano il codice da analizzare e l'identità del server (nome, linguaggio e file_path) — per esempio una query costruita con una f-string non è una vulnerabilità se il compito di quel server è proprio eseguire SQL — e arriviamo a circa 23.000.
3. Lo **Stage 2B** passa i casi ambigui a un LLM locale, che ne capisce il significato — per esempio una anon key pubblica di Supabase, che sembra un segreto ma è pubblica per definizione.
4. Inoltre mcp-scan non ha partecipato a questa parte di analisi poichè già la fa con la sua stessa logica, che ci fornisce più di 4K dati.

Alla fine abbiamo 27.958 dati ad alta confidenza.

## Slide 12 — Manual Audit Validation: Framework Reliability (RQ1) *(~40s)*
Per rispondere alla prima domanda, ho validato la pipeline con una verifica manuale del codice sorgente, ispezionando più di 1500 dati. 
Il risultato è una precisione del 64,8%: quindi i framework sono utili, ma comunque rumorosi.

Il dato interessante è che la precisione è disomogenea. Le categorie dinamiche e semantiche confermano tra l'80 e il 100%, perché guardano il significato. Le categorie statiche invece, valutate con espressioni regolari, confermano molto meno, perché non vedono il contesto né il flusso di dati.

## Slide 13 — Some misconfigurations and intentionally malicious examples *(~40s)*
Per rendere concreti questi scenari, ecco tre esempi.
- Il primo è intenzionalmente malevolo: una descrizione di tool avvelenata. Un semplice tool di addizione espone un'istruzione che dice di mandare tutte le email all'attaccante e non dirlo all'utente. Il modello può interpretarla come parte del comportamento del tool.
- Il secondo è una vulnerabilità: un tool onesto, `execute_command`, che esegue un comando di shell arbitrario — la capacità è dichiarata, ma è pericolosa se concessa a qualsiasi chiamante, incluso un LLM manipolato.
- Il terzo, anch'esso una vulnerabilità, è un credential leak: uno sviluppatore che pubblica il server con una chiave API in chiaro.

## Slide 14 — Vulnerability Distribution (RQ2) *(~35s)*
Per la seconda domanda sulla distribuzione delle vulnerabilità, ho aggregato i 27K dati nei nove scenari. 
La cosa più importante è separare due cose diverse.
Il numero più grande, 15.436, è la non conformità al protocollo: sono problemi di robustezza e di qualità, quindi server che non seguono correttamente le specifiche e sono implementati male.
Le vere vulnerabilità di sicurezza invece sono 12.522, concentrate soprattutto nelle prime categorie, dalla validazione impropria dell'input al contenuto non attendibile.

## Slide 15 — Developer Recommendations (RQ3) *(~50s)*
Per la terza domanda ho raggruppato le raccomandazioni in tre principi chiave.

1. Il primo: trattare ogni input come non attendibile. Quindi validare gli argomenti dei tool nel codice, mai delegando il lavoro all'LLM; e trattare il contenuto recuperato da fonti esterne come dato, non come istruzione.
2. Il secondo: minimo privilegio. Restituire solo i dati necessari e non l'intero ambiente, tenere i segreti fuori dal codice sorgente prima di pubblicare, e isolare le capacità pericolose invece di esporle senza restrizioni.
3. Il terzo: conformarsi al protocollo MCP, che è il problema più diffuso e, per chi installa, usare solo server fidati e verificati.

Il punto è che quasi tutte queste sono problemi di sicurezza classici applicati a una superficie nuova.

## Slide 16 — Limitations *(~45s)*
Alcuni limiti, importanti per interpretare i risultati e il lavoro svolto.
1. Il primo riguarda il dataset: analizzo solo server pubblici e open-source, quindi i server privati restano fuori; ed è una fotografia di un ecosistema in rapida evoluzione, quindi non osservo come i server cambiano nel tempo.
2. Il secondo è di interpretazione: la non conformità al protocollo e le vulnerabilità sfruttabili vanno letti separatamente.
3. Il terzo riguarda la precisione, cioè quanti dei dati segnalati sono reali, e non il recall, perché non esiste un benchmark ufficiale di vulnerabilità MCP; inoltre la precisione è stimata su un campione, non validando a mano tutto, e una parte della classificazione passa da un LLM, che può introdurre incertezza.

## Slide 17 — Conclusions & Future Works *(~45s)*
In conclusione, ecco tre messaggi chiave. 
- I server MCP espongono una superficie di attacco ampia e in rapida crescita, con centinaia o migliaia di server nuovi che escono ogni mese. 
- La maggior parte dei problemi sono errori classici di sicurezza del software, non attacchi specifici degli LLM (sebbene molto presenti). 
- E i framework di analisi aiutano, ma vanno validati e analizzati per essere resi affidabili.

Come lavori futuri propongo:
- un fuzzing degli LLM in stile proxy, per testare la sfruttabilità reale durante l'esecuzione, catturando input e output dei tool che invece un'analisi statica non può rilevare.

## Slide 18 — Chiusura *(~10s)*
Grazie per l'attenzione. Resto a disposizione per eventuali domande.

## Slide 19 — References