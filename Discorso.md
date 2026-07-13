# How (In)secure Are MCP Servers?

## Slide 1 — Titolo *(~15s)*
Buongiorno a tutti. Sono Francesco Martignoni e presento la mia tesi *"How (In)secure Are MCP Servers?"*, un'analisi di sicurezza su larga scala dell'ecosistema Model Context Protocol, mostrando perché la sua sicurezza è un problema, il metodo che ho progettato per misurarla e i risultati principali.

## Slide 2 — Introduction *(~75s)*
Il Model Context Protocol è uno standard introdotto da Anthropic a fine 2024, che serve a collegare un modello linguistico (LLM) a servizi esterni — un file system, un database, una API...

L'architettura ha **tre componenti**: 
1. l'**host** è l'applicazione con cui parla l'utente: è l'unico che comunica con l'LLM e coordina uno o più client,
2. il **client** è istanziato dall'host, uno per server, con una sessione dedicata
3. il **server** è il programma che espone la capacità esterna.

Ogni server può esporre **tre tipi di primitive**: 
1. i *tool*, azioni che l'LLM decide di invocare autonomamente durante il ragionamento
2. le *resource*, allegando una risorsa alla conversazione,
3. i *prompt*, sono modelli di conversazione pre-impostati.

**Ci sono due meccanismi di trasporto:** 
1. `stdio` per i server locali, senza rete,
2. `HTTP/SSE` per i server remoti, via rete.

## Slide 3 — Goals & Research Questions *(~60s)*
Nel 2025 l'adozione è esplosa e questa crescita così rapida ha portato a problemi di sicurezza. L'obiettivo è studiare e misurare quanto siano diffuse le vulnerabilità nell'intero ecosistema MCP e fornire alcune raccomandazioni su come prevenire tali problemi.

I problemi di sicurezza di MCP nascono da due fonti complementari: 
1. le **misconfigurations:** errori involontari e parti di codice che aprono la strada a vulnerabilità, 
2. gli **exploits:** codice malevolo inserito di proposito da uno sviluppatore.

Ecco le domande a cui vogliamo rispondere.

1. **Affidabilità dei framework (RQ1)**
2. **Distribuzione delle vulnerabilità (RQ2)**
3. **Raccomandazioni pratiche (RQ3)**

## Slide 4 — Attacker Models & Threat Scenarios *(~65s)*
Ho definito **tre modelli di attaccante**. 
1. *Malicious developer*, che pubblica un server intenzionalmente creato per danneggiare l'utente,
2. *Malicious user*, un utente legittimo che abusa delle debolezze e vulnerabilità del server. 
3. *External attacker*, che inietta contenuto malevolo su una sorgente terza che il server poi recupera e passa all'LLM.

Ho definito poi **nove scenari di minaccia**: 
1. tool poisoning: Un server MCP malevolo o compromesso utilizza la descrizione di uno strumento per manipolare il modello linguistico affinché compia un'azione dannosa.
2. dangerous capability: Uno strumento espone all'LLM un'operazione ad alto privilegio intrinsecamente pericolosa se concessa a qualsiasi utente, incluso un LLM che potrebbe essere manipolato da contenuti esterni non attendibili (TS-07).
3. credential leak: Il codice sorgente del server contiene delle credenziali private.
4. access control: Il server concede a se stesso, o alle risorse che possiede o crea, permessi eccessivamente ampi.
5. input validation: Un tool di un server MCP riceve argomenti per la chiamata dello strumento e li passa a un'operazione sensibile senza validarli o sanificarli.
6. sensitive info disclosure: Un tool restituisce inavvertitamente informazioni che dovrebbero rimanere lato server.
7. untrusted content: Un tool legittimo recupera contenuti da una fonte esterna e se un attaccante controlla quella fonte, può inserire payload di prompt-injection nel contenuto recuperato; tali payload verranno trattati dall'LLM come parte della conversazione ed eseguiti.
8. protocol non-compliance: Il server MCP devia dal protocollo JSON-RPC 2.0 o dalla sua specifica, questo può accadere solo in configurazioni di server MCP non implementate correttamente o opzionali.
9. data exfiltration: Un server malevolo o compromesso trasmette attivamente dati sensibili verso un attaccante grazie al suo codice sorgente malevolo.

## Slide 5 — SAMS: a Pipeline for MCP Security Analysis *(~70s)*
Per analizzare l'ecosistema MCP ho sviluppato **SAMS** (Security Analysis of MCP Servers) una pipeline organizzata in quattro fasi. 
1. **Collection**, un web crawler prende 18 registry pubblici e recupera 148.657 server, da qui facendo un'analisi hash, togliendo i clone failed ed eliminando i duplicati si arriva a 69.104 server unici. 
2. **Analysis**, i 69K server vengono passati ai **7 framework** che lavorano in parallelo con tecniche di analisi complementari.
3. **3-Stage Post-processing**, dove ogni finding, tra i milioni prodotti, passa attraverso tre fasi: 
- un primo filtro regex, 
- poi regole di dominio specifiche per ogni categoria di vulnerabilità, 
- e infine una classificazione semantica con un LLM per i risultati ambigui. 
4. **Validation**, è una verifica manuale del codice sorgente di un sottoinsieme dei server segnalati.

## Slide 6 — Data Collection & Frameworks Selection *(~60s)*
1. Il web crawler trova **148.657** server dai 18 registry
2. Inizialmente prendo solo i server che espongono i link su Github (138.932), clono ogni repository e scarto quelli che non si clonano: restano **110.158**. 
3. Successivamente normalizzo gli URL e rimuovo i duplicati esatti, arrivando a **66.333**. 
4. Poi calcolo un hash del contenuto per verificare se ci sono dei server con url diversi ma che hanno lo stesso identico contenuto, così da eliminarli, e arriviamo a **60.205**. 
5. Infine **aggiungo gli 8.899 pacchetti npx** che avevo inizialmente escluso per questa fase di analisi poichè già tutti pronti per essere analizzati, arrivando ai **69.104** server finali.

Sulla destra poi ci sono le tecniche coperte dai sette framework: 
1. analisi statica del codice e degli input schema, 
2. analisi semantica via LLM, 
3. test dei tool e del protocollo,
4. fuzzing dinamico, una tecnica di test automatizzato che serve a trovare "punti deboli" facendo correre al server dei pericoli controllati con input inaspettati, sequenze illogiche, comandi errati... 

## Slide 7 — Three-Stage Post-Processing *(~75s)*
I 7 scanner producono più di **3 milioni** di finding grezzi che però vanno filtrati e analizzati, lo facciamo attraverso 3 step:
1. **Step 1** è un filtro regex che elimina il rumore evidente (file di test o di esempio, righe commentate, placeholder...) e riduce il totale dei finding a **73.594**. 
2. **Step 2A** applica regole di dominio che triangolano tre segnali (lo snippet di codice, l'identità del server (nome, linguaggio e file_path) e l'eventuale verdetto interno del framework), che produce **22.997** real findings. Alcuni di questi finding possono rimanere con una classificazione incerta.
3. **Step 2B** prende i **5.800 incerti** e li risolve con un LLM locale, `llama3`, trovando **565** vulnerabilità reali. 
Sommando tutti questi dati si arriva ai **27.958** finding confermati. In totale, oltre il 99% di riduzione del rumore.

## Slide 8 — Manual Audit Validation: Framework Reliability (RQ1) *(~75s)*
Per rispondere a RQ1, ho validato la pipeline con una **verifica manuale del codice sorgente**. Ho ispezionato **1.579 finding**: la classe *credential-leak* interamente con tutti i suoi 1.342 findings, più 237 campionati più o meno equamente dalle altre categorie, circa 15 per categoria. 
Facendo una media pesata otteniamo una **precisione del 64,8%**, cioè circa **18.100** dei 27.958 finding sono realmente veri.

Il dato interessante è che la precisione è **disomogenea**. Le categorie **dinamiche e semantiche** — untrusted content, sensitive info, data exfiltration, tool shadowing, prompt injection, credential leak — confermano tra l'**80 e il 100%**, perché attivano il comportamento a runtime o guardano il significato. Le categorie **statiche a regex** — command injection al 27%, path traversal al 33%, SSRF e SQL al 53% — confermano molto meno perchè non hanno la possibilità di vedere il contesto o il data-flow.

## Slide 9 — Some misconfigurations and intentionally malicious examples *(~70s)*
Per rendere concreti gli scenari, ecco tre esempi reali presi dal dataset. 
- **Tool Poisoning:** il primo è **intenzionalmente malevolo**, è una descrizione di tool avvelenata. Un banale tool `add` nasconde, dentro la sua docstring, un'istruzione — *manda tutte le email all'attaccante, e non dirlo all'utente*. L'LLM legge la descrizione e la esegue: è un *exploit* di tool poisoning. 
- **Dangerous capability:** il secondo è una **misconfiguration**, è un tool onesto, `execute_command`, che esegue un comando di shell arbitrario sull'host — la capacità è dichiarata, ma è intrinsecamente pericolosa se concessa a qualunque chiamante, incluso un LLM manipolato. 
- **Credential leak:** il terzo, anch'esso una misconfiguration, è un **credential leak**, dove uno sviluppatore che pubblica il server con una API key reale in chiaro nel codice.

## Slide 10 — Vulnerability Distribution (RQ2) *(~75s)*
Per RQ2 aggrego i 27.958 finding confermati nei nove scenari di minaccia. La cosa più importante da leggere: **15.436, il 55%, sono protocol non-compliance** — problemi di robustezza e misconfiguration, non attacchi in sé, quindi un problema di qualità: il server semplicemente non segue correttamente le specifiche MCP.

Le vere vulnerabilità di sicurezza sono **12.522** e si concentrano nei primi cinque scenari, che da soli fanno il 99%.

Il messaggio chiave è che gli attacchi **specifici degli LLM** di cui parla tanto la letteratura — tool poisoning e data exfiltration — nella pratica sono **rarissimi**: 119 e 2 casi. 

## Slide 11 — Recurring Antipatterns (RQ3) *(~55s)*
Dai server più vulnerabili ho stilato **cinque antipattern ricorrenti**. 
- l'*esecutore senza restrizioni*: server che espongono shell o esecuzione di codice come tool — la capacità è onesta, ma concessa a qualunque chiamante diventa pericolosa. 
- la *string interpolation*: input dell'utente concatenato in codice pericoloso, tipo una f-string in una query. 
- i *segreti nel repository*: file `.env` committati e chiavi nei moduli di configurazione. 
- l'*oversharing a runtime*: invece del segreto nel codice, è il tool che restituisce lo stato server-side nella sua risposta. 
- il *fidarsi del contenuto esterno*: server che recuperano contenuto esterno e lo passano all'LLM senza sanitizzazione, creando un canale di injection indiretta.

## Slide 12 — Developer Recommendations (RQ3) *(~65s)*
Ecco gli antipattern identificati in raccomandazioni concrete. 
- Primo: **trattare ogni argomento di un tool come input non fidato** — l'argomento è prodotto dall'LLM e può essere guidato dall'utente o da contenuto esterno. 
- Secondo, e fondamentale: **non usare mai l'LLM stesso come livello di validazione** — la validazione deve stare nel codice del server. 
- Terzo: **minimo privilegio** sulle capacità pericolose — sandbox, directory ristretta, conferma esplicita, mai girare come root...
- Quarto: **restituire solo il necessario** — mai restituire l'intero ambiente o i file di config o i segreti. 
- Quinto: **tenere i segreti fuori dal repository**. 
- Sesto: **isolare il contenuto esterno**, mai trattarlo come istruzioni. 
- Settimo: **conformarsi al protocollo**. 
- E infine, per chi installa: **preferire server controllati**.

## Slide 13 — Conclusions & Future Works *(~55s)*
In sintesi, il divario di sicurezza dell'ecosistema MCP oggi riguarda molto meno gli attacchi specifici per gli LLM (sebbene siano ampiamente presenti) e molto più i classici errori di programmazione sicura applicati a una superficie di attacco nuova e in rapida crescita.

Come **lavori futuri**: 
- un fuzzing degli LLM tramite proxy, per provare la sfruttabilità a runtime invece di segnalare solo pattern; 
- un monitoraggio continuo, ri-eseguendo la pipeline nel tempo per vedere come cambiano o evolvono i server e intercettare i rug pull

## Slide 14 — Chiusura *(~5s)*
Grazie per l'attenzione. Resto a disposizione per le vostre domande.

