# How (In)secure Are MCP Servers?

## Slide 1 — Titolo *(~15s)*
Buongiorno a tutti. Sono Francesco Martignoni e presento la mia tesi *"How (In)secure Are MCP Servers?"*, un'analisi di sicurezza su larga scala dell'ecosistema Model Context Protocol, mostrando perché la sua sicurezza è un problema, il metodo che ho progettato per misurarla e i risultati principali.

## Slide 2 — Introduction *(~50s)*
Il Model Context Protocol è uno standard introdotto da Anthropic a fine 2024, che serve a collegare un modello linguistico (LLM) a servizi esterni — un file system, un database, una API...

L'architettura ha **tre componenti**: 
1. l'**host** è l'applicazione con cui parla l'utente ed è l'unico che comunica con l'LLM,
2. il **client** è istanziato dall'host, uno per server, con una sessione dedicata
3. il **server** è il programma che espone la capacità esterna e può esporre **tre tipi di primitive**:
   1. i *tool*, azioni che l'LLM decide di invocare autonomamente durante il ragionamento
   2. le *resource*, allegando una risorsa alla conversazione,
   3. i *prompt*, sono modelli di conversazione pre-impostati.

**Ci sono due meccanismi di trasporto:** 
1. `stdio` per i server locali,
2. `HTTP/SSE` per i server remoti.

## Slide 3 — Goals & Research Questions *(~40s)*
L'obiettivo è studiare e misurare quanto siano diffuse le vulnerabilità nell'intero ecosistema MCP e fornire alcune raccomandazioni su come prevenire tali problemi.

I problemi di sicurezza nascono da due fonti complementari: 
1. le **misconfigurations:** errori involontari o codice sorgente debole che apre la strada a vulnerabilità, 
2. gli **exploits:** codice malevolo inserito di proposito da uno sviluppatore.

Ecco le domande a cui vogliamo rispondere.

1. **Affidabilità dei framework (RQ1)** che abbiamo scelto per l'analisi
2. **Distribuzione delle vulnerabilità (RQ2)** trovate
3. **Raccomandazioni pratiche (RQ3)** per gli sviluppatori

## Slide 4 — Attacker Models & Threat Scenarios *(~90s)*
Per formalizzare l'analisi ho definito **tre modelli di attaccante**. 
1. *Sviluppatore malevolo*, che pubblica un server intenzionalmente creato per danneggiare l'utente,
2. *Utente malevolo*, che abusa delle debolezze e vulnerabilità del server. 
3. *Attaccante esterno*, che inietta contenuto su una sorgente che il server poi recupera e passa all'LLM.

Ho definito poi **nove scenari di minaccia**: 
1. tool poisoning: Un server utilizza la descrizione di un tool per manipolare il modello linguistico affinché compia un'azione dannosa.
2. dangerous capability: Un tool espone un'operazione ad alto privilegio intrinsecamente pericolosa se concessa a qualsiasi utente.
3. credential leak: Il codice sorgente del server contiene delle credenziali private.
4. access control: Il server concede a se stesso permessi eccessivamente ampi.
5. input validation: Un tool di un server riceve argomenti per la chiamata del tool e li passa a un'operazione sensibile senza controllarli.
6. sensitive info disclosure: Un tool restituisce informazioni che dovrebbero rimanere lato server.
7. untrusted content: Un tool recupera contenuti da una fonte esterna che potrebbe contenere payload dannosi che verranno poi eseguiti.
8. data exfiltration: Un server compromesso trasmette dati sensibili verso un attaccante grazie al suo codice sorgente.
9. protocol non-compliance: Il server devia dal protocollo MCP.

## Slide 5 — SAMS: a Pipeline for MCP Security Analysis *(~40s)*
Per l'analisi ho sviluppato **SAMS** (Security Analysis of MCP Servers), una pipeline organizzata in quattro fasi. 
1. **Collection**, un programma recupera più di 148K server, da cui analizzandoli ed eliminando i duplicati arriviamo a 69.104 server unici. 
2. **Analysis**, i 69K server vengono passati a **7 framework** che li analizzano con tecniche complementari.
3. **3-Stage Post-processing**, dove filtriamo e analizziamo i milioni di finding prodotti attraverso 3 stage.
4. **Validation**, che è una verifica manuale del codice sorgente di un sottoinsieme dei server analizzati.

## Slide 6 — Data Collection & Frameworks Selection *(~45s)*
1. Il web crawler trova più di **148K** server da 18 fonti pubbliche diverse
2. Da qui normalizzo gli URL, faccio un analisi hash del contenuto ed elimino i duplicati e arrivo ad una lista finale di 69.104 server.

Sulla destra poi troviamo le tecniche coperte dai sette framework: 
1. analisi statica del codice sorgente, 
2. analisi semantica via LLM del codice sorgente, 
3. test dei tool e del protocollo,
4. fuzzing dinamico, una tecnica che serve a trovare "punti deboli" facendo correre al server dei pericoli controllati con input inaspettati, sequenze illogiche, comandi errati... 

## Slide 7 — Three-Stage Post-Processing *(~50s)*
I 7 scanner producono più di **3 milioni** di finding che però vanno filtrati e analizzati, lo facciamo attraverso 3 step:
1. **Step 1** è un filtro regex che elimina il rumore evidente come file di test, righe commentate... riducendo il totale a circa **73K**. 
2. **Step 2A** applica regole che triangolano tre segnali (lo snippet di codice, l'identità del server (nome, linguaggio e file_path) e l'eventuale verdetto interno del framework), arrivando a **22K** dati. Alcuni di questi finding possono rimanere con una classificazione incerta.
3. **Step 2B** prende i dati incerti e li risolve con un LLM, trovando **565** vulnerabilità reali. 
Sommando tutti questi dati si arriva a più di **27K** finding confermati.

## Slide 8 — Manual Audit Validation: Framework Reliability (RQ1) *(~40s)*
Per rispondere alla prima domanda sull'affidabilità dei framework e della pipeline ho validato il metodo con una **verifica manuale del codice sorgente**, ispezionando più di **1.500 finding**. Facendo una media pesata dei risultati ottenuti abbiamo una **precisione del 64,8%**, cioè circa **18K** dei 27K dati filtrati sono realmente veri.

Il dato interessante è che la precisione è **disomogenea**. Le categorie **dinamiche e semantiche** sulla sinistra confermano tra l'**80 e il 100%**, mentre le categorie **statiche** con analisi regex confermano molto meno perchè non hanno la possibilità di vedere il contesto o il data-flow.

## Slide 9 — Some misconfigurations and intentionally malicious examples *(~50s)*
Per rendere concreti questi scenari, ecco tre esempi reali. 
- **Tool Poisoning:** è un exploit, quindi **intenzionalmente malevolo**, ed è un esempio di tool description dannosa, dove un semplice tool `add` nasconde un'istruzione da far eseguire all'LLM che viene istruito a mandare tutte le email all'attaccante e non dirlo all'utente. 
- **Dangerous capability:** questa è una **misconfiguration**, è un tool `execute_command` onesto che esegue un comando di shell sull'host. La capacità è dichiarata, ma è intrinsecamente pericolosa se concessa a qualunque chiamante, incluso un LLM manipolato. 
- **Credential leak:** il terzo, anch'esso una misconfiguration, è il caso in cui uno sviluppatore pubblica il server con dei dati segreti reali in chiaro nel codice sorgente.

## Slide 10 — Vulnerability Distribution (RQ2) *(~45s)*
Per la seconda domanda sulla distribuzione delle vulnerabilità ho aggregato i 27K finding confermati nei nove scenari di minaccia. La cosa più importante da leggere è che più di **15K sono protocol non-compliance**, quindi molti server hanno problemi di robustezza e misconfiguration, quindi un problema di qualità: i server semplicemente non seguono correttamente le specifiche del protocollo MCP.

Le vere vulnerabilità di sicurezza sono circa **12K** e si concentrano nei primi cinque scenari, da *input validation* fino ad *untrusted content*. 

Al contrario, il messaggio chiave è che gli attacchi **specifici degli LLM** molto presenti nella letteratura, come il tool poisoning, nella pratica sono **molto rari**: 119 e 2 casi. 

## Slide 11 — Recurring Antipatterns (RQ3) *(~50s)*
Per rispondere alla terza domanda, da questa analisi ho stilato **cinque antipattern ricorrenti**. 
- l'*esecuzione senza restrizioni*: server che espongono l'esecuzione di codice come tool: la capacità è onesta, ma concessa a qualunque chiamante diventa pericolosa. 
- l'*input non controllato*: in cui l'input dell'utente concatenato nel codice (ad esempio una query) diventa pericoloso. 
- i *segreti nel codice*: file con credenziali o chiavi segrete esposti in chiaro nei moduli di configurazione. 
- l'*oversharing a runtime*: invece del segreto nel codice, è il tool che restituisce lo stato del server nella sua risposta. 
- il *fidarsi del contenuto esterno*: server che recuperano contenuto esterno e lo passano all'LLM senza sanitizzazione, creando un canale di injection indiretta.

## Slide 12 — Developer Recommendations (RQ3) *(~65s)*
Ecco invece alcune raccomandazioni concrete. 
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

