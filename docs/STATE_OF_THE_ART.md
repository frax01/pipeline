# State of the Art — i paper con cui mi confronto, spiegati semplice

Questo documento spiega, in modo discorsivo, **cosa guarda ogni paper** (il suo focus) e **come lo guarda** (la tecnica), così da poterlo raccontare a voce anche a chi non è del campo. Per ogni paper trovi due righe-ancora (**Cosa guarda / Come lo guarda**) seguite dalla spiegazione. In fondo, un catalogo compatto di tutti gli altri paper letti per la tesi.

## Quattro parole prima di iniziare (mini-glossario)

- **Server MCP (o "plugin")**: un piccolo programma che offre a un'AI degli "strumenti" (leggere un file, interrogare un database, cercare sul web…). L'AI non li scrive, li *usa*.
- **Tool (strumento)**: la singola funzione esposta da un server. Ha un *nome*, una *descrizione* in linguaggio naturale e uno *schema* dei parametri. La descrizione è ciò che l'AI legge per decidere se e come usarlo.
- **SDK**: la "cassetta degli attrezzi" ufficiale (una per linguaggio: Python, TypeScript, Go…) con cui si costruiscono client e server MCP. Nasconde i dettagli del protocollo.
- **Host / client**: l'app con dentro l'AI (es. Claude Desktop, Cursor). L'host decide quali tool chiamare in base alla richiesta dell'utente.
- **Registry / marketplace**: i "negozi" dove trovi e installi i server (mcp.so, PulseMCP, Smithery, npm…).
- **Analisi statica**: leggere il codice/le descrizioni *senza eseguirli*. **Analisi dinamica**: farli *girare* davvero e guardare come si comportano.

## La frase da ricordare

Tutti questi lavori studiano la sicurezza di MCP, ma ognuno guarda **una fetta diversa** e con **una tecnica diversa**. Alcuni contano quanti server esistono, altri leggono il codice, altri ancora fanno *partire* un attacco per vedere se funziona. Il mio lavoro è l'unico che mette insieme **scala grande + analisi per-singolo-server + 7 strumenti diversi** (69.104 server). Nella slide lo dico coi numeri: *lo studio precedente più grande arriva a 67.057 server [8], gli altri stanno tra 1.360 e 8.060 [9–12], io a 69.104.*

| Rif. | Paper | Oggetto (cosa guarda) | Tecnica (come) | Numeri |
|:----:|-------|-----------------------|----------------|-------:|
| **[8]** | Toward Understanding Security Issues | l'**ecosistema**: host + registry + server | qualitativo (design) + conteggio | 67.057 server |
| **[9]** | A Measurement Study (MCPCrawler) | la **salute** dell'ecosistema (mercato/server/client) | crawler + statistica sui metadati | 8.060 server |
| **[10]** | We Urgently Need Privilege Management | l'**uso di API pericolose** nel codice dei server | analisi statica: parser + firme di API | 2.562 server |
| **[11]** | MCP at First Glance | **sicurezza + qualità** del codice dei server | SonarQube (SAST) + mcp-scan | 1.899 server |
| **[12]** | Mind Your Server | una **nuova catena d'attacco** (parasitic toolchain) | LLM classifica i tool + verifica dinamica reale | 1.360 server / 12.230 tool |
| — | **Compatibility at a Cost** | le falle nella **specifica** e nei 10 **SDK** | IR universale + analisi statica-LLM | 10 SDK, 1.265 rischi |
| — | **Il mio lavoro** | **vulnerabilità per-server**, 17 categorie | 7 framework + pipeline a 3 stage | 69.104 server |

---

## Gruppo 1 — Chi fotografa l'ecosistema dall'alto

### [8] Toward Understanding Security Issues in the MCP Ecosystem
*Xiaofan Li, Xing Gao — University of Delaware, ott. 2025*

> **Cosa guarda:** non i singoli server ma **tutto il "centro commerciale"** — i negozi (server), i cataloghi (registry/marketplace) e i clienti (gli host che eseguono l'AI). Cerca le debolezze *strutturali* di come è messo insieme l'ecosistema.
> **Come lo guarda:** in parte **qualitativo** (studiano a mano come funzionano host e registry per capire dove sta la falla di progettazione), in parte **quantitativo** (poi *contano* quanti server sono esposti a quella falla). Non è uno scan del codice riga per riga.

Il messaggio centrale è che il rischio non è (solo) nel singolo server, ma nel modo in cui i pezzi sono collegati. Due debolezze strutturali: (1) gli **host si fidano ciecamente** dell'output di un server — non lo verificano — quindi un server malevolo può manipolare il comportamento dell'AI; (2) i **registry fanno pochi controlli** su chi pubblica, così tanti server sono "dirottabili". Dopo aver individuato queste falle a livello di progettazione, misurano su **67.057 server** (raccolti da 6 registry) quanti ne sono affetti. È il più grande studio esistente prima del mio.

**In cosa siamo diversi.** Loro *contano* quanti server sono a rischio a livello di ecosistema; io *apro il codice* di ogni server e dico *quali vulnerabilità concrete* ha, con veri/falsi positivi. Complementari — e col dataset NPX supero comunque il loro numero.

### [9] A Measurement Study of the MCP Ecosystem
*Hechuan Guo et al. — Shandong University + NTU Singapore, nov. 2025*

> **Cosa guarda:** non la sicurezza, ma lo **stato di salute** dell'ecosistema su tre fronti — **mercato** (quanto cresce), **server** (come sono fatti, che dipendenze hanno) e **client** (come si connettono). La domanda è: "MCP è un ecosistema vivo e solido o gonfiato?".
> **Come lo guarda:** con un crawler automatico, **MCPCrawler**, che per ~14 giorni setaccia 6 marketplace in 3 fasi. (1) **Scoperta + pulizia**: aggrega le voci dai negozi e scarta con regole il rumore (fork inattivi, repository-placeholder, progetti senza codice eseguibile). (2) **Estrazione metadati**: da ogni voce valida ricava dipendenze dichiarate, attività del repo, linguaggio, categoria funzionale, protocollo e modalità di connessione. (3) **Normalizzazione + statistiche** per confrontare i mercati. Analizza *metadati*, non il codice.

Partono da 17.630 voci grezze e ne validano **8.060 server** (+341 client), rispondendo a tre domande. **Mercato:** solo il ~49% delle voci è valido (mcp.so appena il 43%, MCP Market il 26%), e oltre metà sono placeholder, fork o progetti morti → crescita fragile; solo il 6,9% è indicizzato in ≥4 mercati. **Server:** forti *monoculture* di dipendenze (i server Java usano quasi tutti Spring → una falla come SpringShell si propagherebbe a valanga), un server su cinque fermo da oltre un anno, e l'**11,2%** chiama API sensibili (il 43% legate all'autenticazione). **Client:** SSE è ormai lo standard di fatto (**56,9%**) sopra stdio (38,1%), e l'81% gestisce una sola connessione alla volta.

**In cosa siamo diversi — e perché mi torna utile.** Loro misurano *quanto è sana la popolazione*, non le vulnerabilità. Ma il loro dato "**metà dei progetti listati è spazzatura**" giustifica benissimo perché io filtro così tanto prima di analizzare.

---

## Gruppo 2 — Chi apre il codice dei server

### [11] MCP at First Glance
*Mohammed Mehedi Hasan et al. — Queen's University, giu. 2025*

> **Cosa guarda:** il **codice sorgente dei server** su tre dimensioni insieme — **salute/sostenibilità** (il progetto è vivo e mantenuto?), **sicurezza** (vulnerabilità) e **manutenibilità** (code smell e bug). È il paper metodologicamente più vicino al mio.
> **Come lo guarda:** una **pipeline ibrida** con strumenti concreti. Per la salute: metriche di attività (commit/settimana, adozione della CI, contributori) confrontate col software tradizionale. Per sicurezza e qualità: **SonarQube** (un analizzatore statico *generico*, per bug e vulnerabilità classiche) **+ mcp-scan** (uno scanner *specifico per MCP* che legge le descrizioni dei tool per il tool poisoning). Su **1.899 server** (343 dalla collezione ufficiale MCP + 1.556 presi da GitHub).

Il risultato chiave: **SonarQube** segnala vulnerabilità nel **7,2%** dei server (8 pattern; il più comune è l'**esposizione di credenziali**, 3,6%), ma solo 3 di quegli 8 pattern coincidono col software tradizionale — l'MCP porta rischi *nuovi*. E **mcp-scan** trova un **5,5%** di *tool poisoning* che gli strumenti classici non vedono affatto: la lezione è che servono strumenti dedicati all'MCP. Sul fronte qualità, il **66%** ha code smell gravi (soprattutto complessità cognitiva alta) e il **14,4%** ha bug gravi — problemi molto simili al software normale, quindi curabili con le tecniche esistenti. *(Nota: `mcp-scan` è anche uno dei miei 7 framework.)*

**In cosa siamo diversi.** Stessa filosofia, ma io sono **~36× più grande** (69.104 vs 1.899), uso **7 strumenti invece di 1** (loro sostanzialmente SonarQube + mcp-scan), li faccio "votare" tra loro e misuro i falsi positivi con un test cieco.

### [10] We Urgently Need Privilege Management in MCP
*Zhihao Li et al. — Shandong University, lug. 2025*

> **Cosa guarda:** **quanto i server usano API "pericolose"** — cioè che toccano file, rete, sistema o memoria. Attenzione: misura il *potere* che un server si prende, non se ha una vulnerabilità sfruttabile. L'analogia: come si analizzano i permessi delle app Android, ma qui non c'è nessun sandbox a limitarli.
> **Come lo guarda:** analisi statica in 3 fasi. (1) Un **crawler** scarica i repo da MCP Market e li ripulisce (toglie `node_modules`, ambienti virtuali, binari; normalizza la codifica). (2) Un **parser** per ogni linguaggio (Python AST, JavaScript ESTree, JavaParser, con regex di riserva) legge il codice e lo confronta con un **database di "firme" di API** divise in 4 categorie (es. `subprocess`/`exec` = sistema, `socket`/`connect` = rete, `open`/`read` = file). (3) **Conta** le occorrenze e le incrocia con categoria e stelle GitHub.

Su **2.562 server** trovano che quasi tutti toccano rete (1.438) e sistema (1.237), meno i file (613) e la memoria (25). Curiosità utile: i plugin **meno popolari** (0–10 stelle) sono quelli con più chiamate pericolose. Chiudono con 3 casi studio a mano (un blog-publisher, un twitter-mcp, un web-research) per mostrare come questi "poteri" diventano privilege escalation, manipolazione o furto dati.

**In cosa siamo diversi.** Loro misurano il **potenziale** (usare un'API pericolosa ≠ vulnerabilità); io misuro **vulnerabilità realmente presenti** e le classifico. Dataset mio ~27× più grande.

---

## Gruppo 3 — Chi scopre e prova un attacco nuovo

### [12] Mind Your Server
*Shuli Zhao et al. — Shanghai Jiao Tong University, set. 2025*

> **Cosa guarda:** una **nuova catena d'attacco** — il *parasitic toolchain attack*, che chiamano MCP-UPD (fuga di dati privati). L'idea: non serve un server malevolo né toccare la vittima; basta nascondere un "prompt parassita" in un contenuto esterno (un post, un documento). Quando l'AI lo legge durante un compito normale, viene guidata a **incatenare tre tool legittimi** e rubare dati.
> **Come lo guarda:** costruiscono lo scanner **MCP-SEC** in 3 componenti. (1) Un **crawler** raccoglie i server da 3 fonti (PulseMCP, MCP Market, Awesome MCP) e, via il client Python ufficiale, si connette a ciascuno e ne estrae le descrizioni dei tool. (2) Un **LLM legge ogni descrizione** e classifica il tool in una di 3 "capacità": può *ingerire* contenuto esterno (EIT), può *leggere* dati privati (PAT), o può *mandare* dati fuori (NAT). (3) Un **verificatore dinamico** fa *girare davvero* i tool dentro Cursor (con un simulatore di tastiera/mouse) per confermare che l'attacco funziona sul campo. Quindi: statico (leggono le descrizioni) **+ dinamico** (provano l'attacco).

I tre passi dell'attacco corrispondono alle tre capacità: **Ingestion** (un tool tipo `fetch`/`search` porta dentro il prompt parassita) → **Collection** (un tool tipo `read_file` legge dati sensibili) → **Disclosure** (un tool tipo `send_mail` li esfiltra). Su **1.360 server / 12.230 tool** trovano che l'**8,7% dei tool** e il **27,2% dei server** offrono "ingranaggi" sfruttabili, e che **9 catene su 10** costruite a mano rubano davvero i dati in Cursor. La causa profonda: MCP non **isola il contenuto non fidato dai tool potenti** e non impone il **privilegio minimo**.

**Perché per me è importante.** È il paper da citare quando qualcuno obietta "ma allora anche un server legittimo può essere pericoloso se gli arriva un input ostile": sì, ed è *esattamente* questa classe di attacco — che vive nella **composizione** tra più tool, non nel codice di un singolo server. Ecco perché uno scan per-singolo-server come il mio vede gli *ingredienti* separati (una sorgente di untrusted-content, una dangerous-capability) ma non la catena già montata: quella richiede far girare i tool insieme, come fanno loro col verificatore dinamico. Loro coprono questa singola classe su 1.360 server; io copro 17 categorie su 69.104.

### Compatibility at a Cost
*Nanzi Yang, Weiheng Bai, Kangjie Lu — University of Minnesota, mar. 2026*

> **Cosa guarda:** non i server, ma **le fondamenta** — i **10 SDK ufficiali** (Python, TypeScript, Go, e altri 7) e la **specifica** del protocollo. La tesi: per essere compatibile con ogni AI, MCP lascia quasi tutto opzionale (su 275 regole, solo il **21,5% è obbligatorio**), e una regola che si *può* saltare spesso viene saltata — e ogni regola saltata è una guardia di sicurezza che manca.
> **Come lo guarda:** tre passi. (1) Un **IR universale**: traducono ogni SDK, scritto in un linguaggio diverso, in una **rappresentazione comune** (estraggono dal codice un "grafo di chiamate condizionate": quali funzioni vengono chiamate e sotto quali condizioni), così l'analisi vale per tutti i linguaggi. (2) **Analisi ibrida statica + LLM**: l'analisi statica restringe il campo a pochi pezzi di codice rilevanti, poi un LLM ci ragiona sopra (con un ciclo che si auto-raffina), evitando sia le allucinazioni sia migliaia di pattern scritti a mano. (3) **Analisi di sfruttabilità**: una regola mancante è pericolosa solo se l'attaccante può controllare il *contenuto* o il *tempismo* dei messaggi → da qui tre "modalità" d'attacco (PyTy = controlli entrambi → injection silenziosa; PnTy = solo tempismo → DoS; PyTn = solo contenuto).

Esempio concreto: la specifica dice che un server *dovrebbe* avvisare il client quando cambia i suoi tool, ma l'SDK Python **non lo implementa**. Così un server può cambiare di nascosto la descrizione di un tool e infilare istruzioni ostili nell'AI **senza che nessuno se ne accorga**. Trovano **1.265 rischi** sfruttabili sui 10 SDK (con ~86% di precisione, verificata da tre revisori umani), e i manutentori ufficiali di MCP li hanno presi così sul serio da **invitare il loro strumento nel processo ufficiale di conformità (SEP)**.

**Perché mi riguarda da vicino.** È la **base teorica di `mcp-check`**, uno dei 7 strumenti che uso: mcp-check testa proprio queste classi (injection silenziosa, DoS via `ping`, ecc.). Loro le hanno *formalizzate* sugli SDK; io le *misuro sul campo* su decine di migliaia di server reali.

---

## In una riga: perché il mio lavoro è diverso

Nessuno mette insieme le tre cose contemporaneamente:
1. **Scala** — 69.104 server, più di ogni studio empirico MCP precedente.
2. **Profondità per-server** — non un conteggio, ma 17 categorie di vulnerabilità con veri/falsi positivi misurati.
3. **Più strumenti** — 7 scanner diversi fatti "votare" insieme, con validazione cieca del tasso di errore.

> *"[8] ha la scala ma resta qualitativo; [11] ha la profondità ma su 1.899 server; [12] ha la profondità ma su una sola classe di attacco. Io copro tutte e tre le dimensioni insieme."*

---

## Appendice — catalogo compatto degli altri paper letti

Non sono nella slide dello stato dell'arte (sono survey, benchmark o proposte di difesa), ma li ho letti per inquadrare la tesi. Per ognuno: cosa guarda / come.

| Paper | Tipo | Cosa guarda e come |
|-------|------|--------------------|
| Landscape, Security Threats (Hou et al.) | Survey/vision | **Cosa:** tassonomia delle minacce MCP (16 minacce × 4 attaccanti). **Come:** costruzione manuale di 16 server-esempio (PoC) in laboratorio, nessuno scan reale. |
| A Survey of LLM-Driven AI Agent Communication (Kong et al.) | Survey | **Cosa:** sicurezza della comunicazione tra agenti (MCP + A2A/ANP/ACP). **Come:** rassegna di letteratura (327 riferimenti), non empirico. |
| Open Challenges in Multi-Agent Security (Schroeder de Witt) | Position paper | **Cosa:** propone la "Multi-Agent Security" come campo. **Come:** solo discussione teorica. |
| McpGuard: survey delle difese (Bin Wang et al.) | Survey difese | **Cosa:** panorama delle difese MCP (3 classi di minacce). **Come:** rassegna, nessuna analisi propria. (Non è lo scanner.) |
| SoK: Security and Safety in MCP (2512.08290) | SoK | **Cosa:** sistematizza tutta la letteratura di sicurezza MCP. **Come:** survey + tassonomia; auspica framework ibridi statico+dinamico. |
| Securing AI Agent Execution / AgentBound (Bühler et al.) | Difesa empirica | **Cosa:** un sistema di permessi stile Android per MCP. **Come:** genera automaticamente le policy dal codice sorgente (80,9% accuratezza) su 296 server. |
| MCPTox (Wang et al.) | Benchmark | **Cosa:** quanto gli LLM cascano nel tool poisoning. **Come:** 1.312 test da 3 template su 45 server live, provati su 20 LLM. |
| MSB — MCP Security Bench (Zhang et al.) | Benchmark | **Cosa:** la resilienza degli *agenti* a 12 tipi d'attacco. **Come:** 2.000 istanze d'attacco su 400+ tool, 9 agenti LLM. |
| MCPSECBENCH (Yang et al.) | Benchmark | **Cosa:** superficie d'attacco su 4 livelli. **Come:** 17 attacchi provati su 3 provider (Claude/OpenAI/Cursor); >85% buca almeno uno. |
| MCPLIB (Guo et al.) | Benchmark | **Cosa:** libreria di attacchi. **Come:** 31 metodi in 4 classi, con test quantitativi di efficacia. |
| MCP Safety Audit / McpSafetyScanner (Radosevich, Halloran) | Tool difesa | **Cosa:** dimostra exploit e propone uno scanner. **Come:** tool "agentico" che genera adversarial samples e report. |
| MCP Guardian (Kumar et al.) | Framework difesa | **Cosa:** proteggere i sistemi MCP a runtime. **Come:** layer con auth + rate-limiting + logging + WAF. |
| MCP-Guard framework (Xing et al.) | Framework difesa | **Cosa:** rilevare input malevoli verso i tool. **Come:** pipeline a 3 stage (statico → detector neurale E5 96% → arbitro LLM), training su 70k campioni. |
| ETDI (Bhatt et al.) | Proposta difesa | **Cosa:** fermare tool squatting e rug pull. **Come:** estensione MCP con OAuth + definizioni di tool firmate e versionate. |
| Enterprise-Grade Security for MCP (Narajala, Habler) | Framework difesa | **Cosa:** adozione enterprise sicura. **Come:** pattern Zero Trust / Defense-in-Depth, threat modeling. |
| MCPBench (Luo et al.) | Performance (NON sicurezza) | **Cosa:** quanto sono efficaci/veloci i server. **Come:** accuratezza/tempo/token su ~10 server; MCP non batte le function call. |
| Security Analysis of Agentic AI Protocols (Louck et al.) | Comparativo (NON MCP) | **Cosa:** confronto tra protocolli agente-agente. **Come:** tassonomia a 14 punti su CORAL/ACP/A2A. |

---

*File correlati: `PAPER_SOTA_PRESENTAZIONE.md` (stessi 5 paper della slide, in formato "domande del prof"), `THREAT_ANALYSIS_REPORT.md` (report finale), `ESEMPI_VULN_PER_CATEGORIA.md` (un esempio reale per categoria).*
*Ultima revisione: 2026-07-21.*

- Toward understanding: Gli host si fidano ciecamente degli output di un server, per fare questa analisi fanno: Qui non c'è nessuno strumento automatico. Studiano a mano il funzionamento dell'host — cioè come Cursor / Claude Desktop / Cline prendono l'output del modello e lo trasformano in una chiamata a un tool. Seguono il flusso:

l'host legge nomi/parametri/descrizioni dei tool dai server configurati → li mette in una lista unica → manda al modello (system prompt + lista tool + storico) → il modello risponde "chiama il tool X con i parametri Y" → l'host esegue, senza controllare nulla.

Da questo ragionamento sul design deducono la falla di fondo — l'host non verifica l'output del modello — e ne derivano gli scenari concreti che possono nascerne: la tool confusion, il context dangling tool, e gli effetti diretti/indiretti di una descrizione di tool avvelenata
e poi i registry fanno pochi controlli su chi pubblica, questa analisi viene fatta così:
2. Analisi quantitativa → su registry e server (per misurare quanti sono davvero esposti)
Qui invece raccolgono dati e contano. Il procedimento:

Crawling dei 6 registry (4 decentralizzati: mcp.so, MCP Market, MCP Store, Pulse MCP; 2 centralizzati: Smithery, npm) → 67.057 server.
Per ciascun server, vanno a guardare il repository GitHub reale a cui punta. È questo il passaggio-chiave che risponde alla tua domanda: incrociano la voce del registry con il vero repo su GitHub e controllano se quell'aggancio è "attaccabile".
Il caso più chiaro è il numero-simbolo, 304 server vulnerabili a redirection hijacking, e vale la pena spiegare come arrivano a quel 304:

prendono l'URL GitHub dichiarato dal server;
controllano lo stato dell'account/repo: se l'account che ospitava il server è stato cancellato o rinominato, quel nome-utente GitHub torna libero;
un attaccante potrebbe ri-registrare quel nome, ricreare un repo con lo stesso nome e — siccome il registry punta ancora lì — servire un server malevolo al posto dell'originale;
contano quanti server si trovano in questa condizione → 304.
Con la stessa logica verificano gli altri due attacchi ai registry:

token leak di mcp.so: ispezionano il registry stesso e trovano che espone i token dei proprietari → con quel token si inietterebbe codice in un server legittimo;
name-squatting: sui registry centralizzati verificano che è possibile pubblicare un server con nome quasi identico a uno vero.
Infine, estraggono 44.499 tool dai server scritti in Python e ne ispezionano le descrizioni/comportamenti per isolare quelli con intenti malevoli.

- A measurement study: Guardano se i server che recuperano tramite un web crawler (circa 17K) sono validi, infatti alla fine solo 8K sono validi e altri sono server inutilizzati, fork, placeholder...
- Mcp at first Glance: Guarda i codici sorgente lìdel server tramite mcp-scan e sonarQube (un semplice analizzatore per bug) e cerca veulnerabilità a seconda di quello che dicono questi scanner e la cosa che trovano di più sono le credential leak e protocol non compliance
- We urgently need: API come exec/subprocess, connetc ecc... Quelle più frequenti sono chiamate di rete e sistema, meno file e memoria
- Mind your server - Untrusted content con parasitic toolchain in cui concatena tool che hanno descrizioni che impattano con altri tool
- Compatibility at a cost: Controlla il protocollo con cui sono implementati i server su 10sdk diversi attraverso regex e LLM, il messaggio chiave è che la compatibilità di un server è opzionale (può scegliere di non seguire le specifiche) ma ad un costo