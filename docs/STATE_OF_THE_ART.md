# State of the Art — i paper con cui mi confronto, spiegati semplice

Questo documento serve a capire, in modo discorsivo, **cosa fa ogni paper dello stato dell'arte** citato nella presentazione e **con che tecnica**, così da poterlo raccontare a voce anche a chi non è del campo. In fondo trovi un catalogo compatto di tutti gli altri paper letti per la tesi.

## Quattro parole prima di iniziare (mini-glossario)

- **Server MCP**: un piccolo programma che offre a un'AI degli "strumenti" (leggere un file, interrogare un database, cercare sul web…). L'AI non li scrive, li *usa*.
- **SDK**: la "cassetta degli attrezzi" ufficiale (una per linguaggio: Python, TypeScript, Go…) con cui si costruiscono client e server MCP. Nasconde i dettagli del protocollo.
- **Registry / marketplace**: i "negozi" dove trovi e installi i server MCP (mcp.so, Smithery, npm…).
- **Analisi statica**: leggere il codice sorgente *senza eseguirlo*, per cercare pattern pericolosi. **Analisi dinamica**: farlo *girare* e guardare come si comporta.

## La frase da ricordare

Tutti questi lavori studiano la sicurezza di MCP, ma ognuno guarda **una fetta**: chi conta i server, chi misura la salute dell'ecosistema, chi cerca un tipo specifico di attacco. Il mio lavoro è l'unico che mette insieme **scala grande + analisi per-singolo-server + 7 strumenti diversi** sullo stesso dataset (69.104 server). Nella slide lo dico coi numeri: *lo studio precedente più grande arriva a 67.057 server [8], gli altri stanno tra 1.360 e 8.060 [9–12], io a 69.104.*

| Rif. | Paper | Quanti server | Cosa misura | Come |
|:----:|-------|--------------:|-------------|------|
| **[8]** | Toward Understanding Security Issues | 67.057 | sicurezza dell'**ecosistema** (host + registry + server) | qualitativo + conteggio su 6 registry |
| **[9]** | A Measurement Study (MCPCrawler) | 8.060 | **salute** dell'ecosistema (mercato/server/client) | crawler su 6 marketplace |
| **[10]** | We Urgently Need Privilege Management | 2.562 | uso di **API privilegiate** | analisi statica |
| **[11]** | MCP at First Glance | 1.899 | **sicurezza + manutenibilità** dei server | analisi statica ibrida |
| **[12]** | Mind Your Server | 1.360 (12.230 tool) | una **nuova classe di attacco** (parasitic toolchain) | scanner MCP-SEC |
| — | **Compatibility at a Cost** | 10 **SDK** (non server) | falle nella **specifica** del protocollo | IR universale + LLM |
| — | **Il mio lavoro** | **69.104** | vulnerabilità per-server, 17 categorie | 7 framework + pipeline a 3 stage |

---

## Gruppo 1 — Chi fotografa l'ecosistema dall'alto

### [8] Toward Understanding Security Issues in the MCP Ecosystem
*Xiaofan Li, Xing Gao — University of Delaware, ott. 2025*

Immagina di voler capire quanto è sicuro non un singolo negozio, ma **tutto il centro commerciale**: i negozi (i server), le vetrine e i cataloghi (i registry/marketplace) e i clienti che ci entrano (gli host, cioè i programmi con l'AI). Questo paper è il primo a guardare l'MCP a questo livello, non solo il singolo server.

**Come lavorano.** Raccolgono **67.057 server** da **6 registry pubblici** e fanno un'analisi in parte *qualitativa* (studiano che tipo di debolezze ricorrono) e in parte *quantitativa* (contano quanti server ci cascano). Non è uno scan riga-per-riga del codice: è più un censimento ragionato di dove sta il rischio.

**Cosa trovano.** Il punto debole grosso è che **gli host si fidano ciecamente** di quello che un server risponde: non verificano l'output, quindi un server malevolo può manipolare il comportamento dell'AI. E siccome i registry fanno pochi controlli su chi pubblica, un numero notevole di server è "dirottabile". È il più grande studio esistente prima del mio.

**In cosa sono diversi da me.** Loro contano *quanti server sono a rischio a livello di ecosistema*; io apro **il codice di ogni server** e dico *quali vulnerabilità concrete ha*, categoria per categoria, con veri/falsi positivi. Sono complementari — e col mio secondo dataset (NPX) supero comunque il loro numero.

### [9] A Measurement Study of the MCP Ecosystem
*Hechuan Guo et al. — Shandong University + NTU Singapore, nov. 2025*

Questo non è un paper di sicurezza in senso stretto: è una **misurazione dello stato di salute** dell'ecosistema. La domanda di fondo è "l'MCP è un ecosistema vivo e solido, o gonfiato?". Guardano tre cose: il **mercato** (quanto cresce), i **server** (come sono fatti) e i **client** (come si connettono).

**Come lavorano.** Costruiscono **MCPCrawler**, un robot che per **14 giorni** setaccia 6 marketplace, scarta il rumore e normalizza i dati. Partono da 17.630 voci grezze e ne validano **8.060 server** (+341 client).

**Cosa trovano.** Che il mercato è **fragile**: solo il ~49% delle voci è valido, il resto sono placeholder, fork o progetti morti. Un server su cinque è fermo da oltre un anno. E c'è una forte "monocultura" di dipendenze (tutti usano le stesse librerie), che è un rischio supply-chain.

**In cosa sono diversi da me — e perché mi torna utile.** Loro misurano *quanto è sana la popolazione*, non le vulnerabilità sfruttabili. Ma la loro scoperta che **metà dei progetti listati è spazzatura** è un ottimo argomento per giustificare perché io filtro così aggressivamente prima di analizzare.

---

## Gruppo 2 — Chi apre il codice dei server

### [11] MCP at First Glance
*Mohammed Mehedi Hasan et al. — Queen's University, giu. 2025*

Questo è il paper **metodologicamente più vicino al mio**: prende dei server veri e ne analizza il codice per trovare sia problemi di **sicurezza** sia di **qualità/manutenibilità** (i cosiddetti "code smell", cioè codice scritto male ma non necessariamente insicuro).

**Come lavorano.** Una **pipeline ibrida**: uno strumento di analisi statica generico (come quelli che si usano per qualsiasi software) *più* uno scanner fatto apposta per l'MCP, su **1.899 server** open-source.

**Cosa trovano.** **8 categorie di vulnerabilità**, di cui solo 3 in comune col software tradizionale — segno che l'MCP porta rischi *nuovi*. Circa il 7% dei server ha vulnerabilità generiche e il **5,5% ha "tool poisoning"** (descrizioni di strumenti manipolate per ingannare l'AI).

**In cosa sono diversi da me.** Stessa filosofia, ma io sono **~36 volte più grande** (69.104 vs 1.899), uso **7 strumenti invece di 1**, li faccio "votare" tra loro (consensus) e misuro il tasso di falsi positivi con un test cieco.

### [10] We Urgently Need Privilege Management in MCP
*Zhihao Li et al. — Shandong University, lug. 2025*

Idea semplice e potente: un server MCP dovrebbe avere **solo i permessi che gli servono** (principio del privilegio minimo). Questo paper va a misurare **quanto i server usano "poteri" pericolosi** — accesso alla rete, al sistema, ai file — per dimostrare che questo controllo, oggi, manca.

**Come lavorano.** Un framework di **analisi statica automatica** che scandisce il codice di **2.562 server** (divisi in 23 categorie) e conta le chiamate ad API a rischio.

**Cosa trovano.** Tantissimi server toccano rete (1.438), sistema (1.237) e file (613). E, curiosamente, i plugin **meno popolari** sono spesso quelli con la quota più alta di operazioni pericolose.

**In cosa sono diversi da me.** Loro misurano il **potenziale** (usare un'API pericolosa *non* è di per sé una vulnerabilità); io misuro **vulnerabilità realmente presenti** e le classifico. Il mio dataset è ~27 volte più grande.

---

## Gruppo 3 — Chi scopre un tipo di attacco nuovo

### [12] Mind Your Server
*Shuli Zhao et al. — Shanghai Jiao Tong University, set. 2025*

Qui non si contano server: si **scopre e si dà un nome a un attacco nuovo**, il *parasitic toolchain attack*, che porta a una fuga di dati privati non voluta (loro la chiamano MCP-UPD). L'idea: dei dati esterni non fidati entrano nel contesto dell'AI e, passando di strumento in strumento, finiscono per far uscire informazioni riservate.

**Come lavorano.** Modellano l'attacco in **3 fasi** (il contenuto ostile entra → viene raccolto → viene esfiltrato) e costruiscono lo scanner **MCP-SEC** per cercare i "pezzi" sfruttabili su **1.360 server / 12.230 strumenti**.

**Cosa trovano.** Che all'MCP mancano due difese fondamentali: **isolare il contenuto non fidato dagli strumenti potenti** e **imporre il privilegio minimo**. E che l'ecosistema è "pieno di ingranaggi realmente sfruttabili".

**Perché per me è importante.** È il paper da citare quando qualcuno obietta "ma allora anche un server legittimo può essere pericoloso se gli arriva un input ostile": sì, ed è *esattamente* questa classe di attacco — che vive nella **composizione** tra sorgente e strumento, non nel codice del singolo server. Loro si concentrano su questa singola classe; io copro 17 categorie. La loro classe richiede una *traccia di esecuzione*, quindi va oltre lo scan statico puro: un punto di onestà da citare.

### Compatibility at a Cost
*Nanzi Yang, Weiheng Bai, Kangjie Lu — University of Minnesota, mar. 2026*

Questo è il paper "diverso dagli altri": non guarda i server, guarda **le fondamenta**, cioè i **10 SDK ufficiali** (Python, TypeScript, Go, e altri 7). La tesi centrale è elegante: per essere compatibile con qualsiasi AI, la specifica MCP lascia **quasi tutto opzionale**. Su 275 regole, solo il **21,5% è obbligatorio**; il **78,5% è "consigliato" o condizionale**. E una regola che si *può* saltare, spesso viene saltata — e ogni regola saltata è una guardia di sicurezza che manca.

**Esempio concreto.** La specifica dice che un server *dovrebbe* avvisare il client quando cambia i suoi strumenti. L'SDK Python **non implementa** questo avviso. Risultato: un server malevolo può cambiare di nascosto la descrizione di uno strumento e infilare istruzioni ostili nell'AI **senza che nessuno se ne accorga** — una "prompt injection silenziosa".

**Come lavorano (la parte tecnica interessante).** Tre passi: (1) traducono ogni SDK, che è scritto in un linguaggio diverso, in una **rappresentazione comune** (un "IR" neutro, uguale per tutti); (2) fanno un'analisi **ibrida statica + LLM**: l'analisi statica restringe il campo a pochi pezzi di codice, poi un LLM ci ragiona sopra (così l'LLM non allucina e non serve scrivere mille pattern); (3) capiscono quali regole mancanti sono **davvero sfruttabili** guardando se l'attaccante può controllare il *contenuto* o il *tempismo* dei messaggi.

**Cosa trovano.** **1.265 rischi** sfruttabili sui 10 SDK, con circa 86% di precisione. Hanno segnalato i problemi e i manutentori dell'MCP li hanno **presi così sul serio da invitare il loro strumento nel processo ufficiale di conformità (SEP)**.

**Perché mi riguarda da vicino.** È la **base teorica di `mcp-check`**, uno dei 7 strumenti che uso: mcp-check testa proprio le classi di attacco di questo paper (la injection silenziosa, il DoS via `ping`, ecc.). Loro le hanno *formalizzate* sugli SDK; io le *misuro sul campo* su decine di migliaia di server reali.

---

## In una riga: perché il mio lavoro è diverso

Nessuno di questi mette insieme le tre cose contemporaneamente:
1. **Scala** — 69.104 server, più di ogni studio empirico MCP precedente.
2. **Profondità per-server** — non un conteggio, ma 17 categorie di vulnerabilità con veri/falsi positivi misurati.
3. **Più strumenti** — 7 scanner diversi fatti "votare" insieme, con validazione cieca del tasso di errore.

> *"[8] ha la scala ma resta qualitativo; [11] ha la profondità ma su 1.899 server; [12] ha la profondità ma su una sola classe di attacco. Io copro tutte e tre le dimensioni insieme."*

---

## Appendice — catalogo compatto degli altri paper letti

Questi non sono nella slide dello stato dell'arte (sono survey, benchmark o proposte di difesa), ma li ho letti per inquadrare la tesi. Riepilogo di una riga ciascuno.

| Paper | Tipo | In breve |
|-------|------|----------|
| Landscape, Security Threats (Hou et al.) | Survey/vision | Prima tassonomia MCP: 16 minacce × 4 attaccanti, validata con 16 PoC in laboratorio (nessuno scan reale). Paper di riferimento per la tassonomia. |
| A Survey of LLM-Driven AI Agent Communication (Kong et al.) | Survey | Sicurezza della comunicazione tra agenti (MCP + A2A/ANP/ACP), 327 riferimenti. Più ampio del solo MCP. |
| Open Challenges in Multi-Agent Security (Schroeder de Witt) | Position paper | Propone la "Multi-Agent Security" come campo; solo teoria, niente empirico. |
| McpGuard: survey delle difese (Bin Wang et al.) | Survey difese | Nonostante il nome, è una rassegna di difese (3 classi di minacce). Non è lo scanner. |
| SoK: Security and Safety in MCP (2512.08290) | SoK | Sistematizzazione della letteratura; auspica framework ibridi statico+dinamico (che io realizzo). Da leggere per intero. |
| Securing AI Agent Execution / AgentBound (Bühler et al.) | Difesa empirica | Framework di access control stile Android su 296 server; genera policy dal codice con 80,9% di accuratezza. |
| MCPTox (Wang et al.) | Benchmark | Tool poisoning su 45 server live/353 tool, testato su 20 LLM: i modelli più bravi sono più vulnerabili. |
| MSB — MCP Security Bench (Zhang et al.) | Benchmark | 12 attacchi, 400+ tool, 2.000 istanze, 9 agenti LLM. Misura la resilienza degli agenti. |
| MCPSECBENCH (Yang et al.) | Benchmark | 17 attacchi × 3 provider (Claude/OpenAI/Cursor); >85% degli attacchi buca almeno una piattaforma. |
| MCPLIB (Guo et al.) | Benchmark | Libreria di 31 metodi d'attacco in 4 classi, con test quantitativi. |
| MCP Safety Audit / McpSafetyScanner (Radosevich, Halloran) | Tool difesa | Scanner "agentico" multi-agente che genera adversarial samples e report. |
| MCP Guardian (Kumar et al.) | Framework difesa | Layer difensivo: auth + rate-limiting + logging + WAF. |
| MCP-Guard framework (Xing et al.) | Framework difesa | Pipeline a 3 stage (statico → detector neurale E5 96% → arbitro LLM), training su 70k campioni. |
| ETDI (Bhatt et al.) | Proposta difesa | Estensione MCP con OAuth + tool definition firmate contro tool squatting e rug pull. |
| Enterprise-Grade Security for MCP (Narajala, Habler) | Framework difesa | Pattern Zero Trust / Defense-in-Depth per adozione enterprise. |
| MCPBench (Luo et al.) | Performance (NON sicurezza) | Accuratezza/tempo/token su ~10 server; MCP non batte le function call. |
| Security Analysis of Agentic AI Protocols (Louck et al.) | Comparativo (NON MCP) | Confronta CORAL/ACP/A2A, protocolli agente-agente. Utile per inquadramento. |

---

*File correlati: `PAPER_SOTA_PRESENTAZIONE.md` (stessi 5 paper della slide, in formato "domande del prof"), `THREAT_ANALYSIS_REPORT.md` (report finale), `ESEMPI_VULN_PER_CATEGORIA.md` (un esempio reale per categoria).*
*Ultima revisione: 2026-07-21.*
