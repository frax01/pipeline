# State of the Art — I 5 paper citati nella presentazione

Documento di ripasso per la discussione. Copre **solo** i paper dello *state of the art* mostrati nella slide "Framework Selection / Comparison with the state of the art" (riferimenti **[8]–[12]**), quelli con cui confronto la scala del mio lavoro.

> Nella slide dico: *Largest prior study: **67.057** server [8] · Other studies: **between 1.360 and 8.060** servers [9–12] · This work: **69.104** servers*.
> Quindi devo saper spiegare **chi sono quei numeri** e **cosa fa ogni paper**.

---

## Mappa rapida dei numeri (da tenere a mente)

| Rif. | Paper | Server analizzati | Cosa misura | Metodo |
|:----:|-------|------------------:|-------------|--------|
| **[8]** | Toward Understanding Security Issues | **67.057** | sicurezza dell'**ecosistema** (host + registry + server) | qualitative + count su 6 registri |
| **[9]** | A Measurement Study (MCPCrawler) | **8.060** (+341 client) | **misurazione** salute ecosistema (mercato/server/client) | crawler su 6 marketplace |
| **[10]** | We Urgently Need Privilege Management | **2.562** | uso di **API privilegiate** nei server | static analysis |
| **[11]** | MCP at First Glance | **1.899** | **security + maintainability** dei server | hybrid SAST + MCP scanner |
| **[12]** | Mind Your Server | **1.360** (12.230 tool) | nuova classe di attacco (**parasitic toolchain**) | MCP-SEC scanner |
| — | **Il mio lavoro** | **69.104** (60.205 GitHub + 8.899 NPX) | vulnerabilità per-server, 8+ categorie | 7 framework + pipeline 3 stage |

**La frase da dire in una riga:** *"[8] è l'unico più grande del mio, ma fa un'analisi qualitativa a livello di ecosistema; io faccio uno scan di vulnerabilità per-server con 7 framework su un dataset ancora più grande. Gli altri quattro ([9]–[12]) stanno tra 1.360 e 8.060 server, cioè 8–50× più piccoli del mio."*

---

## [8] Toward Understanding Security Issues in the MCP Ecosystem
**Xiaofan Li, Xing Gao** — University of Delaware — arXiv 2510.16558, Ott 2025

- **Cosa fa:** prima analisi di sicurezza dell'intero **ecosistema** MCP, non solo dei server: guarda anche gli **host** (i client/LLM) e i **registry** (i marketplace).
- **Dataset:** **67.057 server** raccolti da **6 registri pubblici** (mcp.so, MCP Market, MCP Store, Pulse MCP, Smithery, npm). È **il più grande studio precedente al mio**.
- **Metodo:** misto **qualitativo + quantitativo** (count). Non è uno scan di vulnerabilità server-per-server: analizzano *pattern* di rischio (es. mancanza di verifica degli output, vetting debole dei registry) e **contano** quanti server sono esposti.
- **Risultati chiave:**
  - Gli host **non verificano** gli output generati dagli LLM → un server malevolo può manipolare il comportamento dell'agente.
  - Un numero rilevante di server è **"hijackable"** per assenza di vetting nei registry.
  - Disclosure responsabile ai 6 registri.
- **Se il prof chiede "ma questo è più grande del tuo":** vero sul conteggio (67k vs 60k GitHub), ma è **qualitative + count a livello di ecosistema**; io faccio **scan per-server con categorie di vulnerabilità, VP/FP e risk score usando 7 framework**. Sono complementari, non sovrapposti — e col dataset NPX il totale mio (69.104) lo supera comunque.

---

## [9] A Measurement Study of Model Context Protocol Ecosystem
**Hechuan Guo, Yongle Hao, Yue Zhang, Minghui Xu, Peizhuo Lv, Jiezhi Chen, Xiuzhen Cheng** — Shandong University + NTU Singapore — arXiv 2509.25292, Nov 2025

- **Cosa fa:** prima **measurement study** su larga scala dell'ecosistema MCP. Non è security-first: fotografa **stato di salute e sostenibilità** dell'ecosistema su tre dimensioni — **mercato, server, client**.
- **Tool:** **MCPCrawler**, framework di misurazione a 3 stage (discovery + filtering rumore → estrazione metadati → normalizzazione/visualizzazione), campagna di **14 giorni** su **6 marketplace**.
- **Dataset:** **17.630 entry grezze → 8.401 validate** = **8.060 server + 341 client**. (È il **8.060** = estremo alto del range "1.360–8.060" della mia slide.)
- **Tre research question:** RQ1 mercato (scala/crescita), RQ2 server (sicurezza/privacy), RQ3 client (protocolli/connessioni).
- **Risultati chiave:**
  - **Mercato fragile:** solo **49,1%** delle entry è valido; **>50%** sono placeholder, fork o progetti abbandonati. MCP.so ormai in plateau; solo 6,9% dei progetti indicizzati in ≥4 mercati.
  - **Server:** forti **monoculture di dipendenze** (Java→Spring, Python/TS→pydantic/zod; Go/Rust senza tutele equivalenti) → rischio supply-chain. **21,9%** dei server inattivi da oltre un anno. **11,2%** dei server invocano **API sensibili**, di cui il **43%** legate all'autenticazione.
  - **Client:** **SSE** domina (56,9%) su stdio (38,1%); **80,9%** supporta una sola connessione server.
- **Se il prof chiede il confronto:** loro **misurano la salute dell'ecosistema** (quanti server "veri", quanto manutenuti, che dipendenze), non le vulnerabilità sfruttabili. Il mio lavoro è **security-first per-server**. Nota utile: anche loro trovano che **metà dei progetti listati è spazzatura** — buon argomento per giustificare il mio filtering aggressivo.

---

## [10] We Urgently Need Privilege Management in MCP: A Measurement of API Usage
**Zhihao Li, Kun Li, Boyang Ma, Minghui Xu, Yue Zhang, Xiuzhen Cheng** — Shandong University — arXiv 2507.06250, Lug 2025

- **Cosa fa:** misura **quanto** i server MCP usano **API privilegiate** (rete, risorse di sistema, file). Tesi del paper: manca la gestione dei privilegi (niente least-privilege).
- **Dataset:** **2.562 server** MCP suddivisi in **23 categorie funzionali**.
- **Metodo:** framework di **static analysis automatizzata** che scansiona il codice sorgente e conta le chiamate ad API a rischio.
- **Risultati chiave:**
  - 1.438 server usano API di **rete**, 1.237 API di **sistema**, 613 API su **file**.
  - Categorie più "API-intensive": *Developer Tools* e *API Development*.
  - I plugin **meno popolari** hanno spesso quote sproporzionate di operazioni ad alto rischio.
- **Se il prof chiede il confronto:** loro misurano **quanti server hanno il *potenziale* privilegio** (uso di API pericolose ≠ vulnerabilità reale). Io misuro **quante vulnerabilità realmente presenti/sfruttabili** ci sono. Dataset mio ~27× più grande.

---

## [11] MCP at First Glance: Studying the Security and Maintainability of MCP Servers
**Mohammed Mehedi Hasan, Hao Li, Emad Fallahzadeh, Gopi Krishnan Rajbahadur, Bram Adams, Ahmed E. Hassan** — Queen's University — arXiv 2506.13538, Giu 2025

- **Cosa fa:** primo studio empirico che unisce **sicurezza + manutenibilità** (health, code smells, bug pattern) dei server MCP. È il paper **metodologicamente più vicino al mio**.
- **Dataset:** **1.899 server** open-source.
- **Metodo:** **pipeline ibrida** = tool di static analysis general-purpose + **scanner MCP-specifico**.
- **Risultati chiave:**
  - **8 categorie di vulnerabilità** identificate (solo 3 in comune con il software tradizionale).
  - **7,2%** dei server con vulnerabilità generali; **5,5%** con **tool poisoning** MCP-specifico.
  - **66%** con code smell, **14,4%** con bug pattern tradizionali.
- **Se il prof chiede il confronto:** stessa filosofia (empirical scan multi-categoria), ma **il mio è ~36× più grande** (69.104 vs 1.899) e usa **7 framework** invece di **1** pipeline ibrida, con **consensus cross-framework** e **validazione blind** del FP rate.

---

## [12] Mind Your Server: A Systematic Study of Parasitic Toolchain Attacks on the MCP Ecosystem
**Shuli Zhao, Qinsheng Hou, Zihan Zhan, Yanhao Wang, Yuchong Xie, Yu Guo, Libo Chen, Shenghong Li, Zhi Xue** — Shanghai Jiao Tong University — arXiv 2509.06572, Set 2025

- **Cosa fa:** identifica una **nuova classe di attacco** — i **Parasitic Toolchain Attacks**, che portano a **MCP-UPD** (Unintended Privacy Disclosure): dati sensibili esfiltrati incrociando più tool.
- **Dataset:** **12.230 tool su 1.360 server** — la loro "prima security census su larga scala". (Il **1.360** = estremo basso del range "1.360–8.060" della mia slide.)
- **Metodo:** modellano il flusso d'attacco in **3 fasi** (Parasitic Ingestion → Privacy Collection → Privacy Disclosure) e costruiscono lo scanner **MCP-SEC** per cercare i "gadget" sfruttabili.
- **Risultati chiave:**
  - MCP manca di **context-tool isolation** e di **least-privilege enforcement**.
  - L'ecosistema è "pieno di gadget realmente sfruttabili".
- **Se il prof chiede il confronto:** loro sono **focalizzati su una singola classe** di attacco (toolchain/privacy), il mio è **broad** (8+ classi). Loro 1.360 server, io 69.104. Nota: la loro classe di attacco richiede *execution trace*, quindi è fuori dalla portata di uno scan statico puro — è un punto di onestà da citare.

---

## Cosa rende il mio lavoro diverso (riassunto per la difesa)

1. **Scala assoluta:** **69.104 server** (60.205 GitHub + 8.899 NPX) — più grande di ogni studio empirico MCP precedente.
2. **Profondità per-server:** non solo un conteggio, ma **8+ categorie di vulnerabilità** per server con **VP/FP** misurati.
3. **Multi-framework consensus:** unico a combinare **7 scanner** diversi (mcp-scan, mcp-watch, mcp-guard, mcp-shield, mcp-security-scan, mcp-check, tool_fuzzing) e a fondere i risultati per grado di accordo.
4. **Validazione blind:** classificazione cieca **n=50/categoria** per stimare il FP rate metodologico (~5%).
5. **Secondo dataset (NPX):** 8.899 pacchetti npm che **nessun altro paper analizza**.

**Frase di chiusura:** *"Nessuno dei precedenti combina scala grande, profondità per-server e più framework insieme: [8] ha scala ma resta qualitativo, [11] ha la profondità ma su 1.899 server, [12] ha profondità ma su una sola classe di attacco. Io copro tutte e tre le dimensioni contemporaneamente."*

---

*Nota: i riferimenti [1]–[7] della presentazione sono i **framework di scanning** (mcp-watch, mcp-guard, mcp-check, mcp-security-scanner, mcp-scan, mcp-shield, mcp-server-fuzzer), non paper accademici — vedi la slide "Framework Selection". Il tracking completo di tutti i 22 paper letti per la tesi è in `docs/STATE_OF_THE_ART.md`.*
