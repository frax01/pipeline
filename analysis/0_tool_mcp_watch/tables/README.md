# MCP Watch — Spiegazione dei grafici

**MCP Watch** e composto da 12 scanner TypeScript in parallelo che eseguono analisi statica basata su regex del codice sorgente. Gli scanner cercano pattern per: toxic flow, credential leak, tool poisoning, prompt injection, tool mutation, input validation, access control, server spoofing, protocol violation, data exfiltration, steganographic attack. Clona il repository e scansiona i file sorgente senza avviare il server.

Server analizzati: **46.982** su 60.205 (78.04%)
Vulnerabilita totali: **9.911.265** (media 210.96 per server)
Stima falsi positivi: **~95%**

---

## 01_languages.png — Distribuzione dei linguaggi

**Cosa mostra**: Linguaggi dei 46.982 server analizzati.

**Interpretazione**: Node.js (25.141) e Python (21.841) coprono la quasi totalita. La copertura del 78% e buona perche MCP Watch necessita solo di clonare il repo e scansionare i file sorgente — non deve avviare il server. Il 22% di fallimento e dovuto a problemi di clonazione (repo rimossi, privati, timeout).

---

## 02_severity.png — Distribuzione delle severity

**Cosa mostra**: I 9.911.265 finding per severity.

- **Medium (6.089.408, 61.4%)**: La maggioranza — dominata da UNTRUSTED_DATA_PROCESSING e GENERIC_TOXIC_FLOW_CHAIN
- **High (2.594.966, 26.2%)**: Include AUTOMATIC_CONTENT_PUBLISHING, PATH_TRAVERSAL, EXCESSIVE_PERMISSIONS
- **Critical (1.226.891, 12.4%)**: Include GENERIC_TOXIC_FLOW_CHAIN (la catena completa: input esterno + accesso privilegiato + output pubblico)

**Perche quasi 10 milioni**: Il problema strutturale di MCP Watch e che i pattern regex sono troppo generici:
- `import { X } from "../utils/Y"` = PATH_TRAVERSAL (qualsiasi `../` e flaggato)
- `console.log(message)` = AUTOMATIC_CONTENT_PUBLISHING (qualsiasi output e "data exfiltration")
- `public` come keyword TypeScript = "public output" in un toxic flow
- `private` come keyword TypeScript = "private data access"
- `create` + `user` nella stessa riga = EXCESSIVE_PERMISSIONS

Un singolo file TypeScript puo generare decine di finding. Con una media di 211 per server, l'output e inutilizzabile senza un massiccio lavoro di triage.

---

## 03_categories_pie.png — Distribuzione categorie

**Cosa mostra**: Proporzione delle 11 categorie di vulnerabilita.

- **Toxic Flow (7.161.734, 72.3%)**: La categoria dominante. Lo scanner GENERIC_TOXIC_FLOW_CHAIN cerca la presenza contemporanea di: (1) input da fonte esterna, (2) accesso a dati privilegiati, (3) output verso destinazione pubblica. Ma i pattern sono cosi generici che quasi ogni server li matcha — `fetch()` = input esterno, `readFile()` = dati privilegiati, `console.log()` = output pubblico
- **Credential Leak (1.034.432, 10.4%)**: Qualsiasi variabile o stringa che assomiglia a una credenziale (API_KEY, TOKEN, SECRET nel codice)
- **Input Validation (828.801, 8.4%)**: Assenza di validazione esplicita nei parametri
- **Access Control (471.419, 4.8%)**: Permessi troppo ampi o assenti
- **Protocol Violation (260.890, 2.6%)**: Violazioni del protocollo MCP (es. HTTP invece di HTTPS)
- **Prompt Injection (61.348, 0.6%)**: Istruzioni nascoste nelle descrizioni — uno dei pochi finding con valore reale
- **Data Exfiltration (24.842, 0.25%)**: Canali di esfiltrazione dati
- **Server Spoofing (22.406, 0.23%)**: Server che impersonano altri server
- **Tool Mutation (21.803, 0.22%)**: Tool le cui descrizioni cambiano dinamicamente
- **Steganographic Attack (17.609, 0.18%)**: Caratteri Unicode invisibili nelle descrizioni
- **Tool Poisoning (5.981, 0.06%)**: Istruzioni malevole nei tool

**I finding con valore reale** (< 1% del totale): prompt-injection, tool-poisoning e steganographic-attack sono le uniche categorie dove il pattern matching ha senso — cercano pattern specifici (`<IMPORTANT>`, zero-width characters, istruzioni nascoste) che sono quasi sempre intenzionali.

---

## 04_categories_bar_log.png — Categorie in scala logaritmica

**Cosa mostra**: Lo stesso dato di 03 ma in scala logaritmica per visualizzare le categorie rare (tool-poisoning, steganographic-attack) altrimenti invisibili.

**Perche scala log**: Toxic flow (7.1M) e 1.200 volte piu grande di tool-poisoning (5.981). Senza scala logaritmica le categorie rare sarebbero pixel invisibili nel grafico. La scala log permette di vedere la varianza di 3 ordini di grandezza.

---

## 05_failure_reasons.png — Motivi di fallimento

**Cosa mostra**: Perche il 21.96% dei server (13.223) non e stato analizzato.

- **Execution Failed (11.790, 89.2%)**: Lo scanner e crashato durante l'analisi — possibile causa: file troppo grandi, encoding non supportato, pattern regex in loop
- **Clone Failed (1.332, 10.1%)**: Impossibile clonare il repository (rimosso, privato, errore di rete)
- **Prepare Timeout (101, 0.8%)**: Timeout durante la preparazione

Il tasso di fallimento del 22% e alto rispetto ad altri tool (MCP Guard 6.3%, MCP Security Scan non riportato) e potrebbe indicare instabilita nei scanner regex su codebase grandi.
