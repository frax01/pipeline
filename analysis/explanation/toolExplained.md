# Classifica Tool di Analisi: dal Migliore al Peggiore

1. Snyk Agent Scan (mcp-scan) — Il Migliore
Cosa fa: Client Python che avvia ogni server MCP, enumera i tool esposti e invia le firme al backend Snyk/Invariant Labs, che esegue l'analisi (check statico + LLM per prompt injection, labeling dei tool come destructive/public_sink/private_data).

Perchè è il migliore:

Numeri contenuti e realistici: 5.352 vulnerabilita su 132.009 tool (1.61%)
Distingue chiaramente tra severity: solo 109 critical (E001 prompt injection), 924 medium, 4.319 low
Analisi fatta da backend professionale (Snyk), non regex locali
I 109 E001 (prompt injection) sono i piu credibili di tutti i tool
Il conteggio "dangerous words" (W001) e onestamente classificato come LOW
Stima falsi positivi: ~15-25% (principalmente nei W001 "dangerous words" — parole come "important" o "critical" usate in contesti legittimi)

2. MCP Security Scanner (mcp-security-scan) — Secondo
Cosa fa: Scanner Python che esegue 15 check su ogni server (protocol testing, analisi statica, fuzzing attivo con payload di injection come ; id, $(whoami), ../../../../etc/passwd).

Perch'e buono:

Architettura multi-livello: statica + dinamica + fuzzing reale
Check molto specifici e mirati (34 prompt injection, 95 rug-pull, 124 path traversal, 7 remote access control)
I numeri bassi per check rari (2 indirect prompt injection, 1 sensitive resource exposure) indicano precisione
88% dei finding e "initialization-error" (info) — correttamente non classificato come vulnerabilita
Sui ~8.500 server funzionanti, 42% ha dangerous capabilities e 39% fallisce injection fuzzing — alto ma plausibile
Stima falsi positivi: ~20-35% (X-02 injection fuzzing puo avere falsi positivi quando "linux" o "stdout" appaiono in contesti innocui)

3. MCP Shield — Terzo
Cosa fa: Analisi statica TypeScript sulle descrizioni e input schema dei tool. 4 detector: sensitive-file-access (regex su parole come "token", "secret"), exfiltration channels (parametri con nomi sospetti come "notes", "metadata"), hidden instructions (tag <instructions>, "ignore previous"), shadowing (tool che cercano di manipolare altri tool).

Perch'e discreto:

I 39 shadowing e 519 hidden instructions sono i finding piu interessanti e probabilmente reali
L'analisi LLM opzionale aggiunge un layer di verifica
Ma "sensitive-file-access" (75% dei finding) e troppo aggressivo: qualsiasi tool che dice "reads content" viene flaggato
Stima falsi positivi: ~60-70% (dominato da sensitive-file-access che matcha troppi pattern legittimi)

4. MCP Check — Quarto
Cosa fa: Test di conformance al protocollo MCP (handshake, tool discovery, tool invocation). NON cerca vulnerabilita di sicurezza ma testa la qualita dell'implementazione: validazione input, gestione tool inesistenti, determinismo, schema validity.

Perch'e a meta classifica:

Non e uno scanner di sicurezza, quindi non ha "falsi positivi di vulnerabilita" — testa la conformita
Dati utili: 12.277 tool che accettano input invalidi, 3.502 che non gestiscono tool inesistenti
I finding sono oggettivi (il test passa o no), non interpretazioni
Ma il 42.86% dei server non avviabili gonfia i numeri di errore
Stima falsi positivi: ~5-10% per la natura dei test (pass/fail oggettivo), ma non misura sicurezza direttamente

5. MCP Guard — Quinto
Cosa fa: Scanner Python con 3 livelli: analisi statica del codice sorgente (regex su pattern come subprocess.run, os.system), analisi dinamica simulata (non avvia il server, simula finding basandosi sul codice), e real fuzzing (avvia il server e testa con payload malevoli). Assegna severity con CVSS v4.0 + AIVSS.

Perch'e problematico:

561.632 vulnerabilita totali, media 9.96 per server — numeri gonfiati
L'80% dell'analisi "dinamica" e in realta statica potenziata (il server non si avvia)
categories_dynamic con 115.706 command injection — numeri enormi perche simulati, non verificati
Le categorie statiche matchano pattern troppo generici (46.370 "missing input validation" = quasi ogni server)
Stima falsi positivi: ~70-80% (analisi dinamica simulata e il problema principale — genera finding senza avviare il server)

6. Fuzzing (mcp-fuzzer) — Sesto
Cosa fa: Fuzzer Python che avvia ogni server e invia input mutati ai tool (fase realistic + aggressive) e messaggi di protocollo malformati (SQL injection, XSS, path traversal, buffer overflow nei campi MCP).

Perch'e basso:

Solo il 10% dei server raggiungibili — copertura molto bassa
Non classifica vulnerabilita di sicurezza — conta solo successi/eccezioni
Il 0% di success rate del protocol fuzzing e il risultato ATTESO (i server rifiutano correttamente input malformati) — ma e presentato in modo fuorviante
0 safety blocked — il safety system non ha mai agito
Utile come stress test, ma non come scanner di vulnerabilita
Stima falsi positivi: N/A (non classifica vulnerabilita, quindi non ha falsi positivi — ma non trova nemmeno nulla di utile in termini di sicurezza)

7. MCP Watch — Il Peggiore
Cosa fa: 12 scanner TypeScript in parallelo che cercano pattern regex nel codice sorgente: toxic flow, credential leak, tool poisoning, prompt injection, tool mutation, input validation, access control, server spoofing, protocol violation, data exfiltration, steganographic attack.

Perch'e il peggiore:

9.911.265 vulnerabilita — quasi 10 milioni, media 211 per server
Il 72% e "toxic-flow" (7.1M finding) causato dal GENERIC_TOXIC_FLOW_CHAIN che cerca keyword scollegate (private come keyword TypeScript = "dati privilegiati", public come modificatore = "output pubblico")
console.log(\Error: ${error.message}`)` e un finding HIGH
"create" + "user" nella stessa riga = EXCESSIVE_PERMISSIONS
Qualsiasi ../ (anche import relativi) = path traversal
Solo prompt-injection (0.06%) e tool-poisoning (0.06%) hanno valore reale
Stima falsi positivi: ~95%+ (i pattern sono cosi generici che praticamente ogni file TypeScript/Python genera decine di finding)