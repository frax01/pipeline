# MCP Security Scan — Spiegazione dei grafici

**MCP Security Scan** e uno scanner Python che esegue fino a 11 check di sicurezza su ogni server MCP. I check coprono: protocol testing (handshake, capabilities), analisi statica del codice, e fuzzing attivo con payload di injection (`; id`, `$(whoami)`, `../../../../etc/passwd`). A differenza di MCP Guard, quando dice "dynamic" intende testing reale — avvia il server e invia payload.

Server analizzati: **54.973** su 60.205 (91.31%)
Finding totali: **140.016** (78.216 passed + 61.800 failed)
Percentuale passed: **55.86%**

---

## 01_languages.png — Distribuzione dei linguaggi

**Cosa mostra**: Linguaggi dei 54.973 server analizzati.

**Interpretazione**: La copertura alta (91.31%) e possibile perche lo scanner esegue sia analisi statica (non richiede avvio del server) che dinamica. Anche se il server non si avvia, l'analisi statica produce comunque finding. Node.js (22.367) e Python (20.750) sono quasi pari, con Go (1.679), Docker (1.140) e unknown (9.037).

---

## 02_severity.png — Distribuzione delle severity

**Cosa mostra**: I 61.800 finding falliti per livello di severity.

- **Info (54.504, 88.19%)**: Quasi tutti "initialization-error" — il server non si e avviato. Correttamente classificati come info, non come vulnerabilita
- **High (3.811, 6.17%)**: Include dangerous-capabilities (tool con capacita distruttive) e input-validation (fuzzing fallito)
- **Critical (3.356, 5.43%)**: Input validation e path traversal verificati con fuzzing reale
- **Medium (129, 0.21%)**: Prompt injection e rug-pull

**La dominanza di info (88%)**: E il dato piu onesto di questo tool — ammette che la maggior parte dei "fallimenti" sono errori di inizializzazione, non vulnerabilita reali. Se escludiamo gli info, i finding reali sono ~7.300.

---

## 03_categories_pass_fail.png — Passed vs Failed per categoria (escl. init errors)

**Cosa mostra**: Per ciascuna delle 10 categorie di sicurezza (escludendo initialization-error), quanti server hanno passato e quanti hanno fallito il check.

**Categorie e interpretazione**:
- **input-validation (5.157 passed / 3.338 failed)**: Il check piu fallito dopo init-error. Lo scanner invia payload di injection ai tool e verifica se vengono accettati. Il 39% di fallimento e alto ma plausibile — molti server non validano gli input
- **dangerous-capabilities (4.945 passed / 3.581 failed)**: Verifica se i tool hanno capacita distruttive (esecuzione comandi, accesso file). Il 42% di fallimento indica che molti server espongono tool potenti senza restrizioni
- **prompt-injection (8.492 passed / 34 failed)**: Solo 34 server con prompt injection nelle descrizioni — numero basso e credibile
- **rug-pull (8.431 passed / 95 failed)**: 95 server le cui descrizioni dei tool cambiano tra invocazioni successive — possibile indicatore di comportamento malevolo
- **path-traversal (8.371 passed / 124 failed)**: 124 server vulnerabili a path traversal verificato con fuzzing
- **sensitive-file-access (8.392 passed / 103 failed)**: 103 server che accedono a file sensibili
- **indirect-prompt-injection (8.493 passed / 2 failed)**: Solo 2 server — il check piu raro e specifico
- **remote-access-control (8.488 passed / 7 failed)**: 7 server con tool che permettono controllo remoto non autenticato
- **sensitive-resource-exposure (8.494 passed / 1 failed)**: 1 solo server che espone risorse sensibili
- **data-leak (8.484 passed / 11 failed)**: 11 server con potenziale fuga di dati

**Punto chiave**: I numeri bassi per check rari (2 indirect injection, 1 sensitive exposure) sono un forte indicatore di precisione — il tool non infla i numeri.

---

## 04_categories_pie.png — Distribuzione categorie (escl. init errors)

**Cosa mostra**: Proporzione delle categorie di vulnerabilita reali (escludendo initialization-error).

**Interpretazione**: dangerous-capabilities (49%) e input-validation (46%) dominano, con path-traversal, sensitive-file-access, rug-pull e le altre a percentuali minime. Questo riflette il fatto che i due check piu comuni (capacita pericolose e validazione input) sono anche i meno specifici — qualsiasi tool che esegue comandi o accede a file viene flaggato.

---

## 05_findings_overview.png — Panoramica findings (passed vs failed)

**Cosa mostra**: Dei 140.016 finding totali (un finding per check per server), 55.86% sono passed e 44.14% failed.

**Contesto**: Il 44.14% di fallimento sembra alto, ma include gli initialization-error (88% dei failed). Se consideriamo solo i check di sicurezza sui server funzionanti, il tasso di finding reali e significativamente piu basso. Questo grafico e utile per mostrare il volume complessivo dell'analisi.
