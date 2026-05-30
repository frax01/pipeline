# tool_fuzzing findings — RE-RUN completo con risposte (2026-05-29)

> ⚠️ **Questo documento riflette il RE-RUN completo** (dataset combinato GitHub+NPX,
> con risposte del server). Il run precedente — che dichiarava **776 VP** senza salvare
> le risposte — è archiviato in `analysisAllData/0_tool_fuzzing.OLD_no_responses/` ed è
> **superato**. Documentazione completa: `analysisAllData/0_tool_fuzzing/README.md`.

## Cosa è cambiato

Il vecchio run non salvava `server_response` / `inputs_successful[].result`, quindi era
impossibile distinguere un input malevolo *eseguito* da uno *ignorato/respinto*. Il
re-run salva le risposte → si può classificare sulla base di cosa il server ha
**davvero fatto**. Risultato: i **776 VP** del vecchio run (di cui 775 protocol) sono
quasi tutti **confermati FP** dalle risposte; restano **13 VP reali**.

- **Dataset**: 69.103 server combinati (60.191 GitHub + 8.912 NPX), shardato su 9 VM.
- **Coverage tool-level**: solo **406 server** con tool fuzzing recuperabile (369 gh + 37 npx);
  35.713 "completed" facevano solo protocol probing. Vedi `_coverage_report.json`.

## Summary 4 categorie (ridisegnate)

| Categoria | Filtered | VP | FP | Nota |
|-----------|---------:|---:|---:|------|
| tool-input-accepted | 580 | **0** | 580 | payload accettato ma ignorato (264) o rifiutato isError (316); 0 exploitation |
| tool-error-disclosure | 1.864 | **6** | 1.858 | svg2png-mcp-server: stack trace Node.js con path sorgente (CWE-209) |
| tool-crash-dos | 417 | **7** | 410 | panic Go INPUT-triggered (3 server); asgardeo/talos config-driven = FP |
| protocol-fuzzing | 1.791 | **0** | 1.791 | response vuota (no processing) o metodo MCP valido gestito |
| **Totale** | **4.652** | **13** | **4.639** | 7 gh (crash) + 6 npx (disclosure), 4 server distinti |

## I 13 VP

### tool-crash-dos — 7 VP / 3 server (panic Go INPUT-triggered, robustezza low, NON DoS)
Type assertion non controllata su input (`interface conversion: interface {} is nil,
not <type>`): un input fuzzato specifico (parziale 1–4/6) crasha l'handler.
- `sonar-mcp-server` (4 tool), `mcp-iot-go` (2), `opgen-mcp-server` (1)
- **severity: low**, **CWE-20** → type-assertion panic (CWE-248). Il panic è
  **recuperato** (`recover()`) → NON è un DoS pieno; è un bug di robustezza/input-handling
  attacker-triggerable. Restano VP (difetto reale) e non FP (non sono falsi allarmi).
- **Conferma cross-framework**: tutti e 3 già nei `panic_or_crash` di mcp-check.

### Riclassificati a FP — asgardeo-mcp-server (19) + talos-mcp (5) = 24 finding
Panicano (`nil pointer dereference`) sul **100% degli input su ogni tool** → client/SDK
`nil` da backend non configurato sulla VM (input-INDEPENDENT, non attacker-triggered) → FP.

### tool-error-disclosure — 6 VP / 1 server
`svg2png-mcp-server` (NPX): stack trace Node.js completi con path sorgente interni
(`index.js:71:11`) nei messaggi d'errore → information disclosure (CWE-209), severity low.

## Perché protocol e input-accepted = 0 VP

- **input-accepted (0 VP)**: i tool **respingono** (316 isError) o **ignorano** (264) i
  payload; prototype pollution droppato dal parsing JSON, path traversal trattato come
  dominio/search term, injection come dato letterale. 0 marker di exploitation nei result.
- **protocol-fuzzing (0 VP)**: i messaggi "accettati" hanno `server_response` vuoto
  (notification-style, no processing) o sono metodi MCP validi gestiti correttamente
  (InitializeRequest → capabilities, CompleteRequest → completions). I 775 "VP protocol"
  del vecchio run sono confermati FP dalle risposte.

## Limiti tool_fuzzing

- **Tool tutti-successo non salvati** (~75%): l'analisi tool-level copre i 406 server con
  ≥1 eccezione. `vuln_findings`/`invariant_violations` del framework sempre vuoti.
- Rileva crash/DoS + injection-eseguita + disclosure; NON SAST/hidden-instructions/creds.

## Output finali

Per ogni categoria in `analysisAllData/0_tool_fuzzing/<cat>/filtered/llm_analysis/`:
`vp.json` (con campi `severity`/`cwe`/`vp_class`/`note`), `fp.json`, `audit.json`.

## Riferimenti

- Doc completa: `analysisAllData/0_tool_fuzzing/README.md`
- Pre-filtro protocol su VM: `analysisAllData/0_tool_fuzzing/_prefilter_protocol_vm.py`
- Aggregazione shard: `analysisAllData/0_tool_fuzzing/_aggregate_shards.py`
- Stage 1: `analysisAllData/0_tool_fuzzing/filter_fuzzing.py`
- Stage 2A + merge: `analysisAllData/0_tool_fuzzing/pipeline_fuzzing.py`
- Coverage report: `analysisAllData/0_tool_fuzzing/_coverage_report.json`
