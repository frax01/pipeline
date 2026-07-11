# autorun — rirun automatica e sorvegliata dell'analisi MCP

Automazione aggiunta per far ripartire l'intera analisi sulle 9 VM con **un solo
comando** e senza doverla sorvegliare a mano. Non modifica il codice esistente:
sono tutti file nuovi in questa cartella.

## Il comando unico

```bash
python autorun/autorun.py go
```

Esegue in sequenza (ognuna è anche un sotto-comando a sé, ri-eseguibile):

1. **preflight** — verifica in sola lettura ogni VM (SSH, venv, pacchetti, framework, disco, dataset). Si ferma se c'è un problema bloccante.
2. **fix** — ripristina i framework mancanti e installa i pacchetti mancanti (vedi sotto).
3. **deploy** — copia l'ultimo codice locale (`run_*.py`, `functions/`, `frameworks/`) sulle VM.
4. **snapshot** — archivia i risultati della run precedente in `~/pipeline_backups/prelaunch_<ts>` su ogni VM (così il reset non distrugge nulla).
5. **smoke** — esegue 1 server per ogni tool per verificare che l'intera catena funzioni. Se qualcosa fallisce, **non lancia**.
6. **launch** — resetta i risultati (una volta sola) e avvia i 7 tool nel layout scelto; installa il **guardian** su ogni VM.

Per saltare la conferma finale: `python autorun/autorun.py go --yes`.

## Layout (deciso con l'utente)

| VM | IP | Tool | Range |
|----|----|------|-------|
| VM1 | .132 | guard | 0 – 34.552 |
| VM8 | .141 | guard | 34.552 – 69.104 |
| VM2 | .133 | watch | intero |
| VM3 | .134 | **fuzzing** | intero — **4 worker paralleli** |
| VM4 | .136 | scan | intero |
| VM5 | .137 | shield | 0 – 34.552 |
| VM9 | .142 | shield | 34.552 – 69.104 |
| VM6 | .138 | security_scan | intero |
| VM7 | .139 | check | intero |

Il **fuzzing** (il tool più lento) gira su VM3 come 4 worker su sotto-intervalli,
in cartelle isolate (`tool_fuzzing_w1..w4/`), con **parametri mcp-fuzzer invariati**
→ ~4× più veloce ma risultati confrontabili col backup.

## Il guardian (su ogni VM)

`guardian.sh` viene installato in `~/pipeline_rerun/` e gira in background. Attende
un *grace period* iniziale (150s, così i tool appena lanciati sono già su e non
vengono duplicati), poi ogni 60s:

- **auto-restart**: se un tool si ferma prima della fine, lo **riprende** da
  `max(last_index, floor_dello_shard)`, **mai** `--reset` → nessuna perdita di dati
  e gli shard non-zero (guard su VM8, shield su VM9, fuzzing w2–w4) ripartono
  dall'indice giusto, non da 0.
- **spazio disco**: se il disco supera il 90%, pulisce le cache di build (npm/uv/go/playwright…).
- **backup + auto-ripristino**: ogni ~30 min fa uno snapshot dei risultati (`~/pipeline_backups`, ne tiene 5); a ogni ciclo, se un file di stats risulta vuoto/corrotto lo ripristina dall'ultimo snapshot buono (protezione anti-cancellazione, utile soprattutto per il fuzzing).
- **resilienza al riavvio**: un cron `@reboot` fa ripartire il guardian se la VM si riavvia; il guardian riprende i tool da dove erano.

Termina da solo quando tutti i tool hanno finito.

## Monitoraggio

```bash
python autorun/autorun.py status            # avanzamento di ogni tool
python autorun/autorun.py guardian-status   # stato dei guardian
python monitorVM/monitor.py                 # dashboard esistente (security_scan/check)
```

## Auto-fix previsti (dallo stato attuale delle VM)

- **VM1**: ripristino `Frameworks/mcp-guard` (da VM8) + `pip install -e`.
- **VM2**: ripristino `Frameworks/mcp-watch` (da VM3, con `node_modules`).
- **VM4**: installazione di `pandas`.

## A fine analisi — confronto col backup

```bash
python autorun/autorun.py finalize          # = compare_results.py --pull --compare
```

Scarica i risultati dalle VM in `rerun_results/`, unisce gli shard (guard×2,
shield×2, fuzzing×4) e li confronta con `pipeline_DATI_BACKUP`. Il confronto di
primo livello è sulle **statistiche grezze**; per i **Veri Positivi finali** va
poi rieseguito il post-processing (`*/postprocessing/stage1_filter.py`,
`stage2_pipeline.py`) sui dati scaricati e infine
`cross_framework/cross_framework_consensus.py`.

## Note

- Richiede di essere sulla rete/VPN che raggiunge `10.79.6.x` (le VM).
- Tutti i sotto-comandi sono **idempotenti**: se qualcosa si interrompe, si
  rilancia lo stesso comando senza danni.
