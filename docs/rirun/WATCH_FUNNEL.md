# mcp-watch — funnel completo e confronto fra le due analisi

Tutti i numeri di ogni passaggio, dal dato grezzo al verde finale, per poter
ricostruire e confrontare i due run. Numeri verificati sui file, non ricavati a
memoria.

---

## 1. Rirun (2026-07) — copertura

| | |
|---|---|
| server analizzati | **69.104 / 69.104 (100%)** |
| di cui GitHub | 60.205 |
| di cui NPX | 8.899 |
| shard raccolti | **50** (1 run principale + 13 worker prima tranche + 36 seconda tranche) |
| VM coinvolte | 9 |

La copertura è stata raggiunta in due tranche: la prima si era fermata a
`[0 – 33.139]` (47,96%) perché ogni worker aveva chiuso il proprio chunk e
nessun orchestratore ne riassegnava altri; la seconda ha coperto
`[33.139 – 69.104]` con 36 worker sandboxed su tutte e 9 le VM.

---

## 2. Rirun — funnel per stadio

> Tutti i numeri della rirun sono **deduplicati**: il perche' e' spiegato una
> volta sola, in [`RECAP_RIRUN.md`](RECAP_RIRUN.md) §2.

```
findings grezzi (merge di 50 shard, distinti)             3.324.593
        │
        ├── Stage 1  stage1_filter.py         (5 categorie)   2.679.064 → 5.351
        └── Stage 1  stage1_filter_remaining.py (4 categorie)   645.529 → 2.674
        │
        ▼
input allo Stage 2A                                            8.025
        │
        ├── HC-VP        1.091
        ├── HC-FP        6.579
        └── UNCERTAIN      355
                          │
                          ▼  Stage 2B (Claude Sonnet, non llama3)
                          ├── VP   133
                          └── FP   222
        ▼
FINALE                       VP 1.224   |   FP 6.801
```

### Stage 1 — dettaglio per categoria (distinti)

| categoria | originali | tenuti | scartati |
|---|---:|---:|---:|
| credential-leak | 1.259.529 | 999 | 99,9% |
| input-validation | 1.022.470 | 284 | 100,0% |
| protocol-violation | 349.293 | 3.530 | 99,0% |
| data-exfiltration | 27.309 | 119 | 99,6% |
| steganographic-attack | 20.463 | 419 | 98,0% |
| *(sotto: `stage1_filter_remaining.py`)* | | | |
| access-control | 548.897 | 26 | 100,0% |
| tool-mutation | 23.180 | 2.615 | 88,7% |
| prompt-injection | 66.465 | 19 | 100,0% |
| tool-poisoning | 6.987 | 14 | 99,8% |
| **totale** | **3.324.593** | **8.025** | **99,8%** |

### Stage 2A / 2B / finale — dettaglio per categoria (distinti)

| categoria | filtrati | HC-VP | HC-FP | UNCERTAIN | **VP** | **FP** |
|---|---:|---:|---:|---:|---:|---:|
| credential-leak | 999 | 531 | 235 | 233 | **652** | 347 |
| protocol-violation | 3.530 | 387 | 3.115 | 28 | **388** | 3.142 |
| input-validation | 284 | 160 | 87 | 37 | **171** | 113 |
| access-control | 26 | 9 | 11 | 6 | **9** | 17 |
| data-exfiltration | 119 | 2 | 88 | 29 | **2** | 117 |
| steganographic-attack | 419 | 2 | 411 | 6 | **2** | 417 |
| tool-mutation | 2.615 | 0 | 2.615 | 0 | **0** | 2.615 |
| prompt-injection | 19 | 0 | 10 | 9 | **0** | 19 |
| tool-poisoning | 14 | 0 | 7 | 7 | **0** | 14 |
| **totale** | **8.025** | **1.091** | **6.579** | **355** | **1.224** | **6.801** |

---

## 3. Prima analisi (2026-05) — stessi stadi

| | |
|---|---:|
| Stage 1: originali | 1.833.246 |
| Stage 1: tenuti | 4.382 (99,8% scartato) |
| **VP finali** | **1.166** |
| **FP finali** | **6.215** |

> Valori originali della prima analisi, da `filter_global_summary.json` (10/04).
> Coprono le **sole 5 categorie** di `stage1_filter.py`, quindi non sono
> confrontabili riga per riga con il totale sulle 9 categorie della rirun.

### Per categoria

| categoria | HC-VP | HC-FP | UNCERTAIN | **VP** | **FP** |
|---|---:|---:|---:|---:|---:|
| credential-leak | 47 | 14 | 20 | **665** | 179 |
| protocol-violation | 278 | 142 | 6 | **357** | 2.902 |
| input-validation | 14 | 2 | 3 | **135** | 105 |
| access-control | 7 | 10 | 0 | **7** | 10 |
| data-exfiltration | 0 | 7 | 3 | **2** | 91 |
| steganographic-attack | 0 | 10 | 0 | **0** | 365 |
| tool-mutation | 0 | 34 | 0 | **0** | 2.548 |
| tool-poisoning | 0 | 7 | 0 | **0** | 7 |
| prompt-injection | 0 | 8 | 0 | **0** | 8 |

> **Avvertenza sui bucket intermedi della prima analisi**: `hc_vp + hc_fp +
> uncertain` non torna con `vp + fp` (es. credential-leak: 81 contro 844). I file
> intermedi archiviati coprono quindi solo una parte del flusso. Il confronto
> stadio-per-stadio è affidabile **solo** su input allo Stage 1 e su VP/FP finali;
> sui bucket HC non lo è.

---

## 4. Confronto diretto

Prima analisi: valori originali. Rirun: **deduplicati** (vedi §2).

| | prima analisi | rirun | delta |
|---|---:|---:|---:|
| server coperti | 60.205 GitHub (+ NPX separata) | 69.104 unificati | +8.899 |
| findings in ingresso allo Stage 1 | 1.833.246 *(5 cat.)* | 3.324.593 *(9 cat.)* | non confrontabili |
| findings dopo Stage 1 | 4.382 *(5 cat.)* | 8.025 *(9 cat.)* | non confrontabili |
| **VP finali** | **1.166** | **1.224** | **+58 (+5,0%)** |
| **FP finali** | **6.215** | **6.801** | +586 |
| server distinti con VP | 650 | 674 | +24 |

> Le due righe di Stage 1 coprono insiemi di categorie diversi (§3): il summary
> archiviato della prima analisi include solo le 5 categorie di
> `stage1_filter.py`. Il confronto regge su **VP/FP finali e server con VP**.

### Per categoria — VP (distinti)

| categoria | prima | rirun | delta |
|---|---:|---:|---:|
| credential-leak | 665 | 652 | **−13** |
| protocol-violation | 357 | 388 | +31 |
| input-validation | 135 | 171 | +36 |
| access-control | 7 | 9 | +2 |
| data-exfiltration | 2 | 2 | 0 |
| steganographic-attack | 0 | 2 | +2 |
| tool-mutation | 0 | 0 | 0 |
| prompt-injection | 0 | 0 | 0 |
| tool-poisoning | 0 | 0 | 0 |

---

## 5. L'aumento del 72% non esiste: era duplicazione

Versioni precedenti di questo documento riportavano **+845 VP (+72%)** per watch.
Quel numero confrontava 2.011 *righe* della rirun con 1.166 VP della prima
analisi: le 2.011 righe contengono pero' solo **1.224 findings distinti**
(meccanismo spiegato in [`RECAP_RIRUN.md`](RECAP_RIRUN.md) §2).

**A parita' di conteggio, watch e' sostanzialmente stabile: +58 VP (+5,0%)** —
e la categoria che sembrava crescere di piu' (`credential-leak`, +511) in realta'
cala di 13.

Cosa resta vero, e va comunque dichiarato:

1. **Il dataset e' piu' ampio**: 69.104 server unificati contro 60.205 GitHub piu'
   una run NPX separata (+15%). I findings distinti di watch crescono pero' di
   ×1,36 senza che aumentino i server che li producono: e' densita' per server,
   non copertura (cfr. `RECAP_RIRUN.md` §2).
2. **Copertura completa in un'unica passata**, mentre la prima analisi univa due
   esecuzioni distinte.
3. **Il cambio di classificatore nello Stage 2B** (llama3 → Claude Sonnet) tocca
   solo 355 casi incerti su 8.025, e ne promuove 133: il **10,9%** dei VP finali.
   Il grosso del risultato viene dalle regole HC, deterministiche e identiche
   nelle due run.

---

## 6. File di riferimento

| cosa | dove |
|---|---|
| shard grezzi scaricati | `pipeline_rerun_pull/watch/` (50 cartelle) |
| merge per categoria | `pipeline_rerun_pull/_merged/watch/` |
| output Stage 1 | `mcp_watch/postprocessing/<cat>/filtered/<cat>_filtered.json` |
| riepilogo Stage 1 | `mcp_watch/postprocessing/filter_global_summary.json` |
| bucket Stage 2A | `mcp_watch/postprocessing/<cat>/filtered/llm_analysis/{hc_vp,hc_fp,uncertain}.json` |
| verdetti Stage 2B | `mcp_watch/postprocessing/<cat>/filtered/llm_analysis/_ollama_cache.json` |
| risultati finali | `mcp_watch/postprocessing/<cat>/filtered/llm_analysis/{vp,fp,audit}.json` |
| prima analisi | `pipeline_DATI_BACKUP/analysisAllData/0_tool_mcp_watch/` |
