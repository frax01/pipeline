# Dati — indice degli archivi non versionati

Questo repository contiene il **codice** della pipeline e i **report** in forma
leggibile. I dati veri e propri — circa **37 GB scompattati**, 3,6 GB in forma
compressa — stanno fuori da git, in quattro archivi separati. Questo documento
dice cosa c'è in ciascuno, come rimetterli al loro posto e cosa si può
ricalcolare una volta fatto.

È il documento da leggere per primo se sei arrivato qui perché nel repo mancano
i dati: non mancano per errore, sono archiviati altrove.

## Perché non sono versionati

Due motivi, entrambi vincolanti:

1. **Dimensione.** GitHub impone un limite di 100 MB per singolo file e
   raccomanda repository sotto i 5 GB. Il solo `mcp_guard/postprocessing/` pesa
   4,0 GB. Git LFS nel piano gratuito offre 1 GB. Non è una strada percorribile.
2. **Credenziali di terzi.** Gli output grezzi contengono, *come finding
   dell'analisi*, credenziali reali di terze parti trovate nei server MCP
   scansionati. Nei report versionati e nel dataset `.xlsx` questi valori sono
   sostituiti da placeholder; negli archivi **no**. Vedi l'avvertenza in fondo.

## Cosa c'è già nel repository

| | |
|---|---|
| Codice della pipeline | scraper, orchestratori, wrapper dei 7 tool, script di merge |
| Script di postprocessing | **49 file `.py`** — `stage1_filter.py`, `stage2_pipeline.py`, i classifier |
| Report di postprocessing | **30 file `.md`** — le analisi leggibili per categoria |
| Report finali | `docs/` — metodologia, threat analysis, audit manuale |
| Dataset di input | `0.0. All servers unified (69104).xlsx` |

Quindi degli script del triage c'è tutto. Quello che manca sono i **1.044 file
`.json`** su cui girano: gli output di ogni stadio e i dati intermedi.

## I quattro archivi

| Archivio | Contenuto | Scompattato | Compresso | File |
|---|---|---|---|---|
| `pipeline_POSTPROCESSING.zip` | Output del triage dei 7 tool + consenso cross-framework | 7,3 GB | 0,83 GB | 1.126 |
| `pipeline_DATI_BACKUP.zip` | Dati grezzi della prima run, excel di input, findings | 19,6 GB | 1,3 GB | 25.179 |
| `pipeline_rerun_pull.zip` | Pull grezzi dalle 9 VM del rirun (per tool e per shard) | 9,0 GB | 729 MB | 2.951 |
| `pipeline_CODE_BACKUP.zip` | Snapshot del codice con `.git`, `node_modules`, cache | 948 MB | 801 MB | 15.822 |

`pipeline_CODE_BACKUP.zip` è in larga parte **ridondante** rispetto a questo
repository: serve solo come fotografia dell'albero di lavoro a una certa data.
Per capire o rieseguire la pipeline non è necessario.

I dati veri stanno negli altri tre, e sono **disgiunti**: nessuno è un
sovrainsieme di un altro, servono tutti e tre. In particolare né
`pipeline_DATI_BACKUP.zip` né `pipeline_rerun_pull.zip` contengono gli output di
`postprocessing/` — quelli vivevano solo nella working copy, ed è la ragione per
cui esiste `pipeline_POSTPROCESSING.zip`.

### Dettaglio di `pipeline_POSTPROCESSING.zip`

| Tool | Peso | File `.json` |
|---|---|---|
| `mcp_guard/postprocessing/` | 4,0 GB | 185 |
| `mcp_watch/postprocessing/` | 3,1 GB | 98 |
| `mcp_check/postprocessing/` | 92 MB | 484 |
| `fuzzing/postprocessing/` | 75 MB | 135 |
| `mcp_security_scan/postprocessing/` | 58 MB | 69 |
| `mcp_shield/postprocessing/` | 57 MB | 34 |
| `mcp_scan/postprocessing/` | 26 MB | 39 |
| `cross_framework/*.json` | 4,3 MB | 3 |

Il grosso del peso sta in `mcp_guard/postprocessing/command-injection-fuzzing/`
(3,0 GB) e `mcp_guard/postprocessing/fuzzing/` (794 MB): sono le risposte
complete dei server al fuzzing, non i soli finding.

I tre file `cross_framework/` sono l'ultimo stadio della pipeline — il consenso
tra i 7 framework, da cui escono la classifica dei server e i numeri di sintesi
del `THREAT_ANALYSIS_REPORT.md`. Sono inclusi qui perché pesano nulla e senza di
essi l'archivio sarebbe monco proprio sul risultato finale.

L'archivio contiene anche i 79 file `.py`/`.md` già versionati, così da essere
navigabile da solo: ogni script sta accanto al proprio output. Sono identici a
quelli del repo.

## Come rimettere i dati al loro posto

I percorsi dentro `pipeline_POSTPROCESSING.zip` sono **relativi alla root del
repository**, quindi l'archivio si scompatta direttamente sopra un clone e
ricostruisce l'albero originale:

```bash
git clone https://github.com/frax01/pipeline.git
cd pipeline
unzip /percorso/a/pipeline_POSTPROCESSING.zip -d .
```

Il risultato è la working copy completa. `git status` resta pulito: tutto ciò
che viene aggiunto è già coperto dalle regole del `.gitignore`

```
*/postprocessing/**/*.json
cross_framework/*.json
```

Gli altri due archivi hanno invece una struttura propria (`pipeline_DATI_BACKUP/`,
`pipeline_rerun_pull/`) e vanno scompattati dove si preferisce: gli script che li
leggono prendono il percorso come parametro.

## Cosa si può rieseguire, una volta ripristinati

| Con | Si può rieseguire |
|---|---|
| `pipeline_rerun_pull.zip` | `<tool>/merge_stats.py` — il merge degli shard delle 9 VM |
| `pipeline_POSTPROCESSING.zip` | `*/postprocessing/stage2_pipeline.py` — il triage a 3 stadi |
| `pipeline_POSTPROCESSING.zip` | `cross_framework/` — il consenso tra framework |
| `pipeline_DATI_BACKUP.zip` | le analisi sui dati grezzi della prima run |

Quello che **non** è rieseguibile end-to-end è la raccolta: i 69.104 server per
7 tool su 9 VM sono settimane di esecuzione distribuita, e i server pubblici nel
frattempo cambiano. Vedi la nota in `README.md` § Quick start.

## ⚠️ Avvertenza sulle credenziali

Gli archivi contengono **credenziali di terze parti in chiaro**: API key, token e
segreti che l'analisi ha trovato hardcoded nei server MCP pubblici scansionati.
Non sono credenziali del progetto, sono i *risultati* dell'analisi.

Nei materiali versionati questi valori sono mascherati con placeholder. Negli
archivi no, perché sono i dati grezzi su cui il mascheramento viene applicato a
valle.

Di conseguenza gli archivi:

- **non** vanno caricati su questo repository, che è pubblico;
- **non** vanno depositati su un archivio pubblico (Zenodo, figshare o simili)
  senza prima passare la redaction;
- vanno condivisi solo per canale privato e solo con chi ha necessità di
  accedervi per la valutazione o la prosecuzione del lavoro.

## Accesso

Gli archivi non sono pubblicati. Per ottenerli contattare l'autore del
repository: vengono condivisi con un link privato su storage istituzionale.
