# Rerun tool_fuzzing — 2026-05-21

## Perche'
Il run precedente NON ha catturato `server_response` ne' `success_details`
(schema vecchio in `frameworks/fuzzing.py`). Le HC rules di
`stage2_pipeline.py` dipendono dalla response del server per
distinguere VP vs FP. Va rifatto su tutti i 69.104 server (60.205 GitHub
+ 8.899 NPX), su un unico Excel unificato.

## Profilo FAST-V2
- `--runs 3`, `--runs-per-type 2` (era 5/3) → -40% sui tool, -33% sui protocol
- `--timeout 15` (era 25), `--watchdog-process-timeout 15` (era 25)
- `process_timeout 90s` (era 150), `SERVER_TIMEOUT 150s` (era 300)
- 17 protocol_types × 2 runs = 34 payload diversi per server — sufficiente
  per saturare le HC rules.

Stima: ~45s avg per server → ~96 ore = ~4 giorni per VM (7679 server/VM).

## Step 1 — locale (una sola volta)

```powershell
# Genera l'Excel unificato (60205 GH + 8899 NPX → 69104 righe)
py -X utf8 fuzzing/postprocessing/special/build_unified_excel.py

# Backup dei dati vecchi locali
py -X utf8 fuzzing/backup_old_fuzzing.py
```

L'Excel `0.0. All servers unified (69104).xlsx` viene salvato in
`~/Desktop/Pipeline/`. Va copiato sulle VM nello stesso path (vedere step 2).

## Step 2 — deploy su tutte le 9 VM

Dal locale:

```powershell
# A) Backup remoto del dataset vecchio (rinomina in OLD_no_responses_<ts>)
py -X utf8 fuzzing/backup_old_fuzzing.py --remote --local-only-skip

# B) Copia Excel unificato + codice aggiornato su ciascuna VM
$VMS = @("10.79.6.132","10.79.6.133","10.79.6.134","10.79.6.136",
         "10.79.6.137","10.79.6.138","10.79.6.139","10.79.6.141",
         "10.79.6.142")
$LOCAL_EXCEL = "$HOME\Desktop\Pipeline\0.0. All servers unified (69104).xlsx"
foreach ($ip in $VMS) {
    scp $LOCAL_EXCEL "tecnico@${ip}:/home/tecnico/Desktop/Pipeline/"
    scp fuzzing/run_fuzzing.py "tecnico@${ip}:/home/tecnico/Desktop/Pipeline/fuzzing/"
    scp frameworks/fuzzing.py        "tecnico@${ip}:/home/tecnico/Desktop/Pipeline/frameworks/"
    scp functions/config.py          "tecnico@${ip}:/home/tecnico/Desktop/Pipeline/functions/"
}
```

In alternativa: `python deploy.py --full-deploy fuzzing` se preferisci il
rsync gia' configurato; assicurati pero' che includa anche l'Excel
nuovo.

## Step 3 — launch su ogni VM

Su OGNI VM, dopo aver fatto SSH:

```bash
cd /home/tecnico/Desktop/Pipeline
source ~/pipeline-env/bin/activate
export PYTHONPATH=/home/tecnico/Desktop/Pipeline
```

Poi il comando specifico per la VM (sostituisce `<START>` e `<END>`):

```bash
nohup python fuzzing/run_fuzzing.py --start <START> --end <END> > fuzzing_output.log 2>&1 &
```

| VM   | IP            | START | END   | server | gh    | npx   |
|------|---------------|------:|------:|-------:|------:|------:|
| VM1  | 10.79.6.132   |     0 |  7679 |  7679  | 7679  |    0  |
| VM2  | 10.79.6.133   |  7679 | 15358 |  7679  | 7679  |    0  |
| VM3  | 10.79.6.134   | 15358 | 23036 |  7678  | 7678  |    0  |
| VM4  | 10.79.6.136   | 23036 | 30714 |  7678  | 7678  |    0  |
| VM5  | 10.79.6.137   | 30714 | 38392 |  7678  | 7678  |    0  |
| VM6  | 10.79.6.138   | 38392 | 46070 |  7678  | 7678  |    0  |
| VM7  | 10.79.6.139   | 46070 | 53748 |  7678  | 7678  |    0  |
| VM8  | 10.79.6.141   | 53748 | 61426 |  7678  | 6457  | 1221  |
| VM9  | 10.79.6.142   | 61426 | 69104 |  7678  |    0  | 7678  |

Comandi nohup esatti:

```bash
# VM1
nohup python fuzzing/run_fuzzing.py --start 0     --end 7679  > fuzzing_output.log 2>&1 &
# VM2
nohup python fuzzing/run_fuzzing.py --start 7679  --end 15358 > fuzzing_output.log 2>&1 &
# VM3
nohup python fuzzing/run_fuzzing.py --start 15358 --end 23036 > fuzzing_output.log 2>&1 &
# VM4
nohup python fuzzing/run_fuzzing.py --start 23036 --end 30714 > fuzzing_output.log 2>&1 &
# VM5
nohup python fuzzing/run_fuzzing.py --start 30714 --end 38392 > fuzzing_output.log 2>&1 &
# VM6
nohup python fuzzing/run_fuzzing.py --start 38392 --end 46070 > fuzzing_output.log 2>&1 &
# VM7
nohup python fuzzing/run_fuzzing.py --start 46070 --end 53748 > fuzzing_output.log 2>&1 &
# VM8
nohup python fuzzing/run_fuzzing.py --start 53748 --end 61426 > fuzzing_output.log 2>&1 &
# VM9
nohup python fuzzing/run_fuzzing.py --start 61426 --end 69104 > fuzzing_output.log 2>&1 &
```

Note:
- `--start <N>` con `N != 0` NON resetta i log → safe per resume.
- Se vuoi riprendere dopo un crash: `--start -1` (riprende da `last_index`
  in `fuzzing_stats.json`).
- Se vuoi ricominciare da zero (pulendo `exceptions/` + `protocol/` +
  stats): `--start 0` (reset implicito).

## Step 4 — monitoring

```bash
# Da locale, status globale
python vmcheck.py

# Tail singola VM
python deploy.py --tail fuzzing

# Tutti i log
python deploy.py --tail-all
```

## Step 5 — pull dei risultati a fine run

```bash
python deploy.py --pull fuzzing
# poi il merge negli fuzzing/postprocessing/
```
