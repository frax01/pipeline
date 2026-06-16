# MCP Fuzzing - Comandi per 9 VM

## 🚀 Deployment e Esecuzione (Tutte le 9 VM)
Lo script `deploy.py` (nella cartella root) gestisce tutto il parco VM.

```bash
# 1. Deploy file essenziali su tutte le 9 VM
python deploy.py --deploy-fuzzing-all
```

## 📋 Comandi di lancio manuali (da eseguire su ogni VM)

# 1 - VM1 (10.79.6.132)
pkill -f 'python.*run_fuzzing.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start 0 --end 6689 --reset > fuzzing_output.log 2>&1 &

# 2 - VM2 (10.79.6.133)
pkill -f 'python.*run_fuzzing.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start 6689 --end 13378 --reset > fuzzing_output.log 2>&1 &

# 3 - VM3 (10.79.6.134)
pkill -f 'python.*run_fuzzing.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start 13378 --end 20067 --reset > fuzzing_output.log 2>&1 &

# 4 - VM4 (10.79.6.136)
pkill -f 'python.*run_fuzzing.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start 20067 --end 26756 --reset > fuzzing_output.log 2>&1 &

# 5 - VM5 (10.79.6.137)
pkill -f 'python.*run_fuzzing.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start 26756 --end 33445 --reset > fuzzing_output.log 2>&1 &

# 6 - VM6 (10.79.6.138)
pkill -f 'python.*run_fuzzing.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start 33445 --end 40134 --reset > fuzzing_output.log 2>&1 &

# 7 - VM7 (10.79.6.139)
pkill -f 'python.*run_fuzzing.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start 40134 --end 46823 --reset > fuzzing_output.log 2>&1 &

# 8 - VM8 (10.79.6.141)
pkill -f 'python.*run_fuzzing.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start 46823 --end 53512 --reset > fuzzing_output.log 2>&1 &

# 9 - VM9 (10.79.6.142)
pkill -f 'python.*run_fuzzing.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start 53512 --end 60205 --reset > fuzzing_output.log 2>&1 &

## 📋 Resume (Ripresa da arresto)

Se lo script si interrompe o la VM si riavvia, usa `--start -1` per riprendere dall'ultimo indice salvato.

### VM1 (10.79.6.132)
```bash
ssh tecnico@10.79.6.132
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 6689 > fuzzing_output.log 2>&1 &
```

### VM2 (10.79.6.133)
```bash
ssh tecnico@10.79.6.133
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 13378 > fuzzing_output.log 2>&1 &
```

### VM3 (10.79.6.134)
```bash
ssh tecnico@10.79.6.134
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 20067 > fuzzing_output.log 2>&1 &
```

### VM4 (10.79.6.136)
```bash
ssh tecnico@10.79.6.136
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 26756 > fuzzing_output.log 2>&1 &
```

### VM5 (10.79.6.137)
```bash
ssh tecnico@10.79.6.137
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 33445 > fuzzing_output.log 2>&1 &
```

### VM6 (10.79.6.138)
```bash
ssh tecnico@10.79.6.138
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 40134 > fuzzing_output.log 2>&1 &
```

### VM7 (10.79.6.139)
```bash
ssh tecnico@10.79.6.139
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 46823 > fuzzing_output.log 2>&1 &
```

### VM8 (10.79.6.141)
```bash
ssh tecnico@10.79.6.141
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 53512 > fuzzing_output.log 2>&1 &
```

### VM9 (10.79.6.142)
```bash
ssh tecnico@10.79.6.142
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 60205 > fuzzing_output.log 2>&1 &
```

## 📥 Raccolta Risultati e Analisi
```bash
# 1. Scarica i risultati (incluse le cartelle exceptions/ e protocol/) da tutte le VM
python deploy.py --pull-fuzzing

# 2. Aggrega tutto in fuzzing/postprocessing/
python deploy.py --merge-fuzzing

# oppure entrambi:
python deploy.py --pull-fuzzing --merge-fuzzing
```

## 📊 Monitoraggio

### Da questo PC (remoto su tutte le VM)
```bash
# Stato riassuntivo di tutte le VM
python deploy.py --status-fuzzing

# Log delle ultime righe da tutte le VM
python deploy.py --tail-fuzzing
```

### Dentro una singola VM (via SSH)
```bash
# Log in tempo reale
tail -f ~/Desktop/Pipeline/fuzzing_output.log

# Ultime 50 righe del log
tail -50 ~/Desktop/Pipeline/fuzzing_output.log

# Statistiche generali
cat ~/Desktop/Pipeline/tool_fuzzing/fuzzing_stats.json | python3 -m json.tool

# Monitoraggio continuo delle statistiche (aggiorna ogni 5s)
watch -n 5 'cat ~/Desktop/Pipeline/tool_fuzzing/fuzzing_stats.json | python3 -m json.tool'

# Processo attivo
ps aux | grep run_fuzzing.py | grep -v grep

# Server processati
cat ~/Desktop/Pipeline/tool_fuzzing/fuzzing_servers.json | python3 -m json.tool
```

### File di analisi per categoria
```bash
# Vedere le cartelle create
ls ~/Desktop/Pipeline/tool_fuzzing/exceptions/
ls ~/Desktop/Pipeline/tool_fuzzing/protocol/

# Contenuto di un file exception
cat ~/Desktop/Pipeline/tool_fuzzing/exceptions/<nome_file>.json | python3 -m json.tool

# Contenuto di un file protocol
cat ~/Desktop/Pipeline/tool_fuzzing/protocol/<nome_file>.json | python3 -m json.tool

# Contare totale file per categoria
echo "=== EXCEPTIONS ===" && ls ~/Desktop/Pipeline/tool_fuzzing/exceptions/*.json 2>/dev/null | wc -l
echo "=== PROTOCOL ===" && ls ~/Desktop/Pipeline/tool_fuzzing/protocol/*.json 2>/dev/null | wc -l
```

ps aux --sort=-%mem | head -20