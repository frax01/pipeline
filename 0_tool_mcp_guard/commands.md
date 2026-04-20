# MCP Guard - Comandi per 9 VM

## 🧪 Primo Test Locale (Consigliato)
Prima di fare il deploy sulle 9 VM, puoi testare la nuova cartellizzazione sulla tua macchina:
```bash
# 1. Spostati nella cartella del tool
cd 0_tool_mcp_guard

# 2. Lancia un test su pochi server (es. da 0 a 5)
python 0_tool_mcp_guard/run_guard.py --start 0 --end 5 --reset

# 3. Verifica la creazione delle cartelle (static/, dynamic/, ecc.)
# Dovresti vedere i file JSON organizzati per categoria.
```

## 🚀 Deployment e Esecuzione (Tutte le 9 VM)
Lo script `deploy.py` (nella cartella root) gestisce tutto il parco VM.

```bash
# 1. Deploy file essenziali su tutte le 9 VM
python deploy.py --deploy-guard-all
```

## 📋 Comandi di lancio manuali (da eseguire su ogni VM)

# 1 - VM1 (10.79.6.132)
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python 0_tool_mcp_guard/run_guard.py --start 0 --end 6689 --reset > guard_output.log 2>&1 &

# 2 - VM2 (10.79.6.133)
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start 6689 --end 13378 --reset > guard_output.log 2>&1 &

# 3 - VM3 (10.79.6.134)
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start 13378 --end 20067 --reset > guard_output.log 2>&1 &

# 4 - VM4 (10.79.6.136)
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start 20067 --end 26756 --reset > guard_output.log 2>&1 &

# 5 - VM5 (10.79.6.137)
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start 26756 --end 33445 --reset > guard_output.log 2>&1 &

# 6 - VM6 (10.79.6.138)
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start 33445 --end 40134 --reset > guard_output.log 2>&1 &

# 7 - VM7 (10.79.6.139)
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start 40134 --end 46823 --reset > guard_output.log 2>&1 &

# 8 - VM8 (10.79.6.141)
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start 46823 --end 53512 --reset > guard_output.log 2>&1 &

# 9 - VM9 (10.79.6.142)
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start 53512 --end 60205 --reset > guard_output.log 2>&1 &

## 📋 Resume (Ripresa da arresto)

Se lo script si interrompe o la VM si riavvia, usa `--start -1` per riprendere dall'ultimo indice salvato.

### VM1 (10.79.6.132)
```bash
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start -1 --end 6689 > guard_output.log 2>&1 &
```

### VM2 (10.79.6.133)
```bash
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start -1 --end 13378 > guard_output.log 2>&1 &
```

### VM3 (10.79.6.134)
```bash
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start -1 --end 20067 > guard_output.log 2>&1 &
```

### VM4 (10.79.6.136)
```bash
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start -1 --end 26756 > guard_output.log 2>&1 &
```

### VM5 (10.79.6.137)
```bash
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start -1 --end 33445 > guard_output.log 2>&1 &
```

### VM6 (10.79.6.138)
```bash
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start -1 --end 40134 > guard_output.log 2>&1 &
```

### VM7 (10.79.6.139)
```bash
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start -1 --end 46823 > guard_output.log 2>&1 &
```

### VM8 (10.79.6.141)
```bash
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start -1 --end 53512 > guard_output.log 2>&1 &
```

### VM9 (10.79.6.142)
```bash
pkill -f 'python.*run_guard.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_guard/run_guard.py --start -1 --end 60205 > guard_output.log 2>&1 &
```

## 📥 Raccolta Risultati e Analisi
```bash
# 1. Scarica i risultati (incluse le cartelle delle categorie) da tutte le VM
python deploy.py --pull-guard (prima cambiare sulla vm1 il nome della cartella da 0_tool_mcp_guard a tool_mcp_guard)

# 2. Aggrega tutto in analysisAllData/0_tool_mcp_guard/
python deploy.py --merge-guard
```

## 📊 Monitoraggio

### Da questo PC (remoto su tutte le VM)
```bash
# Stato riassuntivo di tutte le VM (indice, remaining, percentuale)
python deploy.py --status-guard

# Log delle ultime righe da tutte le VM
python deploy.py --tail-guard
```

### Dentro una singola VM (via SSH)
```bash
# Log in tempo reale
tail -f ~/Desktop/Pipeline/guard_output.log

# Ultime 50 righe del log
tail -50 ~/Desktop/Pipeline/guard_output.log

# Statistiche generali (totale server, percentuali, analysis_types)
cat ~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_stats.json | python3 -m json.tool

# Monitoraggio continuo delle statistiche (aggiorna ogni 5s)
watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_stats.json | python3 -m json.tool'
watch -n 5 'cat ~/Desktop/Pipeline/0_tool_mcp_guard/mcp_guard_stats.json | python3 -m json.tool'

ps aux | grep run_guard.py | grep -v grep

# Server falliti (lista server con motivo del fallimento)
cat ~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_servers.json | python3 -m json.tool
```

### File di analisi per categoria
```bash
# Vedere le cartelle create per tipo di analisi
ls ~/Desktop/Pipeline/tool_mcp_guard/static/
ls ~/Desktop/Pipeline/tool_mcp_guard/dynamic/
ls ~/Desktop/Pipeline/tool_mcp_guard/real_fuzzing/
ls ~/Desktop/Pipeline/tool_mcp_guard/robustness_fuzzing/

# Vulnerabilita' statiche - per categoria
cat ~/Desktop/Pipeline/tool_mcp_guard/static/other/unsafe-mcp-json-rpc-message-handling.json | python3 -m json.tool
cat ~/Desktop/Pipeline/tool_mcp_guard/static/other/mcp-missing-capability-validation.json | python3 -m json.tool

# Vulnerabilita' real_fuzzing - per categoria
cat ~/Desktop/Pipeline/tool_mcp_guard/real_fuzzing/other/command-injection-vulnerability.json | python3 -m json.tool
cat ~/Desktop/Pipeline/tool_mcp_guard/real_fuzzing/other/path-traversal-vulnerability.json | python3 -m json.tool
cat ~/Desktop/Pipeline/tool_mcp_guard/real_fuzzing/other/authorization-bypass.json | python3 -m json.tool
cat ~/Desktop/Pipeline/tool_mcp_guard/real_fuzzing/other/debug-endpoint-exposure.json | python3 -m json.tool
cat ~/Desktop/Pipeline/tool_mcp_guard/real_fuzzing/sensitive-information-disclosed/*.json | python3 -m json.tool

# Vulnerabilita' robustness_fuzzing
cat ~/Desktop/Pipeline/tool_mcp_guard/robustness_fuzzing/other/*.json | python3 -m json.tool

# Contare il totale vulnerabilita' per tipo di analisi
echo "=== STATIC ===" && find ~/Desktop/Pipeline/tool_mcp_guard/static/ -name "*.json" -exec python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(f'{d[\"total\"]} - {sys.argv[1].split(\"/\")[-1]}')" {} \;
echo "=== REAL_FUZZING ===" && find ~/Desktop/Pipeline/tool_mcp_guard/real_fuzzing/ -name "*.json" -exec python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(f'{d[\"total\"]} - {sys.argv[1].split(\"/\")[-1]}')" {} \;
echo "=== ROBUSTNESS_FUZZING ===" && find ~/Desktop/Pipeline/tool_mcp_guard/robustness_fuzzing/ -name "*.json" -exec python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(f'{d[\"total\"]} - {sys.argv[1].split(\"/\")[-1]}')" {} \;
echo "=== DYNAMIC ===" && find ~/Desktop/Pipeline/tool_mcp_guard/dynamic/ -name "*.json" -exec python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(f'{d[\"total\"]} - {sys.argv[1].split(\"/\")[-1]}')" {} \;
```

### Deploy di mcp_scanner.py (se modificato)
```powershell
# Da Windows - copia mcp_scanner.py su tutte le 9 VM
foreach ($ip in @("10.79.6.132","10.79.6.133","10.79.6.134","10.79.6.136","10.79.6.137","10.79.6.138","10.79.6.139","10.79.6.141","10.79.6.142")) { scp C:\Users\francesco\Desktop\Frameworks\mcp-guard\mcp_scanner.py tecnico@${ip}:~/Desktop/Frameworks/mcp-guard/mcp_scanner.py }
```