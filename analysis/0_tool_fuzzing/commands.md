# 0_tool_fuzzing - Commands

## VM Info
| VM  | IP           | Range         |
|-----|--------------|---------------|
| VM1 | 10.79.6.132  | 0 - 6689      |
| VM2 | 10.79.6.133  | 6689 - 13378  |
| VM3 | 10.79.6.134  | 13378 - 20067 |
| VM4 | 10.79.6.136  | 20067 - 26756 |
| VM5 | 10.79.6.137  | 26756 - 33445 |
| VM6 | 10.79.6.138  | 33445 - 40134 |
| VM7 | 10.79.6.139  | 40134 - 46823 |
| VM8 | 10.79.6.141  | 46823 - 53512 |
| VM9 | 10.79.6.142  | 53512 - 60205 |

---

## Setup (da fare 1 volta su ogni VM)
Installa `mcp-fuzzer` e le dipendenze necessarie.

```bash
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pip install mcp-fuzzer psutil pandas openpyxl
mcp-fuzzer --help  # verifica che sia installato
```

---

## Avvio Fuzzing (Nuova Scan / Reset)
Da lanciare su ogni VM per iniziare da zero.

```bash
# VM1 (10.79.6.132)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start 0 --end 6689 --reset > fuzzing_output.log 2>&1 &

# VM2 (10.79.6.133)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start 6689 --end 13378 --reset > fuzzing_output.log 2>&1 &

# VM3 (10.79.6.134)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start 13378 --end 20067 --reset > fuzzing_output.log 2>&1 &

# VM4 (10.79.6.136)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start 20067 --end 26756 --reset > fuzzing_output.log 2>&1 &

# VM5 (10.79.6.137)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start 26756 --end 33445 --reset > fuzzing_output.log 2>&1 &

# VM6 (10.79.6.138)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start 33445 --end 40134 --reset > fuzzing_output.log 2>&1 &

# VM7 (10.79.6.139)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start 40134 --end 46823 --reset > fuzzing_output.log 2>&1 &

# VM8 (10.79.6.141)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start 46823 --end 53512 --reset > fuzzing_output.log 2>&1 &

# VM9 (10.79.6.142)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start 53512 --end 60205 --reset > fuzzing_output.log 2>&1 &
```

---

## Ripresa Fuzzing (Resume)
Usa `--start -1` per riprendere dall'ultimo indice salvato.

```bash
# VM1 (10.79.6.132)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 6689 > fuzzing_output.log 2>&1 &

# VM2 (10.79.6.133)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 13378 > fuzzing_output.log 2>&1 &

# VM3 (10.79.6.134)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 20067 > fuzzing_output.log 2>&1 &

# VM4 (10.79.6.136)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 26756 > fuzzing_output.log 2>&1 &

# VM5 (10.79.6.137)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 33445 > fuzzing_output.log 2>&1 &

# VM6 (10.79.6.138)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 40134 > fuzzing_output.log 2>&1 &

# VM7 (10.79.6.139)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 46823 > fuzzing_output.log 2>&1 &

# VM8 (10.79.6.141)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 53512 > fuzzing_output.log 2>&1 &

# VM9 (10.79.6.142)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 60205 > fuzzing_output.log 2>&1 &
```

---

## Monitoraggio (Live)
Comandi da eseguire dentro la VM.

```bash
# Log in tempo reale
tail -f ~/Desktop/Pipeline/fuzzing_output.log

# Stats aggiornate ogni 5 secondi
watch -n 5 'cat ~/Desktop/Pipeline/tool_fuzzing/fuzzing_stats.json | python3 -m json.tool'

# Verifica processo attivo
ps aux | grep run_fuzzing | grep -v grep

# RAM e disco
free -h | grep Mem; df -h /

# Processi figli attivi (mcp-fuzzer, npm, node, git, ecc.)
ps aux | grep -E 'mcp-fuzzer|npm|node|git' | grep -v grep
```

---

## Diagnostica (se si blocca)

```bash
# Processo principale ancora vivo?
ps aux | grep run_fuzzing | grep -v grep

# Ultimo log
tail -5 ~/Desktop/Pipeline/fuzzing_output.log

# Processi figli bloccati
ps aux | grep -E 'mcp-fuzzer|npm|node|git|go ' | grep -v grep

# Repo in lavorazione (non cancellata)
ls -d ~/Desktop/Pipeline/*/ | grep -v -E 'tool_|pipeline-env|__pycache__|frameworks|functions|npm_runner|node_modules|mcp_scan_storage'

# RAM in tempo reale
watch -n 2 'free -h | grep Mem; echo "---"; ps aux --sort=-%mem | head -5'
```

---

## Stop e Pulizia

```bash
# Ferma lo script
pkill -f 'python.*run_fuzzing.py'

# Pulisce processi orfani (server MCP e fuzzer rimasti attivi)
pkill -f "mcp-fuzzer"; pkill -f "python.*mcp"; pkill -f "node.*mcp"

# Pulisce repo orfane
cd ~/Desktop/Pipeline && ls -d */ | grep -v -E 'tool_|pipeline-env|__pycache__|frameworks|functions|npm_runner|node_modules|mcp_scan_storage' | head -20
```

---

## Cache Cleaner (Background)
Lancia PRIMA del fuzzing per pulire le cache automaticamente ogni 30 minuti.

```bash
nohup bash -c 'while true; do rm -rf ~/go/pkg ~/.cache/uv ~/.cache/pip ~/.cache/camoufox ~/.cache/selenium ~/.cache/pnpm ~/.cache/puccinialin ~/.cache/ffmpeg-static-nodejs ~/.cache/prisma ~/.cache/node-gyp ~/.cache/huggingface ~/.npm ~/.rustup ~/.bun ~/.config/google-chrome-for-testing /tmp/camoufox-* /tmp/node-gyp-* /tmp/phantomjs /tmp/nx-native-file-cache-* /tmp/v8-compile-cache-* /tmp/ncc-cache /tmp/node-compile-cache /tmp/bunx-* /tmp/safe /tmp/test_fuzz 2>/dev/null; sleep 1800; done' > /dev/null 2>&1 &

# Per fermarlo
pkill -f "while true; do rm -rf"
```

---

## Comandi dal PC Locale (deploy.py)

```powershell
# Deploy su tutte le VM
python deploy.py --deploy-fuzzing-all

# Controlla stato di tutte le VM
python deploy.py --status-fuzzing

# Log di tutte le VM
python deploy.py --tail-fuzzing

# Scarica risultati e uniscili
python deploy.py --pull-fuzzing
python deploy.py --merge-fuzzing
```
