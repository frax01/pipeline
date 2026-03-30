# 0_tool_proxy - Commands

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
Il proxy richiede Node.js, ts-node, npm, e **Ollama con llama3**.

```bash
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate

# 1. Installa dipendenze Python
pip install psutil pandas openpyxl

# 2. Installa dipendenze Node.js (ts-node, SDK)
npm install

# 3. Installa Ollama (se non presente)
curl -fsSL https://ollama.com/install.sh | sh

# 4. Scarica il modello llama3
ollama pull llama3

# 5. Avvia Ollama in background (se non gira come servizio)
nohup ollama serve > /dev/null 2>&1 &

# 6. Verifica che tutto funzioni
ollama list                    # deve mostrare llama3
npx ts-node --version          # deve funzionare
```

---

## Avvio Scan (Nuova Scan / Reset)
Da lanciare su ogni VM per iniziare da zero.

```bash
# VM1 (10.79.6.132)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start 0 --end 6689 --reset > proxy_output.log 2>&1 &

# VM2 (10.79.6.133)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start 6689 --end 13378 --reset > proxy_output.log 2>&1 &

# VM3 (10.79.6.134)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start 13378 --end 20067 --reset > proxy_output.log 2>&1 &

# VM4 (10.79.6.136)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start 20067 --end 26756 --reset > proxy_output.log 2>&1 &

# VM5 (10.79.6.137)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start 26756 --end 33445 --reset > proxy_output.log 2>&1 &

# VM6 (10.79.6.138)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start 33445 --end 40134 --reset > proxy_output.log 2>&1 &

# VM7 (10.79.6.139)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start 40134 --end 46823 --reset > proxy_output.log 2>&1 &

# VM8 (10.79.6.141)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start 46823 --end 53512 --reset > proxy_output.log 2>&1 &

# VM9 (10.79.6.142)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start 53512 --end 60205 --reset > proxy_output.log 2>&1 &
```

---

## Ripresa Scan (Resume)
Usa `--start -1` per riprendere dall'ultimo indice salvato.

```bash
# VM1 (10.79.6.132)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start -1 --end 6689 > proxy_output.log 2>&1 &

# VM2 (10.79.6.133)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start -1 --end 13378 > proxy_output.log 2>&1 &

# VM3 (10.79.6.134)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start -1 --end 20067 > proxy_output.log 2>&1 &

# VM4 (10.79.6.136)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start -1 --end 26756 > proxy_output.log 2>&1 &

# VM5 (10.79.6.137)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start -1 --end 33445 > proxy_output.log 2>&1 &

# VM6 (10.79.6.138)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start -1 --end 40134 > proxy_output.log 2>&1 &

# VM7 (10.79.6.139)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start -1 --end 46823 > proxy_output.log 2>&1 &

# VM8 (10.79.6.141)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start -1 --end 53512 > proxy_output.log 2>&1 &

# VM9 (10.79.6.142)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_proxy.py'; sleep 1
nohup python tool_proxy/run_proxy.py --start -1 --end 60205 > proxy_output.log 2>&1 &
```

---

## Monitoraggio (Live)
Comandi da eseguire dentro la VM.

```bash
# Log in tempo reale
tail -f ~/Desktop/Pipeline/proxy_output.log

# Stats aggiornate ogni 5 secondi
watch -n 5 'cat ~/Desktop/Pipeline/tool_proxy/proxy_stats.json | python3 -m json.tool'

# Verifica processo attivo
ps aux | grep run_proxy | grep -v grep

# RAM e disco (IMPORTANTE: Ollama usa molta RAM)
free -h | grep Mem; df -h /

# Processi attivi (proxy + ollama)
ps aux | grep -E 'npm|node|ts-node|ollama|git|run_proxy' | grep -v grep

# Verifica Ollama attivo
curl -s http://localhost:11434/api/tags | python3 -m json.tool
```

---

## Diagnostica (se si blocca)

```bash
# Processo principale ancora vivo?
ps aux | grep run_proxy | grep -v grep

# Ultimo log
tail -5 ~/Desktop/Pipeline/proxy_output.log

# Ollama attivo?
pgrep -a ollama
curl -s http://localhost:11434/api/tags 2>/dev/null | python3 -m json.tool || echo "Ollama non risponde!"

# Se Ollama non risponde, riavvialo
pkill ollama; sleep 2; nohup ollama serve > /dev/null 2>&1 &; sleep 3; ollama list

# Processi figli bloccati
ps aux | grep -E 'ts-node|node.*index.ts|npm|git' | grep -v grep

# Kill processi orfani ts-node/node
pkill -f 'ts-node.*index.ts'; pkill -f 'node.*NewProxy'

# Repo in lavorazione (non cancellata)
ls -d ~/Desktop/Pipeline/*/ | grep -v -E 'tool_|pipeline-env|__pycache__|frameworks|functions|npm_runner|node_modules|mcp_scan_storage'

# RAM in tempo reale
watch -n 2 'free -h | grep Mem; echo "---"; ps aux --sort=-%mem | head -5'

# Memoria usata da Ollama
ps aux | grep ollama | grep -v grep | awk '{print "Ollama RSS:", $6/1024, "MB"}'
```

---

## Stop e Pulizia

```bash
# Ferma lo script
pkill -f 'python.*run_proxy.py'

# Pulisce processi orfani (server MCP + ts-node rimasti attivi)
pkill -f "python.*mcp"; pkill -f "node.*mcp"; pkill -f "ts-node.*index.ts"

# NON killare Ollama (serve per altri run)
# Se vuoi fermarlo: pkill ollama

# Pulisce repo orfane
cd ~/Desktop/Pipeline && ls -d */ | grep -v -E 'tool_|pipeline-env|__pycache__|frameworks|functions|npm_runner|node_modules|mcp_scan_storage' | head -20
```

---

## Cache Cleaner (Background)
Lancia PRIMA dello scan per pulire le cache automaticamente ogni 30 minuti.

```bash
nohup bash -c 'while true; do rm -rf ~/go/pkg ~/.cache/uv ~/.cache/pip ~/.cache/camoufox ~/.cache/selenium ~/.cache/pnpm ~/.cache/puccinialin ~/.cache/ffmpeg-static-nodejs ~/.cache/prisma ~/.cache/node-gyp ~/.cache/huggingface ~/.npm ~/.rustup ~/.bun ~/.config/google-chrome-for-testing /tmp/camoufox-* /tmp/node-gyp-* /tmp/phantomjs /tmp/nx-native-file-cache-* /tmp/v8-compile-cache-* /tmp/ncc-cache /tmp/node-compile-cache /tmp/bunx-* 2>/dev/null; sleep 1800; done' > /dev/null 2>&1 &

# Per fermarlo
pkill -f "while true; do rm -rf"
```

---

## Comandi dal PC Locale (deploy.py)

```powershell
# Deploy su tutte le VM
python deploy.py --deploy-proxy-all

# Deploy su VM specifiche
python deploy.py --deploy-proxy-all VM1 VM5

# Controlla stato di tutte le VM
python deploy.py --status-proxy

# Log di tutte le VM
python deploy.py --tail-proxy

# Scarica risultati da tutte le VM
python deploy.py --pull-proxy

# Merge stats da tutte le VM (dopo pull)
python deploy.py --merge-proxy

# Pull + Merge in un colpo solo
python deploy.py --pull-proxy --merge-proxy
```

---

## Risultati Finali
Dopo il merge, i file unificati si trovano in:
- `tool_proxy/proxy_stats.json` - stats aggregate di tutte le 9 VM
- `tool_proxy/proxy_servers.json` - log di tutti i server analizzati

Per copiarli nella cartella di analisi:
```powershell
copy tool_proxy\proxy_stats.json 0_tool_proxy\proxy_stats.json
copy tool_proxy\proxy_servers.json 0_tool_proxy\proxy_servers.json
```

---

## Note Importanti

### RAM
Il proxy usa **molta RAM** perche Ollama carica llama3 in memoria (4-8GB).
- Minimo consigliato per VM: **16GB RAM**
- Monitora spesso con `free -h`
- Se la VM ha poca RAM, puoi usare un modello piu piccolo modificando `OLLAMA_MODEL` in `frameworks/NewProxy/config.ts`

### Tempo per Server
Il proxy e piu lento degli altri framework (~2-10 min per server) perche:
- Genera prompt tramite LLM per ogni tool (Phase 1)
- Verifica ogni tool call/response con LLM (4 checkpoint)
- Testa centinaia di payload per tool

### Prerequisiti sulle VM
1. Python 3.10+ con venv
2. Node.js 18+ con npm/npx
3. ts-node (`npm install -g ts-node typescript`)
4. Ollama con llama3
5. Pacchetti npm del progetto (`npm install` nella cartella Pipeline)
