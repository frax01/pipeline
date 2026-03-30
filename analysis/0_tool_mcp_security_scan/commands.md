# 0_tool_mcp_security_scan - Commands

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
Installa `mcp-security-scanner` dalla versione GitHub con supporto stdio.

```bash
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pip install --force-reinstall git+https://github.com/sidhpurwala-huzaifa/mcp-security-scanner.git
mcp-scan scan --help  # verifica che ci sia --transport stdio
```

---

## Avvio Scan (Nuova Scan / Reset)
Da lanciare su ogni VM per iniziare da zero.

```bash
# VM1 (10.79.6.132)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start 0 --end 6689 --reset > security_scan_output.log 2>&1 &

# VM2 (10.79.6.133)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start 6689 --end 13378 --reset > security_scan_output.log 2>&1 &

# VM3 (10.79.6.134)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start 13378 --end 20067 --reset > security_scan_output.log 2>&1 &

# VM4 (10.79.6.136)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start 20067 --end 26756 --reset > security_scan_output.log 2>&1 &

# VM5 (10.79.6.137)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start 26756 --end 33445 --reset > security_scan_output.log 2>&1 &

# VM6 (10.79.6.138)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start 33445 --end 40134 --reset > security_scan_output.log 2>&1 &

# VM7 (10.79.6.139)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start 40134 --end 46823 --reset > security_scan_output.log 2>&1 &

# VM8 (10.79.6.141)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start 46823 --end 53512 --reset > security_scan_output.log 2>&1 &

# VM9 (10.79.6.142)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start 53512 --end 60205 --reset > security_scan_output.log 2>&1 &
```

---

## Ripresa Scan (Resume)
Usa `--start -1` per riprendere dall'ultimo indice salvato.

```bash
# VM1 (10.79.6.132)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start -1 --end 6689 > security_scan_output.log 2>&1 &

# VM2 (10.79.6.133)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start -1 --end 13378 > security_scan_output.log 2>&1 &

# VM3 (10.79.6.134)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start -1 --end 20067 > security_scan_output.log 2>&1 &

# VM4 (10.79.6.136)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start -1 --end 26756 > security_scan_output.log 2>&1 &

# VM5 (10.79.6.137)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start -1 --end 33445 > security_scan_output.log 2>&1 &

# VM6 (10.79.6.138)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start -1 --end 40134 > security_scan_output.log 2>&1 &

# VM7 (10.79.6.139)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start -1 --end 46823 > security_scan_output.log 2>&1 &

# VM8 (10.79.6.141)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start -1 --end 53512 > security_scan_output.log 2>&1 &

# VM9 (10.79.6.142)
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python tool_mcp_security_scan/run_security_scan.py --start -1 --end 60205 > security_scan_output.log 2>&1 &
```

---

## Monitoraggio (Live)
Comandi da eseguire dentro la VM.

```bash
# Log in tempo reale
tail -f ~/Desktop/Pipeline/security_scan_output.log

# Stats aggiornate ogni 5 secondi
watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_stats.json | python3 -m json.tool'

# Verifica processo attivo
ps aux | grep run_security_scan | grep -v grep

# RAM e disco
free -h | grep Mem; df -h /

# Processi figli attivi (npm, node, git, ecc.)
ps aux | grep -E 'npm|node|git|mcp-scan' | grep -v grep
```

---

## Stop e Pulizia

```bash
# Ferma lo script
pkill -f 'python.*run_security_scan.py'

# Pulisce processi orfani (server MCP rimasti attivi)
pkill -f "python.*mcp"; pkill -f "node.*mcp"; pkill -f "mcp-scan"

# Pulisce repo orfane (cartelle clonate non cancellate)
cd ~/Desktop/Pipeline && ls -d */ | grep -v -E 'tool_|pipeline-env|__pycache__|frameworks|functions|node_modules' | head -20
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
python deploy.py --deploy-security-scan-all

# Controlla stato di tutte le VM
python deploy.py --status-security-scan

# Log di tutte le VM
python deploy.py --tail-security-scan

# Scarica risultati e uniscili
python deploy.py --pull-security-scan
python deploy.py --merge-security-scan
```
