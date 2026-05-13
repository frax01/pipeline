# NPX Analysis - Commands

## Architettura

Ogni tool di scan gira su una VM dedicata con l'intera lista dei server NPX.
Non serve dividere per range: ogni VM esegue tutti i server.

| VM  | IP           | Tool                | Script                                          |
|-----|--------------|---------------------|------------------------------------------------|
| VM1 | 10.79.6.132  | mcp-scan            | npx_mcp_scan/run_scan.py                       |
| VM2 | 10.79.6.133  | (offline)           | -                                              |
| VM3 | 10.79.6.134  | mcp-check           | npx_mcp_check/run_check.py                     |
| VM4 | 10.79.6.136  | mcp-guard           | npx_mcp_guard/run_guard.py                     |
| VM5 | 10.79.6.137  | mcp-security-scan   | npx_mcp_security_scan/run_security_scan.py     |
| VM6 | 10.79.6.138  | mcp-watch           | npx_mcp_watch/run_watch.py                     |
| VM7 | 10.79.6.139  | fuzzing             | npx_fuzzing/run_fuzzing.py                     |
| VM8 | 10.79.6.141  | mcp-shield          | npx_mcp_shield/run_shield.py                   |
| VM9 | 10.79.6.142  | (vuota)             | -                                              |

---

## Differenze rispetto all'analisi GitHub

- **Nessun git clone** - i server si avviano con `npx -y <package_name>`
- **Nessun build** - npx gestisce tutto automaticamente
- **Lingua sempre nodejs** - sono tutti pacchetti npm
- **Nessuna pulizia repo** - solo kill dei processi orfani

---

## Pre-Deploy: Copia Excel + Script sulle VM

Il file Excel e' `0.0. All servers npx  (8899).xlsx` (8899 server, colonna `Link` con nomi pacchetti npm).
Il path e' gia' configurato in `functions/config.py` come `EXCEL_PATH_NPX`.

```powershell
$IPs = @("10.79.6.132","10.79.6.134","10.79.6.136","10.79.6.137","10.79.6.138","10.79.6.139","10.79.6.141")

# Copia Excel su tutte le VM
foreach ($IP in $IPs) {
    scp "0.0. All servers npx  (8899).xlsx" tecnico@${IP}:~/Desktop/Pipeline/
}

# Copia frameworks/ e functions/ (necessari per gli import)
# Prima rimuovi le vecchie (incomplete), poi copia nella cartella padre
foreach ($IP in $IPs) {
    ssh tecnico@$IP "rm -rf ~/Desktop/Pipeline/frameworks ~/Desktop/Pipeline/functions"
    scp -r frameworks tecnico@${IP}:~/Desktop/Pipeline/
    scp -r functions tecnico@${IP}:~/Desktop/Pipeline/
}

# Crea cartella Npx/ e sottocartelle su ogni VM, poi copia gli script
foreach ($IP in $IPs) {
    ssh tecnico@$IP "mkdir -p ~/Desktop/Pipeline/Npx/npx_mcp_scan ~/Desktop/Pipeline/Npx/npx_mcp_shield ~/Desktop/Pipeline/Npx/npx_mcp_check ~/Desktop/Pipeline/Npx/npx_mcp_guard ~/Desktop/Pipeline/Npx/npx_mcp_security_scan ~/Desktop/Pipeline/Npx/npx_mcp_watch ~/Desktop/Pipeline/Npx/npx_fuzzing"
    scp Npx/npx_mcp_scan/run_scan.py tecnico@${IP}:~/Desktop/Pipeline/Npx/npx_mcp_scan/
    scp Npx/npx_mcp_shield/run_shield.py tecnico@${IP}:~/Desktop/Pipeline/Npx/npx_mcp_shield/
    scp Npx/npx_mcp_check/run_check.py tecnico@${IP}:~/Desktop/Pipeline/Npx/npx_mcp_check/
    scp Npx/npx_mcp_guard/run_guard.py tecnico@${IP}:~/Desktop/Pipeline/Npx/npx_mcp_guard/
    scp Npx/npx_mcp_security_scan/run_security_scan.py tecnico@${IP}:~/Desktop/Pipeline/Npx/npx_mcp_security_scan/
    scp Npx/npx_mcp_watch/run_watch.py tecnico@${IP}:~/Desktop/Pipeline/Npx/npx_mcp_watch/
    scp Npx/npx_fuzzing/run_fuzzing.py tecnico@${IP}:~/Desktop/Pipeline/Npx/npx_fuzzing/
}
```

---

## Setup (1 volta per VM)

Assicurati che ogni VM abbia i tool installati.

```bash
# Su OGNI VM
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pip install pandas openpyxl psutil

# VM1 (mcp-scan) - installa mcp-scan
pip install mcp-scan
# oppure: pip install uvx && uvx mcp-scan --help

# VM8 (mcp-shield) - installa mcp-shield
sudo npm install -g mcp-shield

# VM3 (mcp-check) - installa mcp-check
npm install -g @anthropics/mcp-check

# VM4 (mcp-guard) - installa mcp-guard
pip install --force-reinstall git+https://github.com/AISafetyLab/mcp-guard.git

# VM5 (mcp-security-scan) - installa mcp-security-scanner
pip install --force-reinstall git+https://github.com/sidhpurwala-huzaifa/mcp-security-scanner.git

# VM6 (mcp-watch) - installa mcp-watch
cd ~/Desktop/Frameworks/mcp-watch && npm install

# VM7 (fuzzing) - nessuna installazione extra necessaria
```

---

## Cache Cleaner (Background) - Lanciare PRIMA dello scan su OGNI VM

```bash
nohup bash -c 'while true; do rm -rf ~/go/pkg ~/.cache/uv ~/.cache/pip ~/.cache/camoufox ~/.cache/selenium ~/.cache/pnpm ~/.cache/node-gyp ~/.cache/huggingface ~/.npm ~/.bun /tmp/camoufox-* /tmp/node-gyp-* /tmp/nx-native-file-cache-* /tmp/v8-compile-cache-* /tmp/ncc-cache /tmp/node-compile-cache /tmp/bunx-* 2>/dev/null; sleep 1800; done' > /dev/null 2>&1 &
```

---

## Avvio Scan (Nuova Scan / Reset)

### VM1 - mcp-scan (10.79.6.132)
```bash
ssh tecnico@10.79.6.132
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_scan.py'; sleep 1
nohup python -u Npx/npx_mcp_scan/run_scan.py --start 0 --reset > Npx/npx_mcp_scan/output.log 2>&1 < /dev/null &
```

### VM3 - mcp-check (10.79.6.134)
```bash
ssh tecnico@10.79.6.134
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_check.py'; sleep 1
nohup python -u Npx/npx_mcp_check/run_check.py --start 0 --reset > Npx/npx_mcp_check/output.log 2>&1 < /dev/null &
```

### VM4 - mcp-guard (10.79.6.136)
```bash
ssh tecnico@10.79.6.136
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_guard.py'; sleep 1
nohup python -u Npx/npx_mcp_guard/run_guard.py --start 0 --reset > Npx/npx_mcp_guard/output.log 2>&1 < /dev/null &
```

### VM5 - mcp-security-scan (10.79.6.137)
```bash
ssh tecnico@10.79.6.137
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_security_scan.py'; sleep 1
nohup python -u Npx/npx_mcp_security_scan/run_security_scan.py --start 0 --reset > Npx/npx_mcp_security_scan/output.log 2>&1 < /dev/null &
```

### VM6 - mcp-watch (10.79.6.138)
```bash
ssh tecnico@10.79.6.138
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_watch.py'; sleep 1
nohup python -u Npx/npx_mcp_watch/run_watch.py --start 0 --reset > Npx/npx_mcp_watch/output.log 2>&1 < /dev/null &
```

### VM7 - fuzzing (10.79.6.139)
```bash
ssh tecnico@10.79.6.139
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_fuzzing.py'; sleep 1
nohup python -u Npx/npx_fuzzing/run_fuzzing.py --start 0 --reset > Npx/npx_fuzzing/output.log 2>&1 < /dev/null &
```

### VM8 - mcp-shield (10.79.6.141)
```bash
ssh tecnico@10.79.6.141
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
pkill -f 'python.*run_shield.py'; sleep 1
nohup python -u Npx/npx_mcp_shield/run_shield.py --start 0 --reset > Npx/npx_mcp_shield/output.log 2>&1 < /dev/null &
```

---

## Hotfix: Redeploy config.py (dal PC locale - PowerShell)

Se una VM da `FileNotFoundError` sul path Excel, rideploya il config.py aggiornato:

```powershell
# Redeploy config.py su tutte le VM (o solo quelle con errore)
$IPs = @("10.79.6.132","10.79.6.134","10.79.6.136","10.79.6.137","10.79.6.138","10.79.6.139","10.79.6.141")
foreach ($IP in $IPs) {
    scp "C:\Users\francesco\Desktop\pipeline\functions\config.py" tecnico@${IP}:~/Desktop/Pipeline/functions/config.py
}

# Oppure una singola VM (es. VM8)
scp "C:\Users\francesco\Desktop\pipeline\functions\config.py" tecnico@10.79.6.141:~/Desktop/Pipeline/functions/config.py
```

---

## Avvio Rapido (tutte le VM in una volta dal PC locale - PowerShell)

```powershell
# mcp-scan (VM1)
ssh tecnico@10.79.6.132 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_scan.py'; sleep 1 && nohup python -u Npx/npx_mcp_scan/run_scan.py --start 0 --reset > Npx/npx_mcp_scan/output.log 2>&1 < /dev/null &"

# mcp-check (VM3)
ssh tecnico@10.79.6.134 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_check.py'; sleep 1 && nohup python -u Npx/npx_mcp_check/run_check.py --start 0 --reset > Npx/npx_mcp_check/output.log 2>&1 < /dev/null &"

# mcp-guard (VM4)
ssh tecnico@10.79.6.136 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_guard.py'; sleep 1 && nohup python -u Npx/npx_mcp_guard/run_guard.py --start 0 --reset > Npx/npx_mcp_guard/output.log 2>&1 < /dev/null &"

# mcp-security-scan (VM5)
ssh tecnico@10.79.6.137 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_security_scan.py'; sleep 1 && nohup python -u Npx/npx_mcp_security_scan/run_security_scan.py --start 0 --reset > Npx/npx_mcp_security_scan/output.log 2>&1 < /dev/null &"

# mcp-watch (VM6)
ssh tecnico@10.79.6.138 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_watch.py'; sleep 1 && nohup python -u Npx/npx_mcp_watch/run_watch.py --start 0 --reset > Npx/npx_mcp_watch/output.log 2>&1 < /dev/null &"

# fuzzing (VM7)
ssh tecnico@10.79.6.139 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_fuzzing.py'; sleep 1 && nohup python -u Npx/npx_fuzzing/run_fuzzing.py --start 0 --reset > Npx/npx_fuzzing/output.log 2>&1 < /dev/null &"

# mcp-shield (VM8)
ssh tecnico@10.79.6.141 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_shield.py'; sleep 1 && nohup python -u Npx/npx_mcp_shield/run_shield.py --start 0 --reset > Npx/npx_mcp_shield/output.log 2>&1 < /dev/null &"
```

---

## Resume (Ripresa dopo crash/stop - PowerShell)

Usa `--start -1` per riprendere dall'ultimo indice salvato.

```powershell
# VM1 - mcp-scan
ssh tecnico@10.79.6.132 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_scan.py'; sleep 1 && nohup python -u Npx/npx_mcp_scan/run_scan.py --start -1 > Npx/npx_mcp_scan/output.log 2>&1 < /dev/null &"

# VM8 - mcp-shield
ssh tecnico@10.79.6.141 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_shield.py'; sleep 1 && nohup python -u Npx/npx_mcp_shield/run_shield.py --start -1 > Npx/npx_mcp_shield/output.log 2>&1 < /dev/null &"

# VM3 - mcp-check
ssh tecnico@10.79.6.134 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_check.py'; sleep 1 && nohup python -u Npx/npx_mcp_check/run_check.py --start -1 > Npx/npx_mcp_check/output.log 2>&1 < /dev/null &"

# VM4 - mcp-guard
ssh tecnico@10.79.6.136 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_guard.py'; sleep 1 && nohup python -u Npx/npx_mcp_guard/run_guard.py --start -1 > Npx/npx_mcp_guard/output.log 2>&1 < /dev/null &"

# VM5 - mcp-security-scan
ssh tecnico@10.79.6.137 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_security_scan.py'; sleep 1 && nohup python -u Npx/npx_mcp_security_scan/run_security_scan.py --start -1 > Npx/npx_mcp_security_scan/output.log 2>&1 < /dev/null &"

# VM6 - mcp-watch
ssh tecnico@10.79.6.138 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_watch.py'; sleep 1 && nohup python -u Npx/npx_mcp_watch/run_watch.py --start -1 > Npx/npx_mcp_watch/output.log 2>&1 < /dev/null &"

# VM7 - fuzzing
ssh tecnico@10.79.6.139 "cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate && pkill -f 'python.*run_fuzzing.py'; sleep 1 && nohup python -u Npx/npx_fuzzing/run_fuzzing.py --start -1 > Npx/npx_fuzzing/output.log 2>&1 < /dev/null &"
```

---

## Monitoraggio

### Log in tempo reale (da dentro la VM)
```bash
# mcp-scan (VM1)
tail -f ~/Desktop/Pipeline/Npx/npx_mcp_scan/output.log

# mcp-check (VM3)
tail -f ~/Desktop/Pipeline/Npx/npx_mcp_check/output.log

# mcp-guard (VM4)
tail -f ~/Desktop/Pipeline/Npx/npx_mcp_guard/output.log

# mcp-security-scan (VM5)
tail -f ~/Desktop/Pipeline/Npx/npx_mcp_security_scan/output.log

# mcp-watch (VM6)
tail -f ~/Desktop/Pipeline/Npx/npx_mcp_watch/output.log

# fuzzing (VM7)
tail -f ~/Desktop/Pipeline/Npx/npx_fuzzing/output.log

# mcp-shield (VM8)
tail -f ~/Desktop/Pipeline/Npx/npx_mcp_shield/output.log
```

### Log da remoto (dal PC locale - PowerShell)
```powershell
# Singola VM (es. mcp-scan)
ssh tecnico@10.79.6.132 "tail -50 ~/Desktop/Pipeline/Npx/npx_mcp_scan/output.log"

# Tail live (Ctrl+C per uscire)
ssh tecnico@10.79.6.132 "tail -f ~/Desktop/Pipeline/Npx/npx_mcp_scan/output.log"

# Ultime 5 righe di TUTTI i tool su tutte le VM
$IPs = @("10.79.6.132","10.79.6.134","10.79.6.136","10.79.6.137","10.79.6.138","10.79.6.139","10.79.6.141")
foreach ($IP in $IPs) {
    Write-Host "=== $IP ==="
    ssh tecnico@$IP "tail -5 ~/Desktop/Pipeline/Npx/npx_*/output.log 2>/dev/null"
}

# Cerca errori/eccezioni nei log di tutte le VM
foreach ($IP in $IPs) {
    Write-Host "=== $IP ==="
    ssh tecnico@$IP "grep -i -E 'error|exception|traceback|failed' ~/Desktop/Pipeline/Npx/npx_*/output.log 2>/dev/null | tail -10"
}
```

### Stats in tempo reale (da dentro la VM)
```bash
# mcp-scan (VM1)
watch -n 5 'cat ~/Desktop/Pipeline/Npx/npx_mcp_scan/mcp_scan_stats.json | python3 -m json.tool'

# mcp-check (VM3)
watch -n 5 'cat ~/Desktop/Pipeline/Npx/npx_mcp_check/mcp_check_stats.json | python3 -m json.tool'

# mcp-guard (VM4)
watch -n 5 'cat ~/Desktop/Pipeline/Npx/npx_mcp_guard/mcp_guard_stats.json | python3 -m json.tool'

# mcp-security-scan (VM5)
watch -n 5 'cat ~/Desktop/Pipeline/Npx/npx_mcp_security_scan/mcp_security_scan_stats.json | python3 -m json.tool'

# mcp-watch (VM6)
watch -n 5 'cat ~/Desktop/Pipeline/Npx/npx_mcp_watch/mcp_watch_stats.json | python3 -m json.tool'

# fuzzing (VM7)
watch -n 5 'cat ~/Desktop/Pipeline/Npx/npx_fuzzing/fuzzing_stats.json | python3 -m json.tool'

# mcp-shield (VM8)
watch -n 5 'cat ~/Desktop/Pipeline/Npx/npx_mcp_shield/mcp_shield_stats.json | python3 -m json.tool'
```

### Verifica processi attivi (dal PC locale - PowerShell)

#### Check tutte le VM in un colpo
```powershell
$IPs = @("10.79.6.132","10.79.6.134","10.79.6.136","10.79.6.137","10.79.6.138","10.79.6.139","10.79.6.141")
foreach ($IP in $IPs) {
    Write-Host "=== $IP ==="
    ssh tecnico@$IP "ps aux | grep 'python.*run_' | grep -v grep | head -1"
}
```
Atteso: una riga `python -u Npx/...run_*.py` per ogni VM.

#### Check singola VM (per tool specifico)
```powershell
# VM1 - mcp-scan
ssh tecnico@10.79.6.132 "ps aux | grep 'python.*run_scan' | grep -v grep"

# VM3 - mcp-check
ssh tecnico@10.79.6.134 "ps aux | grep 'python.*run_check' | grep -v grep"

# VM4 - mcp-guard
ssh tecnico@10.79.6.136 "ps aux | grep 'python.*run_guard' | grep -v grep"

# VM5 - mcp-security-scan
ssh tecnico@10.79.6.137 "ps aux | grep 'python.*run_security_scan' | grep -v grep"

# VM6 - mcp-watch
ssh tecnico@10.79.6.138 "ps aux | grep 'python.*run_watch' | grep -v grep"

# VM7 - fuzzing
ssh tecnico@10.79.6.139 "ps aux | grep 'python.*run_fuzzing' | grep -v grep"

# VM8 - mcp-shield
ssh tecnico@10.79.6.141 "ps aux | grep 'python.*run_shield' | grep -v grep"
```

#### Conta processi npx/node figli (se troppi indica orfani)
```powershell
foreach ($IP in $IPs) {
    Write-Host "=== $IP ==="
    ssh tecnico@$IP "ps aux | grep -E 'npx|node.*mcp' | grep -v grep | wc -l"
}
```

### Monitoraggio remoto (dal PC locale - bash)
```bash
# Controlla se il processo e' attivo su ogni VM
for IP in 10.79.6.132 10.79.6.134 10.79.6.136 10.79.6.137 10.79.6.138 10.79.6.139 10.79.6.141; do
    echo "=== $IP ==="
    ssh tecnico@$IP "ps aux | grep 'python.*run_' | grep -v grep | head -1"
done

# Controlla remaining su ogni VM
for IP in 10.79.6.132 10.79.6.134 10.79.6.136 10.79.6.137 10.79.6.138 10.79.6.139 10.79.6.141; do
    echo "=== $IP ==="
    ssh tecnico@$IP "cat ~/Desktop/Pipeline/Npx/npx_*/mcp_*_stats.json ~/Desktop/Pipeline/Npx/npx_*/fuzzing_stats.json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(f\"total: {d.get(\"total\",0)}, remaining: {d.get(\"remaining\",0)}\")' 2>/dev/null"
done

# RAM e disco su ogni VM
for IP in 10.79.6.132 10.79.6.134 10.79.6.136 10.79.6.137 10.79.6.138 10.79.6.139 10.79.6.141; do
    echo "=== $IP ==="
    ssh tecnico@$IP "free -h | grep Mem; df -h / | tail -1"
done
```

---

## Stop

```bash
# Stop un singolo tool (esempio: mcp-scan su VM1)
ssh tecnico@10.79.6.132 "pkill -f 'python.*run_scan.py'"

# Stop tutti i tool su tutte le VM
for IP in 10.79.6.132 10.79.6.134 10.79.6.136 10.79.6.137 10.79.6.138 10.79.6.139 10.79.6.141; do
    echo "Stopping $IP..."
    ssh tecnico@$IP "pkill -f 'python.*run_.*\.py'; pkill -f 'node.*mcp'; pkill -f 'npx'"
done
```

---

## Pulizia Processi Orfani

```bash
# Su una singola VM
pkill -f "python.*mcp"; pkill -f "node.*mcp"; pkill -f "npx -y"

# Su tutte le VM
for IP in 10.79.6.132 10.79.6.134 10.79.6.136 10.79.6.137 10.79.6.138 10.79.6.139 10.79.6.141; do
    echo "Cleaning $IP..."
    ssh tecnico@$IP "pkill -f 'python.*mcp'; pkill -f 'node.*mcp'; pkill -f 'npx -y'" 2>/dev/null
done
```

---

## Download Risultati (dal PC locale)

> **Nota**: nessun merge necessario. Ogni VM ha processato la lista intera degli 8899 server con un solo tool, quindi i file scaricati sono gia' i risultati completi per quel tool. A differenza dell'analisi sharded GitHub (9 VM con range diversi), qui non serve combinare i pezzi.

```bash
# Scarica stats e servers di ogni tool
mkdir -p results_npx

# mcp-scan (VM1)
scp tecnico@10.79.6.132:~/Desktop/Pipeline/Npx/npx_mcp_scan/mcp_scan_stats.json results_npx/
scp tecnico@10.79.6.132:~/Desktop/Pipeline/Npx/npx_mcp_scan/mcp_scan_servers.json results_npx/
scp tecnico@10.79.6.132:~/Desktop/Pipeline/Npx/npx_mcp_scan/mcp_scan_vulnerabilities.json results_npx/ 2>/dev/null

# mcp-shield (VM8)
scp tecnico@10.79.6.141:~/Desktop/Pipeline/Npx/npx_mcp_shield/mcp_shield_stats.json results_npx/
scp tecnico@10.79.6.141:~/Desktop/Pipeline/Npx/npx_mcp_shield/mcp_shield_servers.json results_npx/

# mcp-check (VM3)
scp tecnico@10.79.6.134:~/Desktop/Pipeline/Npx/npx_mcp_check/mcp_check_stats.json results_npx/
scp tecnico@10.79.6.134:~/Desktop/Pipeline/Npx/npx_mcp_check/mcp_check_servers.json results_npx/

# mcp-guard (VM4)
scp tecnico@10.79.6.136:~/Desktop/Pipeline/Npx/npx_mcp_guard/mcp_guard_stats.json results_npx/
scp tecnico@10.79.6.136:~/Desktop/Pipeline/Npx/npx_mcp_guard/mcp_guard_servers.json results_npx/

# mcp-security-scan (VM5)
scp tecnico@10.79.6.137:~/Desktop/Pipeline/Npx/npx_mcp_security_scan/mcp_security_scan_stats.json results_npx/
scp tecnico@10.79.6.137:~/Desktop/Pipeline/Npx/npx_mcp_security_scan/mcp_security_scan_servers.json results_npx/

# mcp-watch (VM6)
scp tecnico@10.79.6.138:~/Desktop/Pipeline/Npx/npx_mcp_watch/mcp_watch_stats.json results_npx/
scp tecnico@10.79.6.138:~/Desktop/Pipeline/Npx/npx_mcp_watch/mcp_watch_servers.json results_npx/

# fuzzing (VM7)
scp tecnico@10.79.6.139:~/Desktop/Pipeline/Npx/npx_fuzzing/fuzzing_stats.json results_npx/
scp tecnico@10.79.6.139:~/Desktop/Pipeline/Npx/npx_fuzzing/fuzzing_servers.json results_npx/
```

### Download tutto in un comando
```bash
mkdir -p results_npx && \
scp tecnico@10.79.6.132:~/Desktop/Pipeline/Npx/npx_mcp_scan/mcp_scan_*.json results_npx/ && \
scp tecnico@10.79.6.141:~/Desktop/Pipeline/Npx/npx_mcp_shield/mcp_shield_*.json results_npx/ && \
scp tecnico@10.79.6.134:~/Desktop/Pipeline/Npx/npx_mcp_check/mcp_check_*.json results_npx/ && \
scp tecnico@10.79.6.136:~/Desktop/Pipeline/Npx/npx_mcp_guard/mcp_guard_*.json results_npx/ && \
scp tecnico@10.79.6.137:~/Desktop/Pipeline/Npx/npx_mcp_security_scan/mcp_security_scan_*.json results_npx/ && \
scp tecnico@10.79.6.138:~/Desktop/Pipeline/Npx/npx_mcp_watch/mcp_watch_*.json results_npx/ && \
scp tecnico@10.79.6.139:~/Desktop/Pipeline/Npx/npx_fuzzing/fuzzing_*.json results_npx/
```

---

## Output per Tool

| Tool              | Stats File                        | Servers File                        | Extra                               |
|-------------------|-----------------------------------|-------------------------------------|-------------------------------------|
| mcp-scan          | mcp_scan_stats.json               | mcp_scan_servers.json               | mcp_scan_vulnerabilities.json       |
| mcp-shield        | mcp_shield_stats.json             | mcp_shield_servers.json             | -                                   |
| mcp-check         | mcp_check_stats.json              | mcp_check_servers.json              | -                                   |
| mcp-guard         | mcp_guard_stats.json              | mcp_guard_servers.json              | -                                   |
| mcp-security-scan | mcp_security_scan_stats.json      | mcp_security_scan_servers.json      | -                                   |
| mcp-watch         | mcp_watch_stats.json              | mcp_watch_servers.json              | -                                   |
| fuzzing           | fuzzing_stats.json                | fuzzing_servers.json                | -                                   |
