# Deploy e Gestione MCP Security Scan su 9 VM

Questo documento contiene i comandi necessari per gestire `mcp-security-scan` sulle 9 virtual machine e per raggruppare i risultati per categoria/severity in locale usando `deploy.py`. Ogni VM processa uno shard di ~6689 server.

---

## 1. Deploy del Codice su Tutte le VM

Questa operazione invia il codice core di security scan (nessuna dipendenza pesante) a tutti i workers:

```bash
python deploy.py --deploy-security-scan-all
```

---

## 2. Lancio Scan (Avvio da Zero)

Copia e incolla ciascuno di questi comandi in 9 terminali separati per avviare il batch intero in parallelo. Il `--reset` serve per riniziare esattamente dall'indice di partenza (ignorando ogni parziale precedente).

### VM1 (10.79.6.132)
```bash
ssh tecnico@10.79.6.132
pkill -f 'python.*run_security_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_security_scan/run_security_scan.py --start 0 --end 6689 --reset > security_scan_output.log 2>&1 &
```

### VM2 (10.79.6.133)
```bash
ssh tecnico@10.79.6.133
pkill -f 'python.*run_security_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_security_scan/run_security_scan.py --start 6689 --end 13378 --reset > security_scan_output.log 2>&1 &
```

### VM3 (10.79.6.134)
```bash
ssh tecnico@10.79.6.134
pkill -f 'python.*run_security_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_security_scan/run_security_scan.py --start 13378 --end 20067 --reset > security_scan_output.log 2>&1 &
```

### VM4 (10.79.6.136)
```bash
ssh tecnico@10.79.6.136
pkill -f 'python.*run_security_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_security_scan/run_security_scan.py --start 20067 --end 26756 --reset > security_scan_output.log 2>&1 &
```

### VM5 (10.79.6.137)
```bash
ssh tecnico@10.79.6.137
pkill -f 'python.*run_security_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_security_scan/run_security_scan.py --start 26756 --end 33445 --reset > security_scan_output.log 2>&1 &
```

### VM6 (10.79.6.138)
```bash
ssh tecnico@10.79.6.138
pkill -f 'python.*run_security_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_security_scan/run_security_scan.py --start 33445 --end 40134 --reset > security_scan_output.log 2>&1 &
```

### VM7 (10.79.6.139)
```bash
ssh tecnico@10.79.6.139
pkill -f 'python.*run_security_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_security_scan/run_security_scan.py --start 40134 --end 46823 --reset > security_scan_output.log 2>&1 &
```

### VM8 (10.79.6.141)
```bash
ssh tecnico@10.79.6.141
pkill -f 'python.*run_security_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_security_scan/run_security_scan.py --start 46823 --end 53512 --reset > security_scan_output.log 2>&1 &
```

### VM9 (10.79.6.142)
```bash
ssh tecnico@10.79.6.142
pkill -f 'python.*run_security_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_security_scan/run_security_scan.py --start 53512 --end 60205 --reset > security_scan_output.log 2>&1 &
```

---

## 3. Resume (Ripresa da arresto)

Esempio pratico: se accade un crash di un plugin o la macchina termina di colpo, puoi riavviare usando il parametro `--start -1` (il parametro start e' intelligente: se `-1`, cerca in locale il json stats e ricomincia dall'ultimo server parsato `last_index`). Metti via il `--reset` per evitare di scartare le vulnerabilita' parziali gia' salvate.

```bash
nohup python tool_mcp_security_scan/run_security_scan.py --start -1 > security_scan_output.log 2>&1 &
```

---

## 4. Monitoraggio dello Stato (Real-time)

**Sulla VM singola:**
```bash
# Log output per monitorare velocita' e crash
tail -f ~/Desktop/Pipeline/security_scan_output.log

# Stats overall e quantita' categories che salgono
watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_stats.json | python3 -m json.tool'

# Esempio per controllare la cartella dangerous-capabilities e la quantita' di item CRITICAL JSON scritti fino a questo momento:
cat ~/Desktop/Pipeline/tool_mcp_security_scan/dangerous-capabilities/dangerous_capabilities_critical.json | python3 -m json.tool

# Controllare se il processo run e' vivo (utile prima di rilanciare)
ps aux | grep run_security_scan.py | grep -v grep
```

**Dal PC Locale:**
Ti basta lanciare per raccogliere i log o guardare `last_index` da deploy.
```bash
python deploy.py --status-security-scan
python deploy.py --tail-security-scan
```

---

## 5. Download e Deep-Merge dei Risultati

A fine esecuzione di tutte le code:

```bash
# 1. Chiude tutto in uno zip (tramite shell locale tar), lo scarica tramite SCP dal tmp della macchina saltando virtualenvs e pycache. Lo fa su tutte e 9
python deploy.py --pull-security-scan

# 2. Riemerge logicamente tutto il pullFromLocal estraendone le statistiche unificate dentro */postprocessing aggregando le sotto-folders a colpi di extend di JSON array in deep state (somma findings fra server VM diversi)
python deploy.py --merge-security-scan
```
