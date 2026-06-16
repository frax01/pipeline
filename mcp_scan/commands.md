# Deploy e Gestione MCP Scan su 9 VM

Questo documento contiene i comandi necessari per gestire `mcp-scan` sulle 9 virtual machine, permettendo la scansione parallela di 60.205 server. Ogni VM processa uno shard di 6689 server.

---

## 1. Deploy del Codice su Tutte le VM

Prima di tutto, invia l'aggiornamento di `mcp_scan` a tutte le 9 macchine:

```bash
# Sincronizza il tool MCP Scan
python deploy.py --deploy-scan-all
```

---

## 2. Lancio Scan (Avvio da Zero)

Ecco i comandi completi da copiare e incollare per ogni VM.  
Questi comandi **uccideranno** ogni scan precedente, entreranno nell'ambiente virtuale e lanceranno lo script in background (nohup) loggando tutto su `scan_output.log`. `mcp-scan` salverà i risultati suddivisi in `server-level/` e `tool-level/`.

### VM1 (10.79.6.132)
```bash
ssh tecnico@10.79.6.132
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 0 --end 6689 --reset > scan_output.log 2>&1 &
```

### VM2 (10.79.6.133)
```bash
ssh tecnico@10.79.6.133
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 6689 --end 13378 --reset > scan_output.log 2>&1 &
```

### VM3 (10.79.6.134)
```bash
ssh tecnico@10.79.6.134
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 13378 --end 20067 --reset > scan_output.log 2>&1 &
```

### VM4 (10.79.6.136)
```bash
ssh tecnico@10.79.6.136
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 20067 --end 26756 --reset > scan_output.log 2>&1 &
```

### VM5 (10.79.6.137)
```bash
ssh tecnico@10.79.6.137
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 26756 --end 33445 --reset > scan_output.log 2>&1 &
```

### VM6 (10.79.6.138)
```bash
ssh tecnico@10.79.6.138
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 33445 --end 40134 --reset > scan_output.log 2>&1 &
```

### VM7 (10.79.6.139)
```bash
ssh tecnico@10.79.6.139
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 40134 --end 46823 --reset > scan_output.log 2>&1 &
```

### VM8 (10.79.6.141)
```bash
ssh tecnico@10.79.6.141
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 46823 --end 53512 --reset > scan_output.log 2>&1 &
```

### VM9 (10.79.6.142)
```bash
ssh tecnico@10.79.6.142
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 53512 --end 60205 --reset > scan_output.log 2>&1 &
```

---

## 3. Resume (Ripresa da arresto)

Se il server si riavvia o lo script si interrompe, esegui lo stesso comando rimuovendo `--reset`, rimuovendo `end` (opzionale) e settando `--start -1`:

```bash
nohup python tool_mcp_scan/run_scan.py --start -1 > scan_output.log 2>&1 &
```

---

## 4. Monitoraggio dello Stato (Real-time)

**Sulla VM:**
Puoi visualizzare le statistiche (`remaining` andrà a scalare) e controllare i file live:
```bash
tail -f ~/Desktop/Pipeline/scan_output.log
watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_stats.json | python3 -m json.tool'

# Esempi per controllare i json separati per issue (in tool-level o server-level):
# tool_level Esempio W001:
cat ~/Desktop/Pipeline/tool_mcp_scan/tool-level/W001.json
# server_level Esempio Toxic Flow (TF001):
cat ~/Desktop/Pipeline/tool_mcp_scan/server-level/TF001.json
cat ~/Desktop/Pipeline/tool_mcp_scan/server-level/W015.json
cat ~/Desktop/Pipeline/tool_mcp_scan/server-level/W016.json

# Controllare se il processo è vivo
ps aux | grep run_scan.py | grep -v grep
```

**Dal tuo PC Locale:**
```bash
python deploy.py --status-scan
python deploy.py --tail-scan
```

---

## 5. Download e Merge Risultati in `*/postprocessing`

Quando vuoi recuperare e aggregare tutti i file JSON splittati da tutte le VM, puoi usare il comando combinato. `deploy.py` zipparà `tool_mcp_scan` via tar, lo scaricherà, lo estrarrà e lo combinerà:

```bash
# Esegue Pull & Merge di MCP Scan in un singolo step:
python deploy.py --pull-scan --merge-scan
```

I risultati appariranno in `mcp_scan/postprocessing/` con la seguente struttura:
- `mcp_scan_stats.json`
- `mcp_scan_servers.json`
- `server-level/Wxxx.json`
- `tool-level/Wxxx.json`