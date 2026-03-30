# Deploy e Gestione MCP Check su 9 VM

Questo documento contiene i comandi necessari per gestire `mcp-check` sulle 9 virtual machine, permettendo la scansione parallela di 60.205 server. Ogni VM processa uno shard di circa 6689 server.

---

## 1. Deploy del Codice su Tutte le VM

Prima di tutto, invia l'aggiornamento di `0_tool_mcp_check` a tutte le 9 macchine:

```bash
# Sincronizza il tool MCP Check
python deploy.py --deploy-check-all
```

---

## 2. Lancio Check (Avvio da Zero)

Ecco i comandi completi da copiare e incollare per ogni VM.  
Questi comandi **uccideranno** ogni check precedente, entreranno nell'ambiente virtuale e lanceranno lo script in background (nohup) loggando tutto su `check_output.log`. `mcp-check` salverà i risultati suddivisi in `handshake/`, `tool_discovery/` e `tool_invocation/`.

### VM1 (10.79.6.132)
```bash
ssh tecnico@10.79.6.132
pkill -f 'python.*run_check.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start 0 --end 6689 --reset > check_output.log 2>&1 &
```

### VM2 (10.79.6.133)
```bash
ssh tecnico@10.79.6.133
pkill -f 'python.*run_check.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start 6689 --end 13378 --reset > check_output.log 2>&1 &
```

### VM3 (10.79.6.134)
```bash
ssh tecnico@10.79.6.134
pkill -f 'python.*run_check.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start 13378 --end 20067 --reset > check_output.log 2>&1 &
```

### VM4 (10.79.6.136)
```bash
ssh tecnico@10.79.6.136
pkill -f 'python.*run_check.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start 20067 --end 26756 --reset > check_output.log 2>&1 &
```

### VM5 (10.79.6.137)
```bash
ssh tecnico@10.79.6.137
pkill -f 'python.*run_check.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start 26756 --end 33445 --reset > check_output.log 2>&1 &
```

### VM6 (10.79.6.138)
```bash
ssh tecnico@10.79.6.138
pkill -f 'python.*run_check.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start 33445 --end 40134 --reset > check_output.log 2>&1 &
```

### VM7 (10.79.6.139)
```bash
ssh tecnico@10.79.6.139
pkill -f 'python.*run_check.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start 40134 --end 46823 --reset > check_output.log 2>&1 &
```

### VM8 (10.79.6.141)
```bash
ssh tecnico@10.79.6.141
pkill -f 'python.*run_check.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start 46823 --end 53512 --reset > check_output.log 2>&1 &
```

### VM9 (10.79.6.142)
```bash
ssh tecnico@10.79.6.142
pkill -f 'python.*run_check.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start 53512 --end 60205 --reset > check_output.log 2>&1 &
```

---

## 3. Resume (Ripresa da arresto)

Se il server si riavvia o lo script si interrompe, usa `--start -1` per riprendere dall'ultimo indice salvato.

### VM1 (10.79.6.132)
```bash
ssh tecnico@10.79.6.132
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start -1 --end 6689 > check_output.log 2>&1 &
```

### VM2 (10.79.6.133)
```bash
ssh tecnico@10.79.6.133
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start -1 --end 13378 > check_output.log 2>&1 &
```

### VM3 (10.79.6.134)
```bash
ssh tecnico@10.79.6.134
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start -1 --end 20067 > check_output.log 2>&1 &
```

### VM4 (10.79.6.136)
```bash
ssh tecnico@10.79.6.136
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start -1 --end 26756 > check_output.log 2>&1 &
```

### VM5 (10.79.6.137)
```bash
ssh tecnico@10.79.6.137
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start -1 --end 33445 > check_output.log 2>&1 &
```

### VM6 (10.79.6.138)
```bash
ssh tecnico@10.79.6.138
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start -1 --end 40134 > check_output.log 2>&1 &
```

### VM7 (10.79.6.139)
```bash
ssh tecnico@10.79.6.139
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start -1 --end 46823 > check_output.log 2>&1 &
```

### VM8 (10.79.6.141)
```bash
ssh tecnico@10.79.6.141
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start -1 --end 53512 > check_output.log 2>&1 &
```

### VM9 (10.79.6.142)
```bash
ssh tecnico@10.79.6.142
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python -u tool_mcp_check/run_check.py --start -1 --end 60205 > check_output.log 2>&1 &
```

---

## 4. Monitoraggio dello Stato (Real-time)

**Sulla VM:**
Puoi visualizzare le statistiche (`remaining` andrà a scalare) e controllare i file live:
```bash
tail -f ~/Desktop/Pipeline/check_output.log
watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_check/mcp_check_stats.json | python3 -m json.tool'

# Esempi per controllare i json separati per suite e categoria:
# Handshake Esempio:
cat ~/Desktop/Pipeline/tool_mcp_check/handshake/timeout/details.json
# Tool Invocation Esempio:
cat ~/Desktop/Pipeline/tool_mcp_check/tool_invocation/schema_violation/Tool_accepted_invalid_input_without_error.json

# Controllare se il processo è vivo
ps aux | grep run_check.py | grep -v grep
```

**Dal tuo PC Locale:**
```bash
python deploy.py --status-check
python deploy.py --tail-check
```

---

## 5. Download e Merge Risultati in `analysisAllData`

Quando vuoi recuperare e aggregare tutti i file JSON organizzati gerarchicamente da tutte le VM, puoi usare i comandi di `deploy.py`:

```bash
# Scarica i risultati (crea tar remoto, scarica ed estrae)
python deploy.py --pull-check

# Aggrega i risultati in analysisAllData/0_tool_mcp_check
python deploy.py --merge-check
```

I risultati appariranno in `analysisAllData/0_tool_mcp_check/` suddivisi per suite:
- `mcp_check_stats.json`
- `mcp_check_servers.json`
- `handshake/...`
- `tool_discovery/...`
- `tool_invocation/...`
