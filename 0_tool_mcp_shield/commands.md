# Deploy e Gestione MCP Shield su 9 VM

Questo documento contiene i comandi necessari per gestire `mcp-shield` sulle 9 virtual machine e per visualizzare ed estrapolare i JSON suddivisi per categoria e severity/risk LLM (LOW, MEDIUM, HIGH). Ogni VM processa uno shard di ~6689 server.

---

## 1. Deploy del Codice su Tutte le VM

Puoi inviare tutto il codice Shield via deploy:

```bash
python deploy.py --deploy-shield-all
```

---

## 2. Lancio Scan (Avvio da Zero)

Ecco i comandi completi da copiare e incollare per ogni VM. Questi comandi resetteranno i database per quella VM, cloneranno le repository e applicheranno la shield.

### VM1 (10.79.6.132)
```bash
ssh tecnico@10.79.6.132
pkill -f 'python.*run_shield.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start 0 --end 6689 --reset > shield_output.log 2>&1 &
```

### VM2 (10.79.6.133)
```bash
ssh tecnico@10.79.6.133
pkill -f 'python.*run_shield.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start 6689 --end 13378 --reset > shield_output.log 2>&1 &
```

### VM3 (10.79.6.134)
```bash
ssh tecnico@10.79.6.134
pkill -f 'python.*run_shield.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start 13378 --end 20067 --reset > shield_output.log 2>&1 &
```

### VM4 (10.79.6.136)
```bash
ssh tecnico@10.79.6.136
pkill -f 'python.*run_shield.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start 20067 --end 26756 --reset > shield_output.log 2>&1 &
```

### VM5 (10.79.6.137)
```bash
ssh tecnico@10.79.6.137
pkill -f 'python.*run_shield.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start 26756 --end 33445 --reset > shield_output.log 2>&1 &
```

### VM6 (10.79.6.138)
```bash
ssh tecnico@10.79.6.138
pkill -f 'python.*run_shield.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start 33445 --end 40134 --reset > shield_output.log 2>&1 &
```

### VM7 (10.79.6.139)
```bash
ssh tecnico@10.79.6.139
pkill -f 'python.*run_shield.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start 40134 --end 46823 --reset > shield_output.log 2>&1 &
```

### VM8 (10.79.6.141)
```bash
ssh tecnico@10.79.6.141
pkill -f 'python.*run_shield.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start 46823 --end 53512 --reset > shield_output.log 2>&1 &
```

### VM9 (10.79.6.142)
```bash
ssh tecnico@10.79.6.142
pkill -f 'python.*run_shield.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start 53512 --end 60205 --reset > shield_output.log 2>&1 &
```

---

## 3. Resume (Ripresa da arresto)

Se il server si riavvia o lo script si interrompe, usa `--start -1` per riprendere dall'ultimo indice salvato.

### VM1 (10.79.6.132)
```bash
ssh tecnico@10.79.6.132
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start -1 --end 6689 > shield_output.log 2>&1 &
```

### VM2 (10.79.6.133)
```bash
ssh tecnico@10.79.6.133
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start -1 --end 13378 > shield_output.log 2>&1 &
```

### VM3 (10.79.6.134)
```bash
ssh tecnico@10.79.6.134
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start -1 --end 20067 > shield_output.log 2>&1 &
```

### VM4 (10.79.6.136)
```bash
ssh tecnico@10.79.6.136
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start -1 --end 26756 > shield_output.log 2>&1 &
```

### VM5 (10.79.6.137)
```bash
ssh tecnico@10.79.6.137
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start -1 --end 33445 > shield_output.log 2>&1 &
```

### VM6 (10.79.6.138)
```bash
ssh tecnico@10.79.6.138
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start -1 --end 40134 > shield_output.log 2>&1 &
```

### VM7 (10.79.6.139)
```bash
ssh tecnico@10.79.6.139
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start -1 --end 46823 > shield_output.log 2>&1 &
```

### VM8 (10.79.6.141)
```bash
ssh tecnico@10.79.6.141
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start -1 --end 53512 > shield_output.log 2>&1 &
```

### VM9 (10.79.6.142)
```bash
ssh tecnico@10.79.6.142
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_shield/run_shield.py --start -1 --end 60205 > shield_output.log 2>&1 &
```

---

## 4. Monitoraggio dello Stato (Real-time)

**Sulla VM:**
```bash
# Log live
tail -f ~/Desktop/Pipeline/shield_output.log

# Stats in continuo aggiornamento
watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_shield/mcp_shield_stats.json | python3 -m json.tool'

# Esempio per controllare gli score LLM salvati per Sensitive File Access in "HIGH" risk:
cat ~/Desktop/Pipeline/tool_mcp_shield/sensitive-file-access/sensitive_file_access_HIGH.json | python3 -m json.tool

# Controllare se il processo è vivo
ps aux | grep run_shield.py | grep -v grep
```

**Dal tuo PC Locale:**
```bash
python deploy.py --status-shield
python deploy.py --tail-shield
```

---

## 5. Download e Merge Risultati

A scansione finita o se vuoi recuperare i risultati parziali splittati per root cause e score:

```bash
# Scarica (via SCP) da tutte e 9 le VM ed esegue il deep-merge in un solo comando:
python deploy.py --pull-shield --merge-shield
```

Tutti i risultati saranno localizzati sotto `analysisAllData/0_tool_mcp_shield/` che conterrà sia le global stats che tutte le cartelle (`sensitive-file-access`, etc.) con all'interno i finding con gli score aggregati.
