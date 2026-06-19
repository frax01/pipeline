# MCP Watch - Comandi per 9 VM

## Deploy su tutte le VM
```bash
python deploy.py --deploy-watch-all
```

## Comandi di lancio (da eseguire su ogni VM)

# 1 - VM1 (10.79.6.132)
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start 0 --end 6689 --reset > watch_output.log 2>&1 &

# 2 - VM2 (10.79.6.133)
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start 6689 --end 13378 --reset > watch_output.log 2>&1 &

# 3 - VM3 (10.79.6.134)
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start 13378 --end 20067 --reset > watch_output.log 2>&1 &

# 4 - VM4 (10.79.6.136)
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start 20067 --end 26756 --reset > watch_output.log 2>&1 &

# 5 - VM5 (10.79.6.137)
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start 26756 --end 33445 --reset > watch_output.log 2>&1 &

# 6 - VM6 (10.79.6.138)
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start 33445 --end 40134 --reset > watch_output.log 2>&1 &

# 7 - VM7 (10.79.6.139)
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start 40134 --end 46823 --reset > watch_output.log 2>&1 &

# 8 - VM8 (10.79.6.141)
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start 46823 --end 53512 --reset > watch_output.log 2>&1 &

# 9 - VM9 (10.79.6.142)
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start 53512 --end 60205 --reset > watch_output.log 2>&1 &

## Monitoraggio

```bash
# watch stats (da dentro una VM)
watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_watch/mcp_watch_stats.json | python3 -m json.tool'

# tail log (da dentro una VM)
tail -f ~/Desktop/Pipeline/watch_output.log

# cat stats
cat ~/Desktop/Pipeline/tool_mcp_watch/mcp_watch_stats.json | python3 -m json.tool

# Controllare se il processo è vivo
ps aux | grep run_watch.py | grep -v grep
```

## Da questo PC (deploy.py)

```bash
# Stato di tutte le VM
python deploy.py --status-watch

# Log da tutte le VM
python deploy.py --tail-watch

# Scarica risultati da tutte le VM
python deploy.py --pull-watch

# Merge risultati
python deploy.py --merge-watch

# Pull + merge in un colpo
python deploy.py --pull-watch --merge-watch
```

## Resume (con -1)

# VM1
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start -1 --end 6689 > watch_output.log 2>&1 &

# VM2
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start -1 --end 13378 > watch_output.log 2>&1 &

# VM3
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start -1 --end 20067 > watch_output.log 2>&1 &

# VM4
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start -1 --end 26756 > watch_output.log 2>&1 &

# VM5
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start -1 --end 33445 > watch_output.log 2>&1 &

# VM6
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start -1 --end 40134 > watch_output.log 2>&1 &

# VM7
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start -1 --end 46823 > watch_output.log 2>&1 &

# VM8
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start -1 --end 53512 > watch_output.log 2>&1 &

# VM9
pkill -f 'python.*run_watch.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_watch/run_watch.py --start -1 --end 60205 > watch_output.log 2>&1 &

## Visualizzare i risultati per categoria (da dentro una VM)

```bash
# toxic-flow medium
cat ~/Desktop/Pipeline/tool_mcp_watch/toxic-flow/toxic_flow_medium.json | python3 -m json.tool | head -50

# toxic-flow critical
cat ~/Desktop/Pipeline/tool_mcp_watch/toxic-flow/toxic_flow_critical.json | python3 -m json.tool | head -50

# toxic-flow high
cat ~/Desktop/Pipeline/tool_mcp_watch/toxic-flow/toxic_flow_high.json | python3 -m json.tool | head -50

# credential-leak critical
cat ~/Desktop/Pipeline/tool_mcp_watch/credential-leak/credential_leak_critical.json | python3 -m json.tool

# credential-leak high
cat ~/Desktop/Pipeline/tool_mcp_watch/credential-leak/credential_leak_high.json | python3 -m json.tool

# prompt-injection critical
cat ~/Desktop/Pipeline/tool_mcp_watch/prompt-injection/prompt_injection_critical.json | python3 -m json.tool

# tool-poisoning critical
cat ~/Desktop/Pipeline/tool_mcp_watch/tool-poisoning/tool_poisoning_critical.json | python3 -m json.tool

# data-exfiltration critical
cat ~/Desktop/Pipeline/tool_mcp_watch/data-exfiltration/data_exfiltration_critical.json | python3 -m json.tool

# contare i findings per categoria/severity
for cat in toxic-flow credential-leak tool-poisoning prompt-injection tool-mutation data-exfiltration steganographic-attack protocol-violation input-validation server-spoofing access-control; do
  for sev in critical high medium low; do
    f=~/Desktop/Pipeline/tool_mcp_watch/$cat/${cat//-/_}_${sev}.json
    if [ -f "$f" ]; then
      total=$(python3 -c "import json; print(json.load(open('$f')).get('total',0))")
      [ "$total" != "0" ] && echo "$cat/$sev: $total"
    fi
  done
done
```

## Deploy framework (solo la prima volta, via tar.gz da Windows)

```powershell
# Dal PC Windows
tar -czf C:\tmp\mcp-watch.tar.gz -C C:\Users\<user>\Desktop\Frameworks mcp-watch
$ips = @("10.79.6.132","10.79.6.133","10.79.6.134","10.79.6.136","10.79.6.137","10.79.6.138","10.79.6.139","10.79.6.141","10.79.6.142")
foreach ($ip in $ips) { echo "--- $ip ---"; scp C:\tmp\mcp-watch.tar.gz tecnico@${ip}:/tmp/; ssh tecnico@$ip "mkdir -p ~/Desktop/Frameworks && cd ~/Desktop/Frameworks && tar xzf /tmp/mcp-watch.tar.gz && rm /tmp/mcp-watch.tar.gz && echo OK" }
```

## Fix numpy/pandas (se serve, su ogni VM)

```bash
pip install --upgrade numpy pandas
```
