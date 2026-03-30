# MCP Fuzzing - Comandi

## 1. Deploy su tutte le VM
```bash
# Da locale (Windows/PowerShell):
# Il deploy copia 0_tool_fuzzing/ come tool_fuzzing/ sulle VM
# TODO: aggiungere --deploy-fuzzing-all a deploy.py se necessario
# Per ora deploy manuale:
# scp -r 0_tool_fuzzing/* tecnico@10.79.6.XXX:~/Desktop/Pipeline/tool_fuzzing/
```

## 2. Lancio (primo avvio con --reset)
```bash
source ~/pipeline-env/bin/activate
cd ~/Desktop/Pipeline
nohup python tool_fuzzing/run_fuzzing.py --start 0 --end <SHARD_END> --reset > fuzzing_output.log 2>&1 &
```

### Comandi per VM:
| VM | IP | Comando |
|----|-----|---------|
| VM1 | 10.79.6.132 | `nohup python tool_fuzzing/run_fuzzing.py --start 0 --end 6689 --reset > fuzzing_output.log 2>&1 &` |
| VM2 | 10.79.6.133 | `nohup python tool_fuzzing/run_fuzzing.py --start 6689 --end 13378 --reset > fuzzing_output.log 2>&1 &` |
| VM3 | 10.79.6.134 | `nohup python tool_fuzzing/run_fuzzing.py --start 13378 --end 20067 --reset > fuzzing_output.log 2>&1 &` |
| VM4 | 10.79.6.136 | `nohup python tool_fuzzing/run_fuzzing.py --start 20067 --end 26756 --reset > fuzzing_output.log 2>&1 &` |
| VM5 | 10.79.6.137 | `nohup python tool_fuzzing/run_fuzzing.py --start 26756 --end 33445 --reset > fuzzing_output.log 2>&1 &` |
| VM6 | 10.79.6.138 | `nohup python tool_fuzzing/run_fuzzing.py --start 33445 --end 40134 --reset > fuzzing_output.log 2>&1 &` |
| VM7 | 10.79.6.139 | `nohup python tool_fuzzing/run_fuzzing.py --start 40134 --end 46823 --reset > fuzzing_output.log 2>&1 &` |
| VM8 | 10.79.6.141 | `nohup python tool_fuzzing/run_fuzzing.py --start 46823 --end 53512 --reset > fuzzing_output.log 2>&1 &` |
| VM9 | 10.79.6.142 | `nohup python tool_fuzzing/run_fuzzing.py --start 53512 --end 60205 --reset > fuzzing_output.log 2>&1 &` |

## 3. Resume (Ripresa da arresto)
```bash
source ~/pipeline-env/bin/activate
cd ~/Desktop/Pipeline
nohup python tool_fuzzing/run_fuzzing.py --start -1 --end <SHARD_END> > fuzzing_output.log 2>&1 &
```

### Comandi per VM:
| VM | IP | Comando |
|----|-----|---------|
| VM1 | 10.79.6.132 | `nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 6689 > fuzzing_output.log 2>&1 &` |
| VM2 | 10.79.6.133 | `nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 13378 > fuzzing_output.log 2>&1 &` |
| VM3 | 10.79.6.134 | `nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 20067 > fuzzing_output.log 2>&1 &` |
| VM4 | 10.79.6.136 | `nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 26756 > fuzzing_output.log 2>&1 &` |
| VM5 | 10.79.6.137 | `nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 33445 > fuzzing_output.log 2>&1 &` |
| VM6 | 10.79.6.138 | `nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 40134 > fuzzing_output.log 2>&1 &` |
| VM7 | 10.79.6.139 | `nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 46823 > fuzzing_output.log 2>&1 &` |
| VM8 | 10.79.6.141 | `nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 53512 > fuzzing_output.log 2>&1 &` |
| VM9 | 10.79.6.142 | `nohup python tool_fuzzing/run_fuzzing.py --start -1 --end 60205 > fuzzing_output.log 2>&1 &` |

## 4. Monitoraggio
```bash
# Log in tempo reale
tail -f ~/Desktop/Pipeline/fuzzing_output.log

# Stats
cat ~/Desktop/Pipeline/tool_fuzzing/fuzzing_stats.json | python3 -m json.tool

# Processi attivi
ps aux | grep run_fuzzing | grep -v grep
```

## 5. Pull e Merge (dal PC locale)
```bash
python deploy.py --pull-fuzzing
python deploy.py --merge-fuzzing
# oppure entrambi:
python deploy.py --pull-fuzzing --merge-fuzzing
```
