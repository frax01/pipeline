from functions.helper import save_summary, force_delete, update_global, load_summary, reset_file, extract_server_name, update_recap_server, detect_language
from functions.recapFramework import update_recap_framework, reset_all_recap_frameworks
from frameworks.mcpGuard import execute_mcp_guard
from frameworks.mcpWatch import execute_mcp_watch
from frameworks.mcpScan import execute_mcp_scan
from frameworks.mcpShield import execute_mcp_shield
from frameworks.mcpSecurityScan import execute_mcp_security_scan
from frameworks.mcpCheck import execute_mcp_check
from frameworks.llmAnalysis import run_llm_analysis
from frameworks.NewProxy.proxyAnalysis import run_llm_proxy_analysis
from frameworks.scanorama import execute_scanorama
from frameworks.mcpValidator import execute_mcp_validator
from frameworks.fuzzing import update_fuzzing_summary, execute_mcp_fuzzing
from functions.buildConfig import build_mcp_config, clone_repo
from functions.stats import update_framework, update_summary_llm_risk
from data.a0setup import generate_all_tables
from functions.config import EXCEL_PATH, FRAMEWORKS, RECAP_SERVER, TABLE_DIR, VALID_SERVER_PATH, init, recap_server
import pandas as pd
import time
from pathlib import Path

def main():
    #start_idx = load_summary(FRAMEWORKS)["last_index"] + 1
    start_idx = 0
    if start_idx == 0:
        reset_file(init, FRAMEWORKS)
        reset_file(recap_server, RECAP_SERVER)
        reset_all_recap_frameworks()
        pd.DataFrame(columns=["Link", "Nome"]).to_excel(VALID_SERVER_PATH, index=False)
    print("START:", start_idx)
    df_excel = pd.read_excel(EXCEL_PATH)
    for idx, row in df_excel.iloc[start_idx:15].iterrows():
        start_time = time.time()
        status_hash = "unique"
        status_guard = "failed"
        status_watch = "failed"
        status_fuzzing = "failed"
        status_scan = "failed"
        status_shield = "failed"
        status_security_scan = "failed"
        status_llm_analysis = "failed"
        status_llm_proxy = "failed"
        status_mcp_check = "failed"
        status_scanorama = "failed"
        status_mcp_validator = "failed"
        server_url = row["Link"]

        server_name = extract_server_name(server_url)
        print("###################")
        print("Index:", idx)
        print("server_name:", server_name)
        print("server_url:", server_url)

        repo_path = clone_repo(server_url, Path.cwd())
        server_language = detect_language(repo_path)
        print("server_language:", server_language)
        server_name, command, elem = build_mcp_config(repo_path, server_language)
        if command is None:
            command = "unknown"
        if elem is None:
            elem = ["unknown"]

        #print("\n=== MCP GUARD ===") ###MCP-GUARD
        #result_mcp_guard = execute_mcp_guard(server_url, repo_path, command, elem[0])
        #status_guard = result_mcp_guard.get("mcp-guard", {}).get("status")
        #print("status_guard:", status_guard)
        #update_recap_framework("mcp-guard", server_url, server_language, status_guard)
#
        summary = update_global(load_summary(FRAMEWORKS), server_language, idx)
        #summary["hash"]["total"] += 1
        #summary["hash"]["unique"] += 1
#
        #if status_guard == "completed":
        #    update_framework(summary, result_mcp_guard["mcp-guard"], "mcp-guard", server_language)
        #else:
        #    summary["mcp-guard"]["percentage"] = summary["mcp-guard"]["total"] / summary["total"] * 100
#
        #print("\n=== MCP WATCH ===") ###MCP-WATCH
        #result_mcp_watch = execute_mcp_watch(server_url, server_language)
        #status_watch = result_mcp_watch.get("mcp-watch", {}).get("status")
        #print("status_watch:", status_watch)
        #update_recap_framework("mcp-watch", server_url, server_language, status_watch)
        #if status_watch == "completed":
        #    update_framework(summary, result_mcp_watch["mcp-watch"], "mcp-watch", server_language)
        #else:
        #    summary["mcp-watch"]["percentage"] = summary["mcp-watch"]["total"] / summary["total"] * 100

        #print("\n=== FUZZING ===") ###FUZZING
        #result_mcp_fuzzing = execute_mcp_fuzzing(repo_path, command, elem[0])
        #status_fuzzing = result_mcp_fuzzing.get("mcp-fuzzing", {}).get("status")
        #print("status_fuzzing:", status_fuzzing)
        #update_recap_framework("fuzzing", server_url, server_language, status_fuzzing)
        #if status_fuzzing == "completed":
        #    update_fuzzing_summary(summary, result_mcp_fuzzing, server_language)
        #else:
        #    summary["fuzzing"]["percentage"] = summary["fuzzing"]["total_servers"] / summary["total"] * 100

        print("\n=== MCP SCAN ===") ###MCP-SCAN
        result_mcp_scan, status_scan = execute_mcp_scan(repo_path)
        print("status_scan:", status_scan)
        update_recap_framework("mcp-scan", server_url, server_language, status_scan)
        if status_scan == "completed":
            update_framework(summary, result_mcp_scan["mcp-scan"], "mcp-scan", server_language)
        else:
            summary["mcp-scan"]["percentage"] = summary["mcp-scan"]["total"] / summary["total"] * 100

        #print("\n=== MCP SHIELD ===") ###MCP-SHIELD
        #result_mcp_shield, status_shield = execute_mcp_shield(repo_path)
        #print("status_shield:", status_shield)
        #update_recap_framework("mcp-shield", server_url, server_language, status_shield)
        #if status_shield == "completed":
        #    update_framework(summary, result_mcp_shield["mcp-shield"], "mcp-shield", server_language)
#
        #    print("\n=== LLM ANALYSIS ===") ###LLM-ANALYSIS
        #    llm = run_llm_analysis(result_mcp_shield["mcp-shield"], repo_path, command, elem)
        #    status_llm_analysis = llm.get("status")
        #    print("status:", llm.get("status"))
        #    update_recap_framework("llm-analysis", server_url, server_language, status_llm_analysis)
        #    update_summary_llm_risk(summary, llm, "static", 0, "", 0)
        #else:
        #    summary["mcp-shield"]["percentage"] = summary["mcp-shield"]["total"] / summary["total"] * 100
#
        #print("\n=== MCP SECURITY SCAN ===") ###MCP-SECURITY-SCAN
        #result_security_scan, status_security_scan = execute_mcp_security_scan(repo_path, command, elem[0])
        #print("status_security_scan:", status_security_scan)
        #update_recap_framework("mcp-security-scan", server_url, server_language, status_security_scan)
        #if status_security_scan == "completed":
        #    update_framework(summary, result_security_scan["mcp-security-scan"], "mcp-security-scan", server_language)
        #else:
        #    summary["mcp-security-scan"]["percentage"] = summary["mcp-security-scan"]["total"] / summary["total"] * 100
#
        #print("\n=== MCP CHECK ===") ###MCP-CHECK
        #result_mcp_check, status_mcp_check = execute_mcp_check(repo_path, command, elem)
        #print("status_mcp_check:", status_mcp_check)
        #update_recap_framework("mcp-check", server_url, server_language, status_mcp_check)
        #if status_mcp_check == "completed":
        #    update_framework(summary, result_mcp_check["mcp-check"], "mcp-check", server_language)
        #else:
        #    summary["mcp-check"]["percentage"] = summary["mcp-check"]["total"] / summary["total"] * 100
#
        #print("\n=== SCANORAMA ===") ###SCANORAMA
        #result_scanorama = execute_scanorama(repo_path)
        #status_scanorama = result_scanorama.get("status")
        #print("status_scanorama:", status_scanorama)
        #update_recap_framework("scanorama", server_url, server_language, status_scanorama)
        #if status_scanorama == "completed":
        #    update_framework(summary, result_scanorama, "scanorama", server_language)
        #else:
        #    summary["scanorama"]["percentage"] = summary["scanorama"]["total"] / summary["total"] * 100
#
        #print("\n=== MCP VALIDATOR ===") ###MCP-VALIDATOR
        #result_mcp_validator = execute_mcp_validator(repo_path, command, elem[0])
        #status_mcp_validator = result_mcp_validator.get("mcp-validator", {}).get("status")
        #print("status_mcp_validator:", status_mcp_validator)
        #update_recap_framework("mcp-validator", server_url, server_language, status_mcp_validator)
        #if status_mcp_validator == "completed":
        #    update_framework(summary, result_mcp_validator["mcp-validator"], "mcp-validator", server_language)
        #else:
        #    summary["mcp-validator"]["percentage"] = summary["mcp-validator"]["total"] / summary["total"] * 100

        #if status_scan=="completed" or status_shield == "completed":
        #    print("\n=== LLM PROXY ===") ###LLM-PROXY
        #    llm_proxy = run_llm_proxy_analysis(repo_path, command, elem)
        #    status_llm_proxy = llm_proxy.get("status")
        #    print("status:", llm_proxy.get("status"))
        #    total = summary.get("total", 0)
        #    if status_llm_proxy == "completed":
        #        print("num:", num)
        #        update_summary_llm_risk(summary, llm_proxy, "proxy", total, server_language, llm_proxy["tool_length"])

        #if status_guard == "completed" and status_watch == "completed" and (status_scan == "completed" or status_shield == "completed") and status_llm_analysis == "completed": # status_fuzzing=="completed" and status_llm_proxy == "completed":
        #    summary["completely-analyzed-servers"]["total"] += 1
        #    total_servers = summary.get("total", 0)
        #    summary["completely-analyzed-servers"]["percentage"] = round(
        #        (summary["completely-analyzed-servers"]["total"] / total_servers) * 100.0, 2
        #    )
        #    summary["completely-analyzed-servers"]["languages"][server_language] = summary["completely-analyzed-servers"]["languages"].get(server_language, 0) + 1
#
        #save_summary(FRAMEWORKS, summary)
#
        #update_recap_server(
        #    recap_server=load_summary(RECAP_SERVER),
        #    server_name=server_name,
        #    repo_url=server_url,
        #    language=server_language,
        #    hash_status=status_hash,
        #    mcp_guard_status=status_guard,
        #    mcp_watch_status=status_watch,
        #    fuzzing_status=status_fuzzing,
        #    mcp_scan_status=status_scan,
        #    mcp_shield_status=status_shield,
        #    mcp_security_scan_status=status_security_scan,
        #    mcp_check_status=status_mcp_check,
        #    llm_analysis_status=status_llm_analysis,
        #    llm_proxy_status="status_llm_proxy",
        #    scanorama_status=status_scanorama,
        #    mcp_validator_status=status_mcp_validator,
        #    path=RECAP_SERVER
        #)
#
        #generate_all_tables(load_summary(FRAMEWORKS), TABLE_DIR)
#
        #if repo_path.exists() and repo_path.is_dir():
        #    force_delete(repo_path)
        #    print("Cartella eliminata")
#
        #analysis_success = any([
        #    status_guard == "completed",
        #    status_watch == "completed",
        #    status_fuzzing == "completed",
        #    status_scan == "completed",
        #    status_shield == "completed",
        #    status_security_scan == "completed",
        #    status_mcp_check == "completed",
        #    status_llm_analysis == "completed",
        #    status_llm_proxy == "completed",
        #    status_scanorama == "completed",
        #    status_mcp_validator == "completed"
        #])
#
        #if analysis_success:
        #    if VALID_SERVER_PATH.exists():
        #        df_results = pd.read_excel(VALID_SERVER_PATH)
        #    else:
        #        df_results = pd.DataFrame(columns=["Link", "Nome"])
#
        #    if server_url not in df_results["Link"].values:
        #        new_row = pd.DataFrame([{"Link": server_url, "Nome": server_name}])
        #        df_results = pd.concat([df_results, new_row], ignore_index=True)
        #        df_results.to_excel(VALID_SERVER_PATH, index=False)
        #        print(f"{server_name} salvato")

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Total time: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()


# MCP CHECK (cd mcp check)
# node ./bin/mcp-check.js test --config "C:\\Users\\francesco\\Desktop\\Pipeline\\docker-mcp-server\\test-config.json"

# SCANORAMA (cd scanorama)
# node dist/index.js --path "C:\Users\francesco\Desktop\github-mcp-server" --provider ollama --model qwen3-coder:480b-cloud --output report.json

# open ~/Library/Application\ Support/Claude

# "localServer": {
#   "command": "python",
#   "args": [
#     "C:\\Users\\francesco\\Desktop\\localServer\\serverLocal.py"
#   ]
# }

# 1. Installa venv e dipendenze di sistema
#sudo apt install python3.12-venv python3-pandas python3-openpyxl -y
#
# 2. Crea symlink per BASE_DIR
#mkdir -p ~/Desktop
#ln -s ~/PipelineZip ~/Desktop/Pipeline
#
# 3. Crea cartella analysis
#mkdir -p ~/PipelineZip/analysis
#
# 4. Crea il file config vuoto
#echo '{}' > ~/Desktop/Pipeline/claude_desktop_config.json
#
# 5. Crea venv e installa dipendenze Python
#cd ~/PipelineZip
#python3 -m venv venv
#source venv/bin/activate
#pip install pandas openpyxl matplotlib
#
# 6. Lancia lo script
#python mainParallel.py -f mcp-guard

#PER VEDERE I RISULTATI:
## VM 1 - mcp-guard (10.79.6.132)
#ssh tecnico@10.79.6.132 "cat ~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_stats.json"
#ssh tecnico@10.79.6.132 "cat ~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_servers.json"
#
## VM 2 - mcp-watch (10.79.6.133)
#ssh tecnico@10.79.6.133 "cat ~/Desktop/Pipeline/tool_mcp_watch/mcp_watch_stats.json"
#ssh tecnico@10.79.6.133 "cat ~/Desktop/Pipeline/tool_mcp_watch/mcp_watch_servers.json"
#
## VM 3 - fuzzing (10.79.6.134)
#ssh tecnico@10.79.6.134 "cat ~/Desktop/Pipeline/tool_fuzzing/fuzzing_stats.json"
#ssh tecnico@10.79.6.134 "cat ~/Desktop/Pipeline/tool_fuzzing/fuzzing_servers.json"
#
## VM 4 - mcp-scan (10.79.6.136)
#ssh tecnico@10.79.6.136 "cat ~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_stats.json"
#ssh tecnico@10.79.6.136 "cat ~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_servers.json"
#
## VM 5 - mcp-shield (10.79.6.137)
#ssh tecnico@10.79.6.137 "cat ~/Desktop/Pipeline/tool_mcp_shield/mcp_shield_stats.json"
#ssh tecnico@10.79.6.137 "cat ~/Desktop/Pipeline/tool_mcp_shield/mcp_shield_servers.json"
#
## VM 6 - mcp-security-scan (10.79.6.138)
#ssh tecnico@10.79.6.138 "cat ~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_stats.json"
#ssh tecnico@10.79.6.138 "cat ~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_servers.json"
#
## VM 7 - mcp-check (10.79.6.139)
#ssh tecnico@10.79.6.139 "cat ~/Desktop/Pipeline/tool_mcp_check/mcp_check_stats.json"
#ssh tecnico@10.79.6.139 "cat ~/Desktop/Pipeline/tool_mcp_check/mcp_check_servers.json"
#
## VM 8 - scanorama (10.79.6.141)
#ssh tecnico@10.79.6.141 "cat ~/Desktop/Pipeline/tool_scanorama/scanorama_stats.json"
#ssh tecnico@10.79.6.141 "cat ~/Desktop/Pipeline/tool_scanorama/scanorama_servers.json"
#
## VM 9 - mcp-validator (10.79.6.142)
#ssh tecnico@10.79.6.142 "cat ~/Desktop/Pipeline/tool_mcp_validator/mcp_validator_stats.json"
#ssh tecnico@10.79.6.142 "cat ~/Desktop/Pipeline/tool_mcp_validator/mcp_validator_servers.json"

# ALTRI COMANDI:
# ssh tecnico@10.79.6.132   # VM 1 - mcp-guard
# ssh tecnico@10.79.6.133   # VM 2 - mcp-watch
# ssh tecnico@10.79.6.134   # VM 3 - fuzzing
# ssh tecnico@10.79.6.136   # VM 4 - mcp-scan
# ssh tecnico@10.79.6.137   # VM 5 - mcp-shield
# ssh tecnico@10.79.6.138   # VM 6 - mcp-security-scan
# ssh tecnico@10.79.6.139   # VM 7 - mcp-check
# ssh tecnico@10.79.6.141   # VM 8 - scanorama
# ssh tecnico@10.79.6.142   # VM 9 - mcp-validator

# setup (da fare ogni volta su ogni singola vm)
# sudo apt update && sudo apt install -y git python3-venv python3-full golang-go
# curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
# sudo apt install -y nodejs
# python3 -m venv ~/pipeline-env
# source ~/pipeline-env/bin/activate
# pip install uv pandas openpyxl requests gitpython mcp-fuzzer mcp-security-scanner
# cd ~/Desktop/Frameworks/mcp-server-fuzzer && pip install -e .
# cd ~/Desktop/Frameworks/mcp-security-scanner && pip install -e .
# cd ~/Desktop/Frameworks/mcp-guard && pip install -e .

# setup npm (solo una volta)
## Solo VM 2 (10.79.6.133)
#cd ~/Desktop/Frameworks/mcp-watch && npm install
## Solo VM 7 (10.79.6.139)
#cd ~/Desktop/Frameworks/mcp-check && npm install
## Solo VM 8 (10.79.6.141)
#cd ~/Desktop/Frameworks/scanorama && npm install && npm run build

# Copiare file dal pc alle vm
# Pipeline + framework (prima volta)
# foreach ($ip in @("10.79.6.132","10.79.6.133","10.79.6.134","10.79.6.136","10.79.6.137","10.79.6.138","10.79.6.139","10.79.6.141","10.79.6.142")) { ssh tecnico@$ip "mkdir -p ~/Desktop"; scp Pipeline.tar.gz Frameworks.tar.gz "tecnico@${ip}:~/Desktop/" }

# Aggiornare solo un file su tutte le vm
# foreach ($ip in @("10.79.6.132","10.79.6.133","10.79.6.134","10.79.6.136","10.79.6.137","10.79.6.138","10.79.6.139","10.79.6.141","10.79.6.142")) { scp "C:\Users\francesco\Desktop\Pipeline\functions\buildConfig.py" "tecnico@${ip}:~/Desktop/Pipeline/functions/buildConfig.py"; scp "C:\Users\francesco\Desktop\Pipeline\functions\config.py" "tecnico@${ip}:~/Desktop/Pipeline/functions/config.py"; scp "C:\Users\francesco\Desktop\Pipeline\frameworks\scanorama.py" "tecnico@${ip}:~/Desktop/Pipeline/frameworks/scanorama.py" }

# aggiornare solo l'excel
# foreach ($ip in @("10.79.6.132","10.79.6.133","10.79.6.134","10.79.6.136","10.79.6.137","10.79.6.138","10.79.6.139","10.79.6.141","10.79.6.142")) { scp "C:\Users\francesco\Desktop\Pipeline\0.0. All servers without duplicates, .git, _, hash and ERRORE (60205).xlsx" "tecnico@${ip}:~/Desktop/Pipeline/" }

# lanciare l'analisi (in ogni vm)
# source ~/pipeline-env/bin/activate && cd ~/Desktop/Pipeline

# e poi per analisi da zero:
## VM 1
#nohup python tool_mcp_guard/run_guard.py --start 0 > guard_output.log 2>&1 &
## VM 2
#nohup python tool_mcp_watch/run_watch.py --start 0 > watch_output.log 2>&1 &
## VM 3
#nohup python tool_fuzzing/run_fuzzing.py --start 0 > fuzzing_output.log 2>&1 &
## VM 4
#nohup python tool_mcp_scan/run_scan.py --start 0 > scan_output.log 2>&1 &
## VM 5
#nohup python tool_mcp_shield/run_shield.py --start 0 > shield_output.log 2>&1 &
## VM 6
#nohup python tool_mcp_security_scan/run_security_scan.py --start 0 > security_scan_output.log 2>&1 &
## VM 7
#nohup python tool_mcp_check/run_check.py --start 0 > check_output.log 2>&1 &
## VM 8
#nohup python tool_scanorama/run_scanorama.py --start 0 > scanorama_output.log 2>&1 &
## VM 9
#nohup python tool_mcp_validator/run_validator.py --start 0 > validator_output.log 2>&1 &

# per riprendere l'analisi:
## VM 1
#nohup python tool_mcp_guard/run_guard.py --start -1 > guard_output.log 2>&1 &
## VM 2
#nohup python tool_mcp_watch/run_watch.py --start -1 > watch_output.log 2>&1 &
## VM 3
#nohup python tool_fuzzing/run_fuzzing.py --start -1 > fuzzing_output.log 2>&1 &
## VM 4
#nohup python tool_mcp_scan/run_scan.py --start -1 > scan_output.log 2>&1 &
## VM 5
#nohup python tool_mcp_shield/run_shield.py --start -1 > shield_output.log 2>&1 &
## VM 6
#nohup python tool_mcp_security_scan/run_security_scan.py --start -1 > security_scan_output.log 2>&1 &
## VM 7
#nohup python tool_mcp_check/run_check.py --start -1 > check_output.log 2>&1 &
## VM 8
#nohup python tool_scanorama/run_scanorama.py --start -1 > scanorama_output.log 2>&1 &
## VM 9
#nohup python tool_mcp_validator/run_validator.py --start -1 > validator_output.log 2>&1 &

# Vedere output in tempo reale (Ctrl+C per uscire)
# tail -f ~/Desktop/Pipeline/guard_output.log          # VM 1
# tail -f ~/Desktop/Pipeline/watch_output.log          # VM 2
# tail -f ~/Desktop/Pipeline/fuzzing_output.log        # VM 3
# tail -f ~/Desktop/Pipeline/scan_output.log           # VM 4
# tail -f ~/Desktop/Pipeline/shield_output.log         # VM 5
# tail -f ~/Desktop/Pipeline/security_scan_output.log  # VM 6
# tail -f ~/Desktop/Pipeline/check_output.log          # VM 7
# tail -f ~/Desktop/Pipeline/scanorama_output.log      # VM 8
# tail -f ~/Desktop/Pipeline/validator_output.log      # VM 9
# 
# # Verificare se il processo è ancora attivo
# ps aux | grep run_guard           # VM 1
# ps aux | grep run_watch           # VM 2
# ps aux | grep run_fuzzing         # VM 3
# ps aux | grep run_scan            # VM 4
# ps aux | grep run_shield          # VM 5
# ps aux | grep run_security_scan   # VM 6
# ps aux | grep run_check           # VM 7
# ps aux | grep run_scanorama       # VM 8
# ps aux | grep run_validator       # VM 9
# 
# # Vedere i JSON dei risultati
# cat ~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_stats.json            # VM 1
# cat ~/Desktop/Pipeline/tool_mcp_watch/mcp_watch_stats.json            # VM 2
# cat ~/Desktop/Pipeline/tool_fuzzing/fuzzing_stats.json                # VM 3
# cat ~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_stats.json              # VM 4
# cat ~/Desktop/Pipeline/tool_mcp_shield/mcp_shield_stats.json          # VM 5
# cat ~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_stats.json  # VM 6
# cat ~/Desktop/Pipeline/tool_mcp_check/mcp_check_stats.json            # VM 7
# cat ~/Desktop/Pipeline/tool_scanorama/scanorama_stats.json            # VM 8
# cat ~/Desktop/Pipeline/tool_mcp_validator/mcp_validator_stats.json    # VM 9
# 
# # Fermare il processo
# kill $(pgrep -f run_guard)           # VM 1
# kill $(pgrep -f run_watch)           # VM 2
# kill $(pgrep -f run_fuzzing)         # VM 3
# kill $(pgrep -f run_scan)            # VM 4
# kill $(pgrep -f run_shield)          # VM 5
# kill $(pgrep -f run_security_scan)   # VM 6
# kill $(pgrep -f run_check)           # VM 7
# kill $(pgrep -f run_scanorama)       # VM 8
# kill $(pgrep -f run_validator)       # VM 9

# monitorare da pc:
# Ultime 20 righe di output
# ssh tecnico@10.79.6.132 "tail -20 ~/Desktop/Pipeline/guard_output.log"
# ssh tecnico@10.79.6.133 "tail -20 ~/Desktop/Pipeline/watch_output.log"
# ssh tecnico@10.79.6.134 "tail -20 ~/Desktop/Pipeline/fuzzing_output.log"
# ssh tecnico@10.79.6.136 "tail -20 ~/Desktop/Pipeline/scan_output.log"
# ssh tecnico@10.79.6.137 "tail -20 ~/Desktop/Pipeline/shield_output.log"
# ssh tecnico@10.79.6.138 "tail -20 ~/Desktop/Pipeline/security_scan_output.log"
# ssh tecnico@10.79.6.139 "tail -20 ~/Desktop/Pipeline/check_output.log"
# ssh tecnico@10.79.6.141 "tail -20 ~/Desktop/Pipeline/scanorama_output.log"
# ssh tecnico@10.79.6.142 "tail -20 ~/Desktop/Pipeline/validator_output.log"
# 
# # Vedere JSON stats
# ssh tecnico@10.79.6.132 "cat ~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_stats.json"
# ssh tecnico@10.79.6.133 "cat ~/Desktop/Pipeline/tool_mcp_watch/mcp_watch_stats.json"
# ssh tecnico@10.79.6.134 "cat ~/Desktop/Pipeline/tool_fuzzing/fuzzing_stats.json"
# ssh tecnico@10.79.6.136 "cat ~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_stats.json"
# ssh tecnico@10.79.6.137 "cat ~/Desktop/Pipeline/tool_mcp_shield/mcp_shield_stats.json"
# ssh tecnico@10.79.6.138 "cat ~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_stats.json"
# ssh tecnico@10.79.6.139 "cat ~/Desktop/Pipeline/tool_mcp_check/mcp_check_stats.json"
# ssh tecnico@10.79.6.141 "cat ~/Desktop/Pipeline/tool_scanorama/scanorama_stats.json"
# ssh tecnico@10.79.6.142 "cat ~/Desktop/Pipeline/tool_mcp_validator/mcp_validator_stats.json"
# 
# # Vedere JSON server log
# ssh tecnico@10.79.6.132 "cat ~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_servers.json"
# ssh tecnico@10.79.6.133 "cat ~/Desktop/Pipeline/tool_mcp_watch/mcp_watch_servers.json"
# ssh tecnico@10.79.6.134 "cat ~/Desktop/Pipeline/tool_fuzzing/fuzzing_servers.json"
# ssh tecnico@10.79.6.136 "cat ~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_servers.json"
# ssh tecnico@10.79.6.137 "cat ~/Desktop/Pipeline/tool_mcp_shield/mcp_shield_servers.json"
# ssh tecnico@10.79.6.138 "cat ~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_servers.json"
# ssh tecnico@10.79.6.139 "cat ~/Desktop/Pipeline/tool_mcp_check/mcp_check_servers.json"
# ssh tecnico@10.79.6.141 "cat ~/Desktop/Pipeline/tool_scanorama/scanorama_servers.json"
# ssh tecnico@10.79.6.142 "cat ~/Desktop/Pipeline/tool_mcp_validator/mcp_validator_servers.json"

# scaricare i risultati da pc
# Tutti i stats JSON
# scp tecnico@10.79.6.132:~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_stats.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_guard\mcp_guard_stats.json"
# scp tecnico@10.79.6.133:~/Desktop/Pipeline/tool_mcp_watch/mcp_watch_stats.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_watch\mcp_watch_stats.json"
# scp tecnico@10.79.6.134:~/Desktop/Pipeline/tool_fuzzing/fuzzing_stats.json "C:\Users\francesco\Desktop\Pipeline\tool_fuzzing\fuzzing_stats.json"
# scp tecnico@10.79.6.136:~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_stats.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_scan\mcp_scan_stats.json"
# scp tecnico@10.79.6.137:~/Desktop/Pipeline/tool_mcp_shield/mcp_shield_stats.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_shield\mcp_shield_stats.json"
# scp tecnico@10.79.6.138:~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_stats.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_security_scan\mcp_security_scan_stats.json"
# scp tecnico@10.79.6.139:~/Desktop/Pipeline/tool_mcp_check/mcp_check_stats.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_check\mcp_check_stats.json"
# scp tecnico@10.79.6.141:~/Desktop/Pipeline/tool_scanorama/scanorama_stats.json "C:\Users\francesco\Desktop\Pipeline\tool_scanorama\scanorama_stats.json"
# scp tecnico@10.79.6.142:~/Desktop/Pipeline/tool_mcp_validator/mcp_validator_stats.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_validator\mcp_validator_stats.json"
# 
# # Tutti i servers JSON
# scp tecnico@10.79.6.132:~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_servers.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_guard\mcp_guard_servers.json"
# scp tecnico@10.79.6.133:~/Desktop/Pipeline/tool_mcp_watch/mcp_watch_servers.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_watch\mcp_watch_servers.json"
# scp tecnico@10.79.6.134:~/Desktop/Pipeline/tool_fuzzing/fuzzing_servers.json "C:\Users\francesco\Desktop\Pipeline\tool_fuzzing\fuzzing_servers.json"
# scp tecnico@10.79.6.136:~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_servers.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_scan\mcp_scan_servers.json"
# scp tecnico@10.79.6.137:~/Desktop/Pipeline/tool_mcp_shield/mcp_shield_servers.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_shield\mcp_shield_servers.json"
# scp tecnico@10.79.6.138:~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_servers.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_security_scan\mcp_security_scan_servers.json"
# scp tecnico@10.79.6.139:~/Desktop/Pipeline/tool_mcp_check/mcp_check_servers.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_check\mcp_check_servers.json"
# scp tecnico@10.79.6.141:~/Desktop/Pipeline/tool_scanorama/scanorama_servers.json "C:\Users\francesco\Desktop\Pipeline\tool_scanorama\scanorama_servers.json"
# scp tecnico@10.79.6.142:~/Desktop/Pipeline/tool_mcp_validator/mcp_validator_servers.json "C:\Users\francesco\Desktop\Pipeline\tool_mcp_validator\mcp_validator_servers.json"


# vm1 bene
# vm2 bene
# vm3 bene
# vm4 bene
# vm5 bene
# vm6 bene
# vm7 bene (forse da togliere)
# vm8 bene (forse da togliere)
# vm9 bene (forse da togliere)