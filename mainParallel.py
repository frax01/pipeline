"""
mainParallel.py - Script per Esecuzione Distribuita su VM

Ogni framework viene eseguito indipendentemente su una VM diversa.
Dipendenze: llm-analysis dipende da mcp-shield (vengono eseguiti insieme).
"""

from enum import Enum
from functions.helper import (
    save_summary, force_delete, update_global, load_summary,
    reset_file, extract_server_name, update_recap_server, detect_language,
    merge_framework_summaries
)
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
from functions.config import EXCEL_PATH, RECAP_SERVER, BASE_DIR, TABLE_DIR, FRAMEWORK_PATHS, FRAMEWORK_INITS
import json
from functions.config import recap_server
import pandas as pd
import time
import argparse
from pathlib import Path


# Mapping da enum Framework alla chiave usata nei JSON
FRAMEWORK_KEY_MAP = {
    "mcp-guard": "mcp-guard",
    "mcp-watch": "mcp-watch",
    "fuzzing": "fuzzing",
    "mcp-scan": "mcp-scan",
    "mcp-shield": "mcp-shield",
    "mcp-security-scan": "mcp-security-scan",
    "mcp-check": "mcp-check",
    "scanorama": "scanorama",
    "mcp-validator": "mcp-validator",
    "llm-proxy": "proxy",
}


def get_framework_key(framework) -> str:
    """Restituisce la chiave JSON per un framework enum"""
    return FRAMEWORK_KEY_MAP[framework.value]


class Framework(Enum):
    """Framework disponibili per l'analisi"""
    MCP_GUARD = "mcp-guard"
    MCP_WATCH = "mcp-watch"
    FUZZING = "fuzzing"
    MCP_SCAN = "mcp-scan"
    MCP_SHIELD = "mcp-shield"  # Include automaticamente llm-analysis
    MCP_SECURITY_SCAN = "mcp-security-scan"
    MCP_CHECK = "mcp-check"
    SCANORAMA = "scanorama"
    MCP_VALIDATOR = "mcp-validator"
    LLM_PROXY = "llm-proxy"  # Richiede mcp-scan o mcp-shield completati


def get_framework_log_path(framework: Framework) -> Path:
    """Restituisce il path del file JSON di log per un framework"""
    return BASE_DIR / f"{framework.value}_servers.json"


def load_framework_log(framework: Framework) -> dict:
    """Carica il log dei server per un framework"""
    path = get_framework_log_path(framework)
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_framework_log(framework: Framework, log: dict) -> None:
    """Salva il log dei server per un framework"""
    path = get_framework_log_path(framework)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=4, ensure_ascii=False)


def update_framework_log(framework: Framework, server_url: str, status: str) -> None:
    """Aggiorna il log di un framework con un nuovo server"""
    log = load_framework_log(framework)
    log[server_url] = status
    save_framework_log(framework, log)


def prepare_server(server_url: str) -> dict:
    """
    Prepara il server per l'analisi: clone, build config.

    Returns:
        dict con i dati del server
    """
    server_name = extract_server_name(server_url)
    print(f"Server: {server_name}")
    print(f"URL: {server_url}")

    # Clone repo
    repo_path = clone_repo(server_url, Path.cwd())
    server_language = detect_language(repo_path)
    print(f"Language: {server_language}")

    # Build config
    server_name, command, elem = build_mcp_config(repo_path, server_language)
    if command is None:
        command = "unknown"
    if elem is None:
        elem = ["unknown"]

    return {
        "server_name": server_name,
        "server_url": server_url,
        "server_language": server_language,
        "repo_path": repo_path,
        "command": command,
        "elem": elem
    }


def run_single_framework(framework: Framework, server_data: dict) -> dict:
    """
    Esegue un singolo framework sul server.
    
    Returns:
        dict con status e risultati del framework
    """
    repo_path = server_data["repo_path"]
    server_url = server_data["server_url"]
    server_language = server_data["server_language"]
    command = server_data["command"]
    elem = server_data["elem"]
    
    result = {
        "framework": framework.value,
        "status": "failed",
        "data": None
    }
    
    try:
        if framework == Framework.MCP_GUARD:
            print("\n=== MCP GUARD ===")
            framework_result = execute_mcp_guard(server_url, repo_path, command, elem[0])
            status = framework_result.get("mcp-guard", {}).get("status")
            result["status"] = status
            result["data"] = framework_result
            
        elif framework == Framework.MCP_WATCH:
            print("\n=== MCP WATCH ===")
            framework_result = execute_mcp_watch(server_url, server_language)
            status = framework_result.get("mcp-watch", {}).get("status")
            result["status"] = status
            result["data"] = framework_result
            
        elif framework == Framework.FUZZING:
            print("\n=== FUZZING ===")
            framework_result = execute_mcp_fuzzing(repo_path, command, elem[0])
            status = framework_result.get("mcp-fuzzing", {}).get("status")
            result["status"] = status
            result["data"] = framework_result
            
        elif framework == Framework.MCP_SCAN:
            print("\n=== MCP SCAN ===")
            framework_result, status = execute_mcp_scan(repo_path)
            result["status"] = status
            result["data"] = framework_result
            
        elif framework == Framework.MCP_SHIELD:
            print("\n=== MCP SHIELD ===")
            framework_result, status = execute_mcp_shield(repo_path)
            result["status"] = status
            result["data"] = framework_result
            
            # LLM Analysis dipende da MCP Shield
            if status == "completed":
                print("\n=== LLM ANALYSIS (dipendenza da MCP Shield) ===")
                llm_result = run_llm_analysis(
                    framework_result["mcp-shield"], 
                    repo_path, 
                    command, 
                    elem
                )
                result["llm_analysis"] = {
                    "status": llm_result.get("status"),
                    "data": llm_result
                }
                
        elif framework == Framework.MCP_SECURITY_SCAN:
            print("\n=== MCP SECURITY SCAN ===")
            framework_result, status = execute_mcp_security_scan(repo_path, command, elem[0])
            result["status"] = status
            result["data"] = framework_result

        elif framework == Framework.MCP_CHECK:
            print("\n=== MCP CHECK ===")
            framework_result, status = execute_mcp_check(repo_path, command, elem)
            result["status"] = status
            result["data"] = framework_result

        elif framework == Framework.SCANORAMA:
            print("\n=== SCANORAMA ===")
            framework_result = execute_scanorama(repo_path)
            status = framework_result.get("status")
            result["status"] = status
            result["data"] = framework_result

        elif framework == Framework.MCP_VALIDATOR:
            print("\n=== MCP VALIDATOR ===")
            framework_result = execute_mcp_validator(repo_path, command, elem[0])
            status = framework_result.get("mcp-validator", {}).get("status")
            result["status"] = status
            result["data"] = framework_result

        elif framework == Framework.LLM_PROXY:
            print("\n=== LLM PROXY ===")
            llm_proxy_result = run_llm_proxy_analysis(repo_path, command, elem)
            status = llm_proxy_result.get("status")
            result["status"] = status
            result["data"] = llm_proxy_result
            
    except Exception as e:
        print(f"Errore durante l'esecuzione di {framework.value}: {e}")
        result["status"] = "error"
        result["error"] = str(e)
    
    print(f"Status {framework.value}: {result['status']}")
    return result


def update_summary_for_framework(
    framework: Framework, 
    result: dict, 
    server_language: str,
    summary: dict
) -> dict:
    """Aggiorna il summary per un singolo framework"""
    
    if result["status"] != "completed":
        return summary
    
    data = result.get("data", {})
    
    if framework == Framework.MCP_GUARD:
        update_framework(summary, data["mcp-guard"], "mcp-guard", server_language)
        
    elif framework == Framework.MCP_WATCH:
        update_framework(summary, data["mcp-watch"], "mcp-watch", server_language)
        
    elif framework == Framework.FUZZING:
        update_fuzzing_summary(summary, data, server_language)
        
    elif framework == Framework.MCP_SCAN:
        update_framework(summary, data["mcp-scan"], "mcp-scan", server_language)
        
    elif framework == Framework.MCP_SHIELD:
        update_framework(summary, data["mcp-shield"], "mcp-shield", server_language)
        # Aggiorna anche LLM analysis se presente
        if "llm_analysis" in result and result["llm_analysis"]["status"] == "completed":
            update_summary_llm_risk(
                summary, 
                result["llm_analysis"]["data"], 
                "static", 0, "", 0
            )
            
    elif framework == Framework.MCP_SECURITY_SCAN:
        update_framework(summary, data["mcp-security-scan"], "mcp-security-scan", server_language)

    elif framework == Framework.MCP_CHECK:
        update_framework(summary, data["mcp-check"], "mcp-check", server_language)

    elif framework == Framework.SCANORAMA:
        update_framework(summary, data, "scanorama", server_language)

    elif framework == Framework.MCP_VALIDATOR:
        update_framework(summary, data["mcp-validator"], "mcp-validator", server_language)

    elif framework == Framework.LLM_PROXY:
        tool_length = data.get("tool_length", 0)
        total_servers = summary.get("total", 1)
        update_summary_llm_risk(
            summary, data, "proxy",
            total_servers, server_language, tool_length
        )

    return summary


def mainParallel(framework: Framework, start_idx: int = 0, end_idx: int = None):
    """
    Entry point per esecuzione su una singola VM.
    
    Args:
        framework: Il framework da eseguire
        start_idx: Indice iniziale nel file Excel
        end_idx: Indice finale nel file Excel (default: tutti)
    """
    fw_key = get_framework_key(framework)
    fw_path = FRAMEWORK_PATHS[fw_key]
    fw_init = FRAMEWORK_INITS[fw_key]

    print(f"=== AVVIO VM per {framework.value} ===")
    print(f"Range server: {start_idx} - {end_idx if end_idx else 'fine'}")

    # Reset file se si inizia dall'inizio
    results_excel_path = "onlyValidServers.xlsx"
    start_idx = 0
    if start_idx == 0:
        reset_file(fw_init, fw_path)
        reset_file(recap_server, RECAP_SERVER)
        pd.DataFrame(columns=["Link", "Nome"]).to_excel(results_excel_path, index=False)
        print("File inizializzati")

    df_excel = pd.read_excel(EXCEL_PATH)

    if end_idx is None:
        end_idx = len(df_excel)

    for idx, row in df_excel.iloc[start_idx:end_idx].iterrows():
        start_time = time.time()
        server_url = row["Link"]

        print("\n" + "=" * 50)
        print(f"Index: {idx}")

        # Prepara il server
        server_data = prepare_server(server_url)

        # Esegui il framework
        result = run_single_framework(framework, server_data)

        # Aggiorna summary nel file specifico del framework
        summary = update_global(
            load_summary(fw_path),
            server_data["server_language"],
            idx
        )

        summary = update_summary_for_framework(
            framework,
            result,
            server_data["server_language"],
            summary
        )
        save_summary(fw_path, summary)

        # Aggiorna recap_server con lo status del framework eseguito
        # Tutti gli altri framework sono "not_run" poiché eseguiti su altre VM
        status_guard = result["status"] if framework == Framework.MCP_GUARD else "not_run"
        status_watch = result["status"] if framework == Framework.MCP_WATCH else "not_run"
        status_fuzzing = result["status"] if framework == Framework.FUZZING else "not_run"
        status_scan = result["status"] if framework == Framework.MCP_SCAN else "not_run"
        status_shield = result["status"] if framework == Framework.MCP_SHIELD else "not_run"
        status_security_scan = result["status"] if framework == Framework.MCP_SECURITY_SCAN else "not_run"
        status_mcp_check = result["status"] if framework == Framework.MCP_CHECK else "not_run"
        status_llm_analysis = result.get("llm_analysis", {}).get("status", "not_run") if framework == Framework.MCP_SHIELD else "not_run"
        status_llm_proxy = result["status"] if framework == Framework.LLM_PROXY else "not_run"
        status_scanorama = result["status"] if framework == Framework.SCANORAMA else "not_run"
        status_mcp_validator = result["status"] if framework == Framework.MCP_VALIDATOR else "not_run"

        update_recap_server(
            recap_server=load_summary(RECAP_SERVER),
            server_name=server_data["server_name"],
            repo_url=server_data["server_url"],
            language=server_data["server_language"],
            hash_status="unique",
            mcp_guard_status=status_guard,
            mcp_watch_status=status_watch,
            fuzzing_status=status_fuzzing,
            mcp_scan_status=status_scan,
            mcp_shield_status=status_shield,
            mcp_security_scan_status=status_security_scan,
            mcp_check_status=status_mcp_check,
            llm_analysis_status=status_llm_analysis,
            llm_proxy_status=status_llm_proxy,
            scanorama_status=status_scanorama,
            mcp_validator_status=status_mcp_validator,
            path=RECAP_SERVER
        )

        # Aggiorna il log del framework (url -> status)
        update_framework_log(framework, server_data["server_url"], result["status"])

        # Genera le tabelle aggiornate (merge di tutti i file framework)
        merged_summary = merge_framework_summaries(FRAMEWORK_PATHS)
        generate_all_tables(merged_summary, TABLE_DIR)

        # Aggiorna onlyValidServers.xlsx se l'analisi è andata a buon fine
        if result["status"] == "completed":
            if Path(results_excel_path).exists():
                df_results = pd.read_excel(results_excel_path)
            else:
                df_results = pd.DataFrame(columns=["Link", "Nome"])

            if server_data["server_url"] not in df_results["Link"].values:
                new_row = pd.DataFrame([{
                    "Link": server_data["server_url"],
                    "Nome": server_data["server_name"]
                }])
                df_results = pd.concat([df_results, new_row], ignore_index=True)
                df_results.to_excel(results_excel_path, index=False)
                print(f"{server_data['server_name']} salvato in {results_excel_path}")

        # Cleanup
        repo_path = server_data["repo_path"]
        if repo_path.exists() and repo_path.is_dir():
            force_delete(repo_path)
            print("Cartella eliminata")

        end_time = time.time()
        elapsed = end_time - start_time
        print(f"Tempo totale: {elapsed:.2f}s")


def parse_args():
    """Parse argomenti da linea di comando"""
    parser = argparse.ArgumentParser(
        description="Esegui un singolo framework di analisi MCP su VM"
    )
    parser.add_argument(
        "--framework", "-f",
        type=str,
        required=True,
        choices=[f.value for f in Framework],
        help="Framework da eseguire"
    )
    parser.add_argument(
        "--start", "-s",
        type=int,
        default=0,
        help="Indice iniziale (default: 0)"
    )
    parser.add_argument(
        "--end", "-e",
        type=int,
        default=None,
        help="Indice finale (default: tutti)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    # Converti stringa in enum
    framework = Framework(args.framework)
    
    mainParallel(framework, args.start, args.end)

# =============================================================================
# COME ESEGUIRE QUESTO FILE
# =============================================================================
#
# Framework disponibili:
#   - mcp-guard
#   - mcp-watch
#   - fuzzing
#   - mcp-scan
#   - mcp-shield        (include automaticamente llm-analysis)
#   - mcp-security-scan
#   - mcp-check
#   - scanorama
#   - mcp-validator
#   - llm-proxy
#
# Esempi:
#   python mainParallel.py --framework mcp-guard
#   python mainParallel.py -f mcp-shield
#   python mainParallel.py -f fuzzing --start 0 --end 100
#   python mainParallel.py -f mcp-scan -s 50 -e 150
#
# Argomenti:
#   --framework, -f  : (obbligatorio) framework da eseguire
#   --start, -s      : (opzionale) indice iniziale nel file Excel (default: 0)
#   --end, -e        : (opzionale) indice finale nel file Excel (default: tutti)
#
# Output:
#   - analysis/{framework}.json : statistiche per singolo framework
#   - recap_server.json         : status per ogni server
#   - {framework}_servers.json  : dizionario {url: status} per ogni framework
# =============================================================================
