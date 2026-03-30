from functions.helper import save_summary, force_delete, update_global_npx, load_summary, reset_file, update_recap_server_npx
from frameworks.mcpScan import execute_mcp_scan
from frameworks.mcpShield import execute_mcp_shield
from frameworks.llmAnalysis import run_llm_analysis
from frameworks.NewProxy.proxyAnalysis import run_llm_proxy_analysis
from buildConfig import write_mcp_config
from functions.stats import update_framework_npx, update_summary_llm_risk
from data.setup import generate_all_tables
from config import EXCEL_PATH_NPX, FRAMEWORKS_NPX, RECAP_SERVER_NPX, TABLE_DIR_NPX
from config import init_npx, recap_server_npx
import pandas as pd
import time
from pathlib import Path

def main():
    start_idx = load_summary(FRAMEWORKS_NPX)["last_index"] + 1
    #start_idx = 0
    results_excel_path = "onlyValidServersNpx.xlsx"
    if start_idx == 0:
        reset_file(init_npx, FRAMEWORKS_NPX)
        reset_file(recap_server_npx, RECAP_SERVER_NPX)
        pd.DataFrame(columns=["Link", "Nome"]).to_excel(results_excel_path, index=False)
    print("START:", start_idx)
    df_excel = pd.read_excel(EXCEL_PATH_NPX)
    for idx, row in df_excel.iloc[start_idx:].iterrows():
        start_time = time.time()
        status_scan = "failed"
        status_shield = "failed"
        status_llm_analysis = "failed"
        status_llm_proxy = "failed"
        server_name = row["Link"]
        server_language = "nodejs"
        repo_path = Path.cwd()
        print("###################")
        print("Index:", idx)
        print("server_name:", server_name)

        command = "npx"
        elem = ["-y", f"{server_name}"]

        write_mcp_config(
            server_name = server_name,
            command = command,
            args = elem,
            cwd = repo_path
        )

        summary = update_global_npx(load_summary(FRAMEWORKS_NPX), idx)
 
        print("\n=== MCP SCAN ===") ###MCP-SCAN
        result_mcp_scan, status_scan = execute_mcp_scan(repo_path)
        print("status_scan:", status_scan)
        if status_scan == "completed":
            update_framework_npx(summary, result_mcp_scan["mcp-scan"], "mcp-scan")
        else:
            summary["mcp-scan"]["percentage"] = summary["mcp-scan"]["total"] / summary["total"] * 100

        print("\n=== MCP SHIELD ===") ###MCP-SHIELD
        result_mcp_shield, status_shield = execute_mcp_shield(repo_path)
        print("status_shield:", status_shield)
        if status_shield == "completed":
            update_framework_npx(summary, result_mcp_shield["mcp-shield"], "mcp-shield")

            print("\n=== LLM ANALYSIS ===") ###LLM-ANALYSIS
            llm = run_llm_analysis(result_mcp_shield["mcp-shield"], repo_path, command, elem)
            status_llm_analysis = llm.get("status")
            print("status:", llm.get("status"))
            update_summary_llm_risk(summary, llm, "static", 0, "", 0)
        else:
            summary["mcp-shield"]["percentage"] = summary["mcp-shield"]["total"] / summary["total"] * 100

        if status_scan=="completed" or status_shield == "completed":
            print("\n=== LLM PROXY ===") ###LLM-PROXY
            llm_proxy = run_llm_proxy_analysis(repo_path, command, elem)
            status_llm_proxy = llm_proxy.get("status")
            print("status:", llm_proxy.get("status"))
            total = summary.get("total", 0)
            if status_llm_proxy == "completed":
                update_summary_llm_risk(summary, llm_proxy, "proxy", total, server_language, llm_proxy["tool_length"])

        if (status_scan == "completed" or (status_shield == "completed" and status_llm_analysis == "completed")):
            summary["completely-analyzed-servers"]["total"] += 1
            total_servers = summary.get("total", 0)
            summary["completely-analyzed-servers"]["percentage"] = round(
                (summary["completely-analyzed-servers"]["total"] / total_servers) * 100.0, 2
            )

        save_summary(FRAMEWORKS_NPX, summary)

        update_recap_server_npx(
            recap_server=load_summary(RECAP_SERVER_NPX),
            server_name=server_name,
            mcp_scan_status=status_scan,
            mcp_shield_status=status_shield,
            llm_analysis_status=status_llm_analysis,
            llm_proxy_status="status_llm_proxy",
            path=RECAP_SERVER_NPX
        )

        generate_all_tables(load_summary(FRAMEWORKS_NPX), TABLE_DIR_NPX)

        if repo_path.exists() and repo_path.is_dir():
            force_delete(repo_path)
            print("Cartella eliminata")

        analysis_success = any([
            status_scan == "completed",
            status_shield == "completed",
            status_llm_analysis == "completed",
            status_llm_proxy == "completed"
        ])

        if analysis_success:
            # Carichiamo i risultati esistenti o creiamo nuovo se non esiste (sicurezza extra)
            if Path(results_excel_path).exists():
                df_results = pd.read_excel(results_excel_path)
            else:
                df_results = pd.DataFrame(columns=["Nome"])

            # Verifichiamo se il server è già presente per evitare duplicati in caso di restart
            if server_name not in df_results["Nome"].values:
                new_row = pd.DataFrame([{"Nome": server_name}])
                df_results = pd.concat([df_results, new_row], ignore_index=True)
                df_results.to_excel(results_excel_path, index=False)
                print(f"{server_name} salvato")

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Total time: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()