#!/usr/bin/env python3
"""
Monitor mcp-security-scanner e mcp-check su tutte le 9 VM.
Si aggiorna ogni N secondi con una dashboard nel terminale.

Uso:
  python monitorVM/monitor.py                  # refresh ogni 30s, mostra security-scan + check
  python monitorVM/monitor.py --interval 10    # refresh ogni 10s
  python monitorVM/monitor.py --tools check    # solo mcp-check
  python monitorVM/monitor.py --tools security_scan  # solo mcp-security-scan
  python monitorVM/monitor.py --once           # una sola esecuzione (no loop)
  python monitorVM/monitor.py --tail 20        # mostra anche ultime 20 righe di log
"""

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── VM Configuration (stessa di deploy.py) ──────────────────────────────────
TOOLS = {
    "guard":         {"vm": "VM1", "addr": "tecnico@10.79.6.132"},
    "watch":         {"vm": "VM2", "addr": "tecnico@10.79.6.133"},
    "fuzzing":       {"vm": "VM3", "addr": "tecnico@10.79.6.134"},
    "scan":          {"vm": "VM4", "addr": "tecnico@10.79.6.136"},
    "shield":        {"vm": "VM5", "addr": "tecnico@10.79.6.137"},
    "security_scan": {"vm": "VM6", "addr": "tecnico@10.79.6.138"},
    "check":         {"vm": "VM7", "addr": "tecnico@10.79.6.139"},
    "scanorama":     {"vm": "VM8", "addr": "tecnico@10.79.6.141"},
    "validator":     {"vm": "VM9", "addr": "tecnico@10.79.6.142"},
}

# Cosa monitorare per ogni tool
MONITOR_CONFIG = {
    "security_scan": {
        "label": "mcp-security-scanner",
        "stats_path": "~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_stats.json",
        "process_grep": "python.*run_security_scan.py",
        "log_path": "~/Desktop/Pipeline/security_scan_output.log",
    },
    "check": {
        "label": "mcp-check",
        "stats_path": "~/Desktop/Pipeline/tool_mcp_check/mcp_check_stats.json",
        "process_grep": "python.*run_check.py",
        "log_path": "~/Desktop/Pipeline/check_output.log",
    },
}

# ── Colori ANSI ─────────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def ssh_cmd(addr, command, timeout=20):
    """Esegue un comando SSH e ritorna (ok, output)."""
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no", addr, command],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, ""
    except (subprocess.TimeoutExpired, Exception):
        return False, ""


def query_vm(vm_name, cfg, tool_key, mon_cfg, tail_lines=0):
    """Interroga una singola VM per un tool. Ritorna un dict con i risultati."""
    addr = cfg["addr"]
    ip = addr.split("@")[1]
    result = {
        "vm": cfg["vm"],
        "ip": ip,
        "tool": tool_key,
        "reachable": False,
        "running": False,
        "last_index": "---",
        "total": "---",
        "remaining": "---",
        "ram_used": "---",
        "ram_total": "---",
        "disk_pct": "---",
        "tail": "",
    }

    # Comando combinato: stats + process check + risorse (tutto in una SSH)
    combined = (
        f"cat {mon_cfg['stats_path']} 2>/dev/null || echo '__NO_STATS__';"
        f" echo '---SEPARATOR---';"
        f" pgrep -af '{mon_cfg['process_grep']}' 2>/dev/null || echo '__NOT_RUNNING__';"
        f" echo '---SEPARATOR---';"
        f" free -h 2>/dev/null | grep Mem || echo '__NO_FREE__';"
        f" echo '---SEPARATOR---';"
        f" df -h / 2>/dev/null | tail -1 || echo '__NO_DF__'"
    )
    if tail_lines > 0:
        combined += (
            f"; echo '---SEPARATOR---';"
            f" tail -{tail_lines} {mon_cfg['log_path']} 2>/dev/null || echo '__NO_LOG__'"
        )

    ok, output = ssh_cmd(addr, combined, timeout=20)
    if not ok:
        return result

    result["reachable"] = True
    parts = output.split("---SEPARATOR---")

    # Parse stats JSON
    if len(parts) > 0:
        stats_raw = parts[0].strip()
        if stats_raw and "__NO_STATS__" not in stats_raw:
            try:
                data = json.loads(stats_raw)
                result["last_index"] = data.get("last_index", "---")
                result["total"] = data.get("total", "---")
                result["remaining"] = data.get("remaining", "---")
            except (json.JSONDecodeError, ValueError):
                pass

    # Parse process check
    if len(parts) > 1:
        proc_raw = parts[1].strip()
        result["running"] = "__NOT_RUNNING__" not in proc_raw and len(proc_raw) > 0

    # Parse RAM
    if len(parts) > 2:
        mem_raw = parts[2].strip()
        if "__NO_FREE__" not in mem_raw:
            # Mem:           7.7Gi       5.2Gi       ...
            cols = mem_raw.split()
            if len(cols) >= 3:
                result["ram_total"] = cols[1]
                result["ram_used"] = cols[2]

    # Parse Disk
    if len(parts) > 3:
        df_raw = parts[3].strip()
        if "__NO_DF__" not in df_raw:
            cols = df_raw.split()
            if len(cols) >= 5:
                result["disk_pct"] = cols[4]  # e.g. "42%"

    # Parse tail log
    if tail_lines > 0 and len(parts) > 4:
        tail_raw = parts[4].strip()
        if "__NO_LOG__" not in tail_raw:
            result["tail"] = tail_raw

    return result


def print_dashboard(results_by_tool, tail_lines=0):
    """Stampa la dashboard nel terminale."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    width = 95

    print(f"\n{BOLD}{'=' * width}{RESET}")
    print(f"{BOLD}  PIPELINE VM MONITOR{RESET}  {DIM}| {now} |{RESET}")
    print(f"{BOLD}{'=' * width}{RESET}")

    for tool_key, results in results_by_tool.items():
        label = MONITOR_CONFIG[tool_key]["label"]
        running_count = sum(1 for r in results if r["running"])
        total_vms = len(results)
        reachable = sum(1 for r in results if r["reachable"])
        unreachable = total_vms - reachable

        status_color = GREEN if running_count == total_vms else (YELLOW if running_count > 0 else RED)
        print(f"\n  {BOLD}{CYAN}{label}{RESET}  "
              f"{status_color}{running_count}/{total_vms} running{RESET}"
              f"{f'  {RED}{unreachable} unreachable{RESET}' if unreachable > 0 else ''}")
        print(f"  {'-' * (width - 4)}")
        print(f"  {'VM':<6} {'IP':<16} {'Status':<12} {'Index':<10} {'Total':<10} {'Remaining':<12} {'RAM':<14} {'Disk'}")
        print(f"  {'-' * (width - 4)}")

        for r in results:
            if not r["reachable"]:
                status = f"{RED}OFFLINE{RESET}"
            elif r["running"]:
                status = f"{GREEN}RUNNING{RESET}"
            else:
                status = f"{YELLOW}STOPPED{RESET}"

            # Calcola progress bar se abbiamo dati numerici
            idx_str = str(r["last_index"])
            total_str = str(r["total"])
            remaining_str = str(r["remaining"])

            ram_str = f"{r['ram_used']}/{r['ram_total']}" if r["ram_used"] != "---" else "---"
            disk_str = r["disk_pct"]

            print(f"  {r['vm']:<6} {r['ip']:<16} {status:<21} {idx_str:<10} {total_str:<10} {remaining_str:<12} {ram_str:<14} {disk_str}")

        # Progresso totale
        total_remaining = 0
        total_items = 0
        has_data = False
        for r in results:
            if isinstance(r["remaining"], int) and isinstance(r["total"], int):
                total_remaining += r["remaining"]
                total_items += r["total"]
                has_data = True
        if has_data and total_items > 0:
            done = total_items - total_remaining
            pct = (done / total_items) * 100
            bar_len = 40
            filled = int(bar_len * done / total_items)
            bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
            print(f"\n  {BOLD}Progresso totale:{RESET} [{bar}] {pct:.1f}%  ({done:,}/{total_items:,})")

        # Tail dei log
        if tail_lines > 0:
            for r in results:
                if r["tail"]:
                    print(f"\n  {DIM}--- Log {r['vm']} ({r['ip']}) ---{RESET}")
                    for line in r["tail"].split("\n")[-tail_lines:]:
                        print(f"  {DIM}{line}{RESET}")

    print(f"\n{BOLD}{'=' * width}{RESET}")


def run_monitor(tools_to_monitor, interval, once, tail_lines):
    """Loop principale di monitoraggio."""
    while True:
        results_by_tool = {}

        # Query tutte le VM in parallelo
        futures = {}
        with ThreadPoolExecutor(max_workers=18) as pool:
            for tool_key in tools_to_monitor:
                mon_cfg = MONITOR_CONFIG[tool_key]
                for vm_name, cfg in TOOLS.items():
                    f = pool.submit(query_vm, vm_name, cfg, tool_key, mon_cfg, tail_lines)
                    futures[f] = (tool_key, vm_name)

            for tool_key in tools_to_monitor:
                results_by_tool[tool_key] = []

            for future in as_completed(futures):
                tool_key, vm_name = futures[future]
                try:
                    result = future.result()
                    results_by_tool[tool_key].append(result)
                except Exception as e:
                    results_by_tool[tool_key].append({
                        "vm": TOOLS[vm_name]["vm"],
                        "ip": TOOLS[vm_name]["addr"].split("@")[1],
                        "tool": tool_key,
                        "reachable": False, "running": False,
                        "last_index": "---", "total": "---", "remaining": "---",
                        "ram_used": "---", "ram_total": "---", "disk_pct": "---",
                        "tail": "",
                    })

        # Ordina per numero VM
        for tool_key in results_by_tool:
            results_by_tool[tool_key].sort(key=lambda r: r["vm"])

        # Pulisci schermo e stampa
        os.system("cls" if os.name == "nt" else "clear")
        print_dashboard(results_by_tool, tail_lines)

        if once:
            break

        print(f"\n  {DIM}Auto-refresh ogni {interval}s | Ctrl+C per uscire{RESET}")
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Monitor fermato.{RESET}")
            break


def main():
    parser = argparse.ArgumentParser(description="Monitor mcp-security-scanner e mcp-check sulle 9 VM")
    parser.add_argument("--tools", nargs="+", choices=["security_scan", "check"],
                        default=["security_scan", "check"],
                        help="Tool da monitorare (default: entrambi)")
    parser.add_argument("--interval", type=int, default=30,
                        help="Intervallo di refresh in secondi (default: 30)")
    parser.add_argument("--once", action="store_true",
                        help="Esegui una sola volta senza loop")
    parser.add_argument("--tail", type=int, default=0,
                        help="Mostra anche le ultime N righe di log per ogni VM")
    args = parser.parse_args()
    run_monitor(args.tools, args.interval, args.once, args.tail)


if __name__ == "__main__":
    main()
