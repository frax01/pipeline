#!/usr/bin/env python3
"""
Mostra lo stato di tutti i tool su tutte le 9 VM in una tabella compatta.

Uso:
    python vmcheck.py              # tabella completa
    python vmcheck.py --no-proc    # senza controllare i processi (piu' veloce)
"""
import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Fix Windows console encoding
if sys.platform == "win32":
    os.system("")  # enable ANSI escape codes on Windows
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Config ──────────────────────────────────────────────────────────────────
VMS = [
    ("VM1", "132", "tecnico@10.79.6.132"),
    ("VM2", "133", "tecnico@10.79.6.133"),
    ("VM3", "134", "tecnico@10.79.6.134"),
    ("VM4", "136", "tecnico@10.79.6.136"),
    ("VM5", "137", "tecnico@10.79.6.137"),
    ("VM6", "138", "tecnico@10.79.6.138"),
    ("VM7", "139", "tecnico@10.79.6.139"),
    ("VM8", "141", "tecnico@10.79.6.141"),
    ("VM9", "142", "tecnico@10.79.6.142"),
]

TOOLS = [
    ("check",         "tool_mcp_check/mcp_check_stats.json",         "run_check.py"),
    ("shield",        "tool_mcp_shield/mcp_shield_stats.json",       "run_shield.py"),
    ("guard",         "tool_mcp_guard/mcp_guard_stats.json",         "run_guard.py"),
    ("watch",         "tool_mcp_watch/mcp_watch_stats.json",         "run_watch.py"),
    ("security_scan", "tool_mcp_security_scan/mcp_security_scan_stats.json", "run_security_scan.py"),
    ("scan",          "tool_mcp_scan/mcp_scan_stats.json",           "run_scan.py"),
]

TOTAL_SERVERS = 60205
CHUNK = TOTAL_SERVERS // 9  # 6689


# ── Helpers ─────────────────────────────────────────────────────────────────
def ssh_cmd(addr, command, timeout=15):
    """Run a command via SSH, return (ok, stdout)."""
    try:
        r = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no", addr, command],
            capture_output=True, timeout=timeout,
        )
        # decode as utf-8 with replace to avoid cp1252 issues on Windows
        stdout = r.stdout.decode("utf-8", errors="replace") if r.stdout else ""
        return r.returncode == 0, stdout.strip()
    except subprocess.TimeoutExpired:
        return False, ""
    except Exception:
        return False, ""


def get_stats_remote(addr, stats_path):
    """Read a JSON stats file via SSH using remote python (avoids encoding issues)."""
    cmd = (
        f"python3 -c \""
        f"import json,sys;"
        f"d=json.load(open('/home/tecnico/Desktop/Pipeline/{stats_path}'));"
        f"print(json.dumps({{'last_index':d.get('last_index',0),'total':d.get('total',0),'range_end':d.get('range_end',0)}}))\" 2>/dev/null"
    )
    ok, out = ssh_cmd(addr, cmd)
    if ok and out:
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            pass
    return None


def get_running_tools(addr):
    """Return set of running tool script names."""
    ok, out = ssh_cmd(addr, "pgrep -af 'python.*run_' 2>/dev/null")
    running = set()
    if ok and out:
        for line in out.splitlines():
            for _, _, script in TOOLS:
                if script in line:
                    running.add(script)
    return running


def chunk_size(vm_index):
    """Return the chunk size for a given VM (0-based index)."""
    if vm_index == 8:
        return TOTAL_SERVERS - 8 * CHUNK
    return CHUNK


def fetch_vm(vm_index, vm_name, ip, addr, check_procs):
    """Fetch all tool stats (and optionally running procs) for one VM."""
    row = {"vm": vm_name, "ip": ip, "tools": {}}

    running = get_running_tools(addr) if check_procs else set()
    csz = chunk_size(vm_index)

    for tool_name, stats_path, script in TOOLS:
        data = get_stats_remote(addr, stats_path)
        if data is None:
            row["tools"][tool_name] = {"status": "---", "running": script in running}
        else:
            total = data["total"]
            done = total >= csz
            pct = total / csz * 100 if csz > 0 else 0
            row["tools"][tool_name] = {
                "processed": total,
                "chunk": csz,
                "pct": pct,
                "done": done,
                "running": script in running,
            }
    return row


# ── ANSI colors ─────────────────────────────────────────────────────────────
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def colorize_cell(info):
    """Return a formatted cell string for a tool on a VM."""
    if info.get("status") == "---":
        return f"{DIM}---{RESET}"

    if info["done"]:
        text = f"{GREEN}\u2713{RESET}"
    else:
        pct = info["pct"]
        n = info["processed"]
        c = info["chunk"]
        if pct >= 75:
            color = GREEN
        elif pct >= 40:
            color = YELLOW
        else:
            color = RED
        text = f"{color}{n}/{c}{RESET} {DIM}({pct:.0f}%){RESET}"

    if info.get("running"):
        text += f" {CYAN}\u25cf{RESET}"

    return text


# ── Main ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Stato dei tool su tutte le 9 VM")
    parser.add_argument("--no-proc", action="store_true", help="Non controllare i processi attivi (piu' veloce)")
    args = parser.parse_args()

    check_procs = not args.no_proc
    tool_names = [t[0] for t in TOOLS]

    # column widths
    COL_W = 18

    print(f"\n{BOLD}  Raccolta dati da 9 VM...{RESET}", end="", flush=True)

    # fetch all VMs in parallel
    rows = [None] * len(VMS)
    with ThreadPoolExecutor(max_workers=9) as pool:
        futures = {}
        for i, (vm_name, ip, addr) in enumerate(VMS):
            f = pool.submit(fetch_vm, i, vm_name, ip, addr, check_procs)
            futures[f] = i
        for f in as_completed(futures):
            idx = futures[f]
            rows[idx] = f.result()
            print(".", end="", flush=True)

    print(f" {GREEN}done{RESET}\n")

    # header
    hdr = f"  {BOLD}{'VM':<5} {'IP':<5}"
    for t in tool_names:
        hdr += f" {t:^{COL_W}}"
    hdr += RESET
    print(hdr)
    print("  " + "\u2500" * (5 + 5 + COL_W * len(tool_names) + len(tool_names)))

    # totals for summary
    totals = {t: {"done": 0, "processed": 0, "chunk": 0} for t in tool_names}

    for row in rows:
        line = f"  {BOLD}{row['vm']:<5}{RESET} {row['ip']:<5}"
        for t in tool_names:
            info = row["tools"][t]
            cell = colorize_cell(info)
            # calculate visible length for padding
            visible = len(cell.encode("ascii", "ignore").decode())  # rough
            # just use fixed padding; ANSI makes exact alignment tricky
            line += f" {cell:}{' ' * max(0, COL_W - len(strip_ansi(cell)))}"

            if info.get("status") != "---":
                totals[t]["chunk"] += info.get("chunk", 0)
                totals[t]["processed"] += info.get("processed", 0)
                if info.get("done"):
                    totals[t]["done"] += 1
        print(line)

    print("  " + "\u2500" * (5 + 5 + COL_W * len(tool_names) + len(tool_names)))

    # summary row
    summary = f"  {BOLD}{'TOT':<5}{RESET} {'':5}"
    for t in tool_names:
        d = totals[t]
        if d["chunk"] > 0:
            pct = d["processed"] / d["chunk"] * 100
            vms_done = d["done"]
            if vms_done == 9:
                cell = f"{GREEN}\u2713 9/9{RESET}"
            else:
                color = GREEN if pct >= 75 else (YELLOW if pct >= 40 else RED)
                cell = f"{color}{d['processed']}/{d['chunk']}{RESET} {DIM}({pct:.0f}%){RESET}"
        else:
            cell = f"{DIM}---{RESET}"
        summary += f" {cell}{' ' * max(0, COL_W - len(strip_ansi(cell)))}"
    print(summary)

    # legend
    print(f"\n  {CYAN}\u25cf{RESET} = processo attivo   {GREEN}\u2713{RESET} = completato")
    print()


def strip_ansi(s):
    """Remove ANSI escape sequences for length calculation."""
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


if __name__ == "__main__":
    main()
