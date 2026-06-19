#!/usr/bin/env python3
"""
Launcher per i tool della Pipeline.
Uso:
    python launch.py scan              # lancia mcp-scan da zero
    python launch.py fuzzing           # lancia fuzzing da zero
    python launch.py shield            # lancia mcp-shield da zero
    python launch.py guard             # lancia mcp-guard da zero
    python launch.py watch             # lancia mcp-watch da zero
    python launch.py security_scan     # lancia mcp-security-scan da zero
    python launch.py check             # lancia mcp-check da zero

    python launch.py scan --resume     # riprende da dove si era fermato
    python launch.py scan --start 500  # parte dall'indice 500

    python launch.py --status          # mostra lo stato di tutti i tool
    python launch.py --kill            # killa tutti i processi run_*.py
"""
import argparse
import json
import subprocess
import sys
import os
import signal
from pathlib import Path

BASE_DIR = Path(__file__).parent

# Cartelle locali dei tool. Sulle VM, dopo il deploy, hanno il prefisso "tool_"
# (es. mcp_scan -> tool_mcp_scan): _tool_dir() risolve l'una o l'altra.
TOOLS = {
    "scan": {
        "dir": "mcp_scan",
        "script": "run_scan.py",
        "stats": "mcp_scan_stats.json",
        "log": "mcp_scan_servers.json",
        "output": "scan_output.log",
    },
    "fuzzing": {
        "dir": "fuzzing",
        "script": "run_fuzzing.py",
        "stats": "fuzzing_stats.json",
        "log": "fuzzing_servers.json",
        "output": "fuzzing_output.log",
    },
    "shield": {
        "dir": "mcp_shield",
        "script": "run_shield.py",
        "stats": "mcp_shield_stats.json",
        "log": "mcp_shield_servers.json",
        "output": "shield_output.log",
    },
    "guard": {
        "dir": "mcp_guard",
        "script": "run_guard.py",
        "stats": "mcp_guard_stats.json",
        "log": "mcp_guard_servers.json",
        "output": "guard_output.log",
    },
    "watch": {
        "dir": "mcp_watch",
        "script": "run_watch.py",
        "stats": "mcp_watch_stats.json",
        "log": "mcp_watch_servers.json",
        "output": "watch_output.log",
    },
    "security_scan": {
        "dir": "mcp_security_scan",
        "script": "run_security_scan.py",
        "stats": "mcp_security_scan_stats.json",
        "log": "mcp_security_scan_servers.json",
        "output": "security_scan_output.log",
    },
    "check": {
        "dir": "mcp_check",
        "script": "run_check.py",
        "stats": "mcp_check_stats.json",
        "log": "mcp_check_servers.json",
        "output": "check_output.log",
    },
}


def _tool_dir(cfg):
    """Cartella del tool: locale (es. mcp_scan) o remota su VM (tool_mcp_scan)."""
    local = BASE_DIR / cfg["dir"]
    if local.exists():
        return local
    return BASE_DIR / f"tool_{cfg['dir']}"


def kill_running(tool_name=None):
    """Kill running run_*.py processes."""
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["tasklist", "/FO", "CSV"], capture_output=True, text=True
            )
            # On Windows we can't easily filter, just inform
            print("Su Windows, killa manualmente i processi Python dal Task Manager.")
            return

        # Linux/Mac
        result = subprocess.run(
            ["pgrep", "-af", "python.*run_"], capture_output=True, text=True
        )
        if not result.stdout.strip():
            print("Nessun processo run_*.py attivo.")
            return

        lines = result.stdout.strip().split("\n")
        for line in lines:
            pid = int(line.split()[0])
            proc_name = " ".join(line.split()[1:])

            # Se specificato un tool, killa solo quello
            if tool_name:
                tool_cfg = TOOLS.get(tool_name)
                if tool_cfg and tool_cfg["script"] not in proc_name:
                    continue

            try:
                os.kill(pid, signal.SIGTERM)
                print(f"  Killato PID {pid}: {proc_name}")
            except ProcessLookupError:
                pass
    except FileNotFoundError:
        print("pgrep non disponibile, killa manualmente.")


def reset_stats(tool_cfg):
    """Reset stats and log files to empty."""
    tool_dir = _tool_dir(tool_cfg)
    stats_path = tool_dir / tool_cfg["stats"]
    log_path = tool_dir / tool_cfg["log"]

    with open(stats_path, "w") as f:
        json.dump({}, f)
    with open(log_path, "w") as f:
        json.dump({}, f)
    print(f"  Reset: {stats_path.name}, {log_path.name}")


def show_status():
    """Show status of all tools."""
    print("\n" + "=" * 60)
    print(f"{'Tool':<18} {'Last Index':<12} {'Total':<10} {'Status'}")
    print("=" * 60)

    for name, cfg in TOOLS.items():
        stats_path = _tool_dir(cfg) / cfg["stats"]
        if stats_path.exists():
            try:
                with open(stats_path, "r") as f:
                    data = json.load(f)
                last_idx = data.get("last_index", 0)
                total = data.get("total", 0)

                # Check if process is running (Linux only)
                status = "stopped"
                try:
                    result = subprocess.run(
                        ["pgrep", "-af", f"python.*{cfg['script']}"],
                        capture_output=True, text=True
                    )
                    if result.stdout.strip():
                        status = "RUNNING"
                except FileNotFoundError:
                    status = "?"

                print(f"  {name:<16} {last_idx:<12} {total:<10} {status}")
            except Exception:
                print(f"  {name:<16} {'error':<12} {'error':<10}")
        else:
            print(f"  {name:<16} {'---':<12} {'---':<10} not started")

    print("=" * 60 + "\n")


def launch_tool(tool_name, start_idx, resume=False):
    """Launch a tool."""
    if tool_name not in TOOLS:
        print(f"Tool sconosciuto: {tool_name}")
        print(f"Tool disponibili: {', '.join(TOOLS.keys())}")
        sys.exit(1)

    cfg = TOOLS[tool_name]
    script_path = _tool_dir(cfg) / cfg["script"]
    output_path = BASE_DIR / cfg["output"]

    if not script_path.exists():
        print(f"Script non trovato: {script_path}")
        sys.exit(1)

    # Kill existing process for this tool
    print(f"\nLancio {tool_name}...")
    kill_running(tool_name)

    if resume:
        start_arg = "-1"
        print(f"  Modalità: RESUME (riprende da dove si era fermato)")
    else:
        start_arg = str(start_idx)
        if start_idx == 0:
            reset_stats(cfg)
            print(f"  Modalità: DA ZERO (reset stats)")
        else:
            print(f"  Modalità: da indice {start_idx}")

    # Launch with nohup
    cmd = f"nohup {sys.executable} {script_path} --start {start_arg} > {output_path} 2>&1 &"

    if sys.platform == "win32":
        # On Windows, use subprocess directly (no nohup)
        print(f"  Su Windows non puoi lanciare in background con nohup.")
        print(f"  Esegui sul server:")
        print(f"    cd ~/Desktop/Pipeline")
        print(f"    nohup python tool_{cfg['dir']}/{cfg['script']} --start {start_arg} > {cfg['output']} 2>&1 &")
        print(f"    tail -f {cfg['output']}")
        return

    os.system(cmd)
    print(f"  Avviato in background. Log: {output_path}")
    print(f"  Per seguire: tail -f {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Pipeline Launcher - Lancia e gestisci i tool di analisi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  python launch.py scan                  # lancia scan da zero
  python launch.py fuzzing --resume      # riprende fuzzing
  python launch.py guard --start 500     # guard da indice 500
  python launch.py --status              # stato di tutti i tool
  python launch.py --kill                # killa tutti i processi
        """
    )
    parser.add_argument("tool", nargs="?", help=f"Tool da lanciare: {', '.join(TOOLS.keys())}")
    parser.add_argument("--start", "-s", type=int, default=0, help="Indice di partenza (default: 0 = da zero)")
    parser.add_argument("--resume", "-r", action="store_true", help="Riprendi da dove si era fermato")
    parser.add_argument("--status", action="store_true", help="Mostra lo stato di tutti i tool")
    parser.add_argument("--kill", "-k", action="store_true", help="Killa tutti i processi run_*.py")

    args = parser.parse_args()

    if args.status:
        show_status()
        return

    if args.kill:
        kill_running()
        return

    if not args.tool:
        parser.print_help()
        return

    launch_tool(args.tool, args.start, args.resume)


if __name__ == "__main__":
    main()
