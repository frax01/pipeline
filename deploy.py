#!/usr/bin/env python3
"""
Deploy e lancia i tool della Pipeline sui server remoti.

Ogni tool ha la sua VM dedicata:
    guard          -> VM1  10.79.6.132
    watch          -> VM2  10.79.6.133
    fuzzing        -> VM3  10.79.6.134
    scan           -> VM4  10.79.6.136
    shield         -> VM5  10.79.6.137
    security_scan  -> VM6  10.79.6.138
    check          -> VM7  10.79.6.139
    scanorama      -> VM8  10.79.6.141
    validator      -> VM9  10.79.6.142

Uso:
    python deploy.py                          # deploy tutti gli script sulle rispettive VM
    python deploy.py scan                     # deploy solo scan sulla sua VM
    python deploy.py --launch scan            # deploy + lancia scan da zero
    python deploy.py --launch fuzzing         # deploy + lancia fuzzing da zero
    python deploy.py --launch shield --resume # deploy + riprende shield
    python deploy.py --launch-all             # deploy + lancia TUTTI da zero
    python deploy.py --launch-all --resume    # deploy + riprende TUTTI
    python deploy.py --status                 # mostra stato di tutti i tool
    python deploy.py --pull                   # scarica tutti i risultati (stats + servers JSON)
    python deploy.py --pull scan              # scarica solo i risultati di scan
    python deploy.py --tail scan              # mostra ultime 30 righe del log di scan
    python deploy.py --tail-all               # mostra ultime 10 righe di TUTTI i log
    python deploy.py --full-deploy fuzzing    # sincronizza tutto il progetto sulla VM3
    python deploy.py --pull-guard             # scarica mcp-guard results da TUTTE le 9 VM
    python deploy.py --merge-guard            # merge dei risultati mcp-guard scaricati
    python deploy.py --pull-guard --merge-guard  # pull + merge in un colpo solo
    python deploy.py --pull-fuzzing           # scarica fuzzing results da TUTTE le 9 VM
    python deploy.py --merge-fuzzing          # merge dei risultati fuzzing scaricati
    python deploy.py --pull-fuzzing --merge-fuzzing  # pull + merge fuzzing
    python deploy.py --deploy-fuzzing-all         # copia file fuzzing su TUTTE le 9 VM (senza lanciare)
    python deploy.py --status-fuzzing             # mostra stato fuzzing su tutte le VM
    python deploy.py --tail-fuzzing               # mostra log fuzzing da tutte le VM
    python deploy.py --deploy-scan-all            # copia file mcp-scan su TUTTE le 9 VM (senza lanciare)
    python deploy.py --pull-scan                  # scarica mcp-scan results da TUTTE le 9 VM
    python deploy.py --merge-scan                 # merge dei risultati mcp-scan scaricati
    python deploy.py --status-scan                # mostra stato mcp-scan su tutte le VM
    python deploy.py --tail-scan                  # mostra log mcp-scan da tutte le VM
    python deploy.py --pull-shield                # scarica mcp-shield results da TUTTE le 9 VM
    python deploy.py --merge-shield               # merge dei risultati mcp-shield scaricati
    python deploy.py --pull-shield --merge-shield # pull + merge shield in un colpo solo
    python deploy.py --deploy-check-all            # copia file mcp-check su TUTTE le 9 VM (senza lanciare)
    python deploy.py --deploy-check-all VM7 VM8    # copia solo su VM specifiche
    python deploy.py --status-check                # mostra stato mcp-check su tutte le VM
    python deploy.py --tail-check                  # mostra log mcp-check da tutte le VM
    python deploy.py --pull-check                  # scarica mcp-check results da TUTTE le 9 VM
    python deploy.py --deploy-frameworks-all       # copia mcp-server-fuzzer + mcp-guard su TUTTE le VM via tar.gz
    python deploy.py --deploy-frameworks-all VM1 VM3  # solo su VM specifiche
    python deploy.py --deploy-frameworks-all --deploy-framework mcp-server-fuzzer  # solo un framework
"""
import argparse
import subprocess
import sys
import json
from pathlib import Path

BASE_DIR = Path(__file__).parent

# Mapping: tool -> (VM name, IP, tool_dir, script, stats_file, log_file, output_log)
TOOLS = {
    "guard": {
        "vm": "VM1",
        "addr": "tecnico@10.79.6.132",
        "dir": "0_tool_mcp_guard",
        "script": "0_tool_mcp_guard/run_guard.py",
        "stats": "mcp_guard_stats.json",
        "log": "mcp_guard_servers.json",
        "output": "guard_output.log",
    },
    "watch": {
        "vm": "VM2",
        "addr": "tecnico@10.79.6.133",
        "dir": "0_tool_mcp_watch",
        "script": "0_tool_mcp_watch/run_watch.py",
        "stats": "mcp_watch_stats.json",
        "log": "mcp_watch_servers.json",
        "output": "watch_output.log",
    },
    "fuzzing": {
        "vm": "VM3",
        "addr": "tecnico@10.79.6.134",
        "dir": "analysis/0_tool_fuzzing",
        "script": "analysis/0_tool_fuzzing/run_fuzzing.py",
        "stats": "fuzzing_stats.json",
        "log": "fuzzing_servers.json",
        "output": "fuzzing_output.log",
    },
    "scan": {
        "vm": "VM4",
        "addr": "tecnico@10.79.6.136",
        "dir": "0_tool_mcp_scan",
        "script": "0_tool_mcp_scan/run_scan.py",
        "stats": "mcp_scan_stats.json",
        "log": "mcp_scan_servers.json",
        "output": "scan_output.log",
    },
    "shield": {
        "vm": "VM5",
        "addr": "tecnico@10.79.6.137",
        "dir": "0_tool_mcp_shield",
        "script": "0_tool_mcp_shield/run_shield.py",
        "stats": "mcp_shield_stats.json",
        "log": "mcp_shield_servers.json",
        "output": "shield_output.log",
    },
    "security_scan": {
        "vm": "VM6",
        "addr": "tecnico@10.79.6.138",
        "dir": "0_tool_mcp_security_scan",
        "script": "0_tool_mcp_security_scan/run_security_scan.py",
        "stats": "mcp_security_scan_stats.json",
        "log": "mcp_security_scan_servers.json",
        "output": "security_scan_output.log",
    },
    "check": {
        "vm": "VM7",
        "addr": "tecnico@10.79.6.139",
        "dir": "0_tool_mcp_check",
        "script": "0_tool_mcp_check/run_check.py",
        "stats": "mcp_check_stats.json",
        "log": "mcp_check_servers.json",
        "output": "check_output.log",
    },
    "scanorama": {
        "vm": "VM8",
        "addr": "tecnico@10.79.6.141",
        "dir": "tool_scanorama",
        "script": "tool_scanorama/run_scanorama.py",
        "stats": "scanorama_stats.json",
        "log": "scanorama_servers.json",
        "output": "scanorama_output.log",
    },
    "validator": {
        "vm": "VM9",
        "addr": "tecnico@10.79.6.142",
        "dir": "tool_mcp_validator",
        "script": "tool_mcp_validator/run_validator.py",
        "stats": "mcp_validator_stats.json",
        "log": "mcp_validator_servers.json",
        "output": "validator_output.log",
    },
}

EXTRA_FILES = ["launch.py"]


def scp_file(local_path, server_addr, remote_path):
    """Copy a file to remote server via SCP."""
    cmd = ["scp", str(local_path), f"{server_addr}:{remote_path}"]
    try:
        result = subprocess.run(cmd, timeout=300)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"    [TIMEOUT] scp_file fallito dopo 300s")
        return False


def scp_download(server_addr, remote_path, local_path):
    """Download a file from remote server via SCP."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["scp", f"{server_addr}:{remote_path}", str(local_path)]
    try:
        result = subprocess.run(cmd, timeout=300)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"    [TIMEOUT] scp_download fallito dopo 300s")
        return False


def deploy_frameworks_all(target_vms=None, frameworks=None):
    """Copia le cartelle Frameworks sulle VM via tar.gz, escludendo .git, __pycache__, docs, tests."""
    import tarfile
    import tempfile
    import os

    all_vms = [cfg["addr"] for cfg in TOOLS.values()]
    if target_vms:
        # Filtra per nome VM (es. "VM1") o IP
        addrs = []
        for vm in target_vms:
            for cfg in TOOLS.values():
                if cfg["vm"] == vm or vm in cfg["addr"]:
                    addrs.append(cfg["addr"])
        addrs = list(dict.fromkeys(addrs))
    else:
        addrs = list(dict.fromkeys(all_vms))

    local_frameworks = BASE_DIR.parent / "frameworks"
    if not local_frameworks.exists():
        print(f"Cartella Frameworks non trovata: {local_frameworks}")
        return

    # Quali framework copiare
    fw_names = frameworks if frameworks else ["mcp-server-fuzzer", "mcp-guard"]
    fw_paths = [(name, local_frameworks / name) for name in fw_names if (local_frameworks / name).exists()]

    if not fw_paths:
        print(f"Nessun framework trovato in {local_frameworks}")
        return

    EXCLUDE = {".git", "__pycache__", "docs", "tests", "node_modules", ".tox", "*.egg-info"}

    def _exclude(tarinfo):
        parts = Path(tarinfo.name).parts
        for part in parts:
            if part in EXCLUDE or part.endswith(".egg-info"):
                return None
        return tarinfo

    for fw_name, fw_path in fw_paths:
        print(f"\n=== Deploy {fw_name} su {len(addrs)} VM ===")

        # Crea tar.gz in una temp dir
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            print(f"  Creando archivio {fw_name}.tar.gz...")
            with tarfile.open(tmp_path, "w:gz") as tar:
                tar.add(fw_path, arcname=fw_name, filter=_exclude)

            size_mb = os.path.getsize(tmp_path) / (1024 * 1024)
            print(f"  Archivio pronto: {size_mb:.1f} MB")

            for addr in addrs:
                ip = addr.split("@")[1]
                print(f"  -> {ip} ...", end=" ", flush=True)
                try:
                    # Crea la directory remota
                    subprocess.run(["ssh", addr, "mkdir -p ~/Desktop/Frameworks"], timeout=60)
                    # Copia il tar.gz
                    result = subprocess.run(
                        ["scp", tmp_path, f"{addr}:~/Desktop/Frameworks/{fw_name}.tar.gz"],
                        timeout=180, capture_output=True
                    )
                    if result.returncode != 0:
                        print(f"ERRORE scp")
                        continue
                    # Estrai e rimuovi il tar.gz
                    subprocess.run(
                        ["ssh", addr, f"cd ~/Desktop/Frameworks && tar -xzf {fw_name}.tar.gz && rm {fw_name}.tar.gz"],
                        timeout=60
                    )
                    # Reinstalla il pacchetto (usa path assoluto invece di source)
                    subprocess.run(
                        ["ssh", addr, f"~/pipeline-env/bin/pip install -e ~/Desktop/Frameworks/{fw_name} -q"],
                        timeout=180
                    )
                    print("OK")
                except subprocess.TimeoutExpired:
                    print("TIMEOUT")
                except Exception as e:
                    print(f"ERRORE: {e}")
        finally:
            os.unlink(tmp_path)

    print("\nDeploy Frameworks completato.")


def ssh_cmd(server_addr, command, timeout=60, capture=False):
    """Execute a command on remote server via SSH."""
    cmd = ["ssh", server_addr, command]
    try:
        if capture:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0:
                return False, result.stderr.strip() if result.stderr else ""
            return True, result.stdout.strip()
        else:
            result = subprocess.run(cmd, timeout=timeout)
            return result.returncode == 0, ""
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"


def deploy(tool_names, full=False, frameworks=False):
    """Deploy scripts to their respective servers."""
    # Ensure remote directories exist
    ensured_addrs = {}
    for name in tool_names:
        cfg = TOOLS[name]
        addr = cfg["addr"]
        if addr not in ensured_addrs:
            ensured_addrs[addr] = set()
        ensured_addrs[addr].add(cfg["dir"])

    for addr, dirs in ensured_addrs.items():
        # Create base and tool dirs
        dirs_str = " ".join(f"~/Desktop/Pipeline/{d}" for d in dirs)
        try:
            subprocess.run(["ssh", addr, f"mkdir -p {dirs_str} ~/Desktop/Pipeline/functions ~/Desktop/Pipeline/frameworks ~/Desktop/Pipeline/data ~/Desktop/Pipeline/npm_runner"], timeout=15)
        except: pass

    for name in tool_names:
        cfg = TOOLS[name]
        addr = cfg["addr"]

        # 1. Sync the tool script
        rel_path = cfg["script"]
        scp_file(BASE_DIR / rel_path, addr, f"~/Desktop/Pipeline/{rel_path}")

        # 2. Deploy EXTRA_FILES
        for extra in EXTRA_FILES:
            if (BASE_DIR / extra).exists():
                scp_file(BASE_DIR / extra, addr, f"~/Desktop/Pipeline/{extra}")

        # 3. Full deploy (folders + Excel)
        if full:
            print(f"   Sincronizzazione cartelle core su {cfg['vm']}...")
            folders = ["functions", "frameworks", "data", "tool_mcp_guard", "tool_fuzzing"]
            for folder in folders:
                local_path = BASE_DIR / folder
                if local_path.exists():
                    # Use scp -r for folders
                    cmd = ["scp", "-r", str(local_path), f"{addr}:~/Desktop/Pipeline/"]
                    subprocess.run(cmd, timeout=120)
            
            # Sync Excel files from root
            for excel in BASE_DIR.glob("*.xlsx"):
                scp_file(excel, addr, f"~/Desktop/Pipeline/{excel.name}")
            
            print(f"   Sincronizzazione core completata")

        # 4. Sync Frameworks
        if frameworks:
            print(f"   Sincronizzazione cartella Frameworks su {addr.split('@')[1]}...")
            local_frameworks = BASE_DIR.parent / "Frameworks"
            if local_frameworks.exists():
                try:
                    subprocess.run(["ssh", addr, "mkdir -p ~/Desktop/Frameworks"], timeout=60)
                except (subprocess.TimeoutExpired, Exception) as e:
                    print(f"    mkdir timeout su {addr.split('@')[1]}: {e}, provo comunque scp...")

                for fw_name in ["mcp-guard", "mcp-server-fuzzer"]:
                    fw_path = local_frameworks / fw_name
                    if fw_path.exists():
                        print(f"    - Invio {fw_name}...")
                        try:
                            cmd = ["scp", "-r", str(fw_path), f"{addr}:~/Desktop/Frameworks/"]
                            subprocess.run(cmd, timeout=300)
                        except (subprocess.TimeoutExpired, Exception) as e:
                            print(f"     {fw_name} timeout/errore: {e}")
                print(f"   Sincronizzazione Frameworks completata")
            else:
                print(f"    Cartella Frameworks locale non trovata in {local_frameworks}")

        print(f"   {name:<16} -> {cfg['vm']} ({addr.split('@')[1]})")


def remote_launch(tool_name, start_idx=0, resume=False):
    """Launch a tool on its dedicated server."""
    cfg = TOOLS[tool_name]
    addr = cfg["addr"]

    if resume:
        start_arg = "-1"
        mode = "RESUME"
    else:
        start_arg = str(start_idx)
        mode = "DA ZERO" if start_idx == 0 else f"da indice {start_idx}"

    print(f"   {tool_name:<16} {cfg['vm']} ({addr.split('@')[1]}) [{mode}]")

    # Kill existing process
    ssh_cmd(addr, f"pkill -f 'python.*{cfg['script'].split('/')[-1]}' 2>/dev/null; sleep 1")

    # Reset stats if starting from 0
    if not resume and start_idx == 0:
        ssh_cmd(addr, f"cd ~/Desktop/Pipeline && echo '{{}}' > {cfg['dir']}/{cfg['stats']} && echo '{{}}' > {cfg['dir']}/{cfg['log']}")

    # Launch
    launch_cmd = (
        f"cd ~/Desktop/Pipeline && "
        f"source ~/pipeline-env/bin/activate && "
        f"nohup python {cfg['script']} --start {start_arg} > {cfg['output']} 2>&1 &"
    )
    ssh_cmd(addr, launch_cmd)


def show_status():
    """Show status of all tools across all VMs."""
    print(f"\n{'Tool':<18} {'VM':<6} {'IP':<16} {'Index':<10} {'Total':<10} {'Running'}")
    print("=" * 75)

    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        ip = addr.split("@")[1]

        # Get stats
        ok, output = ssh_cmd(addr, f"cat ~/Desktop/Pipeline/{cfg['dir']}/{cfg['stats']} 2>/dev/null", timeout=30, capture=True)
        last_idx = "---"
        total = "---"
        if ok and output:
            try:
                data = json.loads(output)
                last_idx = data.get("last_index", 0)
                total = data.get("total", 0)
            except Exception:
                pass

        # Check if running
        ok, output = ssh_cmd(addr, f"pgrep -af 'python.*{cfg['script'].split('/')[-1]}' 2>/dev/null", timeout=30, capture=True)
        running = "RUNNING" if ok and output else "stopped"

        print(f"  {name:<16} {cfg['vm']:<6} {ip:<16} {str(last_idx):<10} {str(total):<10} {running}")

    print("=" * 75)


def pull_results(tool_names):
    """Download stats and server log JSON from remote servers."""
    print("\nScaricamento risultati...")
    for name in tool_names:
        cfg = TOOLS[name]
        addr = cfg["addr"]

        # Download stats
        remote_stats = f"~/Desktop/Pipeline/{cfg['dir']}/{cfg['stats']}"
        local_stats = BASE_DIR / cfg["dir"] / cfg["stats"]
        ok = scp_download(addr, remote_stats, local_stats)
        if ok:
            print(f"   {name:<16} stats  <- {cfg['vm']}")

        # Download server log
        remote_log = f"~/Desktop/Pipeline/{cfg['dir']}/{cfg['log']}"
        local_log = BASE_DIR / cfg["dir"] / cfg["log"]
        ok = scp_download(addr, remote_log, local_log)
        if ok:
            print(f"   {name:<16} log    <- {cfg['vm']}")


def pull_tool_all(tool_dir, stats_name, servers_name):
    """Download a tool's results from ALL 9 VMs (for split analysis).
    Saves as vm{i}_stats.json and vm{i}_servers.json in tool_dir/."""
    print(f"\nScaricamento risultati {tool_dir} da tutte le 9 VM...")
    local_dir = BASE_DIR / tool_dir
    local_dir.mkdir(exist_ok=True)

    for i, (name, cfg) in enumerate(TOOLS.items(), 1):
        addr = cfg["addr"]
        vm = cfg["vm"]

        # Download stats
        remote_stats = f"~/Desktop/Pipeline/{tool_dir}/{stats_name}"
        local_stats = local_dir / f"vm{i}_stats.json"
        ok = scp_download(addr, remote_stats, local_stats)
        if ok:
            print(f"   {vm} ({addr.split('@')[1]:<16}) -> vm{i}_stats.json")
        else:
            print(f"   {vm} ({addr.split('@')[1]:<16}) stats non trovato")

        # Download server log
        remote_log = f"~/Desktop/Pipeline/{tool_dir}/{servers_name}"
        local_log = local_dir / f"vm{i}_servers.json"
        ok = scp_download(addr, remote_log, local_log)
        if ok:
            print(f"   {vm} ({addr.split('@')[1]:<16}) -> vm{i}_servers.json")
        else:
            print(f"   {vm} ({addr.split('@')[1]:<16}) servers non trovato")

    print(f"\nFile scaricati in {local_dir}")


def pull_tool_all_deep(tool_dir):
    """Download a tool's results directory from ALL 9 VMs using tar.
    Saves and extracts to pullFromVM/vm{i}/{tool_dir}."""
    print(f"\nScaricamento profondo risultati {tool_dir} da tutte le 9 VM...")
    base_pull_dir = BASE_DIR / "pullFromVM"
    base_pull_dir.mkdir(exist_ok=True)

    import tarfile
    from datetime import datetime

    for i, (name, cfg) in enumerate(TOOLS.items(), 1):
        addr = cfg["addr"]
        vm = cfg["vm"]
        vm_pull_dir = base_pull_dir / f"vm{i}"
        vm_pull_dir.mkdir(exist_ok=True)

        print(f"  --- {vm} ({addr.split('@')[1]:<16}) ---")

        # 1. Create tarball on remote
        tar_file = f"{tool_dir}_results.tar.gz"
        remote_tar = f"~/Desktop/Pipeline/{tar_file}"
        # Clear previous tar if exists and create new one
        tar_cmd = f"cd ~/Desktop/Pipeline && rm -f {tar_file} && tar -czf {tar_file} {tool_dir}"
        ok, _ = ssh_cmd(addr, tar_cmd, timeout=300)
        
        if not ok:
            print(f"    [ERRORE] Creazione tarball fallita su {vm}")
            continue

        # 2. Download tarball
        local_tar = vm_pull_dir / tar_file
        ok = scp_download(addr, remote_tar, local_tar)
        
        if ok:
            print(f"    [OK] Tarball scaricato")
            # 3. Extract locally — sanitize member names for Windows (no <>:"|?*)
            import re
            def _sanitize(n):
                return re.sub(r'[<>:"|?*]', '_', n)
            try:
                skipped = 0
                with tarfile.open(local_tar, "r:gz") as tar:
                    for m in tar.getmembers():
                        safe = _sanitize(m.name)
                        if safe != m.name:
                            m.name = safe
                        try:
                            tar.extract(m, path=vm_pull_dir)
                        except Exception as ex:
                            skipped += 1
                msg = f"    [OK] Estratto in {vm_pull_dir}/{tool_dir}"
                if skipped:
                    msg += f" ({skipped} file saltati)"
                print(msg)
                local_tar.unlink() # Cleanup local tar
            except Exception as e:
                print(f"    [ERRORE] Estrazione locale fallita: {e}")
        else:
            print(f"    [ERRORE] Download fallito")

        # 4. Cleanup remote tarball (optional, don't crash if fails)
        try:
            ssh_cmd(addr, f"rm ~/Desktop/Pipeline/{tar_file}", timeout=20)
        except Exception:
            pass

    print(f"\nPull profondo completato in {base_pull_dir}")


def merge_tool_servers(tool_dir, output_name):
    """Merge vm*_servers.json into a single servers file."""
    local_dir = BASE_DIR / tool_dir
    merged_servers = {}
    count = 0
    for i in range(1, 10):
        f = local_dir / f"vm{i}_servers.json"
        if f.exists():
            with open(f, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
                merged_servers.update(data)
                count += 1
                print(f"  vm{i}_servers.json: {len(data)} server")

    if merged_servers:
        output_servers = local_dir / output_name
        with open(output_servers, 'w', encoding='utf-8') as fh:
            json.dump(merged_servers, fh, indent=4, ensure_ascii=False)
        print(f"\nMerge servers completato: {len(merged_servers)} server totali da {count} VM")
        print(f"  -> {output_servers}")


def pull_guard_all():
    pull_tool_all_deep("tool_mcp_guard")


def merge_guard():
    import sys
    module_dir = BASE_DIR / "0_tool_mcp_guard"
    sys.path.insert(0, str(module_dir))
    from merge_stats import merge_guard_all
    sys.path.pop(0)

    base_pull_dir = BASE_DIR / "pullFromVM"
    out_dir = BASE_DIR / "analysisAllData" / "0_tool_mcp_guard"

    if not base_pull_dir.exists():
        print(f"[ERRORE] Cartella non trovata: {base_pull_dir}. Esegui prima --pull-guard")
        return

    merge_guard_all(base_pull_dir, out_dir)


def pull_fuzzing_all():
    pull_tool_all("tool_fuzzing", "fuzzing_stats.json", "fuzzing_servers.json")


def merge_fuzzing():
    import sys as _sys
    module_dir = BASE_DIR / "0_tool_fuzzing"
    _sys.path.insert(0, str(module_dir))
    from merge_stats import merge_fuzzing_stats
    _sys.path.pop(0)
    fuzzing_dir = BASE_DIR / "tool_fuzzing"
    stats_files = [str(fuzzing_dir / f"vm{i}_stats.json") for i in range(1, 10)]
    existing = [f for f in stats_files if Path(f).exists()]
    print(f"\nMerge fuzzing stats: trovati {len(existing)}/9 file")
    if existing:
        merge_fuzzing_stats(existing, str(fuzzing_dir / "fuzzing_stats.json"))
    merge_tool_servers("tool_fuzzing", "fuzzing_servers.json")


TOTAL_SERVERS = 60205  # rows in Excel


def deploy_guard_all(target_vms=None):
    """Deploy ONLY mcp-guard-essential files to all 9 VMs (or specific ones).
    Prints the manual launch commands for each VM."""
    chunk = TOTAL_SERVERS // 9

    py_files = {
        "0_tool_mcp_guard/run_guard.py": "tool_mcp_guard/run_guard.py",
        "0_tool_mcp_guard/merge_stats.py": "tool_mcp_guard/merge_stats.py",
        "functions/helper.py": "functions/helper.py",
        "functions/buildConfig.py": "functions/buildConfig.py",
        "functions/config.py": "functions/config.py",
        "functions/stats.py": "functions/stats.py",
        "functions/hash.py": "functions/hash.py",
        "functions/hashCache.py": "functions/hashCache.py",
        "functions/recapFramework.py": "functions/recapFramework.py",
        "frameworks/mcpGuard.py": "frameworks/mcpGuard.py",
        "launch.py": "launch.py",
    }

    excel_files = list(BASE_DIR.glob("*.xlsx"))

    print(f"\n Deploy mcp-guard su tutte le 9 VM (solo file essenziali)...")

    launch_commands = []

    for i, (name, cfg) in enumerate(TOOLS.items()):
        addr = cfg["addr"]
        vm = cfg["vm"]

        # Filter by target_vms if provided
        if target_vms and vm not in target_vms:
            continue

        start = i * chunk
        end = TOTAL_SERVERS if i == 8 else (i + 1) * chunk

        print(f"\n  --- {vm} ({addr.split('@')[1]}) range [{start}-{end}) ---")

        try:
            ssh_cmd(addr, "mkdir -p ~/Desktop/Pipeline/tool_mcp_guard ~/Desktop/Pipeline/functions ~/Desktop/Pipeline/frameworks", timeout=15)
        except Exception:
            print(f"    mkdir failed, trying anyway...")

        for local_rel, remote_rel in py_files.items():
            local_path = BASE_DIR / local_rel
            if local_path.exists():
                scp_file(local_path, addr, f"~/Desktop/Pipeline/{remote_rel}")

        for excel in excel_files:
            scp_file(excel, addr, f"~/Desktop/Pipeline/{excel.name}")

        print(f"   File copiati su {vm}")

        launch_commands.append({
            "vm": vm,
            "addr": addr,
            "start": start,
            "end": end,
        })

    print(f"\n Deploy completato!")
    print(f"\n Comandi per lanciare mcp-guard manualmente su ogni VM:")
    print("=" * 80)
    for lc in launch_commands:
        print(f"\n  # {lc['vm']} ({lc['addr'].split('@')[1]}) - range [{lc['start']}-{lc['end']})")
        print(f"  ssh {lc['addr']}")
        print(f"  pkill -f 'python.*run_guard.py'; sleep 1")
        print(f"  cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate")
        print(f"  nohup python tool_mcp_guard/run_guard.py --start {lc['start']} --end {lc['end']} --reset > guard_output.log 2>&1 &")
    print("\n" + "=" * 80)
    print(f"\n Monitoraggio:")
    print(f"  # Da dentro la VM:")
    print(f"  tail -f ~/Desktop/Pipeline/guard_output.log")
    print(f"  watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_stats.json | python3 -m json.tool'")
    print(f"")
    print(f"  # Da questo PC:")
    print(f"  python deploy.py --status-guard")
    print(f"  python deploy.py --tail-guard")


def deploy_scanner_all():
    """Copy ONLY mcp_scanner.py to all 9 VMs (fast, no tar.gz)."""
    local_scanner = BASE_DIR.parent / "Frameworks" / "mcp-guard" / "mcp_scanner.py"
    if not local_scanner.exists():
        # Try Linux-style path for VMs
        local_scanner = Path.home() / "Desktop" / "Frameworks" / "mcp-guard" / "mcp_scanner.py"
    if not local_scanner.exists():
        print(f"mcp_scanner.py not found at {local_scanner}")
        return

    remote_path = "~/Desktop/Frameworks/mcp-guard/mcp_scanner.py"
    all_addrs = list(dict.fromkeys(cfg["addr"] for cfg in TOOLS.values()))

    print(f"\n Deploying mcp_scanner.py to {len(all_addrs)} VMs...")
    for addr in all_addrs:
        ip = addr.split("@")[1]
        ok = scp_file(local_scanner, addr, remote_path)
        status = "OK" if ok else "FAILED"
        print(f"  {ip}: {status}")

    # Also clear __pycache__ on all VMs
    print(f"\n Clearing __pycache__...")
    for addr in all_addrs:
        ssh_cmd(addr, "rm -rf ~/Desktop/Frameworks/mcp-guard/__pycache__", timeout=10)
    print(" Done!")


def launch_guard_all(reset=True):
    """Kill and relaunch mcp-guard on all 9 VMs with correct ranges."""
    chunk = TOTAL_SERVERS // 9
    all_addrs = list(dict.fromkeys(cfg["addr"] for cfg in TOOLS.values()))

    print(f"\n Launching mcp-guard on all {len(all_addrs)} VMs...")
    reset_flag = "--reset" if reset else "--resume"

    for i, addr in enumerate(all_addrs):
        start = i * chunk
        end = TOTAL_SERVERS if i == 8 else (i + 1) * chunk
        ip = addr.split("@")[1]
        vm = f"VM{i+1}"

        print(f"\n  --- {vm} ({ip}) range [{start}-{end}) ---")

        # Kill existing guard process
        print(f"    Killing existing guard...")
        ssh_cmd(addr, "pkill -9 -f 'python.*run_guard.py' 2>/dev/null; sleep 1", timeout=15)

        # Launch new guard
        launch_cmd = (
            f"bash -c '"
            f"cd ~/Desktop/Pipeline && "
            f"(source ~/pipeline-env/bin/activate 2>/dev/null || true) && "
            f"nohup python tool_mcp_guard/run_guard.py --start {start} --end {end} {reset_flag} "
            f"> guard_output.log 2>&1 < /dev/null & disown"
            f"'"
        )
        print(f"    Launching: --start {start} --end {end} {reset_flag}")
        ok, _ = ssh_cmd(addr, launch_cmd, timeout=20)
        if ok:
            print(f"    Started!")
        else:
            print(f"    FAILED to launch!")

    print(f"\n All VMs launched!")
    print(f" Monitor: python deploy.py --status-guard")
    print(f" Logs:    python deploy.py --tail-guard")


def show_guard_status():
    """Show status of mcp-guard across all 9 VMs."""
    print(f"\n{'VM':<6} {'IP':<16} {'Index':<10} {'Total':<10} {'Remaining':<12} {'Running'}")
    print("=" * 72)

    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        ip = addr.split("@")[1]

        ok, output = ssh_cmd(addr, "cat ~/Desktop/Pipeline/tool_mcp_guard/mcp_guard_stats.json 2>/dev/null", timeout=30, capture=True)
        last_idx = "---"
        total = "---"
        remaining = "---"
        if ok and output:
            try:
                data = json.loads(output)
                last_idx = data.get("last_index", 0)
                total = data.get("total", 0)
                remaining = data.get("remaining", "---")
            except Exception:
                pass

        ok, output = ssh_cmd(addr, "pgrep -af 'python.*run_guard.py' 2>/dev/null", timeout=30, capture=True)
        running = "RUNNING" if ok and output else "stopped"

        print(f"  {cfg['vm']:<6} {ip:<16} {str(last_idx):<10} {str(total):<10} {str(remaining):<12} {running}")

    print("=" * 72)


def tail_guard_all(lines=10):
    """Show last N lines of mcp-guard output logs from all VMs."""
    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        print(f"\n--- {cfg['vm']} ({addr.split('@')[1]}) ---")
        ok, output = ssh_cmd(addr, f"tail -n {lines} ~/Desktop/Pipeline/guard_output.log 2>/dev/null", timeout=30, capture=True)
        if ok and output:
            print(output)
        else:
            print("  (nessun log)")


def deploy_fuzzing_all():
    """Deploy ONLY fuzzing-essential files to all 9 VMs (no launch).
    Prints the manual launch commands for each VM."""
    chunk = TOTAL_SERVERS // 9

    # Files to copy (only what fuzzing needs)
    py_files = {
        "0_tool_fuzzing/run_fuzzing.py": "tool_fuzzing/run_fuzzing.py",
        "0_tool_fuzzing/merge_stats.py": "tool_fuzzing/merge_stats.py",
        "functions/helper.py": "functions/helper.py",
        "functions/buildConfig.py": "functions/buildConfig.py",
        "functions/config.py": "functions/config.py",
        "functions/stats.py": "functions/stats.py",
        "functions/hash.py": "functions/hash.py",
        "functions/hashCache.py": "functions/hashCache.py",
        "functions/recapFramework.py": "functions/recapFramework.py",
        "frameworks/fuzzing.py": "frameworks/fuzzing.py",
        "launch.py": "launch.py",
    }

    # Find Excel
    excel_files = list(BASE_DIR.glob("*.xlsx"))

    print(f"\n Deploy fuzzing su tutte le 9 VM (solo file essenziali)...")

    launch_commands = []

    for i, (name, cfg) in enumerate(TOOLS.items()):
        addr = cfg["addr"]
        vm = cfg["vm"]
        start = i * chunk
        end = TOTAL_SERVERS if i == 8 else (i + 1) * chunk

        print(f"\n  --- {vm} ({addr.split('@')[1]}) range [{start}-{end}) ---")

        # Create dirs
        try:
            ssh_cmd(addr, "mkdir -p ~/Desktop/Pipeline/tool_fuzzing ~/Desktop/Pipeline/functions ~/Desktop/Pipeline/frameworks", timeout=15)
        except Exception:
            print(f"    mkdir failed, trying anyway...")

        # Copy Python files
        for local_rel, remote_rel in py_files.items():
            local_path = BASE_DIR / local_rel
            if local_path.exists():
                scp_file(local_path, addr, f"~/Desktop/Pipeline/{remote_rel}")

        # Copy Excel (only the main one)
        for excel in excel_files:
            scp_file(excel, addr, f"~/Desktop/Pipeline/{excel.name}")

        print(f"   File copiati su {vm}")

        # Save launch command for this VM
        launch_commands.append({
            "vm": vm,
            "addr": addr,
            "start": start,
            "end": end,
        })

    print(f"\n Deploy completato su tutte le 9 VM!")
    print(f"\n Comandi per lanciare il fuzzing manualmente su ogni VM:")
    print("=" * 80)
    for lc in launch_commands:
        print(f"\n  # {lc['vm']} ({lc['addr'].split('@')[1]}) - range [{lc['start']}-{lc['end']})")
        print(f"  ssh {lc['addr']}")
        print(f"  cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate")
        print(f"  nohup python tool_fuzzing/run_fuzzing.py --start {lc['start']} --end {lc['end']} > fuzzing_output.log 2>&1 &")
    print("\n" + "=" * 80)
    print(f"  Monitora con: python deploy.py --status-fuzzing")


def show_fuzzing_status():
    """Show status of fuzzing across all 9 VMs."""
    print(f"\n{'VM':<6} {'IP':<16} {'Index':<10} {'Total':<10} {'Servers':<10} {'Running'}")
    print("=" * 70)

    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        ip = addr.split("@")[1]

        ok, output = ssh_cmd(addr, "cat ~/Desktop/Pipeline/tool_fuzzing/fuzzing_stats.json 2>/dev/null", timeout=30, capture=True)
        last_idx = "---"
        total = "---"
        servers = "---"
        if ok and output:
            try:
                data = json.loads(output)
                last_idx = data.get("last_index", 0)
                total = data.get("total", 0)
                servers = data.get("fuzzing", {}).get("total_servers", 0)
            except Exception:
                pass

        ok, output = ssh_cmd(addr, "pgrep -af 'python.*run_fuzzing.py' 2>/dev/null", timeout=30, capture=True)
        running = "RUNNING" if ok and output else "stopped"

        print(f"  {cfg['vm']:<6} {ip:<16} {str(last_idx):<10} {str(total):<10} {str(servers):<10} {running}")

    print("=" * 70)


def tail_fuzzing_all(lines=10):
    """Show last N lines of fuzzing output logs from all VMs."""
    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        print(f"\n--- {cfg['vm']} ({addr.split('@')[1]}) ---")
        ok, output = ssh_cmd(addr, f"tail -{lines} ~/Desktop/Pipeline/fuzzing_output.log 2>/dev/null", timeout=30, capture=True)
        if ok and output:
            print(output)
        else:
            print("  (nessun log)")


def deploy_shield_all(target_vms=None):
    """Deploy ONLY mcp-shield-essential files to all 9 VMs (or specific ones).
    Prints the manual launch commands for each VM."""
    chunk = TOTAL_SERVERS // 9

    py_files = {
        "0_tool_mcp_shield/run_shield.py": "tool_mcp_shield/run_shield.py",
        "0_tool_mcp_shield/merge_stats.py": "tool_mcp_shield/merge_stats.py",
        "functions/helper.py": "functions/helper.py",
        "functions/buildConfig.py": "functions/buildConfig.py",
        "functions/config.py": "functions/config.py",
        "functions/stats.py": "functions/stats.py",
        "functions/hash.py": "functions/hash.py",
        "functions/hashCache.py": "functions/hashCache.py",
        "functions/recapFramework.py": "functions/recapFramework.py",
        "frameworks/mcpShield.py": "frameworks/mcpShield.py",
        "frameworks/llmAnalysis.py": "frameworks/llmAnalysis.py",
        "frameworks/listTools.ts": "frameworks/listTools.ts",
        "launch.py": "launch.py",
    }

    excel_files = list(BASE_DIR.glob("*.xlsx"))

    print(f"\n Deploy mcp-shield su tutte le 9 VM (solo file essenziali)...")

    # Fix line endings locally for .sh files before deploying
    for local_rel in py_files.keys():
        if local_rel.endswith(".sh"):
            local_path = BASE_DIR / local_rel
            if local_path.exists():
                content = local_path.read_bytes()
                new_content = content.replace(b"\r\n", b"\n")
                if new_content != content:
                    local_path.write_bytes(new_content)

    launch_commands = []

    for i, (name, cfg) in enumerate(TOOLS.items()):
        addr = cfg["addr"]
        vm = cfg["vm"]
        
        # Filter by target_vms if provided
        if target_vms and vm not in target_vms:
            continue

        start = i * chunk
        end = TOTAL_SERVERS if i == 8 else (i + 1) * chunk

        print(f"\n  --- {vm} ({addr.split('@')[1]}) range [{start}-{end}) ---")

        try:
            ssh_cmd(addr, "mkdir -p ~/Desktop/Pipeline/tool_mcp_shield ~/Desktop/Pipeline/functions ~/Desktop/Pipeline/frameworks ~/Desktop/Pipeline/npm_runner", timeout=30)
        except Exception:
            print(f"    mkdir failed, trying anyway...")

        for local_rel, remote_rel in py_files.items():
            local_path = BASE_DIR / local_rel
            if local_path.exists():
                scp_file(local_path, addr, f"~/Desktop/Pipeline/{remote_rel}")

        for excel in excel_files:
            scp_file(excel, addr, f"~/Desktop/Pipeline/{excel.name}")

        print(f"   File copiati su {vm}")

        launch_commands.append({
            "vm": vm,
            "addr": addr,
            "start": start,
            "end": end,
        })

    print(f"\n Deploy completato su tutte le 9 VM!")
    print(f"\n Comandi per lanciare mcp-shield manualmente su ogni VM:")
    print("=" * 80)
    for lc in launch_commands:
        print(f"\n  # {lc['vm']} ({lc['addr'].split('@')[1]}) - range [{lc['start']}-{lc['end']})")
        print(f"  ssh {lc['addr']}")
        print(f"  pkill -f 'python.*run_shield.py'; sleep 1")
        print(f"  cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate")
        print(f"  nohup python tool_mcp_shield/run_shield.py --start {lc['start']} --end {lc['end']} > shield_output.log 2>&1 &")
    print("\n" + "=" * 80)
    print(f"\n Monitoraggio:")
    print(f"  # Da dentro la VM:")
    print(f"  tail -f ~/Desktop/Pipeline/shield_output.log")
    print(f"  watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_shield/mcp_scan_stats.json | python3 -m json.tool'")
    print(f"")
    print(f"  # Da questo PC:")
    print(f"  python deploy.py --status-scan")
    print(f"  python deploy.py --tail-scan")



def show_shield_status():
    '''Show status of mcp-shield across all 9 VMs.'''
    print(f"\n{'VM':<6} {'IP':<16} {'Index':<10} {'Total':<10} {'Remaining':<12} {'Running'}")
    print("=" * 72)

    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        ip = addr.split("@")[1]

        ok, output = ssh_cmd(addr, "cat ~/Desktop/Pipeline/tool_mcp_shield/mcp_shield_stats.json 2>/dev/null", timeout=30, capture=True)
        last_idx = "---"
        total = "---"
        remaining = "---"
        if ok and output:
            try:
                import json
                data = json.loads(output)
                last_idx = data.get("last_index", 0)
                total = data.get("total", 0)
                remaining = data.get("remaining", "---")
            except Exception:
                pass

        ok, output = ssh_cmd(addr, "pgrep -af 'python.*run_shield.py' 2>/dev/null", timeout=30, capture=True)
        running = "RUNNING" if ok and output else "stopped"

        print(f"  {cfg['vm']:<6} {ip:<16} {str(last_idx):<10} {str(total):<10} {str(remaining):<12} {running}")

    print("=" * 72)


def tail_shield_all(lines=10):
    '''Show last N lines of mcp-shield output logs from all VMs.'''
    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        print(f"\n--- {cfg['vm']} ({addr.split('@')[1]}) ---")
        ok, output = ssh_cmd(addr, f"tail -n {lines} ~/Desktop/Pipeline/shield_output.log 2>/dev/null", timeout=30, capture=True)
        if ok and output:
            print(output)
        else:
            print("  (nessun log)")

def clean_npx_all(target_vms=None):
    """Clear npx cache (rm -rf ~/.npm/_npx) on all or specific VMs."""
    print(f"\n[Cleanup] Pulizia cache npx su {'tutte le VM' if not target_vms else ', '.join(target_vms)}...")
    for name, cfg in TOOLS.items():
        if target_vms and cfg['vm'] not in target_vms:
            continue
        addr = cfg["addr"]
        print(f"  --- {cfg['vm']} ({addr.split('@')[1]}) ---")
        ok, _ = ssh_cmd(addr, "rm -rf ~/.npm/_npx && echo 'Cache svuotata'", timeout=30)
        if ok:
            print(f"  [OK] Cache pulita")
        else:
            print(f"  [ERROR] Errore durante la pulizia")



def pull_shield_all():
    pull_tool_all_deep("tool_mcp_shield")


def merge_shield():
    import sys
    module_dir = BASE_DIR / "0_tool_mcp_shield"
    sys.path.insert(0, str(module_dir))
    from merge_stats import merge_shield_all
    sys.path.pop(0)

    base_pull_dir = BASE_DIR / "pullFromVM"
    out_dir = BASE_DIR / "analysisAllData" / "0_tool_mcp_shield"

    if not base_pull_dir.exists():
        print(f"[ERRORE] Cartella non trovata: {base_pull_dir}. Esegui prima --pull-shield")
        return

    merge_shield_all(base_pull_dir, out_dir)


def deploy_scan_all(target_vms=None):
    """Deploy ONLY mcp-scan-essential files to all 9 VMs (or specific ones).
    Prints the manual launch commands for each VM."""
    chunk = TOTAL_SERVERS // 9

    py_files = {
        "0_tool_mcp_scan/run_scan.py": "tool_mcp_scan/run_scan.py",
        "functions/helper.py": "functions/helper.py",
        "functions/buildConfig.py": "functions/buildConfig.py",
        "functions/config.py": "functions/config.py",
        "functions/stats.py": "functions/stats.py",
        "functions/hash.py": "functions/hash.py",
        "functions/hashCache.py": "functions/hashCache.py",
        "functions/recapFramework.py": "functions/recapFramework.py",
        "frameworks/mcpScan.py": "frameworks/mcpScan.py",
        "npm_runner/npm_build.sh": "npm_runner/npm_build.sh",
        "launch.py": "launch.py",
    }

    excel_files = list(BASE_DIR.glob("*.xlsx"))

    print(f"\n Deploy mcp-scan su tutte le 9 VM (solo file essenziali)...")

    # Fix line endings locally for .sh files before deploying
    for local_rel in py_files.keys():
        if local_rel.endswith(".sh"):
            local_path = BASE_DIR / local_rel
            if local_path.exists():
                content = local_path.read_bytes()
                new_content = content.replace(b"\r\n", b"\n")
                if new_content != content:
                    local_path.write_bytes(new_content)

    launch_commands = []

    for i, (name, cfg) in enumerate(TOOLS.items()):
        addr = cfg["addr"]
        vm = cfg["vm"]
        
        # Filter by target_vms if provided
        if target_vms and vm not in target_vms:
            continue

        start = i * chunk
        end = TOTAL_SERVERS if i == 8 else (i + 1) * chunk

        print(f"\n  --- {vm} ({addr.split('@')[1]}) range [{start}-{end}) ---")

        try:
            ssh_cmd(addr, "mkdir -p ~/Desktop/Pipeline/tool_mcp_scan ~/Desktop/Pipeline/functions ~/Desktop/Pipeline/frameworks ~/Desktop/Pipeline/npm_runner", timeout=30)
        except Exception:
            print(f"    mkdir failed, trying anyway...")

        for local_rel, remote_rel in py_files.items():
            local_path = BASE_DIR / local_rel
            if local_path.exists():
                scp_file(local_path, addr, f"~/Desktop/Pipeline/{remote_rel}")

        for excel in excel_files:
            scp_file(excel, addr, f"~/Desktop/Pipeline/{excel.name}")

        print(f"   File copiati su {vm}")

        launch_commands.append({
            "vm": vm,
            "addr": addr,
            "start": start,
            "end": end,
        })

    print(f"\n Deploy completato su tutte le 9 VM!")
    print(f"\n Comandi per lanciare mcp-scan manualmente su ogni VM:")
    print("=" * 80)
    for lc in launch_commands:
        print(f"\n  # {lc['vm']} ({lc['addr'].split('@')[1]}) - range [{lc['start']}-{lc['end']})")
        print(f"  ssh {lc['addr']}")
        print(f"  pkill -f 'python.*run_scan.py'; sleep 1")
        print(f"  cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate")
        print(f"  nohup python tool_mcp_scan/run_scan.py --start {lc['start']} --end {lc['end']} > scan_output.log 2>&1 &")
    print("\n" + "=" * 80)
    print(f"\n Monitoraggio:")
    print(f"  # Da dentro la VM:")
    print(f"  tail -f ~/Desktop/Pipeline/scan_output.log")
    print(f"  watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_stats.json | python3 -m json.tool'")
    print(f"")
    print(f"  # Da questo PC:")
    print(f"  python deploy.py --status-scan")
    print(f"  python deploy.py --tail-scan")


def pull_watch_all():
    pull_tool_all_deep("tool_mcp_watch")


def merge_watch():
    import sys
    module_dir = BASE_DIR / "0_tool_mcp_watch"
    sys.path.insert(0, str(module_dir))
    from merge_stats import merge_watch_all
    sys.path.pop(0)

    base_pull_dir = BASE_DIR / "pullFromVM"
    out_dir = BASE_DIR / "analysisAllData" / "0_tool_mcp_watch"

    if not base_pull_dir.exists():
        print(f"[ERRORE] Cartella non trovata: {base_pull_dir}. Esegui prima --pull-watch")
        return

    merge_watch_all(base_pull_dir, out_dir)


def pull_fuzzing_all():
    pull_tool_all_deep("tool_fuzzing")


def merge_fuzzing():
    import sys
    module_dir = BASE_DIR / "0_tool_fuzzing"
    sys.path.insert(0, str(module_dir))
    from merge_stats import merge_fuzzing_all
    sys.path.pop(0)

    base_pull_dir = BASE_DIR / "pullFromVM"
    out_dir = BASE_DIR / "analysisAllData" / "0_tool_fuzzing"

    if not base_pull_dir.exists():
        print(f"[ERRORE] Cartella non trovata: {base_pull_dir}. Esegui prima --pull-fuzzing")
        return

    merge_fuzzing_all(base_pull_dir, out_dir)


def pull_scan_all():
    pull_tool_all_deep("tool_mcp_scan")


def merge_scan():
    import sys
    module_dir = BASE_DIR / "0_tool_mcp_scan"
    sys.path.insert(0, str(module_dir))
    from merge_stats import merge_scan_all
    sys.path.pop(0)
    
    base_pull_dir = BASE_DIR / "pullFromVM"
    out_dir = BASE_DIR / "analysisAllData" / "0_tool_mcp_scan"
    
    if not base_pull_dir.exists():
        print(f"[ERRORE] Cartella non trovata: {base_pull_dir}. Esegui prima --pull-scan")
        return
        
    merge_scan_all(base_pull_dir, out_dir)


def show_scan_status():
    """Show status of mcp-scan across all 9 VMs."""
    print(f"\n{'VM':<6} {'IP':<16} {'Index':<10} {'Total':<10} {'Remaining':<12} {'Running'}")
    print("=" * 72)

    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        ip = addr.split("@")[1]

        ok, output = ssh_cmd(addr, "cat ~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_stats.json 2>/dev/null", timeout=30, capture=True)
        last_idx = "---"
        total = "---"
        remaining = "---"
        if ok and output:
            try:
                data = json.loads(output)
                last_idx = data.get("last_index", 0)
                total = data.get("total", 0)
                remaining = data.get("remaining", "---")
            except Exception:
                pass

        ok, output = ssh_cmd(addr, "pgrep -af 'python.*run_scan.py' 2>/dev/null", timeout=30, capture=True)
        running = "RUNNING" if ok and output else "stopped"

        print(f"  {cfg['vm']:<6} {ip:<16} {str(last_idx):<10} {str(total):<10} {str(remaining):<12} {running}")

    print("=" * 72)


def tail_scan_all(lines=10):
    """Show last N lines of mcp-scan output logs from all VMs."""
    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        print(f"\n--- {cfg['vm']} ({addr.split('@')[1]}) ---")
        ok, output = ssh_cmd(addr, f"tail -{lines} ~/Desktop/Pipeline/scan_output.log 2>/dev/null", timeout=30, capture=True)
        if ok and output:
            print(output)
        else:
            print("  (nessun log)")


def deploy_security_scan_all(target_vms=None):
    """Deploy ONLY mcp-security-scan-essential files to all 9 VMs (or specific ones).
    Prints the manual launch commands for each VM."""
    chunk = TOTAL_SERVERS // 9

    py_files = {
        "0_tool_mcp_security_scan/run_security_scan.py": "tool_mcp_security_scan/run_security_scan.py",
        "0_tool_mcp_security_scan/merge_stats.py": "tool_mcp_security_scan/merge_stats.py",
        "functions/helper.py": "functions/helper.py",
        "functions/buildConfig.py": "functions/buildConfig.py",
        "functions/config.py": "functions/config.py",
        "functions/stats.py": "functions/stats.py",
        "functions/hash.py": "functions/hash.py",
        "functions/hashCache.py": "functions/hashCache.py",
        "functions/recapFramework.py": "functions/recapFramework.py",
        "frameworks/mcpSecurityScan.py": "frameworks/mcpSecurityScan.py",
        "npm_runner/npm_build.sh": "npm_runner/npm_build.sh",
        "launch.py": "launch.py",
    }

    excel_files = list(BASE_DIR.glob("*.xlsx"))

    print(f"\n Deploy mcp-security-scan su tutte le 9 VM (solo file essenziali)...")

    # Fix line endings locally for .sh files before deploying
    for local_rel in py_files.keys():
        if local_rel.endswith(".sh"):
            local_path = BASE_DIR / local_rel
            if local_path.exists():
                content = local_path.read_bytes()
                new_content = content.replace(b"\r\n", b"\n")
                if new_content != content:
                    local_path.write_bytes(new_content)

    launch_commands = []

    for i, (name, cfg) in enumerate(TOOLS.items()):
        addr = cfg["addr"]
        vm = cfg["vm"]

        # Filter by target_vms if provided
        if target_vms and vm not in target_vms:
            continue

        start = i * chunk
        end = TOTAL_SERVERS if i == 8 else (i + 1) * chunk

        print(f"\n  --- {vm} ({addr.split('@')[1]}) range [{start}-{end}) ---")

        try:
            ssh_cmd(addr, "mkdir -p ~/Desktop/Pipeline/tool_mcp_security_scan ~/Desktop/Pipeline/functions ~/Desktop/Pipeline/frameworks ~/Desktop/Pipeline/npm_runner", timeout=30)
        except Exception:
            print(f"  mkdir failed, trying anyway...")

        for local_rel, remote_rel in py_files.items():
            local_path = BASE_DIR / local_rel
            if local_path.exists():
                scp_file(local_path, addr, f"~/Desktop/Pipeline/{remote_rel}")

        for excel in excel_files:
            scp_file(excel, addr, f"~/Desktop/Pipeline/{excel.name}")

        print(f"  File copiati su {vm}")

        launch_commands.append({
            "vm": vm,
            "addr": addr,
            "start": start,
            "end": end,
        })

    print(f"\n Deploy completato su tutte le 9 VM!")
    print(f"\n Comandi per lanciare mcp-security-scan manualmente su ogni VM:")
    print("=" * 80)
    for lc in launch_commands:
        print(f"\n  # {lc['vm']} ({lc['addr'].split('@')[1]}) - range [{lc['start']}-{lc['end']})")
        print(f"  ssh {lc['addr']}")
        print(f"  pkill -f 'python.*run_security_scan.py'; sleep 1")
        print(f"  cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate")
        print(f"  nohup python tool_mcp_security_scan/run_security_scan.py --start {lc['start']} --end {lc['end']} > security_scan_output.log 2>&1 &")
    print("\n" + "=" * 80)
    print(f"\n Monitoraggio:")
    print(f"  # Da dentro la VM:")
    print(f"  tail -f ~/Desktop/Pipeline/security_scan_output.log")
    print(f"  watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_stats.json | python3 -m json.tool'")
    print(f"")
    print(f"  # Da questo PC:")
    print(f"  python deploy.py --status-security-scan")
    print(f"  python deploy.py --tail-security-scan")


def pull_security_scan_all():
    pull_tool_all_deep("tool_mcp_security_scan")


def merge_security_scan():
    import sys
    module_dir = BASE_DIR / "0_tool_mcp_security_scan"
    sys.path.insert(0, str(module_dir))
    from merge_stats import merge_security_scan_all
    sys.path.pop(0)

    base_pull_dir = BASE_DIR / "pullFromVM"
    out_dir = BASE_DIR / "analysisAllData" / "0_tool_mcp_security_scan"

    if not base_pull_dir.exists():
        print(f"[ERRORE] Cartella non trovata: {base_pull_dir}. Esegui prima --pull-security-scan")
        return

    merge_security_scan_all(base_pull_dir, out_dir)


def show_security_scan_status():
    """Show status of mcp-security-scan across all 9 VMs."""
    print(f"\n{'VM':<6} {'IP':<16} {'Index':<10} {'Total':<10} {'Remaining':<12} {'Running'}")
    print("=" * 72)

    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        ip = addr.split("@")[1]

        ok, output = ssh_cmd(addr, "cat ~/Desktop/Pipeline/tool_mcp_security_scan/mcp_security_scan_stats.json 2>/dev/null", timeout=30, capture=True)
        last_idx = "---"
        total = "---"
        remaining = "---"
        if ok and output:
            try:
                data = json.loads(output)
                last_idx = data.get("last_index", 0)
                total = data.get("total", 0)
                remaining = data.get("remaining", "---")
            except Exception:
                pass

        ok, output = ssh_cmd(addr, "pgrep -af 'python.*run_security_scan.py' 2>/dev/null", timeout=30, capture=True)
        running = "RUNNING" if ok and output else "stopped"

        print(f"  {cfg['vm']:<6} {ip:<16} {str(last_idx):<10} {str(total):<10} {str(remaining):<12} {running}")

    print("=" * 72)


def tail_security_scan_all(lines=10):
    """Show last N lines of mcp-security-scan output logs from all VMs."""
    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        print(f"\n--- {cfg['vm']} ({addr.split('@')[1]}) ---")
        ok, output = ssh_cmd(addr, f"tail -{lines} ~/Desktop/Pipeline/security_scan_output.log 2>/dev/null", timeout=30, capture=True)
        if ok and output:
            print(output)
        else:
            print("  (nessun log)")


def deploy_check_all(target_vms=None):
    """Deploy ONLY mcp-check-essential files to all 9 VMs (or specific ones).
    Prints the manual launch commands for each VM."""
    chunk = TOTAL_SERVERS // 9

    py_files = {
        "0_tool_mcp_check/run_check.py": "tool_mcp_check/run_check.py",
        "functions/helper.py": "functions/helper.py",
        "functions/buildConfig.py": "functions/buildConfig.py",
        "functions/config.py": "functions/config.py",
        "functions/stats.py": "functions/stats.py",
        "functions/hash.py": "functions/hash.py",
        "functions/hashCache.py": "functions/hashCache.py",
        "functions/recapFramework.py": "functions/recapFramework.py",
        "frameworks/mcpCheck.py": "frameworks/mcpCheck.py",
        "npm_runner/npm_build.sh": "npm_runner/npm_build.sh",
        "launch.py": "launch.py",
    }

    excel_files = list(BASE_DIR.glob("*.xlsx"))

    print(f"\n Deploy mcp-check su tutte le 9 VM (solo file essenziali)...")

    # Fix line endings locally for .sh files before deploying
    for local_rel in py_files.keys():
        if local_rel.endswith(".sh"):
            local_path = BASE_DIR / local_rel
            if local_path.exists():
                content = local_path.read_bytes()
                new_content = content.replace(b"\r\n", b"\n")
                if new_content != content:
                    local_path.write_bytes(new_content)

    launch_commands = []

    for i, (name, cfg) in enumerate(TOOLS.items()):
        addr = cfg["addr"]
        vm = cfg["vm"]

        # Filter by target_vms if provided
        if target_vms and vm not in target_vms:
            continue

        start = i * chunk
        end = TOTAL_SERVERS if i == 8 else (i + 1) * chunk

        print(f"\n  --- {vm} ({addr.split('@')[1]}) range [{start}-{end}) ---")

        try:
            ssh_cmd(addr, "mkdir -p ~/Desktop/Pipeline/tool_mcp_check ~/Desktop/Pipeline/functions ~/Desktop/Pipeline/frameworks ~/Desktop/Pipeline/npm_runner", timeout=30)
        except Exception:
            print(f"    mkdir failed, trying anyway...")

        for local_rel, remote_rel in py_files.items():
            local_path = BASE_DIR / local_rel
            if local_path.exists():
                scp_file(local_path, addr, f"~/Desktop/Pipeline/{remote_rel}")

        for excel in excel_files:
            scp_file(excel, addr, f"~/Desktop/Pipeline/{excel.name}")

        print(f"   File copiati su {vm}")

        launch_commands.append({
            "vm": vm,
            "addr": addr,
            "start": start,
            "end": end,
        })

    print(f"\n Deploy completato su tutte le 9 VM!")
    print(f"\n Comandi per lanciare mcp-check manualmente su ogni VM:")
    print("=" * 80)
    for lc in launch_commands:
        print(f"\n  # {lc['vm']} ({lc['addr'].split('@')[1]}) - range [{lc['start']}-{lc['end']})")
        print(f"  ssh {lc['addr']}")
        print(f"  pkill -f 'python.*run_check.py'; sleep 1")
        print(f"  cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate")
        print(f"  nohup python tool_mcp_check/run_check.py --start {lc['start']} --end {lc['end']} --reset > check_output.log 2>&1 &")
    print("\n" + "=" * 80)
    print(f"\n Monitoraggio:")
    print(f"  # Da dentro la VM:")
    print(f"  tail -f ~/Desktop/Pipeline/check_output.log")
    print(f"  watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_check/mcp_check_stats.json | python3 -m json.tool'")
    print(f"")
    print(f"  # Da questo PC:")
    print(f"  python deploy.py --status-check")
    print(f"  python deploy.py --tail-check")


def pull_check_all():
    pull_tool_all_deep("tool_mcp_check")


def merge_check():
    import sys
    module_dir = BASE_DIR / "0_tool_mcp_check"
    sys.path.insert(0, str(module_dir))
    from merge_stats import merge_check_all
    sys.path.pop(0)

    base_pull_dir = BASE_DIR / "pullFromVM"
    out_dir = BASE_DIR / "analysisAllData" / "0_tool_mcp_check"

    if not base_pull_dir.exists():
        print(f"[ERRORE] Cartella non trovata: {base_pull_dir}. Esegui prima --pull-check")
        return

    merge_check_all(base_pull_dir, out_dir)


def show_check_status():
    """Show status of mcp-check across all 9 VMs."""
    print(f"\n{'VM':<6} {'IP':<16} {'Index':<10} {'Total':<10} {'Remaining':<12} {'Running'}")
    print("=" * 72)

    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        ip = addr.split("@")[1]

        ok, output = ssh_cmd(addr, "cat ~/Desktop/Pipeline/tool_mcp_check/mcp_check_stats.json 2>/dev/null", timeout=30, capture=True)
        last_idx = "---"
        total = "---"
        remaining = "---"
        if ok and output:
            try:
                data = json.loads(output)
                last_idx = data.get("last_index", 0)
                total = data.get("total", 0)
                remaining = data.get("remaining", "---")
            except Exception:
                pass

        ok, output = ssh_cmd(addr, "pgrep -af 'python.*run_check.py' 2>/dev/null", timeout=30, capture=True)
        running = "RUNNING" if ok and output else "stopped"

        print(f"  {cfg['vm']:<6} {ip:<16} {str(last_idx):<10} {str(total):<10} {str(remaining):<12} {running}")

    print("=" * 72)


def tail_check_all(lines=10):
    """Show last N lines of mcp-check output logs from all VMs."""
    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        print(f"\n--- {cfg['vm']} ({addr.split('@')[1]}) ---")
        ok, output = ssh_cmd(addr, f"tail -{lines} ~/Desktop/Pipeline/check_output.log 2>/dev/null", timeout=30, capture=True)
        if ok and output:
            print(output)
        else:
            print("  (nessun log)")


def deploy_proxy_all(target_vms=None):
    """Deploy ONLY proxy-essential files to all 9 VMs (or specific ones).
    Includes NewProxy TypeScript files, data/ JSON datasets, and Python bridge.
    Prints the manual launch commands for each VM."""
    chunk = TOTAL_SERVERS // 9

    # Python files to copy
    py_files = {
        "0_tool_proxy/run_proxy.py": "tool_proxy/run_proxy.py",
        "0_tool_proxy/merge_stats.py": "tool_proxy/merge_stats.py",
        "functions/helper.py": "functions/helper.py",
        "functions/buildConfig.py": "functions/buildConfig.py",
        "functions/config.py": "functions/config.py",
        "functions/stats.py": "functions/stats.py",
        "functions/hash.py": "functions/hash.py",
        "functions/hashCache.py": "functions/hashCache.py",
        "functions/recapFramework.py": "functions/recapFramework.py",
        "frameworks/NewProxy/proxyAnalysis.py": "frameworks/NewProxy/proxyAnalysis.py",
        "launch.py": "launch.py",
    }

    # TypeScript files for the proxy
    ts_files = {
        "frameworks/NewProxy/index.ts": "frameworks/NewProxy/index.ts",
        "frameworks/NewProxy/config.ts": "frameworks/NewProxy/config.ts",
        "frameworks/NewProxy/types.ts": "frameworks/NewProxy/types.ts",
        "frameworks/NewProxy/validators.ts": "frameworks/NewProxy/validators.ts",
        "frameworks/NewProxy/llm.ts": "frameworks/NewProxy/llm.ts",
        "frameworks/NewProxy/payload_loader.ts": "frameworks/NewProxy/payload_loader.ts",
        "frameworks/NewProxy/tsconfig.json": "frameworks/NewProxy/tsconfig.json",
    }

    # Dataset JSON files
    data_files = {}
    data_dir = BASE_DIR / "frameworks" / "NewProxy" / "data"
    if data_dir.exists():
        for json_file in data_dir.glob("*.json"):
            rel = f"frameworks/NewProxy/data/{json_file.name}"
            data_files[rel] = rel

    # Also include promptFilter JSONs if available
    pf_files = {}
    pf_dir = BASE_DIR / "promptFilter"
    if pf_dir.exists():
        for json_file in pf_dir.glob("*.json"):
            rel = f"promptFilter/{json_file.name}"
            pf_files[rel] = rel

    # Root config files needed for npm/ts-node
    root_files = {
        "package.json": "package.json",
        "tsconfig.json": "tsconfig.json",
    }

    all_files = {**py_files, **ts_files, **data_files, **pf_files, **root_files}

    excel_files = list(BASE_DIR.glob("*.xlsx"))

    print(f"\n Deploy proxy su tutte le 9 VM (file essenziali + TypeScript + datasets)...")

    launch_commands = []

    for i, (name, cfg) in enumerate(TOOLS.items()):
        addr = cfg["addr"]
        vm = cfg["vm"]

        # Filter by target_vms if provided
        if target_vms and vm not in target_vms:
            continue

        start = i * chunk
        end = TOTAL_SERVERS if i == 8 else (i + 1) * chunk

        print(f"\n  --- {vm} ({addr.split('@')[1]}) range [{start}-{end}) ---")

        # Create all necessary directories
        try:
            ssh_cmd(addr, (
                "mkdir -p ~/Desktop/Pipeline/tool_proxy "
                "~/Desktop/Pipeline/functions "
                "~/Desktop/Pipeline/frameworks/NewProxy/data "
                "~/Desktop/Pipeline/promptFilter"
            ), timeout=30)
        except Exception:
            print(f"    mkdir failed, trying anyway...")

        # Copy all files
        for local_rel, remote_rel in all_files.items():
            local_path = BASE_DIR / local_rel
            if local_path.exists():
                scp_file(local_path, addr, f"~/Desktop/Pipeline/{remote_rel}")

        # Copy Excel (only the main one)
        for excel in excel_files:
            scp_file(excel, addr, f"~/Desktop/Pipeline/{excel.name}")

        print(f"   File copiati su {vm}")

        launch_commands.append({
            "vm": vm,
            "addr": addr,
            "start": start,
            "end": end,
        })

    print(f"\n Deploy completato su tutte le 9 VM!")
    print(f"\n  IMPORTANTE: Su ogni VM assicurati che siano installati:")
    print(f"    1. Node.js + npm (npm install nella cartella Pipeline)")
    print(f"    2. Ollama con llama3 (ollama pull llama3 && ollama serve)")
    print(f"\n Comandi per lanciare il proxy manualmente su ogni VM:")
    print("=" * 80)
    for lc in launch_commands:
        print(f"\n  # {lc['vm']} ({lc['addr'].split('@')[1]}) - range [{lc['start']}-{lc['end']})")
        print(f"  ssh {lc['addr']}")
        print(f"  pkill -f 'python.*run_proxy.py'; sleep 1")
        print(f"  cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate")
        print(f"  nohup python tool_proxy/run_proxy.py --start {lc['start']} --end {lc['end']} --reset > proxy_output.log 2>&1 &")
    print("\n" + "=" * 80)
    print(f"\n Monitoraggio:")
    print(f"  # Da dentro la VM:")
    print(f"  tail -f ~/Desktop/Pipeline/proxy_output.log")
    print(f"  watch -n 5 'cat ~/Desktop/Pipeline/tool_proxy/proxy_stats.json | python3 -m json.tool'")
    print(f"")
    print(f"  # Da questo PC:")
    print(f"  python deploy.py --status-proxy")
    print(f"  python deploy.py --tail-proxy")


def pull_proxy_all():
    """Download proxy results (stats + servers JSON) from all 9 VMs."""
    proxy_dir = BASE_DIR / "tool_proxy"
    proxy_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n Scarico proxy results da tutte le 9 VM...")

    for i, (name, cfg) in enumerate(TOOLS.items()):
        addr = cfg["addr"]
        vm = cfg["vm"]
        vm_num = i + 1

        print(f"\n  --- {vm} ({addr.split('@')[1]}) ---")

        # Download stats
        local_stats = proxy_dir / f"vm{vm_num}_stats.json"
        ok = scp_download(addr, "~/Desktop/Pipeline/tool_proxy/proxy_stats.json", local_stats)
        if ok:
            print(f"   Stats scaricati -> {local_stats.name}")
        else:
            print(f"   Stats non trovati")

        # Download servers log
        local_servers = proxy_dir / f"vm{vm_num}_servers.json"
        ok = scp_download(addr, "~/Desktop/Pipeline/tool_proxy/proxy_servers.json", local_servers)
        if ok:
            print(f"   Servers scaricati -> {local_servers.name}")
        else:
            print(f"   Servers non trovati")

    print(f"\n Pull completato! File in: {proxy_dir}")


def merge_proxy():
    """Merge proxy stats from all 9 VMs into a single file."""
    import sys as _sys
    module_dir = BASE_DIR / "0_tool_proxy"
    _sys.path.insert(0, str(module_dir))
    from merge_stats import merge_proxy_stats, merge_proxy_servers
    _sys.path.pop(0)

    proxy_dir = BASE_DIR / "tool_proxy"

    # Stats merge
    stats_files = [str(proxy_dir / f"vm{i}_stats.json") for i in range(1, 10)]
    existing = [f for f in stats_files if Path(f).exists()]
    print(f"\nMerge proxy stats: trovati {len(existing)}/9 file")
    if existing:
        merge_proxy_stats(existing, str(proxy_dir / "proxy_stats.json"))

    # Servers merge
    server_files = [str(proxy_dir / f"vm{i}_servers.json") for i in range(1, 10)]
    existing_srv = [f for f in server_files if Path(f).exists()]
    if existing_srv:
        merge_proxy_servers(existing_srv, str(proxy_dir / "proxy_servers.json"))


def show_proxy_status():
    """Show status of proxy analysis across all 9 VMs."""
    print(f"\n{'VM':<6} {'IP':<16} {'Index':<10} {'Total':<10} {'Servers':<10} {'Trials':<10} {'Remaining':<12} {'Running'}")
    print("=" * 90)

    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        ip = addr.split("@")[1]

        ok, output = ssh_cmd(addr, "cat ~/Desktop/Pipeline/tool_proxy/proxy_stats.json 2>/dev/null", timeout=30, capture=True)
        last_idx = "---"
        total = "---"
        servers = "---"
        trials = "---"
        remaining = "---"
        if ok and output:
            try:
                data = json.loads(output)
                last_idx = data.get("last_index", 0)
                total = data.get("total", 0)
                remaining = data.get("remaining", "---")
                proxy = data.get("proxy", {})
                servers = proxy.get("total_server", 0)
                trials = proxy.get("total_trials", 0)
            except Exception:
                pass

        ok, output = ssh_cmd(addr, "pgrep -af 'python.*run_proxy.py' 2>/dev/null", timeout=30, capture=True)
        running = "RUNNING" if ok and output else "stopped"

        # Also check if ollama is running
        ok2, output2 = ssh_cmd(addr, "pgrep -a ollama 2>/dev/null", timeout=10, capture=True)
        ollama_status = "ollama:OK" if ok2 and output2 else "ollama:OFF"

        print(f"  {cfg['vm']:<6} {ip:<16} {str(last_idx):<10} {str(total):<10} {str(servers):<10} {str(trials):<10} {str(remaining):<12} {running} {ollama_status}")

    print("=" * 90)


def tail_proxy_all(lines=10):
    """Show last N lines of proxy output logs from all VMs."""
    for name, cfg in TOOLS.items():
        addr = cfg["addr"]
        print(f"\n--- {cfg['vm']} ({addr.split('@')[1]}) ---")
        ok, output = ssh_cmd(addr, f"tail -{lines} ~/Desktop/Pipeline/proxy_output.log 2>/dev/null", timeout=30, capture=True)
        if ok and output:
            print(output)
        else:
            print("  (nessun log)")


def tail_log(tool_name, lines=30):
    """Show last N lines of a tool's output log."""
    cfg = TOOLS[tool_name]
    addr = cfg["addr"]
    print(f"\n--- {tool_name} ({cfg['vm']} {addr.split('@')[1]}) - ultime {lines} righe ---")
    ok, output = ssh_cmd(addr, f"tail -{lines} ~/Desktop/Pipeline/{cfg['output']} 2>/dev/null", timeout=30, capture=True)
    if ok and output:
        print(output)
    else:
        print("  (nessun log trovato)")


def tail_all(lines=10):
    """Show last N lines of ALL tools' output logs."""
    for name in TOOLS:
        tail_log(name, lines)
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Deploy e lancia i tool della Pipeline sui server remoti",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  python deploy.py                              # deploy tutti gli script
  python deploy.py scan                         # deploy solo scan
  python deploy.py --launch scan                # deploy + lancia scan da zero
  python deploy.py --launch fuzzing --resume    # deploy + riprende fuzzing
  python deploy.py --launch-all                 # deploy + lancia TUTTI da zero
  python deploy.py --launch-all --resume        # deploy + riprende TUTTI
  python deploy.py --status                     # stato di tutti i tool
  python deploy.py --pull                       # scarica tutti i risultati
  python deploy.py --pull scan                  # scarica solo risultati di scan
  python deploy.py --tail scan                  # ultime 30 righe del log di scan
  python deploy.py --tail-all                   # ultime 10 righe di TUTTI i log
        """
    )
    parser.add_argument("tool", nargs="?", choices=list(TOOLS.keys()), help="Tool specifico (opzionale)")
    parser.add_argument("--launch", "-l", choices=list(TOOLS.keys()), help="Deploy + lancia un tool")
    parser.add_argument("--launch-all", action="store_true", help="Deploy + lancia TUTTI i tool")
    parser.add_argument("--start", type=int, default=0, help="Indice di partenza (default: 0)")
    parser.add_argument("--resume", "-r", action="store_true", help="Riprendi da dove si era fermato")
    parser.add_argument("--status", action="store_true", help="Mostra lo stato di tutti i tool")
    parser.add_argument("--pull", nargs="?", const="__all__", help="Scarica risultati (tutti o specifico tool)")
    parser.add_argument("--tail", choices=list(TOOLS.keys()), help="Mostra ultime righe del log di un tool")
    parser.add_argument("--tail-all", action="store_true", help="Mostra ultime righe di TUTTI i log")
    parser.add_argument("--full-deploy", action="store_true", help="Sincronizza anche cartelle core (functions, frameworks, data, Excel)")
    parser.add_argument("--frameworks", action="store_true", help="Sincronizza anche la cartella Frameworks locale")
    parser.add_argument("--pull-guard", action="store_true", help="Scarica mcp-guard results da TUTTE le 9 VM")
    parser.add_argument("--merge-guard", action="store_true", help="Merge dei risultati mcp-guard scaricati dalle VM")
    parser.add_argument("--pull-fuzzing", action="store_true", help="Scarica fuzzing results da TUTTE le 9 VM")
    parser.add_argument("--merge-fuzzing", action="store_true", help="Merge dei risultati fuzzing scaricati dalle VM")
    parser.add_argument("--deploy-fuzzing-all", action="store_true", help="Copia file fuzzing su TUTTE le 9 VM (senza lanciare)")
    parser.add_argument("--launch-fuzzing-all", action="store_true", help="Alias per --deploy-fuzzing-all (retrocompatibilit)")
    parser.add_argument("--status-fuzzing", action="store_true", help="Mostra stato fuzzing su tutte le 9 VM")
    parser.add_argument("--tail-fuzzing", action="store_true", help="Mostra ultime righe dei log fuzzing da tutte le VM")
    parser.add_argument("--pull-watch", action="store_true", help="Scarica mcp-watch results da TUTTE le 9 VM")
    parser.add_argument("--merge-watch", action="store_true", help="Merge dei risultati mcp-watch scaricati dalle VM")
    parser.add_argument("--deploy-scan-all", nargs="*", help="Copia file mcp-scan su tutte le 9 VM (o solo su alcune, es: --deploy-scan-all VM4 VM6)")
    parser.add_argument("--pull-scan", action="store_true", help="Scarica mcp-scan results da TUTTE le 9 VM")
    parser.add_argument("--merge-scan", action="store_true", help="Merge dei risultati mcp-scan scaricati dalle VM")
    parser.add_argument("--status-scan", action="store_true", help="Mostra stato mcp-scan su tutte le 9 VM")
    parser.add_argument("--tail-scan", action="store_true", help="Mostra ultime righe dei log mcp-scan da tutte le VM")
    parser.add_argument("--deploy-shield-all", nargs="*", help="Copia file mcp-shield su tutte le 9 VM (opzionale specificarle)")
    parser.add_argument("--status-shield", action="store_true", help="Mostra stato mcp-shield su tutte le 9 VM")
    parser.add_argument("--tail-shield", action="store_true", help="Mostra log mcp-shield da tutte le VM")
    parser.add_argument("--pull-shield", action="store_true", help="Scarica mcp-shield results da TUTTE le 9 VM")
    parser.add_argument("--merge-shield", action="store_true", help="Merge dei risultati mcp-shield scaricati dalle VM")
    parser.add_argument("--deploy-guard-all", nargs="*", help="Copia file mcp-guard su tutte le 9 VM (opzionale specificarle)")
    parser.add_argument("--status-guard", action="store_true", help="Mostra stato mcp-guard su tutte le 9 VM")
    parser.add_argument("--tail-guard", action="store_true", help="Mostra log mcp-guard da tutte le VM")
    parser.add_argument("--deploy-security-scan-all", nargs="*", help="Copia file mcp-security-scan su tutte le 9 VM (opzionale specificarle)")
    parser.add_argument("--pull-security-scan", action="store_true", help="Scarica mcp-security-scan results da TUTTE le 9 VM")
    parser.add_argument("--merge-security-scan", action="store_true", help="Merge dei risultati mcp-security-scan scaricati dalle VM")
    parser.add_argument("--status-security-scan", action="store_true", help="Mostra stato mcp-security-scan su tutte le 9 VM")
    parser.add_argument("--tail-security-scan", action="store_true", help="Mostra log mcp-security-scan da tutte le VM")
    parser.add_argument("--deploy-check-all", nargs="*", help="Copia file mcp-check su tutte le 9 VM (opzionale specificarle, es: --deploy-check-all VM7 VM8)")
    parser.add_argument("--pull-check", action="store_true", help="Scarica mcp-check results da TUTTE le 9 VM")
    parser.add_argument("--merge-check", action="store_true", help="Merge mcp-check stats da tutte le 9 VM")
    parser.add_argument("--status-check", action="store_true", help="Mostra stato mcp-check su tutte le 9 VM")
    parser.add_argument("--tail-check", action="store_true", help="Mostra log mcp-check da tutte le VM")
    parser.add_argument("--deploy-proxy-all", nargs="*", help="Copia file proxy su tutte le 9 VM (opzionale specificarle, es: --deploy-proxy-all VM1 VM5)")
    parser.add_argument("--pull-proxy", action="store_true", help="Scarica proxy results da TUTTE le 9 VM")
    parser.add_argument("--merge-proxy", action="store_true", help="Merge proxy stats da tutte le 9 VM")
    parser.add_argument("--status-proxy", action="store_true", help="Mostra stato proxy su tutte le 9 VM")
    parser.add_argument("--tail-proxy", action="store_true", help="Mostra log proxy da tutte le VM")
    parser.add_argument("--clean-npx", nargs="*", help="Pulisci cache npx su tutte le VM (o solo su alcune)")
    parser.add_argument("--deploy-frameworks-all", nargs="*", metavar="VM", help="Copia mcp-server-fuzzer e mcp-guard su tutte le VM via tar.gz (es: --deploy-frameworks-all VM1 VM3)")
    parser.add_argument("--deploy-framework", nargs="*", metavar="NAME", help="Specifica quali framework copiare (es: --deploy-framework mcp-server-fuzzer)")
    parser.add_argument("--deploy-scanner", action="store_true", help="Copia solo mcp_scanner.py su tutte le 9 VM")
    parser.add_argument("--launch-guard-all", action="store_true", help="Kill + reset + rilancia guard su tutte le 9 VM con range corretti")
    parser.add_argument("--resume-guard-all", action="store_true", help="Kill + riprendi guard su tutte le 9 VM (senza reset)")

    args = parser.parse_args()

    # --deploy-frameworks-all
    if args.deploy_frameworks_all is not None:
        target_vms = args.deploy_frameworks_all if args.deploy_frameworks_all else None
        fw_names = args.deploy_framework if args.deploy_framework else None
        deploy_frameworks_all(target_vms=target_vms, frameworks=fw_names)
        return

    # --deploy-scanner (solo mcp_scanner.py su tutte le VM)
    if args.deploy_scanner:
        deploy_scanner_all()
        return

    # --launch-guard-all / --resume-guard-all
    if args.launch_guard_all or args.resume_guard_all:
        reset = not args.resume_guard_all
        launch_guard_all(reset=reset)
        return

    # --deploy-guard-all
    if args.deploy_guard_all is not None:
        deploy_guard_all(target_vms=args.deploy_guard_all if args.deploy_guard_all else None)
        return

    # --status-guard
    if args.status_guard:
        show_guard_status()
        return

    # --tail-guard
    if args.tail_guard:
        tail_guard_all(lines=50)
        return

    # --deploy-fuzzing-all (or --launch-fuzzing-all for backward compat)
    if args.deploy_fuzzing_all or args.launch_fuzzing_all:
        deploy_fuzzing_all()
        return

    # --status-fuzzing
    if args.status_fuzzing:
        show_fuzzing_status()
        return

    # --tail-fuzzing
    if args.tail_fuzzing:
        tail_fuzzing_all()
        return

    # --deploy-shield-all
    if args.deploy_shield_all is not None:
        deploy_shield_all(target_vms=args.deploy_shield_all if args.deploy_shield_all else None)
        return

    # --status-shield
    if args.status_shield:
        show_shield_status()
        return

    # --tail-shield
    if args.tail_shield:
        tail_shield_all(lines=50) # Increased lines because of full outputs
        return

    # --pull-shield
    if args.pull_shield:
        pull_shield_all()
        if not args.merge_shield:
            return

    # --merge-shield
    if args.merge_shield:
        merge_shield()
        return

    # --deploy-scan-all
    if args.deploy_scan_all is not None:
        deploy_scan_all(target_vms=args.deploy_scan_all if args.deploy_scan_all else None)
        return

    # --status-scan
    if args.status_scan:
        show_scan_status()
        return

    # --tail-scan
    if args.tail_scan:
        tail_scan_all()
        return

    # --pull-watch
    if args.pull_watch:
        pull_watch_all()
        if not args.merge_watch:
            return

    # --merge-watch
    if args.merge_watch:
        merge_watch()
        return

    # --pull-fuzzing
    if args.pull_fuzzing:
        pull_fuzzing_all()
        if not args.merge_fuzzing:
            return

    # --merge-fuzzing
    if args.merge_fuzzing:
        merge_fuzzing()
        return

    # --pull-scan
    if args.pull_scan:
        pull_scan_all()
        if not args.merge_scan:
            return

    # --merge-scan
    if args.merge_scan:
        merge_scan()
        return

    # --deploy-security-scan-all
    if args.deploy_security_scan_all is not None:
        deploy_security_scan_all(target_vms=args.deploy_security_scan_all if args.deploy_security_scan_all else None)
        return

    # --status-security-scan
    if args.status_security_scan:
        show_security_scan_status()
        return

    # --tail-security-scan
    if args.tail_security_scan:
        tail_security_scan_all(lines=50)
        return

    # --pull-security-scan
    if args.pull_security_scan:
        pull_security_scan_all()
        if not args.merge_security_scan:
            return

    # --merge-security-scan
    if args.merge_security_scan:
        merge_security_scan()
        return

    # --deploy-check-all
    if args.deploy_check_all is not None:
        deploy_check_all(target_vms=args.deploy_check_all if args.deploy_check_all else None)
        return

    # --status-check
    if args.status_check:
        show_check_status()
        return

    # --tail-check
    if args.tail_check:
        tail_check_all(lines=50)
        return

    # --pull-check
    if args.pull_check:
        pull_check_all()
        if not args.merge_check:
            return

    # --merge-check
    if args.merge_check:
        merge_check()
        return

    # --deploy-proxy-all
    if args.deploy_proxy_all is not None:
        deploy_proxy_all(target_vms=args.deploy_proxy_all if args.deploy_proxy_all else None)
        return

    # --status-proxy
    if args.status_proxy:
        show_proxy_status()
        return

    # --tail-proxy
    if args.tail_proxy:
        tail_proxy_all(lines=50)
        return

    # --pull-proxy
    if args.pull_proxy:
        pull_proxy_all()
        if not args.merge_proxy:
            return

    # --merge-proxy
    if args.merge_proxy:
        merge_proxy()
        return

    # --status
    if args.status:
        show_status()
        return

    # --tail
    if args.tail:
        tail_log(args.tail)
        return

    # --tail-all
    if args.tail_all:
        tail_all()
        return

    # --pull-guard
    if args.pull_guard:
        pull_guard_all()
        if not args.merge_guard:
            return

    # --merge-guard
    if args.merge_guard:
        merge_guard()
        return

    # --clean-npx
    if args.clean_npx is not None:
        clean_npx_all(target_vms=args.clean_npx if args.clean_npx else None)
        return

    # --pull
    if args.pull is not None:
        if args.pull == "__all__":
            pull_results(list(TOOLS.keys()))
        else:
            if args.pull in TOOLS:
                pull_results([args.pull])
            else:
                print(f"Tool sconosciuto: {args.pull}")
                sys.exit(1)
        return

    # Determine which tools to deploy
    tool_names = [args.tool] if args.tool else list(TOOLS.keys())

    # Deploy
    print("\n[Deploy] script...")
    deploy(tool_names, full=args.full_deploy, frameworks=args.frameworks)

    # --launch (single tool)
    if args.launch:
        print(f"\n Lancio...")
        remote_launch(args.launch, args.start, args.resume)
        cfg = TOOLS[args.launch]
        print(f"\n  Per seguire: ssh {cfg['addr']} \"tail -f ~/Desktop/Pipeline/{cfg['output']}\"")

    # --launch-all
    if args.launch_all:
        print(f"\n Lancio TUTTI i tool...")
        for name in TOOLS:
            remote_launch(name, args.start, args.resume)
        print(f"\n  Tutti lanciati! Usa 'python deploy.py --status' per monitorare.")

    print("\n Done!")


if __name__ == "__main__":
    main()
