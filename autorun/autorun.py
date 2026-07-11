#!/usr/bin/env python3
"""
autorun.py — Rilancio automatico e sorvegliato dell'intera analisi MCP sulle 9 VM.

Un solo comando fa TUTTO: preflight -> auto-fix -> deploy codice -> snapshot dei
dati vecchi -> smoke test -> lancio dei 7 tool nel layout scelto -> installazione
di un "guardian" su ogni VM che tiene tutto vivo, libera spazio e fa backup.

    python autorun/autorun.py go          # sequenza completa (chiede conferma prima del lancio vero)
    python autorun/autorun.py go --yes     # come sopra, senza conferma finale

Singole fasi (tutte idempotenti, ri-eseguibili in sicurezza):
    python autorun/autorun.py preflight    # solo verifica stato (sola lettura)
    python autorun/autorun.py fix          # ripristina framework mancanti + pandas
    python autorun/autorun.py deploy        # copia l'ultimo codice sulle VM
    python autorun/autorun.py snapshot      # archivia i risultati vecchi sulle VM
    python autorun/autorun.py smoke         # test 1-server per ogni tool
    python autorun/autorun.py launch --yes  # reset+lancio dei tool + guardian
    python autorun/autorun.py status        # dashboard avanzamento
    python autorun/autorun.py guardian-status  # stato dei guardian
    python autorun/autorun.py finalize      # pull + merge + confronto col backup

LAYOUT (deciso con l'utente — bilanciato, guard e shield splittati; fuzzing
parallelo a 4 worker su VM3, parametri invariati):

    VM1 .132  guard          [0 - 34552)
    VM8 .141  guard          [34552 - 69104)
    VM2 .133  watch          [0 - 69104)
    VM3 .134  fuzzing        [0 - 69104)   -> 4 worker paralleli
    VM4 .136  scan           [0 - 69104)
    VM5 .137  shield         [0 - 34552)
    VM9 .142  shield         [34552 - 69104)
    VM6 .138  security_scan  [0 - 69104)
    VM7 .139  check          [0 - 69104)
"""
import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ── Percorsi ────────────────────────────────────────────────────────────────
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
REMOTE_PIPE = "~/Desktop/Pipeline"
REMOTE_FW = "~/Desktop/Frameworks"
VENV_ACT = "source ~/pipeline-env/bin/activate"
REMOTE_GUARD_DIR = "~/pipeline_rerun"
REMOTE_BACKUP_DIR = "~/pipeline_backups"

TOTAL = 69104
HALF = TOTAL // 2  # 34552
FUZZ_WORKERS = 4
PH = "$HOME/Desktop/Pipeline"   # base path (bash espande $HOME)

# Worker paralleli PER SHARD di ogni tool (per accelerare i tool lenti come
# fatto col fuzzing). Ogni worker gira in una sotto-cartella isolata con la
# propria MCP_CONFIG (e per guard una copia del framework) -> nessuna collisione.
# Scelti per portare tutti i tool a ~1 settimana viste le rate misurate.
# NB: conteggi moderati per il vincolo DISCO (96GB/VM). La cache Go cresce
# molto; con la pulizia read-only corretta (helper.py/guardian) resta limitata,
# ma troppi worker concorrenti saturano comunque. 5/3/2 è il compromesso sicuro.
WORKERS = {
    "guard": 2, "watch": 1, "fuzzing": 3, "scan": 2,
    "shield": 3, "security_scan": 5, "check": 2,
}

EXCEL_NAME = "0.0. All servers unified (69104).xlsx"

# ── Layout: una riga per (tool, shard) ──────────────────────────────────────
# vm, ip, tool, start, end
ASSIGN = [
    ("VM1", "10.79.6.132", "guard",         0,     HALF),
    ("VM8", "10.79.6.141", "guard",         HALF,  TOTAL),
    ("VM2", "10.79.6.133", "watch",         0,     TOTAL),
    ("VM3", "10.79.6.134", "fuzzing",       0,     TOTAL),
    ("VM4", "10.79.6.136", "scan",          0,     TOTAL),
    ("VM5", "10.79.6.137", "shield",        0,     HALF),
    ("VM9", "10.79.6.142", "shield",        HALF,  TOTAL),
    ("VM6", "10.79.6.138", "security_scan", 0,     TOTAL),
    ("VM7", "10.79.6.139", "check",         0,     TOTAL),
]

USER = "tecnico"

# ── Descrizione di ogni tool ────────────────────────────────────────────────
# remote_dir: cartella del tool sulla VM (con prefisso tool_)
# script:     nome dello script run_*.py
# stats:      nome del file di statistiche
# files:      mappa file_locale_relativo -> path_remoto_relativo (sotto ~/Desktop/Pipeline)
FUNCTIONS = {
    "functions/helper.py": "functions/helper.py",
    "functions/buildConfig.py": "functions/buildConfig.py",
    "functions/config.py": "functions/config.py",
    "functions/stats.py": "functions/stats.py",
    "functions/hash.py": "functions/hash.py",
    "functions/hashCache.py": "functions/hashCache.py",
    "functions/recapFramework.py": "functions/recapFramework.py",
}

TOOLS = {
    "guard": {
        "remote_dir": "tool_mcp_guard", "script": "run_guard.py",
        "stats": "mcp_guard_stats.json", "log": "guard_output.log",
        "pgrep": "run_guard.py",
        "files": {
            "mcp_guard/run_guard.py": "tool_mcp_guard/run_guard.py",
            "mcp_guard/merge_stats.py": "tool_mcp_guard/merge_stats.py",
            "frameworks/mcpGuard.py": "frameworks/mcpGuard.py",
        },
    },
    "watch": {
        "remote_dir": "tool_mcp_watch", "script": "run_watch.py",
        "stats": "mcp_watch_stats.json", "log": "watch_output.log",
        "pgrep": "run_watch.py",
        "files": {
            "mcp_watch/run_watch.py": "tool_mcp_watch/run_watch.py",
            "mcp_watch/merge_stats.py": "tool_mcp_watch/merge_stats.py",
            "frameworks/mcpWatch.py": "frameworks/mcpWatch.py",
        },
    },
    "fuzzing": {
        "remote_dir": "tool_fuzzing", "script": "run_fuzzing.py",
        "stats": "fuzzing_stats.json", "log": "fuzzing_output.log",
        "pgrep": "run_fuzzing.py",
        "files": {
            "fuzzing/run_fuzzing.py": "tool_fuzzing/run_fuzzing.py",
            "fuzzing/merge_stats.py": "tool_fuzzing/merge_stats.py",
            "frameworks/fuzzing.py": "frameworks/fuzzing.py",
        },
    },
    "scan": {
        "remote_dir": "tool_mcp_scan", "script": "run_scan.py",
        "stats": "mcp_scan_stats.json", "log": "scan_output.log",
        "pgrep": "run_scan.py",
        "files": {
            "mcp_scan/run_scan.py": "tool_mcp_scan/run_scan.py",
            "frameworks/mcpScan.py": "frameworks/mcpScan.py",
            "npm_runner/npm_build.sh": "npm_runner/npm_build.sh",
        },
    },
    "shield": {
        "remote_dir": "tool_mcp_shield", "script": "run_shield.py",
        "stats": "mcp_shield_stats.json", "log": "shield_output.log",
        "pgrep": "run_shield.py",
        "files": {
            "mcp_shield/run_shield.py": "tool_mcp_shield/run_shield.py",
            "mcp_shield/merge_stats.py": "tool_mcp_shield/merge_stats.py",
            "frameworks/mcpShield.py": "frameworks/mcpShield.py",
            "frameworks/llmAnalysis.py": "frameworks/llmAnalysis.py",
            "frameworks/listTools.ts": "frameworks/listTools.ts",
        },
    },
    "security_scan": {
        "remote_dir": "tool_mcp_security_scan", "script": "run_security_scan.py",
        "stats": "mcp_security_scan_stats.json", "log": "security_scan_output.log",
        "pgrep": "run_security_scan.py",
        "files": {
            "mcp_security_scan/run_security_scan.py": "tool_mcp_security_scan/run_security_scan.py",
            "mcp_security_scan/merge_stats.py": "tool_mcp_security_scan/merge_stats.py",
            "frameworks/mcpSecurityScan.py": "frameworks/mcpSecurityScan.py",
            "npm_runner/npm_build.sh": "npm_runner/npm_build.sh",
        },
    },
    "check": {
        "remote_dir": "tool_mcp_check", "script": "run_check.py",
        "stats": "mcp_check_stats.json", "log": "check_output.log",
        "pgrep": "run_check.py",
        "files": {
            "mcp_check/run_check.py": "tool_mcp_check/run_check.py",
            "frameworks/mcpCheck.py": "frameworks/mcpCheck.py",
            "npm_runner/npm_build.sh": "npm_runner/npm_build.sh",
        },
    },
}

# VM "piene" da cui copiare i framework mancanti verso VM1/VM2
DONOR_GUARD = "10.79.6.141"   # VM8 ha mcp_scanner.py
DONOR_WATCH = "10.79.6.134"   # VM3 ha Frameworks/mcp-watch


def addr(ip):
    return f"{USER}@{ip}"


# ── SSH / SCP helper ────────────────────────────────────────────────────────
SSH_OPTS = ["-o", "ConnectTimeout=12", "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes"]


def ssh(ip, command, timeout=60, capture=True):
    cmd = ["ssh", *SSH_OPTS, addr(ip), command]
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace")
        return r.returncode == 0, (r.stdout or "").strip() if capture else ""
    except subprocess.TimeoutExpired:
        return False, "__TIMEOUT__"
    except Exception as e:
        return False, f"__ERR__ {e}"


def scp(local_path, ip, remote_rel, timeout=300):
    remote = f"{addr(ip)}:{REMOTE_PIPE}/{remote_rel}"
    cmd = ["scp", *SSH_OPTS, str(local_path), remote]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


def each_vm(fn, rows=None, workers=9):
    """Esegue fn(row) su ogni riga di ASSIGN in parallelo. Ritorna lista risultati."""
    rows = rows if rows is not None else ASSIGN
    out = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(fn, r): r for r in rows}
        for f in as_completed(futs):
            out.append((futs[f], f.result()))
    return out


def read_last_index(ip, remote_dir, stats):
    ok, o = ssh(ip, f"cat {REMOTE_PIPE}/{remote_dir}/{stats} 2>/dev/null")
    if ok and o:
        try:
            d = json.loads(o)
            return d.get("last_index", 0), d.get("total", 0), d.get("remaining", "?")
        except Exception:
            pass
    return None, None, None


# ── PREFLIGHT ───────────────────────────────────────────────────────────────
PREFLIGHT_SNIPPET = r'''
set +e
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:$PATH"
P="$HOME/Desktop/Pipeline"; FR="$HOME/Desktop/Frameworks"
V="$HOME/pipeline-env"; PY="$V/bin/python"
echo "reach=OK"
df -h / | tail -1 | awk '{print "disk_free="$4}'
df -h / | tail -1 | awk '{print "disk_used="$5}'
free -m | awk '/Mem:/{print "ram_free_mb="$7}'
[ -x "$PY" ] && echo "venv=OK" || { echo "venv=MISSING"; PY="$(command -v python3)"; }
for m in pandas psutil openpyxl; do "$PY" -c "import $m" 2>/dev/null && echo "py_$m=OK" || echo "py_$m=MISSING"; done
for c in node npx uv uvx git; do command -v $c >/dev/null 2>&1 && echo "bin_$c=OK" || echo "bin_$c=MISSING"; done
[ -f "$FR/mcp-guard/mcp_scanner.py" ] && echo "fw_guard=OK" || echo "fw_guard=MISSING"
[ -d "$FR/mcp-watch" ] && echo "fw_watch=OK" || echo "fw_watch=MISSING"
[ -f "$P/'''+EXCEL_NAME+r'''" ] && echo "dataset=OK" || echo "dataset=MISSING"
pgrep -f '[r]un_.*\.py' >/dev/null 2>&1 && echo "running=YES" || echo "running=no"
'''


def _pg(pattern):
    """Trasforma 'run_guard.py' in '[r]un_guard.py' così pgrep/pkill non
    matchano la shell stessa che contiene il pattern (falso positivo)."""
    return "[" + pattern[0] + "]" + pattern[1:]


def _preflight_one(row):
    _, ip, tool, s, e = row
    ok, out = ssh(ip, PREFLIGHT_SNIPPET, timeout=40)
    d = {"reach": ok}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            d[k.strip()] = v.strip()
    return d


def preflight():
    print("\n=== PREFLIGHT (sola lettura) ===")
    res = {r[1]: (r, d) for r, d in each_vm(_preflight_one)}
    hard = []
    print(f"{'VM':4} {'IP':15} {'tool':14} {'reach':6} {'venv':5} {'pandas':7} "
          f"{'uvx':4} {'fw':10} {'data':5} {'disk':6} {'run'}")
    for row in ASSIGN:
        vm, ip, tool, s, e = row
        d = res.get(ip, (row, {}))[1]
        fw = "-"
        if tool == "guard":
            fw = d.get("fw_guard", "?")
        elif tool == "watch":
            fw = d.get("fw_watch", "?")
        reach = "OK" if d.get("reach") else "DOWN"
        pandas = d.get("py_pandas", "?")
        line = (f"{vm:4} {ip:15} {tool:14} {reach:6} {d.get('venv','?'):5} "
                f"{pandas:7} {d.get('bin_uvx','?'):4} {fw:10} {d.get('dataset','?'):5} "
                f"{d.get('disk_free','?'):6} {d.get('running','?')}")
        print(line)
        if not d.get("reach"):
            hard.append(f"{vm} irraggiungibile")
        if d.get("dataset") == "MISSING":
            hard.append(f"{vm} dataset mancante")
    # gap auto-fixabili (non-hard)
    gaps = []
    for row in ASSIGN:
        vm, ip, tool, s, e = row
        d = res.get(ip, (row, {}))[1]
        if tool == "guard" and d.get("fw_guard") == "MISSING":
            gaps.append(f"{vm}: mcp-guard da ripristinare")
        if tool == "watch" and d.get("fw_watch") == "MISSING":
            gaps.append(f"{vm}: mcp-watch da ripristinare")
        if d.get("py_pandas") == "MISSING":
            gaps.append(f"{vm}: pandas da installare")
    if gaps:
        print("\nGap auto-fixabili (fase 'fix'):")
        for g in gaps:
            print("  -", g)
    if hard:
        print("\n[!] Problemi bloccanti:")
        for h in hard:
            print("  -", h)
    return res, hard, gaps


# ── FIX (ripristino framework + pandas) ─────────────────────────────────────
def _vm_to_ip(vm):
    for r in ASSIGN:
        if r[0] == vm:
            return r[1]
    return None


def fix():
    print("\n=== FIX: ripristino framework mancanti + pandas ===")
    res, hard, gaps = preflight()

    for row in ASSIGN:
        vm, ip, tool, s, e = row
        d = res.get(ip, (row, {}))[1]

        # pandas mancante -> installa (versione del requirements)
        if d.get("py_pandas") == "MISSING":
            print(f"  [{vm}] installo pandas...")
            ssh(ip, "~/pipeline-env/bin/pip install -q 'pandas==2.3.3' openpyxl", timeout=300)

        # guard framework mancante -> copia da donor + pip install -e
        if tool == "guard" and d.get("fw_guard") == "MISSING":
            print(f"  [{vm}] ripristino Frameworks/mcp-guard da {DONOR_GUARD} ...")
            _vm_to_vm_copy(DONOR_GUARD, ip, "mcp-guard")
            ssh(ip, f"~/pipeline-env/bin/pip install -e {REMOTE_FW}/mcp-guard -q", timeout=300)
            ok, _ = ssh(ip, f"test -f {REMOTE_FW}/mcp-guard/mcp_scanner.py && echo OK")
            print(f"     mcp_scanner.py presente: {'sì' if ok else 'NO — verificare'}")

        # watch framework mancante -> copia da donor (con node_modules)
        if tool == "watch" and d.get("fw_watch") == "MISSING":
            print(f"  [{vm}] ripristino Frameworks/mcp-watch da {DONOR_WATCH} (può richiedere qualche minuto)...")
            _vm_to_vm_copy(DONOR_WATCH, ip, "mcp-watch")
            ok, _ = ssh(ip, f"test -d {REMOTE_FW}/mcp-watch/node_modules && echo OK")
            if not ok:
                print(f"     node_modules assente, eseguo npm install...")
                ssh(ip, f"cd {REMOTE_FW}/mcp-watch && npm install --no-audit --no-fund", timeout=600)
    print("Fix completato.")


def _vm_to_vm_copy(src_ip, dst_ip, fw_name):
    """Copia REMOTE_FW/<fw_name> da src a dst facendo passare il tar per il PC locale."""
    ssh(dst_ip, f"mkdir -p {REMOTE_FW}")
    # src: crea tar; dst: estrai. Colleghiamo i due ssh via pipe locale.
    src = ["ssh", *SSH_OPTS, addr(src_ip),
           f"tar czf - -C {REMOTE_FW} {fw_name}"]
    dst = ["ssh", *SSH_OPTS, addr(dst_ip),
           f"tar xzf - -C {REMOTE_FW}"]
    try:
        p1 = subprocess.Popen(src, stdout=subprocess.PIPE)
        p2 = subprocess.Popen(dst, stdin=p1.stdout)
        p1.stdout.close()
        p2.communicate(timeout=1200)
        return p2.returncode == 0
    except Exception as ex:
        print(f"     [!] copia {fw_name} {src_ip}->{dst_ip} fallita: {ex}")
        return False


# ── DEPLOY (sincronizza il codice locale sulle VM) ──────────────────────────
def _deploy_one(row):
    vm, ip, tool, s, e = row
    spec = TOOLS[tool]
    # crea cartelle
    dirs = f"{REMOTE_PIPE}/{spec['remote_dir']} {REMOTE_PIPE}/functions {REMOTE_PIPE}/frameworks {REMOTE_PIPE}/npm_runner"
    ssh(ip, f"mkdir -p {dirs}")
    files = {**FUNCTIONS, **spec["files"]}
    n_ok = 0
    for local_rel, remote_rel in files.items():
        lp = REPO / local_rel
        if lp.exists():
            # normalizza CRLF per gli .sh
            if local_rel.endswith(".sh"):
                b = lp.read_bytes().replace(b"\r\n", b"\n")
                lp.write_bytes(b)
            if scp(lp, ip, remote_rel):
                n_ok += 1
    return f"{vm} {tool}: {n_ok}/{len(files)} file"


def deploy():
    print("\n=== DEPLOY codice sulle VM ===")
    for row, msg in each_vm(_deploy_one):
        print("  ", msg)
    print("Deploy completato.")


# ── SNAPSHOT dei dati vecchi (prima del reset) ──────────────────────────────
def _snapshot_one(row):
    vm, ip, tool, s, e = row
    spec = TOOLS[tool]
    ts = time.strftime("%Y%m%d_%H%M%S")
    dst = f"{REMOTE_BACKUP_DIR}/prelaunch_{ts}"
    d = spec["remote_dir"]
    cmd = (f"mkdir -p {dst} && "
           f"if [ -d {REMOTE_PIPE}/{d} ]; then "
           f"tar czf {dst}/{d}.tar.gz -C {REMOTE_PIPE} {d} 2>/dev/null; fi && echo done")
    ok, _ = ssh(ip, cmd, timeout=600)
    return f"{vm} {tool}: {'ok' if ok else 'FALLITO'}"


def snapshot():
    print("\n=== SNAPSHOT risultati vecchi (su ~/pipeline_backups) ===")
    for row, msg in each_vm(_snapshot_one):
        print("  ", msg)


# ── SMOKE TEST (1 server per tool, in dir usa-e-getta) ──────────────────────
SMOKE_ERR_MARKERS = ("Traceback", "ModuleNotFoundError", "ImportError",
                     "command not found", "No such file", "cannot import")


def _smoke_one(row):
    vm, ip, tool, s, e = row
    spec = TOOLS[tool]
    # dir isolata SOTTO Pipeline: parent.parent resta ~/Desktop/Pipeline
    # (così `from functions...` funziona), ma stats/clone/reports restano separati
    sdir = f"{REMOTE_PIPE}/smoke_{tool}"
    src = f"{REMOTE_PIPE}/{spec['remote_dir']}/{spec['script']}"
    cmd = (f"bash -lc 'rm -rf {sdir} && mkdir -p {sdir} && cp {src} {sdir}/ && "
           f"cd {sdir} && source $HOME/pipeline-env/bin/activate && "
           f"timeout 420 python {sdir}/{spec['script']} --start {s} --end {s+1} --reset "
           f"> {sdir}/smoke.log 2>&1; echo RC=$?; tail -5 {sdir}/smoke.log; rm -rf {sdir}'")
    ok, out = ssh(ip, cmd, timeout=480)
    has_err = any(m in out for m in SMOKE_ERR_MARKERS)
    verdict = "OK" if (ok and not has_err) else "ERRORE"
    tail = out.replace("\n", " | ")[-180:]
    return (verdict, f"{vm} {tool}: {verdict}  … {tail}")


def smoke():
    print("\n=== SMOKE TEST (1 server per tool) — può richiedere alcuni minuti ===")
    results = each_vm(_smoke_one)
    bad = []
    for row, (verdict, msg) in results:
        print("  ", msg)
        if verdict == "ERRORE":
            bad.append(row[0])
    if bad:
        print(f"\n[!] Smoke test con problemi su: {', '.join(bad)} — controlla i tail sopra.")
    return len(bad) == 0


# ── LAUNCH (reset una volta + start + guardian) ─────────────────────────────
def _workers_of(row):
    """Lista dei worker per (tool,shard). n=1 -> tool singolo nella dir
    principale (comportamento originale). n>1 -> sotto-cartelle isolate, ognuna
    con la propria MCP_CONFIG (e per guard una copia del framework) così più
    worker dello stesso tool non collidono sul file di config condiviso."""
    vm, ip, tool, s, e = row
    spec = TOOLS[tool]
    n = WORKERS.get(tool, 1)
    rd = spec["remote_dir"]
    if n == 1:
        return [dict(name=tool, pat=spec["pgrep"], cwd=PH, floor=s, end=e,
                     script=f"{rd}/{spec['script']}",
                     stats=f"{PH}/{rd}/{spec['stats']}",
                     log=f"{PH}/{spec['log']}", env="", pre="")]
    out, span = [], (e - s) // n
    for w in range(n):
        ws = s + w * span
        we = e if w == n - 1 else s + (w + 1) * span
        wd = f"{rd}_w{w+1}"; wdir = f"{PH}/{wd}"
        env = f"MCP_CONFIG={wdir}/claude_desktop_config.json"
        pre = f"mkdir -p {wdir} && cp {PH}/{rd}/{spec['script']} {wdir}/"
        if tool == "guard":  # guard scrive/legge json nella dir del framework:
            # basta copiare mcp_scanner.py (il pacchetto arriva dal venv) e
            # puntarci MCP_GUARD_DIR -> output isolato per worker, nessuna collisione.
            fwsrc = PH.replace("/Desktop/Pipeline", "/Desktop/Frameworks") + "/mcp-guard/mcp_scanner.py"
            env += f" MCP_GUARD_DIR={wdir}/fw"
            pre += f" && mkdir -p {wdir}/fw && cp {fwsrc} {wdir}/fw/"
        out.append(dict(name=f"{tool}_w{w+1}", pat=f"{wd}/{spec['script']}",
                        cwd=wdir, floor=ws, end=we, script=f"{wdir}/{spec['script']}",
                        stats=f"{wdir}/{spec['stats']}", log=f"{PH}/{wd}.log",
                        env=env, pre=pre))
    return out


def _launch_row(row):
    vm, ip, tool, s, e = row
    spec = TOOLS[tool]
    # kill eventuali processi vecchi del tool (bracket-trick)
    ssh(ip, f"pkill -9 -f '{_pg(spec['pgrep'])}' 2>/dev/null; sleep 1")
    workers = _workers_of(row)
    msgs = []
    for wk in workers:
        prep = f"{wk['pre']} && " if wk["pre"] else ""
        envp = f"export {wk['env']} && " if wk["env"] else ""
        cmd = (f"bash -lc '{prep}cd {wk['cwd']} && {VENV_ACT} && {envp}"
               f"setsid nohup python {wk['script']} --start {wk['floor']} --end {wk['end']} --reset "
               f"> {wk['log']} 2>&1 < /dev/null &'")
        ok, _ = ssh(ip, cmd, timeout=120)  # la copia del framework (guard) può richiedere tempo
        msgs.append(f"[{wk['floor']}-{wk['end']}):{'ok' if ok else 'FAIL'}")
    return f"{vm} {tool} ×{len(workers)} -> " + " ".join(msgs)


def _guardian_tasks(row):
    """TSV a 9 colonne (name, pat, cwd, stats, floor, end, script, log, env)
    per ogni worker. 'floor' = indice di partenza dello shard: il guardian
    riprende sempre da max(last_index, floor); 'env' = variabili da esportare
    (MCP_CONFIG / MCP_GUARD_DIR per i worker isolati)."""
    lines = []
    for wk in _workers_of(row):
        lines.append("\t".join([
            wk["name"], wk["pat"], wk["cwd"], wk["stats"],
            str(wk["floor"]), str(wk["end"]), wk["script"], wk["log"],
            wk["env"]]))
    return "\n".join(lines) + "\n"


def _install_guardian(row):
    """Genera guardian_tasks.tsv, avvia il guardian e mette un cron @reboot."""
    vm, ip = row[0], row[1]
    ssh(ip, f"mkdir -p {REMOTE_GUARD_DIR} {REMOTE_BACKUP_DIR}")

    scp_ok = subprocess.run(
        ["scp", *SSH_OPTS, str(HERE / "guardian.sh"),
         f"{addr(ip)}:{REMOTE_GUARD_DIR}/guardian.sh"],
        capture_output=True).returncode == 0

    tsv = _guardian_tasks(row)
    ssh(ip, f"cat > {REMOTE_GUARD_DIR}/guardian_tasks.tsv <<'GUARDIAN_EOF'\n{tsv}GUARDIAN_EOF")

    # cron @reboot: il guardian riparte anche se la VM si riavvia (idempotente)
    reboot_cmd = (f"@reboot bash -lc 'cd {REMOTE_GUARD_DIR} && "
                  f"nohup bash guardian.sh > guardian.log 2>&1 &'")
    ssh(ip, "(crontab -l 2>/dev/null | grep -v guardian.sh; "
            f"echo \"{reboot_cmd}\") | crontab - 2>/dev/null")

    # avvia il guardian (kill vecchio + nohup); bracket-trick nel pkill
    ssh(ip, f"pkill -9 -f '{_pg('guardian.sh')}' 2>/dev/null; sleep 1")
    ssh(ip, f"bash -lc 'cd {REMOTE_GUARD_DIR} && chmod +x guardian.sh && "
            f"nohup bash guardian.sh > guardian.log 2>&1 < /dev/null & disown'", timeout=20)
    time.sleep(1)
    ok, o = ssh(ip, f"pgrep -f '{_pg('guardian.sh')}' >/dev/null && echo UP")
    up = ok and "UP" in o
    return f"{vm}: guardian {'attivo' if (up and scp_ok) else 'PROBLEMA'}"


def launch(assume_yes=False, only=None):
    """Lancia i tool. only=set di tool -> rilancia solo quelli (utile per
    parallelizzare/accelerare senza toccare i tool già in corsa)."""
    rows = [r for r in ASSIGN if (not only or r[2] in only)]
    if not assume_yes:
        tgt = "TUTTI i tool" if not only else ", ".join(sorted(only))
        print(f"\n[!] Sto per RESETTARE e (ri)lanciare: {tgt}")
        print("    (i dati vecchi sono già archiviati con 'snapshot').")
        r = input("    Procedo? [scrivi 'si' per continuare] ").strip().lower()
        if r not in ("si", "sì", "s", "yes", "y"):
            print("Annullato.")
            return
    print("\n=== LAUNCH: avvio dei tool ===")
    for row, msg in each_vm(_launch_row, rows=rows):
        print("  ", msg)
    print("\n=== GUARDIAN: installazione ===")
    for row, msg in each_vm(_install_guardian, rows=rows):
        print("  ", msg)
    print("\nFatto. Monitora con:  python autorun/autorun.py status")


# ── STATUS ──────────────────────────────────────────────────────────────────
def _status_one(row):
    vm, ip, tool, s, e = row
    workers = _workers_of(row)
    done = 0
    running = 0
    for wk in workers:
        # stats path relativo a Pipeline: toglie il prefisso "$HOME/Desktop/Pipeline/"
        rel = wk["stats"].replace(PH + "/", "")
        d = rel.rsplit("/", 1)[0]; sname = rel.rsplit("/", 1)[-1]
        li, _, _ = read_last_index(ip, d, sname)
        if li is not None:
            done += max(0, li - wk["floor"])
        ok, o = ssh(ip, f"pgrep -f '{_pg(wk['pat'])}' >/dev/null && echo Y")
        running += 1 if (ok and "Y" in o) else 0
    n = len(workers)
    stato = "RUNNING" if running == n else (f"{running}/{n} worker" if running else "stopped")
    return (vm, tool, f"{done}/{e-s}", stato)


def status():
    print("\n=== STATUS ===")
    print(f"{'VM':5} {'tool':14} {'progress':16} {'stato'}")
    rows = sorted(each_vm(_status_one), key=lambda x: x[1][0])
    for _, (vm, tool, prog, st) in rows:
        print(f"{vm:5} {tool:14} {prog:16} {st}")


def guardian_status():
    print("\n=== GUARDIAN status ===")
    def _g(row):
        vm, ip = row[0], row[1]
        ok, o = ssh(ip, "pgrep -f '[g]uardian.sh' >/dev/null && echo UP || echo down; "
                        f"tail -2 {REMOTE_GUARD_DIR}/guardian.log 2>/dev/null")
        return f"{vm}: {o.replace(chr(10),' | ')}"
    for _, m in each_vm(_g):
        print("  ", m)


# ── GO (sequenza completa) ──────────────────────────────────────────────────
def go(assume_yes=False, skip_smoke=False):
    res, hard, gaps = preflight()
    if hard:
        print("\n[!] Ci sono problemi bloccanti — risolvili prima di procedere.")
        return
    fix()
    deploy()
    snapshot()
    if not skip_smoke:
        if not smoke():
            print("\n[!] Alcuni smoke test sono falliti. Correggi prima di lanciare "
                  "(oppure ri-lancia con --skip-smoke se sai cosa stai facendo).")
            return
    launch(assume_yes=assume_yes)


# ── FINALIZE ────────────────────────────────────────────────────────────────
def finalize():
    print("\n=== FINALIZE: pull + merge + confronto ===")
    print("Delego a compare_results.py (pull dei risultati + confronto col backup).")
    subprocess.run([sys.executable, str(HERE / "compare_results.py"), "--pull"])


def main():
    ap = argparse.ArgumentParser(description="Rilancio automatico analisi MCP sulle 9 VM")
    ap.add_argument("cmd", nargs="?", default="preflight",
                    choices=["go", "preflight", "fix", "deploy", "snapshot",
                             "smoke", "launch", "status", "guardian-status", "finalize"])
    ap.add_argument("--yes", action="store_true", help="Non chiedere conferma al lancio")
    ap.add_argument("--skip-smoke", action="store_true", help="Salta gli smoke test")
    ap.add_argument("--only", default="", help="launch: solo questi tool (csv), es: --only security_scan,scan")
    args = ap.parse_args()
    only = set(t.strip() for t in args.only.split(",") if t.strip()) or None

    if args.cmd == "preflight":
        preflight()
    elif args.cmd == "fix":
        fix()
    elif args.cmd == "deploy":
        deploy()
    elif args.cmd == "snapshot":
        snapshot()
    elif args.cmd == "smoke":
        smoke()
    elif args.cmd == "launch":
        launch(assume_yes=args.yes, only=only)
    elif args.cmd == "status":
        status()
    elif args.cmd == "guardian-status":
        guardian_status()
    elif args.cmd == "finalize":
        finalize()
    elif args.cmd == "go":
        go(assume_yes=args.yes, skip_smoke=args.skip_smoke)


if __name__ == "__main__":
    main()
