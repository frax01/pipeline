#!/usr/bin/env python3
"""
compare_results.py — scarica i risultati della rirun dalle 9 VM, unisce gli shard
e li confronta con il backup precedente (pipeline_DATI_BACKUP).

    python autorun/compare_results.py --pull        # scarica stats+output dalle VM
    python autorun/compare_results.py --compare      # confronta col backup
    python autorun/compare_results.py --pull --compare

Il confronto di primo livello è sulle STATISTICHE GREZZE (server processati,
conteggi per categoria di ogni tool). Il confronto sui Veri Positivi finali
richiede il post-processing (stage1/stage2) sui dati grezzi scaricati — vedi
README_AUTORUN.md.
"""
import argparse
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
OUT = REPO / "rerun_results"
BACKUP = Path.home() / "Desktop" / "pipeline_DATI_BACKUP"
REMOTE_PIPE = "~/Desktop/Pipeline"

# Import del layout da autorun.py (stessa cartella)
import importlib.util
_spec = importlib.util.spec_from_file_location("autorun", HERE / "autorun.py")
_ar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ar)
ASSIGN, TOOLS, FUZZ_WORKERS = _ar.ASSIGN, _ar.TOOLS, _ar.FUZZ_WORKERS
SSH_OPTS = _ar.SSH_OPTS


def _scp_from(ip, remote_rel, local_path):
    local_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["scp", *SSH_OPTS, f"tecnico@{ip}:{REMOTE_PIPE}/{remote_rel}", str(local_path)]
    return subprocess.run(cmd, capture_output=True).returncode == 0


def _pull_dir(ip, remote_dir, local_dir):
    """Scarica una cartella di risultati via tar."""
    local_dir.mkdir(parents=True, exist_ok=True)
    tar = subprocess.Popen(
        ["ssh", *SSH_OPTS, f"tecnico@{ip}",
         f"tar czf - -C {REMOTE_PIPE} {remote_dir} 2>/dev/null"],
        stdout=subprocess.PIPE)
    ext = subprocess.Popen(["tar", "xzf", "-", "-C", str(local_dir)],
                           stdin=tar.stdout)
    tar.stdout.close()
    ext.communicate()
    return ext.returncode == 0


def pull():
    print(f"=== PULL risultati -> {OUT} ===")
    OUT.mkdir(parents=True, exist_ok=True)
    for vm, ip, tool, s, e in ASSIGN:
        spec = TOOLS[tool]
        if tool == "fuzzing":
            for w in range(FUZZ_WORKERS):
                rd = f"tool_fuzzing_w{w+1}"
                ok = _pull_dir(ip, rd, OUT / f"{vm}_{rd}")
                print(f"  {vm} {rd}: {'ok' if ok else 'FALLITO'}")
        else:
            ok = _pull_dir(ip, spec["remote_dir"], OUT / f"{vm}_{spec['remote_dir']}")
            print(f"  {vm} {tool}: {'ok' if ok else 'FALLITO'}")
    print("Pull completato.")


def _load_json(p):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return None


def _find_stats_files(root, stats_name):
    return list(Path(root).rglob(stats_name)) if Path(root).exists() else []


def _sum_numeric(dicts, key):
    tot = 0
    for d in dicts:
        v = d.get(key) if isinstance(d, dict) else None
        if isinstance(v, (int, float)):
            tot += v
    return tot


def compare():
    print(f"=== CONFRONTO nuovo (rerun_results) vs backup ({BACKUP.name}) ===")
    lines = ["# Confronto rirun vs backup precedente\n"]
    for tool in ["guard", "watch", "fuzzing", "scan", "shield", "security_scan", "check"]:
        spec = TOOLS[tool]
        stats_name = spec["stats"]
        # nuovi shard
        new_files = _find_stats_files(OUT, stats_name)
        new_stats = [_load_json(f) for f in new_files]
        new_stats = [d for d in new_stats if d]
        new_total = _sum_numeric(new_stats, "total")
        new_last = max([d.get("last_index", 0) for d in new_stats], default=0)
        # vecchi (nel backup, per nome file)
        old_files = _find_stats_files(BACKUP, stats_name)
        old_stats = [_load_json(f) for f in old_files]
        old_stats = [d for d in old_stats if d]
        old_total = _sum_numeric(old_stats, "total")

        lines.append(f"\n## {tool}")
        lines.append(f"- shard nuovi trovati: {len(new_stats)} | server processati (somma `total`): "
                     f"**{new_total}** (last_index max {new_last})")
        lines.append(f"- backup: {len(old_stats)} file stats | server processati: **{old_total}**")
        delta = new_total - old_total
        lines.append(f"- Δ server processati: **{delta:+d}**")
        print(f"  {tool:14} nuovo={new_total:<7} vecchio={old_total:<7} Δ={delta:+d}")

    report = OUT / "CONFRONTO.md"
    OUT.mkdir(parents=True, exist_ok=True)
    report.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nReport scritto in {report}")
    print("NB: confronto di primo livello (statistiche grezze). Per i Veri Positivi "
          "finali serve il post-processing sui dati scaricati in rerun_results/.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pull", action="store_true")
    ap.add_argument("--compare", action="store_true")
    args = ap.parse_args()
    if not (args.pull or args.compare):
        args.pull = args.compare = True
    if args.pull:
        pull()
    if args.compare:
        compare()


if __name__ == "__main__":
    main()
