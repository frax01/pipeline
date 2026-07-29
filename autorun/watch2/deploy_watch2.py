#!/usr/bin/env python3
"""
deploy_watch2.py — rilancia mcp-watch sulla parte mancante del dataset.

La prima tranche della rirun ha coperto [0, 33139); questo script partiziona
[33139, 69104) fra N worker sandboxed distribuiti su tutte le 9 VM, li avvia e
installa il keeper (cron) che li riprende in resume se cadono.

Ogni worker gira in una sandbox systemd separata (HOME redirezionato,
/home/tecnico/Desktop inaccessibile): i server MCP analizzati sono codice non
fidato e almeno uno di essi cancella ~/Desktop.

Uso:
    python autorun/watch2/deploy_watch2.py --plan        # mostra solo il piano
    python autorun/watch2/deploy_watch2.py --template    # (ri)costruisce+distribuisce il template
    python autorun/watch2/deploy_watch2.py --launch      # crea le sandbox e avvia i worker
    python autorun/watch2/deploy_watch2.py --keeper      # installa il keeper in cron
    python autorun/watch2/deploy_watch2.py --status      # avanzamento dei worker
    python autorun/watch2/deploy_watch2.py --go          # template + launch + keeper
"""
import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
USER = "tecnico"
TEMPLATE_VM = "10.79.6.133"          # VM con la sandbox watch di riferimento

START = 33139                        # fine della prima tranche
END = 69104                          # dimensione del dataset unico

# VM -> numero di worker (pesato sullo spazio disco libero misurato)
VMS = {
    "10.79.6.132": 3,
    "10.79.6.133": 5,
    "10.79.6.134": 3,
    "10.79.6.136": 4,
    "10.79.6.137": 4,
    "10.79.6.138": 5,
    "10.79.6.139": 4,
    "10.79.6.141": 4,
    "10.79.6.142": 4,
}

SSH = ["ssh", "-o", "ConnectTimeout=25", "-o", "StrictHostKeyChecking=no",
       "-o", "ServerAliveInterval=15"]


def ssh(ip, cmd, timeout=600):
    try:
        r = subprocess.run(SSH + [f"{USER}@{ip}", cmd], capture_output=True,
                           text=True, timeout=timeout, encoding="utf-8", errors="replace")
        return r.returncode == 0, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"


def scp(src, ip, dst, timeout=1800):
    try:
        r = subprocess.run(["scp", "-o", "ConnectTimeout=25",
                            "-o", "StrictHostKeyChecking=no", "-q", str(src),
                            f"{USER}@{ip}:{dst}"],
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"


def build_plan():
    """Partiziona [START, END) fra tutti i worker: chunk contigui, uno per worker."""
    total_workers = sum(VMS.values())
    span = END - START
    base, extra = divmod(span, total_workers)
    plan, cur, gid = [], START, 0
    for ip, n in VMS.items():
        for _ in range(n):
            gid += 1
            size = base + (1 if gid <= extra else 0)
            plan.append({"ip": ip, "wid": f"n{gid:02d}", "start": cur, "end": cur + size})
            cur += size
    assert cur == END, f"partizione incoerente: {cur} != {END}"
    return plan


def cmd_plan(plan):
    print(f"{'VM':<14} {'worker':<6} {'start':>7} {'end':>7} {'server':>7}")
    for p in plan:
        print(f"{p['ip']:<14} {p['wid']:<6} {p['start']:>7} {p['end']:>7} {p['end']-p['start']:>7}")
    print(f"\n{len(plan)} worker su {len(VMS)} VM — "
          f"{END-START:,} server da analizzare ([{START}, {END}))")


def cmd_template():
    print(f"[1/2] costruisco il template su {TEMPLATE_VM} ...")
    ok, out = ssh(TEMPLATE_VM, "mkdir -p ~/watch2 && bash ~/watch2/build_template.sh", timeout=1800)
    print(out.strip()[-1500:])
    if not ok:
        sys.exit("build del template FALLITO")

    local = HERE / "template.tar.gz"
    print(f"[2/2] scarico il template e lo distribuisco alle altre VM ...")
    r = subprocess.run(["scp", "-o", "StrictHostKeyChecking=no", "-q",
                        f"{USER}@{TEMPLATE_VM}:/home/tecnico/watch2/template.tar.gz", str(local)],
                       capture_output=True, text=True, timeout=3600)
    if r.returncode != 0:
        sys.exit(f"download template FALLITO: {r.stderr}")
    print(f"   template locale: {local.stat().st_size/1e6:.1f} MB")

    def push(ip):
        if ip == TEMPLATE_VM:
            return ip, True, "gia' presente"
        ssh(ip, "mkdir -p ~/watch2")
        ok, out = scp(local, ip, "/home/tecnico/watch2/template.tar.gz")
        return ip, ok, out.strip()[:200]

    with ThreadPoolExecutor(max_workers=9) as ex:
        for ip, ok, msg in ex.map(push, VMS):
            print(f"   {ip}: {'ok' if ok else 'FAIL ' + msg}")


def push_scripts():
    """Copia setup_worker.sh / keeper2.sh / build_template.sh su tutte le VM."""
    def push(ip):
        ssh(ip, "mkdir -p ~/watch2")
        oks = []
        for f in ("setup_worker.sh", "keeper2.sh", "build_template.sh"):
            ok, _ = scp(HERE / f, ip, f"/home/tecnico/watch2/{f}")
            oks.append(ok)
        ssh(ip, "chmod +x ~/watch2/*.sh")
        return ip, all(oks)
    with ThreadPoolExecutor(max_workers=9) as ex:
        for ip, ok in ex.map(push, VMS):
            print(f"   script -> {ip}: {'ok' if ok else 'FAIL'}")


def cmd_launch(plan):
    print("distribuisco gli script ...")
    push_scripts()

    by_vm = {}
    for p in plan:
        by_vm.setdefault(p["ip"], []).append(p)

    def launch(ip):
        out = []
        for p in by_vm[ip]:
            ok, o = ssh(ip, f"bash ~/watch2/setup_worker.sh {p['wid']} {p['start']} {p['end']}",
                        timeout=1800)
            out.append(f"   {ip} {p['wid']} [{p['start']}-{p['end']}): "
                       f"{'ok' if ok else 'FAIL'} {o.strip().splitlines()[-1] if o.strip() else ''}")
        # tasks.tsv per il keeper
        tsv = "".join(
            f"watch2_{p['wid']}\t/home/tecnico/gsafe_watch2/{p['wid']}"
            f"\ttool_mcp_watch_{p['wid']}\t{p['end']}\n" for p in by_vm[ip])
        ssh(ip, f"cat > ~/watch2/tasks.tsv <<'EOF'\n{tsv}EOF")
        return "\n".join(out)

    with ThreadPoolExecutor(max_workers=9) as ex:
        for res in ex.map(launch, by_vm):
            print(res)


def cmd_keeper():
    def install(ip):
        cron = ("*/15 * * * * /bin/bash /home/tecnico/watch2/keeper2.sh >/dev/null 2>&1")
        boot = ("@reboot /bin/bash /home/tecnico/watch2/keeper2.sh >/dev/null 2>&1")
        cmd = (f"( crontab -l 2>/dev/null | grep -v 'watch2/keeper2.sh' ; "
               f"echo '{cron}' ; echo '{boot}' ) | crontab -")
        ok, out = ssh(ip, cmd)
        return ip, ok, out.strip()[:200]
    with ThreadPoolExecutor(max_workers=9) as ex:
        for ip, ok, msg in ex.map(install, VMS):
            print(f"   keeper -> {ip}: {'ok' if ok else 'FAIL ' + msg}")


def cmd_status(plan):
    by_vm = {}
    for p in plan:
        by_vm.setdefault(p["ip"], []).append(p)

    def probe(ip):
        rows = []
        for p in by_vm[ip]:
            s = (f"/home/tecnico/gsafe_watch2/{p['wid']}/work/Pipeline/"
                 f"tool_mcp_watch_{p['wid']}/mcp_watch_stats.json")
            cmd = (f"echo -n \"$(systemctl is-active watch2_{p['wid']} 2>/dev/null)|\"; "
                   f"python3 -c \"import json;print(json.load(open('{s}')).get('last_index',0))\" "
                   f"2>/dev/null || echo 0")
            ok, out = ssh(ip, cmd, timeout=90)
            st, _, li = (out.strip().splitlines()[-1] if out.strip() else "?|0").partition("|")
            try:
                li = int(li)
            except ValueError:
                li = 0
            rows.append((p, st, li))
        return ip, rows

    done = tot = 0
    with ThreadPoolExecutor(max_workers=9) as ex:
        for ip, rows in ex.map(probe, by_vm):
            for p, st, li in rows:
                span = p["end"] - p["start"]
                cur = max(0, min(li, p["end"]) - p["start"]) if li else 0
                done += cur
                tot += span
                pct = cur / span * 100 if span else 0
                bar = "#" * int(pct / 10) + "." * (10 - int(pct / 10))
                print(f"{ip:<14} {p['wid']:<5} {st:<10} [{bar}] {pct:5.1f}%  "
                      f"{cur:>5}/{span:<5} ({p['start']}-{p['end']})")
    print(f"\nTRANCHE 2: {done:,}/{tot:,} = {done/tot*100:.2f}%")
    print(f"TOTALE watch: {START+done:,}/{END:,} = {(START+done)/END*100:.2f}%")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--template", action="store_true")
    ap.add_argument("--launch", action="store_true")
    ap.add_argument("--keeper", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--go", action="store_true")
    a = ap.parse_args()

    plan = build_plan()
    if a.plan or not any(vars(a).values()):
        cmd_plan(plan); return
    if a.template or a.go:
        push_scripts(); cmd_template()
    if a.launch or a.go:
        cmd_launch(plan)
    if a.keeper or a.go:
        cmd_keeper()
    if a.status:
        cmd_status(plan)


if __name__ == "__main__":
    main()
