#!/usr/bin/env python3
"""
pull6.py — scarica dalle VM i risultati dei 6 tool completi della rirun.

Scarica SOLO le directory dei findings (non i repository clonati che restano
nelle working dir dei worker): per ogni shard fa un tar.gz sulla VM con le sole
directory in allowlist, lo copia e lo estrae in

    <DEST>/<tool>/<shard>/...

Per il fuzzing esegue prima sulla VM `prefilter_protocol_vm.py`, che riduce i
~1.5 GB di protocol/*.json per shard al solo `protocol_accepted.json` (i server
che hanno ACCETTATO un messaggio malformato); e' lo script gia' previsto dalla
pipeline per il pull.

Uso:
    python autorun/pull6.py --list                # inventario degli shard
    python autorun/pull6.py --prefilter           # solo il pre-filtro fuzzing
    python autorun/pull6.py --pull [--tool guard] # scarica (tutti o un tool)
"""
import argparse
import subprocess
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

USER = "tecnico"
HERE = Path(__file__).resolve().parent
DEST = Path(r"C:\Users\francesco\Desktop\pipeline_rerun_pull")

SSH = ["ssh", "-o", "ConnectTimeout=25", "-o", "StrictHostKeyChecking=no",
       "-o", "ServerAliveInterval=15"]

# Directory dei findings da scaricare, per tool (tutto il resto = cloni/rumore)
KEEP = {
    "guard":         ["static", "dynamic", "fuzzing", "protocol"],
    "scan":          ["server-level", "tool-level"],
    "shield":        ["hidden-instructions", "potential-exfiltration",
                      "sensitive-file-access", "shadowing-detected"],
    "security_scan": ["initialization-error", "dangerous-capabilities", "prompt-injection",
                      "rug-pull", "path-traversal", "sensitive-file-access",
                      "sensitive-resource-exposure", "input-validation", "data-leak",
                      "indirect-prompt-injection", "remote-access-control"],
    "check":         ["handshake", "tool_discovery", "tool_invocation"],
    "fuzzing":       ["exceptions"],          # protocol/ -> protocol_accepted.json
    # watch: solo le 9 categorie usate da stage1/stage2. toxic-flow e
    # server-spoofing sono escluse di proposito: nessuno dei due stage le
    # elabora e toxic-flow da sola pesa piu' di tutto il resto insieme.
    "watch":         ["credential-leak", "data-exfiltration", "input-validation",
                      "steganographic-attack", "protocol-violation", "tool-poisoning",
                      "prompt-injection", "tool-mutation", "access-control"],
}
# File singoli da portare via sempre (glob sulla dir dello shard)
FILES = {
    "guard":         ["mcp_guard_stats.json", "mcp_guard_servers.json"],
    "scan":          ["mcp_scan_stats.json", "mcp_scan_servers.json",
                      "mcp_scan_vulnerabilities.json"],
    "shield":        ["mcp_shield_stats.json", "mcp_shield_servers.json"],
    "security_scan": ["mcp_security_scan_stats.json", "mcp_security_scan_servers.json"],
    "check":         ["mcp_check_stats.json", "mcp_check_servers.json"],
    "fuzzing":       ["fuzzing_stats.json", "fuzzing_servers.json", "protocol_accepted.json"],
    "watch":         ["mcp_watch_stats.json", "mcp_watch_servers.json"],
}

P = "/home/tecnico/Desktop/Pipeline"
GF = "/home/tecnico/gsafe_fuzz"
GG = "/home/tecnico/gsafe"
GW = "/home/tecnico/gsafe_watch"        # watch tranche 1
GW2 = "/home/tecnico/gsafe_watch2"      # watch tranche 2 (rilancio)

# (ip, worker_id) della tranche 2, stessa ripartizione di autorun/watch2/deploy_watch2.py
_WATCH2, _n = [], 0
for _ip, _k in ((132, 3), (133, 5), (134, 3), (136, 4), (137, 4),
                (138, 5), (139, 4), (141, 4), (142, 4)):
    for _ in range(_k):
        _n += 1
        _WATCH2.append((_ip, f"n{_n:02d}"))

# (tool, nome_shard, ip, dir_remota)
SHARDS = [
    # ── guard: VM1 sandbox [0,34552) + VM8 [34552,69104) ──
    ("guard", "vm132_w1", "10.79.6.132", f"{GG}/w1/work/Pipeline/tool_mcp_guard_w1"),
    ("guard", "vm132_w2", "10.79.6.132", f"{GG}/w2/work/Pipeline/tool_mcp_guard_w2"),
    ("guard", "vm141_w1", "10.79.6.141", f"{P}/tool_mcp_guard_w1"),
    ("guard", "vm141_w2", "10.79.6.141", f"{P}/tool_mcp_guard_w2"),
    # ── scan: VM4 ──
    ("scan", "vm136_w1", "10.79.6.136", f"{P}/tool_mcp_scan_w1"),
    ("scan", "vm136_w2", "10.79.6.136", f"{P}/tool_mcp_scan_w2"),
    # ── shield: VM5 [0,34552) + VM9 [34552,69104) ──
    ("shield", "vm137_w1", "10.79.6.137", f"{P}/tool_mcp_shield_w1"),
    ("shield", "vm137_w2", "10.79.6.137", f"{P}/tool_mcp_shield_w2"),
    ("shield", "vm137_w3", "10.79.6.137", f"{P}/tool_mcp_shield_w3"),
    ("shield", "vm142_w1", "10.79.6.142", f"{P}/tool_mcp_shield_w1"),
    ("shield", "vm142_w2", "10.79.6.142", f"{P}/tool_mcp_shield_w2"),
    ("shield", "vm142_w3", "10.79.6.142", f"{P}/tool_mcp_shield_w3"),
    # ── security_scan: VM6 ──
    *[("security_scan", f"vm138_w{i}", "10.79.6.138", f"{P}/tool_mcp_security_scan_w{i}")
      for i in range(1, 7)],
    # ── check: VM7 ──
    ("check", "vm139_w1", "10.79.6.139", f"{P}/tool_mcp_check_w1"),
    ("check", "vm139_w2", "10.79.6.139", f"{P}/tool_mcp_check_w2"),
    # ── fuzzing: 3 worker su ciascuna di 5 VM ──
    *[("fuzzing", f"vm{ip}_w{w}", f"10.79.6.{ip}", f"{GF}/w{w}/work/Pipeline/tool_fuzzing_w{w}")
      for ip in (134, 136, 137, 138, 139) for w in (1, 2, 3)],

    # ── watch, tranche 1 = [0, 33139) ──
    # NB: `tool_mcp_watch` fa parte della rirun SOLO su .133 (e' la run
    # principale, indici 0-21155). Le omonime su .136-.142 sono della run
    # vecchia a 9 shard e NON vanno raccolte.
    ("watch", "t1_vm133_main", "10.79.6.133", f"{P}/tool_mcp_watch"),
    *[("watch", f"t1_vm{ip}_w{w}", f"10.79.6.{ip}",
       f"{GW}/w{w}/work/Pipeline/tool_mcp_watch_w{w}")
      for ip, ws in ((132, (1, 2, 3)), (133, (1, 2, 3, 4)),
                     (141, (1, 2, 3)), (142, (1, 2, 3))) for w in ws],

    # ── watch, tranche 2 = [33139, 69104): 36 worker sulle 9 VM ──
    *[("watch", f"t2_{wid}", f"10.79.6.{ip}",
       f"{GW2}/{wid}/work/Pipeline/tool_mcp_watch_{wid}")
      for ip, wid in _WATCH2],
]


# I nomi delle categorie dei findings derivano dai pattern rilevati e contengono
# caratteri illegali su Windows (: * ? " < > |). Li percent-encodiamo: la
# codifica e' deterministica, quindi lo stesso file mantiene lo stesso nome su
# tutti gli shard e il merge continua ad accoppiarli correttamente.
_ILLEGAL = {c: f"%{ord(c):02X}" for c in '<>:"|?*'}


def win_safe(name: str) -> str:
    for c, repl in _ILLEGAL.items():
        name = name.replace(c, repl)
    return name.rstrip(" .") or "_"


def safe_extract(tf: tarfile.TarFile, outdir: Path) -> int:
    n = 0
    for m in tf.getmembers():
        parts = [win_safe(p) for p in m.name.split("/") if p not in ("", ".", "..")]
        if not parts:
            continue
        target = outdir.joinpath(*parts)
        if m.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not m.isfile():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        src = tf.extractfile(m)
        if src is None:
            continue
        with open(target, "wb") as fh:
            while chunk := src.read(1 << 20):
                fh.write(chunk)
        n += 1
    return n


def ssh(ip, cmd, timeout=3600):
    try:
        r = subprocess.run(SSH + [f"{USER}@{ip}", cmd], capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace")
        return r.returncode == 0, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"


def cmd_list():
    print(f"{'tool':<15} {'shard':<10} {'VM':<14} dir")
    for tool, shard, ip, d in SHARDS:
        print(f"{tool:<15} {shard:<10} {ip:<14} {d}")
    print(f"\n{len(SHARDS)} shard totali")


def prefilter_one(job):
    """Esegue prefilter_protocol_vm.py nella dir dello shard fuzzing."""
    tool, shard, ip, d = job
    ok, out = ssh(ip, f"test -d {d}/protocol && echo HASPROTO || echo NOPROTO", timeout=120)
    if "NOPROTO" in out:
        return f"   {shard}: nessuna dir protocol/ (salto)"
    ok, out = ssh(ip, f"cd {d} && cp /home/tecnico/watch2/prefilter_protocol_vm.py . 2>/dev/null; "
                      f"python3 prefilter_protocol_vm.py", timeout=5400)
    last = out.strip().splitlines()[-1] if out.strip() else ""
    return f"   {shard}: {'ok' if ok else 'FAIL'} {last[:120]}"


def cmd_prefilter():
    fz = [s for s in SHARDS if s[0] == "fuzzing"]
    print(f"distribuisco prefilter_protocol_vm.py ...")
    src = HERE.parent / "fuzzing" / "postprocessing" / "special" / "prefilter_protocol_vm.py"
    ips = sorted({s[2] for s in fz})
    for ip in ips:
        ssh(ip, "mkdir -p ~/watch2")
        subprocess.run(["scp", "-o", "StrictHostKeyChecking=no", "-q", str(src),
                        f"{USER}@{ip}:/home/tecnico/watch2/prefilter_protocol_vm.py"],
                       capture_output=True, timeout=300)
    print(f"pre-filtro protocol su {len(fz)} shard fuzzing (puo' richiedere minuti) ...")
    with ThreadPoolExecutor(max_workers=5) as ex:
        for r in ex.map(prefilter_one, fz):
            print(r)


def pull_one(job):
    tool, shard, ip, d = job
    keep, files = KEEP[tool], FILES[tool]
    inc = " ".join(f"'{k}'" for k in keep) + " " + " ".join(f"'{f}'" for f in files)
    tarball = f"/home/tecnico/watch2/pull_{tool}_{shard}.tar.gz"
    # -h risolve eventuali symlink; gli elementi assenti vengono ignorati
    cmd = (f"cd {d} 2>/dev/null || exit 9; "
           f"L=''; for x in {inc}; do [ -e \"$x\" ] && L=\"$L $x\"; done; "
           f"[ -z \"$L\" ] && exit 8; "
           f"tar czf {tarball} $L 2>/dev/null; du -h {tarball} | cut -f1")
    ok, out = ssh(ip, cmd, timeout=5400)
    if not ok:
        return f"   {tool}/{shard}: FAIL ({out.strip()[:100]})"
    size = out.strip().splitlines()[-1] if out.strip() else "?"

    outdir = DEST / tool / shard
    outdir.mkdir(parents=True, exist_ok=True)
    local_tar = outdir / "pull.tar.gz"
    r = subprocess.run(["scp", "-o", "StrictHostKeyChecking=no", "-q",
                        f"{USER}@{ip}:{tarball}", str(local_tar)],
                       capture_output=True, text=True, timeout=7200)
    if r.returncode != 0:
        return f"   {tool}/{shard}: SCP FAIL {r.stderr[:120]}"
    try:
        with tarfile.open(local_tar, "r:gz") as tf:
            nfiles = safe_extract(tf, outdir)
    except Exception as e:
        return f"   {tool}/{shard}: EXTRACT FAIL {e}"
    local_tar.unlink(missing_ok=True)
    ssh(ip, f"rm -f {tarball}", timeout=120)
    return f"   {tool}/{shard}: ok ({size} compressi, {nfiles} file)"


def cmd_pull(only_tool=None):
    jobs = [s for s in SHARDS if not only_tool or s[0] == only_tool]
    print(f"pull di {len(jobs)} shard -> {DEST}")
    # in parallelo per VM (una VM alla volta per non saturarne il disco/banda)
    by_ip = {}
    for j in jobs:
        by_ip.setdefault(j[2], []).append(j)

    def run_vm(ip):
        return "\n".join(pull_one(j) for j in by_ip[ip])

    with ThreadPoolExecutor(max_workers=len(by_ip)) as ex:
        for r in ex.map(run_vm, by_ip):
            print(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--prefilter", action="store_true")
    ap.add_argument("--pull", action="store_true")
    ap.add_argument("--tool", default=None, choices=sorted(KEEP))
    a = ap.parse_args()
    if a.list or not any((a.list, a.prefilter, a.pull)):
        cmd_list(); return
    if a.prefilter:
        cmd_prefilter()
    if a.pull:
        cmd_pull(a.tool)


if __name__ == "__main__":
    main()
