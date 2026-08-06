#!/usr/bin/env python3
"""
relist_run.py — ri-interroga `tools/list` sui server della baseline di maggio.

Terza passata, molto piu' leggera delle prime due: **nessun fuzzing, nessuna
analisi statica, nessun LLM**. Per ogni server: clone (o `npm pack` per gli npx),
avvio, una sola chiamata `tools/list`, spegnimento, pulizia. Serve solo a sapere
quali tool il server dichiara OGGI, per confrontarli con quelli di maggio.

ATTENZIONE — DA ESEGUIRE SOLO SULLE VM SANDBOXATE.
Avviare un server MCP significa eseguire codice di terzi non fidato. Durante la
prima analisi questo ha cancellato `~/Desktop` su VM1. Non eseguire su una
macchina personale.

Riusa l'infrastruttura gia' esistente della pipeline (`clone_repo`,
`npm_pack_source`, `detect_language`, `build_mcp_config`, `frameworks/listTools.ts`),
quindi il modo in cui i server vengono avviati e' identico a quello delle due
analisi precedenti — condizione necessaria perche' il confronto sia valido.

Uso (per VM, con shard):
    python autorun/relist_run.py --start 0 --end 700
    python autorun/relist_run.py --start -1 --end 700     # resume
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# I server MCP Python vengono avviati con `uv`, che sta in ~/.local/bin. Quel
# percorso NON e' nel PATH di una shell ssh non interattiva
# (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:...), quindi
# senza questa riga ogni server Python fallisce con `spawn uv ENOENT` e si
# scambia un ambiente rotto per mortalita' dell'ecosistema.
for _p in (Path.home() / ".local" / "bin", Path.home() / ".cargo" / "bin"):
    if _p.is_dir() and str(_p) not in os.environ.get("PATH", "").split(":"):
        os.environ["PATH"] = f"{_p}:{os.environ.get('PATH', '')}"

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from functions.config import TS_SCRIPT, NPX                      # noqa: E402
from functions.buildConfig import (clone_repo, build_mcp_config,  # noqa: E402
                                   npm_pack_source)
from functions.helper import detect_language, force_delete        # noqa: E402

BASELINE = REPO / "autorun" / "baseline_maggio_tools.json"
OUT = REPO / "autorun" / "relist_risultati.json"
STATS = REPO / "autorun" / "relist_stats.json"
TIMEOUT = 90


def npx_command():
    import platform
    return "npx" if platform.system() in ("Darwin", "Linux") else NPX


def lista_tool(repo_path: Path, command: str, args: list) -> list | None:
    """Invoca listTools.ts. None se il server non parte."""
    cmd = [npx_command(), "tsx", str(TS_SCRIPT), str(repo_path), str(command)]
    cmd.extend(str(a) for a in args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        return json.loads(r.stdout)
    except Exception:
        return None


def carica(p: Path, default):
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return default


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", type=int, default=-1, help="-1 = resume")
    ap.add_argument("--end", type=int, default=None)
    a = ap.parse_args()

    base = json.loads(BASELINE.read_text(encoding="utf-8"))
    chiavi = sorted(base)                       # ordine deterministico = shard stabili
    fine = a.end if a.end is not None else len(chiavi)

    ris = carica(OUT, {})
    st = carica(STATS, {})
    # Il floor dello shard va ricordato: se si riprende con --start -1 e il file
    # di stats manca o e' azzerato, senza floor la VM ripartirebbe da 0 e
    # rifarebbe lo shard di un'altra.
    if a.start >= 0:
        # range esplicito: comanda lui. Senza questo, il `last_index` di uno
        # shard precedente gia' concluso (piu' alto del nuovo range) produce un
        # intervallo vuoto e il processo esce subito senza fare nulla.
        floor = inizio = a.start
    else:
        floor = st.get("range_start", 0)
        inizio = max(st.get("last_index", floor - 1) + 1, floor)
    st["range_start"] = floor

    print(f"[relist] range [{inizio}, {fine}) su {len(chiavi):,} server")
    print(f"[relist] uv: {'trovato' if any((Path(p) / 'uv').exists() for p in os.environ['PATH'].split(':')) else 'NON TROVATO — i server Python falliranno'}")
    for i in range(inizio, fine):
        s = chiavi[i]
        rec = base[s]
        # Un server gia' interrogato con successo non si rifa': cosi' il rilancio
        # dopo una correzione d'ambiente ricalcola solo i falliti.
        if ris.get(s, {}).get("esito") == "ok":
            st["last_index"] = i
            continue
        u = rec["server_url"]
        t0 = time.time()
        repo_path = None
        try:
            if u.startswith("http"):
                repo_path = clone_repo(u, Path.cwd())
                lang = detect_language(repo_path)
            else:
                repo_path = npm_pack_source(u, Path.cwd())
                lang = detect_language(repo_path) if repo_path else None

            if not repo_path:
                # `clone_repo` restituisce None anche quando il repo non esiste
                # piu' (cancellato o reso privato). Verificato su tutti i 172
                # casi del 2026-08: 172/172 rispondono "Repository not found".
                # Va distinto dal server che c'e' ma non parte: sono due forme
                # diverse di mortalita'.
                esito, tools = "repo_sparito", None
            else:
                _, command, args = build_mcp_config(repo_path, lang)
                if not command:
                    esito, tools = "not_runnable", None
                else:
                    out = lista_tool(repo_path, command, args)
                    if out is None:
                        esito, tools = "start_failed", None
                    else:
                        esito = "ok"
                        tools = {t.get("name", ""): t.get("description", "")
                                 for t in out if isinstance(t, dict)}
        except Exception as e:
            esito, tools = f"error:{type(e).__name__}", None
        finally:
            if repo_path and Path(repo_path).exists():
                try:
                    force_delete(Path(repo_path))
                except Exception:
                    pass

        ris[s] = {"server_url": u, "esito": esito, "tools": tools,
                  "n_tool_maggio": rec["n_tool"],
                  "secondi": round(time.time() - t0, 1)}
        st["last_index"] = i
        st["range_end"] = fine
        OUT.write_text(json.dumps(ris, ensure_ascii=False), encoding="utf-8")
        STATS.write_text(json.dumps(st), encoding="utf-8")
        if (i - inizio) % 25 == 0:
            ok = sum(1 for v in ris.values() if v["esito"] == "ok")
            print(f"  [{i}/{fine}] {s} -> {esito}   (ok finora: {ok})")

    ok = sum(1 for v in ris.values() if v["esito"] == "ok")
    print(f"\nfatto: {len(ris):,} server processati, {ok:,} avviati con successo")


if __name__ == "__main__":
    main()
