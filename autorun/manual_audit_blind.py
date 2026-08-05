#!/usr/bin/env python3
"""
manual_audit_blind.py — campione CIECO per misurare la concordanza inter-rater.

Estrae dai verdetti gia' dati nella prima analisi (`docs/MANUAL.md`) un campione
di casi, ne recupera il sorgente da GitHub e li presenta **senza il verdetto
originale**. Ri-giudicandoli alla cieca e confrontando si ottiene un numero di
concordanza da riportare nell'articolo, invece di una nota qualitativa sul fatto
che l'auditor e' cambiato.

    autorun/manual_audit/cieco_da_giudicare.json  -> senza verdetto (input)
    autorun/manual_audit/cieco_chiave.json        -> con verdetto (NON aprire prima)

Uso:
    python autorun/manual_audit_blind.py --estrai --n 30
    python autorun/manual_audit_blind.py --confronta   # dopo aver giudicato
"""
import argparse
import json
import re
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANUAL = REPO / "docs" / "MANUAL.md"
OUT = REPO / "autorun" / "manual_audit"
CTX = 12

# Le tabelle di MANUAL.md non hanno lo stesso ordine di colonne in tutte le
# sezioni (§1 usa File:Line, §2 "Tipo server", §3 Evidence...). Quindi non si
# parsa per posizione: si spezza la riga sulle pipe e si cerca in QUALSIASI cella
# il verdetto, il repo e il riferimento file:riga.
VERDETTO = re.compile(r"\b(VP-C|VP-L|VP-D|FP)\b")
REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
FILE_RE = re.compile(r"^[\w./_-]+\.\w+(?::\d+)?$")


def parse_riga(riga):
    """Ritorna (repo, file, line, verdetto) leggendo le celle in ordine libero."""
    if not riga.lstrip().startswith("|"):
        return None
    celle = [c.strip() for c in riga.strip().strip("|").split("|")]
    if len(celle) < 3:
        return None
    repo = file = line = verdetto = None
    for c in celle:
        nudo = c.replace("*", "").strip()
        tick = re.findall(r"`([^`]+)`", c)
        for t in tick:
            if repo is None and REPO_RE.match(t):
                repo = t
            elif file is None and FILE_RE.match(t):
                file = t
        # il verdetto e' la prima cella che e' SOLO un verdetto (+ eventuale
        # parentesi col giudizio della pipeline): evita di pescarlo dalle note
        if verdetto is None:
            m = VERDETTO.match(nudo)
            if m and len(nudo) <= 20:
                verdetto = m.group(1)
    if not (repo and verdetto):
        return None
    if file and ":" in file:
        f, _, l = file.rpartition(":")
        try:
            line = int(l); file = f
        except ValueError:
            pass
    return repo, file, line, verdetto


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "manual-audit/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


_TREE = {}


def risolvi_path(repo, path):
    """I percorsi in MANUAL.md sono abbreviati (es. `server.py` invece di
    `src/pkg/server.py`): li si risolve elencando l'albero del repo e cercando
    il percorso che termina con quello citato. Ritorna (path_completo, branch)."""
    if repo not in _TREE:
        alberi = {}
        for br in ("main", "master"):
            try:
                d = json.loads(fetch(
                    f"https://api.github.com/repos/{repo}/git/trees/{br}?recursive=1"))
                alberi[br] = [t["path"] for t in d.get("tree", []) if t.get("type") == "blob"]
                break
            except Exception:
                continue
        _TREE[repo] = alberi
        time.sleep(0.6)                      # API non autenticata: 60 req/ora
    for br, paths in _TREE[repo].items():
        p = str(path).lstrip("/")
        cand = [x for x in paths if x == p or x.endswith("/" + p)]
        if not cand:                          # ultimo tentativo: solo il basename
            base = p.rsplit("/", 1)[-1]
            cand = [x for x in paths if x.rsplit("/", 1)[-1] == base]
        if cand:
            return min(cand, key=len), br
    return None, None


def cmd_estrai(n):
    testo = MANUAL.read_text(encoding="utf-8").splitlines()
    cat = None
    casi = []
    for riga in testo:
        m = re.match(r"^##\s+\d+\.\s+([a-z-]+)", riga)
        if m:
            cat = m.group(1)
            continue
        p = parse_riga(riga)
        if not p or not cat:
            continue
        repo, f, l, verdetto = p
        casi.append({"categoria": cat, "repo": repo, "file": f, "line": l,
                     "verdetto_originale": verdetto,
                     "nota_originale": riga.strip()[:300]})

    # campiona uniformemente sulle categorie disponibili
    per_cat = {}
    for c in casi:
        per_cat.setdefault(c["categoria"], []).append(c)
    sel, giro = [], 0
    while len(sel) < n and giro < 20:
        for c in sorted(per_cat):
            if len(per_cat[c]) > giro and len(sel) < n:
                sel.append(per_cat[c][giro])
        giro += 1

    ok = 0
    for rec in sel:
        testo_file = None
        if rec.get("file"):
            full, br = risolvi_path(rec["repo"], rec["file"])
            if full:
                try:
                    testo_file = fetch(
                        f"https://raw.githubusercontent.com/{rec['repo']}/{br}/{full}")
                    rec["file_risolto"] = full
                except Exception:
                    pass
        if testo_file is None:
            rec["sorgente"] = {"errore": "path non risolto o repo non disponibile"}
            continue
        righe = testo_file.splitlines()
        if rec["line"] and 1 <= rec["line"] <= len(righe):
            a, b = max(0, rec["line"] - 1 - CTX), min(len(righe), rec["line"] + CTX)
            rec["sorgente"] = {"estratto": "\n".join(
                f"{i+1:5d}| {righe[i]}" for i in range(a, b))[:6000]}
        else:
            rec["sorgente"] = {"estratto": "\n".join(
                f"{i+1:5d}| {righe[i]}" for i in range(min(40, len(righe))))[:6000]}
        ok += 1
        time.sleep(0.25)

    OUT.mkdir(parents=True, exist_ok=True)
    json.dump(sel, open(OUT / "cieco_chiave.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    cieco = [{k: v for k, v in r.items()
              if k not in ("verdetto_originale", "nota_originale")} for r in sel]
    json.dump(cieco, open(OUT / "cieco_da_giudicare.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print(f"casi estratti da MANUAL.md: {len(casi)}")
    print(f"campione cieco: {len(sel)} (sorgente recuperato per {ok})")
    print(f"  -> {OUT/'cieco_da_giudicare.json'}  (input, senza verdetto)")
    print(f"  -> {OUT/'cieco_chiave.json'}        (chiave, non aprire prima)")


def cmd_confronta():
    chiave = {(r["repo"], r["file"], r["line"]): r
              for r in json.load(open(OUT / "cieco_chiave.json", encoding="utf-8"))}
    p = OUT / "cieco_verdetti.json"
    if not p.exists():
        raise SystemExit(f"manca {p}: prima vanno dati i verdetti alla cieca")
    dati = json.load(open(p, encoding="utf-8"))
    acc = disacc = 0
    righe = []
    for v in dati:
        k = (v["repo"], v["file"], v.get("line"))
        orig = chiave.get(k)
        if not orig:
            continue
        uguale = v["verdetto"] == orig["verdetto_originale"]
        acc += uguale
        disacc += not uguale
        righe.append((v["repo"], orig["verdetto_originale"], v["verdetto"], uguale))
    tot = acc + disacc
    print(f"concordanza inter-rater: {acc}/{tot} = {acc/tot*100:.1f}%\n" if tot else "nessun confronto")
    for r, a, b, u in righe:
        if not u:
            print(f"  DIVERGE  {r:<45} prima={a:<6} ora={b}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--estrai", action="store_true")
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--confronta", action="store_true")
    a = ap.parse_args()
    if a.estrai:
        cmd_estrai(a.n)
    if a.confronta:
        cmd_confronta()


if __name__ == "__main__":
    main()
