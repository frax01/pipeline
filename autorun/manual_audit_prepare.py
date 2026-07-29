#!/usr/bin/env python3
"""
manual_audit_prepare.py — prepara il campione per la validazione manuale della rirun.

Replica l'impianto di `docs/MANUAL.md` / `docs/MANUAL_CHECKLIST.md`: le stesse 17
categorie, campionate, con verdetto a 4 livelli VP-C / VP-L / VP-D / FP deciso
leggendo il **codice sorgente reale** preso da GitHub.

Questo script fa solo le due parti meccaniche:
  1. campiona i VP della rirun per categoria (stratificato per server, cosi' un
     singolo repo non monopolizza il campione)
  2. scarica da GitHub il file citato nel finding ed estrae la riga +- contesto

Il verdetto lo assegna una persona (o un modello) applicando la checklist: qui
non c'e' nessuna euristica che decide al posto suo.

Uso:
    python autorun/manual_audit_prepare.py --campiona --per-categoria 15
    python autorun/manual_audit_prepare.py --fetch          # scarica i sorgenti
"""
import argparse
import json
import re
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "autorun" / "manual_audit"
CTX = 12          # righe di contesto attorno alla riga citata

# categoria MANUAL.md -> (cartella tool, filtro sul percorso della categoria)
CATEGORIE = {
    "sql-injection":              ("mcp_guard", "sql-injection-static"),
    "dangerous-capabilities":     ("mcp_security_scan", "dangerous-capabilities"),
    "credential-leak":            ("mcp_watch", "credential-leak"),
    "ssrf":                       ("mcp_guard", "ssrf-static"),
    "untrusted-content":          ("mcp_scan", "W015"),
    "path-traversal-static":      ("mcp_guard", "path-traversal-static"),
    "command-injection-static":   ("mcp_guard", "command-injection-static"),
    "code-injection-static":      ("mcp_guard", "code-injection-static"),
    "input-validation":           ("mcp_watch", "input-validation"),
    "protocol-violation":         ("mcp_watch", "protocol-violation"),
    "prompt-injection":           ("mcp_scan", "E001"),
    "insecure-deserialization":   ("mcp_guard", "insecure-deserialization-static"),
    "sensitive-file-access":      ("mcp_shield", "sensitive-file-access"),
    "sensitive-info-disclosure":  ("mcp_guard", "sensitive-info-disclosed-fuzzing"),
    "access-control":             ("mcp_watch", "access-control"),
    "data-exfiltration":          ("mcp_watch", "data-exfiltration"),
    "tool-shadowing":             ("mcp_shield", "shadowing-detected"),
}


def items(d):
    return d if isinstance(d, list) else (d.get("findings") or d.get("entries") or [])


def repo_of(url):
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)", str(url or ""))
    return m.group(1).rstrip("/") if m else None


def line_of(f):
    if f.get("line"):
        try:
            return int(f["line"])
        except (TypeError, ValueError):
            pass
    m = re.search(r"at line (\d+)", str(f.get("description") or ""))
    return int(m.group(1)) if m else None


def cmd_campiona(n_per_cat):
    OUT.mkdir(parents=True, exist_ok=True)
    campione = {}
    for cat, (tooldir, filtro) in CATEGORIE.items():
        base = REPO / tooldir / "postprocessing"
        trovati = []
        for p in base.rglob("vp.json"):
            if filtro not in p.as_posix():
                continue
            try:
                its = items(json.load(open(p, encoding="utf-8")))
            except Exception:
                continue
            for f in its:
                trovati.append(f)
        # stratifica: al massimo 2 finding per server, poi taglia
        per_srv = defaultdict(list)
        for f in trovati:
            per_srv[repo_of(f.get("server_url") or f.get("github_url"))].append(f)
        sel, giro = [], 0
        while len(sel) < n_per_cat and giro < 3:
            for srv in sorted(k for k in per_srv if k):
                if len(per_srv[srv]) > giro and len(sel) < n_per_cat:
                    sel.append(per_srv[srv][giro])
            giro += 1
        campione[cat] = [{
            "categoria": cat,
            "repo": repo_of(f.get("server_url") or f.get("github_url")),
            "file": f.get("file"),
            "line": line_of(f),
            "verdetto_pipeline": f.get("_final_verdict") or f.get("llm_verdict")
                                 or f.get("_llm_verdict") or "VP",
            "provenance": f.get("_provenance", "rirun"),
            "evidence": (f.get("evidence") or f.get("description") or "")[:400],
            "tool_name": f.get("tool_name"),
            "sorgente": None,
        } for f in sel]
        print(f"  {cat:28s} disponibili={len(trovati):>6,}  campionati={len(campione[cat])}")

    json.dump(campione, open(OUT / "campione.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    tot = sum(len(v) for v in campione.values())
    print(f"\ncampione totale: {tot} finding -> {OUT/'campione.json'}")


def raw_url(repo, path, branch):
    return f"https://raw.githubusercontent.com/{repo}/{branch}/{str(path).lstrip('/')}"


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "manual-audit/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def cmd_fetch():
    p = OUT / "campione.json"
    campione = json.load(open(p, encoding="utf-8"))
    ok = ko = 0
    for cat, lista in campione.items():
        for rec in lista:
            if rec.get("sorgente") is not None:
                continue
            repo, path, line = rec["repo"], rec["file"], rec["line"]
            if not repo or not path:
                rec["sorgente"] = {"errore": "repo o file mancante"}; ko += 1; continue
            testo = None
            for br in ("main", "master"):
                try:
                    testo = fetch(raw_url(repo, path, br))
                    rec["branch"] = br
                    break
                except urllib.error.HTTPError as e:
                    rec["http"] = e.code
                except Exception as e:
                    rec["http"] = e.__class__.__name__
                time.sleep(0.2)
            if testo is None:
                rec["sorgente"] = {"errore": f"non recuperabile ({rec.get('http')})"}
                ko += 1
                continue
            righe = testo.splitlines()
            if line and 1 <= line <= len(righe):
                a, b = max(0, line - 1 - CTX), min(len(righe), line + CTX)
                estratto = "\n".join(f"{i+1:5d}| {righe[i]}" for i in range(a, b))
            else:
                estratto = "\n".join(f"{i+1:5d}| {righe[i]}" for i in range(min(40, len(righe))))
            rec["sorgente"] = {"righe_totali": len(righe), "estratto": estratto[:6000]}
            ok += 1
            print(f"  ok  {cat:26s} {repo}/{path}:{line}")
            time.sleep(0.25)
    json.dump(campione, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"\nsorgenti recuperati: {ok}  falliti: {ko}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campiona", action="store_true")
    ap.add_argument("--per-categoria", type=int, default=15)
    ap.add_argument("--fetch", action="store_true")
    a = ap.parse_args()
    if a.campiona:
        cmd_campiona(a.per_categoria)
    if a.fetch:
        cmd_fetch()


if __name__ == "__main__":
    main()
