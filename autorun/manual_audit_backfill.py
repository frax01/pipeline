#!/usr/bin/env python3
"""
manual_audit_backfill.py — completa l'evidenza per le categorie description-based.

Cinque delle 17 categorie non si validano leggendo un file sorgente ma la
**descrizione del tool** (e' l'entry point dichiarato in MANUAL_CHECKLIST.md):

    dangerous-capabilities   -> campo `details` (JSON: name, description, inputSchema)
    tool-shadowing           -> campo `tool_description`
    sensitive-file-access    -> campo `tool_description`
    untrusted-content (W015) -> campi `message` / `extra_data`
    prompt-injection (E001)  -> solo `tool_name` + `labels`: la descrizione NON e'
                                salvata, va cercata nel sorgente del repo

Lo script riempie `evidence` nel campione gia' estratto, accoppiando per
repo + tool_name, senza toccare i record che hanno gia' il sorgente scaricato.

Uso:
    python autorun/manual_audit_backfill.py
"""
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CAMP = REPO / "autorun" / "manual_audit" / "campione.json"

SORGENTI = {
    "dangerous-capabilities": ("mcp_security_scan", "dangerous-capabilities"),
    "untrusted-content":      ("mcp_scan", "W015"),
    "prompt-injection":       ("mcp_scan", "E001"),
    "sensitive-file-access":  ("mcp_shield", "sensitive-file-access"),
    "tool-shadowing":         ("mcp_shield", "shadowing-detected"),
}


def items(d):
    return d if isinstance(d, list) else (d.get("findings") or d.get("entries") or [])


def repo_of(url):
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)", str(url or ""))
    return m.group(1).rstrip("/") if m else str(url or "")


def evidenza(f, cat):
    """Estrae il testo su cui si esprime il verdetto, secondo la categoria."""
    if cat == "dangerous-capabilities":
        try:
            det = json.loads(f.get("details") or "[]")
            det = det[0] if isinstance(det, list) and det else det
        except Exception:
            det = {}
        return json.dumps({
            "tool": det.get("name"),
            "description": det.get("description"),
            "inputSchema": det.get("inputSchema"),
            "match_del_framework": det.get("_filter_reason"),
        }, ensure_ascii=False)[:2500]
    if cat in ("tool-shadowing", "sensitive-file-access"):
        return json.dumps({
            "tool": f.get("tool_name"),
            "tool_description": f.get("tool_description"),
            "trigger": f.get("descriptions"),
            "risk": f.get("risk"),
        }, ensure_ascii=False)[:2500]
    if cat == "untrusted-content":
        return json.dumps({
            "message": f.get("message"),
            "extra_data": f.get("extra_data"),
            "severity": f.get("severity"),
        }, ensure_ascii=False)[:2500]
    if cat == "prompt-injection":
        return json.dumps({
            "tool": f.get("tool_name"),
            "labels": f.get("labels"),
            "extra_data": f.get("extra_data"),
            "nota": "descrizione del tool non salvata dal framework: "
                    "va cercata nel sorgente del repo",
        }, ensure_ascii=False)[:2500]
    return ""


def main():
    camp = json.load(open(CAMP, encoding="utf-8"))
    for cat, (tooldir, filtro) in SORGENTI.items():
        if cat not in camp:
            continue
        # indicizza i finding originali per (repo, tool_name)
        idx = {}
        for p in (REPO / tooldir / "postprocessing").rglob("vp.json"):
            if filtro not in p.as_posix():
                continue
            try:
                its = items(json.load(open(p, encoding="utf-8")))
            except Exception:
                continue
            for f in its:
                idx.setdefault((repo_of(f.get("server_url")), f.get("tool_name")), f)
        n = 0
        for rec in camp[cat]:
            if rec.get("evidence"):
                continue
            f = idx.get((rec["repo"], rec["tool_name"])) or idx.get((rec["repo"], None))
            if f is None:
                continue
            rec["evidence"] = evidenza(f, cat)
            n += 1
        print(f"  {cat:26s} evidenze completate: {n}/{len(camp[cat])}")
    json.dump(camp, open(CAMP, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"\naggiornato {CAMP}")


if __name__ == "__main__":
    main()
