#!/usr/bin/env python3
"""
stage2b_extract.py — prepara gli UNCERTAIN dello Stage 2A per la classificazione LLM.

Nella tesi lo Stage 2B usava llama3 via ollama; qui i verdetti li produce Claude
(Sonnet) in chat. Questo script NON chiama nessun modello: estrae i finding
UNCERTAIN da tutti i tool, ne costruisce una rappresentazione compatta con le
sole informazioni che servono a decidere, li raggruppa in *cluster* di finding
equivalenti (stessa evidenza => stesso verdetto) e li scrive in batch numerati.

  batches/batch_NNN.json   -> da classificare (un record per cluster)
  index.json               -> cluster -> lista di finding originali (per riapplicare)

Uso:
    python autorun/stage2b_extract.py --extract
    python autorun/stage2b_extract.py --stats
"""
import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "autorun" / "stage2b"
BATCHES = OUT / "batches"
BATCH_SIZE = 60

TOOL_OF = {"mcp_guard": "guard", "mcp_watch": "watch", "fuzzing": "fuzzing",
           "mcp_scan": "scan", "mcp_shield": "shield",
           "mcp_security_scan": "security_scan", "mcp_check": "check"}


def sha(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode("utf-8", "replace")).hexdigest()[:12]


def clip(s, n):
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s[:n] + ("…" if len(s) > n else "")


def short_server(url):
    u = str(url or "")
    return u.replace("https://github.com/", "gh:").replace("http://github.com/", "gh:")


def evidence(tool, f):
    """Testo su cui si decide, per famiglia di finding."""
    cat = f.get("_category") or f.get("category") or ""
    # ── guard / statica: conta la riga di codice e il percorso del file ──
    desc = f.get("description") or ""
    if "Code: " in desc:
        code = desc.split("Code: ", 1)[1]
        return {"tipo": "static", "file": f.get("file"), "code": clip(code, 400)}
    # ── guard / fuzzing: conta il payload inviato e la risposta ──
    if f.get("payload") or f.get("response"):
        issues = desc.split("Issues found:", 1)[1] if "Issues found:" in desc else desc
        return {"tipo": "fuzzing", "issue": clip(issues, 200),
                "payload": clip(f.get("payload"), 400),
                "response": clip(f.get("response"), 700)}
    # ── check: messaggi di errore dei test di conformance ──
    if f.get("errors"):
        e = f["errors"][0] if isinstance(f["errors"], list) and f["errors"] else {}
        return {"tipo": "check", "test": e.get("test"), "err": e.get("type"),
                "msg": clip(e.get("message"), 300)}
    # ── security_scan: descrizione+schema del tool segnalato ──
    if f.get("details"):
        try:
            det = json.loads(f["details"])
            det = det[0] if isinstance(det, list) and det else det
        except Exception:
            det = {}
        return {"tipo": "capability", "tool": det.get("name"),
                "desc": clip(det.get("description"), 300),
                "schema": clip(json.dumps(det.get("inputSchema", {}), ensure_ascii=False), 300),
                "match": det.get("_filter_reason")}
    # ── shield / generico ──
    return {"tipo": "generico",
            "txt": clip(json.dumps({k: v for k, v in f.items()
                                    if not k.startswith("_") and k not in
                                    ("server_url", "server_name", "remediation", "references")},
                                   ensure_ascii=False), 700)}


def norm_sig(ev):
    """Firma per il clustering: stessa evidenza (valori normalizzati) = stesso verdetto."""
    s = json.dumps(ev, sort_keys=True, ensure_ascii=False)
    s = re.sub(r"\b[0-9a-f]{8,}\b", "HEX", s)      # hash/id volatili
    s = re.sub(r"\b\d+\b", "N", s)                  # numeri (porte, id, righe)
    return s


def iter_uncertain():
    for p in sorted(REPO.glob("*/postprocessing/**/uncertain.json")):
        tool = TOOL_OF.get(p.relative_to(REPO).parts[0])
        if not tool:
            continue
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception as e:
            print(f"  [WARN] {p}: {e}")
            continue
        items = d if isinstance(d, list) else (d.get("findings") or d.get("entries") or [])
        cat = d.get("category") if isinstance(d, dict) else None
        rel = p.relative_to(REPO).as_posix()
        for i, f in enumerate(items):
            yield tool, cat or f.get("_category") or f.get("category") or "?", rel, i, f


def cmd_extract(only_tool=None, start_batch=1):
    """Estrae gli UNCERTAIN in batch numerati.

    Con --tool i batch esistenti NON vengono cancellati e la numerazione parte da
    --start-batch: serve per aggiungere un tool arrivato dopo (es. watch) senza
    invalidare i verdetti gia' prodotti, che sono indicizzati per numero di batch.
    Gli id dei cluster sono hash del contenuto, quindi restano stabili.
    """
    OUT.mkdir(parents=True, exist_ok=True)
    if only_tool is None and BATCHES.exists():
        for old in BATCHES.glob("*.json"):
            old.unlink()
    BATCHES.mkdir(parents=True, exist_ok=True)

    clusters = {}          # sig -> record
    members = defaultdict(list)
    n = 0
    for tool, cat, rel, idx, f in iter_uncertain():
        if only_tool and tool != only_tool:
            continue
        n += 1
        ev = evidence(tool, f)
        sig = sha(tool, cat, norm_sig(ev))
        members[sig].append({"src": rel, "i": idx,
                             "server": short_server(f.get("server_url")),
                             "file": f.get("file")})
        if sig not in clusters:
            clusters[sig] = {"id": sig, "tool": tool, "categoria": cat,
                             "severita": f.get("severity"), "linguaggio": f.get("language"),
                             "esempio_server": short_server(f.get("server_url")),
                             "evidenza": ev}
    for sig, rec in clusters.items():
        rec["n_finding"] = len(members[sig])
        srv = {m["server"] for m in members[sig]}
        rec["n_server"] = len(srv)

    ordered = sorted(clusters.values(), key=lambda r: (r["tool"], r["categoria"], -r["n_finding"]))
    for b in range(0, len(ordered), BATCH_SIZE):
        chunk = ordered[b:b + BATCH_SIZE]
        bn = b // BATCH_SIZE + start_batch
        json.dump({"batch": bn, "n_cluster": len(chunk),
                   "n_finding": sum(c["n_finding"] for c in chunk),
                   "istruzioni": ("Per ogni cluster assegnare verdetto VP (vero positivo, "
                                  "vulnerabilita' reale e raggiungibile) o FP (falso positivo), "
                                  "con motivazione breve."),
                   "cluster": chunk},
                  open(BATCHES / f"batch_{bn:03d}.json", "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)

    idx_path = OUT / "index.json"
    full = {}
    if only_tool and idx_path.exists():      # preserva la mappatura dei tool gia' estratti
        full = json.load(open(idx_path, encoding="utf-8"))
    full.update({sig: members[sig] for sig in clusters})
    json.dump(full, open(idx_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    print(f"finding UNCERTAIN : {n:,}")
    print(f"cluster distinti  : {len(clusters):,}  (fattore {n/max(len(clusters),1):.1f}x)")
    print(f"batch da {BATCH_SIZE}      : {(len(ordered)+BATCH_SIZE-1)//BATCH_SIZE}")
    print(f"output            : {BATCHES}")


def cmd_stats():
    per = defaultdict(lambda: [0, 0])
    for tool, cat, rel, idx, f in iter_uncertain():
        per[(tool, cat)][0] += 1
    for (tool, cat), (c, _) in sorted(per.items(), key=lambda x: -x[1][0]):
        print(f"{tool:<16} {str(cat):<45} {c:>6}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--extract", action="store_true")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--tool", default=None,
                    help="estrae solo questo tool, senza cancellare i batch esistenti")
    ap.add_argument("--start-batch", type=int, default=1,
                    help="numero del primo batch generato (per non sovrascriverne di esistenti)")
    a = ap.parse_args()
    if a.stats:
        cmd_stats()
    else:
        cmd_extract(only_tool=a.tool, start_batch=a.start_batch)


if __name__ == "__main__":
    main()
