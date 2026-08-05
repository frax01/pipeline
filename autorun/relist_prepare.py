#!/usr/bin/env python3
"""
relist_prepare.py — costruisce la baseline di maggio per il ri-listing dei tool.

Estrae dai finding X-01 di `mcp-security-scan` della prima analisi l'inventario
COMPLETO dei tool di ogni server (nel campo `details` c'e' l'intera lista
restituita da `tools/list`, non solo i tool segnalati).

Questa e' la fotografia contro cui confrontare il ri-listing di oggi: stessa
sorgente semantica (cio' che il server dichiara interrogandolo dal vivo), quindi
il confronto e' esatto e non euristico.

Uso:
    python autorun/relist_prepare.py
"""
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = Path.home() / "Desktop" / "pipeline_DATI_BACKUP" / "analysisAllData" / "0_tool_mcp_security_scan"
OUT = REPO / "autorun" / "baseline_maggio_tools.json"


def items(d):
    if isinstance(d, list):
        return d
    for k in ("findings", "vulnerabilities", "entries"):
        v = d.get(k)
        if isinstance(v, list):
            return v
    return []


def main():
    inv, url = defaultdict(dict), {}
    for p in SRC.rglob("*.json"):
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        for f in items(d):
            if not isinstance(f, dict):
                continue
            u = str(f.get("server_url") or "").strip().rstrip("/")
            s = re.sub(r"^https?://github\.com/", "", u).lower()
            det = f.get("details")
            if not s or not isinstance(det, str) or not det.lstrip().startswith("["):
                continue
            try:
                tools = json.loads(det)
            except Exception:
                continue
            url[s] = u
            for t in tools:
                if isinstance(t, dict) and t.get("name"):
                    inv[s].setdefault(t["name"], {
                        "description": t.get("description") or "",
                        "inputSchema": t.get("inputSchema"),
                    })

    out = {s: {"server_url": url[s], "n_tool": len(v), "tools": v}
           for s, v in inv.items()}
    OUT.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")

    n = [v["n_tool"] for v in out.values()]
    gh = sum(1 for v in out.values() if v["server_url"].startswith("http"))
    print(f"server con inventario completo di maggio : {len(out):,}")
    print(f"  di cui GitHub                          : {gh:,}")
    print(f"  di cui npx                             : {len(out) - gh:,}")
    print(f"tool totali                              : {sum(n):,}")
    print(f"tool per server: mediana {statistics.median(n):.0f}, "
          f"media {statistics.mean(n):.1f}, max {max(n)}")
    print(f"\n-> {OUT}")


if __name__ == "__main__":
    main()
