#!/usr/bin/env python3
"""
relist_prepare.py — costruisce la baseline di maggio per il ri-listing dei tool.

Estrae dai finding X-01 di `mcp-security-scan` della prima analisi i tool di
ogni server con la loro descrizione.

ATTENZIONE alla natura di questa baseline. X-01 e' "Dangerous capability
detection in tools": nel campo `details` mette **solo i tool che ha giudicato
pericolosi**, non l'intera lista restituita da `tools/list`. Verificato su casi
concreti: per `aardeshir/youtube-mcp` registra il solo `delete_playlist` mentre
il server ne espone cinque; sui 4.772 server confrontabili sono 16.303 tool
contro i 68.739 del ri-listing di oggi.

Ne seguono due cose. Il confronto delle descrizioni e' esatto sui nomi presenti
in entrambe le fotografie, perche' entrambe riportano cio' che il server dichiara
via protocollo. Ma la copertura e' asimmetrica: un tool sparito lo si conta con
sicurezza, un tool che appare solo oggi non e' distinguibile da uno che c'era e
che X-01 non riteneva pericoloso.

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
