#!/usr/bin/env python3
"""
rugpull_diff.py — cerca rug pull confrontando le tool description dei server MCP
fra la prima analisi (maggio 2026) e la rirun (luglio 2026).

Un rug pull e' un server che cambia il proprio comportamento dichiarato DOPO
essere stato approvato: la descrizione che l'agente legge oggi non e' quella su
cui l'utente ha dato il consenso.

**Da dove vengono i dati.** `mcp-security-scan` e `mcp-shield` non leggono il
sorgente: avviano il server e gli chiedono `tools/list`. La descrizione che
finiscono nel finding e' quindi cio' che il server dichiarava di se' nell'istante
della scansione — esattamente cio' che vedrebbe un client MCP. Entrambe le run
hanno salvato questi inventari, a due mesi di distanza.

  security_scan  -> campo `details`: lista JSON completa dei tool del server
  shield         -> campi `tool_name` + `tool_description`

**Limite dichiarato.** Nessuna delle due run ha salvato un inventario completo:
le descrizioni esistono solo dentro i finding, quindi il confronto copre i soli
server flaggati in ENTRAMBE le passate. E' un campione con bias di selezione, non
una misura sull'intero ecosistema (per quella serve la git history dei repo).

Uso:
    python autorun/rugpull_diff.py                    # report a schermo
    python autorun/rugpull_diff.py --out docs/rirun/RUGPULL_raw.md   # + report markdown
    python autorun/rugpull_diff.py --json rugpull.json
"""
import argparse
import difflib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUN1 = Path.home() / "Desktop" / "pipeline_DATI_BACKUP" / "analysisAllData"
RUN2 = Path.home() / "Desktop" / "pipeline_rerun_pull"

SRC1 = ["0_tool_mcp_security_scan", "0_tool_mcp_shield"]
SRC2 = ["security_scan", "shield"]

# Segnali di capability in una descrizione. La comparsa di uno di questi in una
# descrizione che prima non ce l'aveva e' il segnale che interessa: il tool
# dichiara di poter fare qualcosa che prima non dichiarava.
CAPABILITY = {
    "scrittura": r"\b(write|create|update|modify|edit|insert|upsert|patch|set|save|mutation|mutate)\b",
    "cancellazione": r"\b(delete|remove|drop|destroy|purge|truncate|wipe|erase)\b",
    "esecuzione": r"\b(execute|exec|run|spawn|shell|command|eval|subprocess|bash|powershell)\b",
    "rete": r"\b(fetch|request|http|url|endpoint|webhook|upload|download|send)\b",
    "credenziali": r"\b(token|api[_ ]?key|secret|password|credential|auth)\b",
    "filesystem": r"\b(file|path|directory|folder|read_file|write_file)\b",
    "privilegi": r"\b(admin|root|sudo|privileg|permission|grant|elevat)\b",
}

# Frasi tipiche del prompt-injection nascosto in una descrizione.
INIETTIVI = r"(ignore (all )?(previous|prior)|do not (tell|mention|inform)|" \
            r"without (telling|informing|asking)|<IMPORTANT>|system prompt|" \
            r"you must|always call|before (using|calling) any other)"


def items(d):
    if isinstance(d, list):
        return d
    for k in ("findings", "vulnerabilities", "entries"):
        v = d.get(k)
        if isinstance(v, list):
            return v
    return []


def norm_server(u):
    u = str(u or "").strip().rstrip("/")
    u = re.sub(r"^https?://github\.com/", "", u)
    return u.lower()


def harvest(root: Path, subdirs):
    """server -> {tool_name: description}. Il primo valore visto vince: gli
    stadi del post-processing ricopiano lo stesso finding piu' volte."""
    inv = defaultdict(dict)
    for sub in subdirs:
        base = root / sub
        if not base.is_dir():
            continue
        for p in base.rglob("*.json"):
            try:
                d = json.load(open(p, encoding="utf-8"))
            except Exception:
                continue
            for f in items(d):
                if not isinstance(f, dict):
                    continue
                srv = norm_server(f.get("server_url") or f.get("server_name"))
                if not srv:
                    continue
                tn, td = f.get("tool_name"), f.get("tool_description")
                if tn and isinstance(td, str):
                    inv[srv].setdefault(tn, td)
                det = f.get("details")
                if isinstance(det, str) and det.lstrip().startswith("["):
                    try:
                        tools = json.loads(det)
                    except Exception:
                        continue
                    if isinstance(tools, list):
                        for t in tools:
                            if isinstance(t, dict) and t.get("name"):
                                inv[srv].setdefault(t["name"], t.get("description") or "")
    return inv


def capability_delta(prima, dopo):
    """Capability dichiarate solo DOPO (comparse) e solo PRIMA (sparite)."""
    a, b = prima.lower(), dopo.lower()
    comparse, sparite = [], []
    for nome, pat in CAPABILITY.items():
        in_a, in_b = bool(re.search(pat, a)), bool(re.search(pat, b))
        if in_b and not in_a:
            comparse.append(nome)
        elif in_a and not in_b:
            sparite.append(nome)
    return comparse, sparite


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="report markdown")
    ap.add_argument("--json", default=None, help="dump dei cambi")
    a = ap.parse_args()

    i1, i2 = harvest(RUN1, SRC1), harvest(RUN2, SRC2)
    comuni = set(i1) & set(i2)

    cambi, aggiunti, rimossi = [], [], []
    scartati_vuoti = 0
    for s in sorted(comuni):
        A, B = i1[s], i2[s]
        for t in sorted(set(A) | set(B)):
            if t not in B:
                rimossi.append((s, t))
                continue
            if t not in A:
                aggiunti.append((s, t, B[t]))
                continue
            x, y = (A[t] or "").strip(), (B[t] or "").strip()
            if x == y:
                continue
            if not x or not y:
                # un lato senza descrizione: artefatto della sorgente, non un
                # cambiamento osservato
                scartati_vuoti += 1
                continue
            sim = difflib.SequenceMatcher(None, x, y).ratio()
            comparse, sparite = capability_delta(x, y)
            iniett = bool(re.search(INIETTIVI, y, re.I)) and \
                not bool(re.search(INIETTIVI, x, re.I))
            cambi.append({
                "server": s, "tool": t, "similarita": round(sim, 3),
                "capability_comparse": comparse, "capability_sparite": sparite,
                "iniettivo_comparso": iniett,
                "prima": x, "dopo": y,
            })

    sost = [c for c in cambi if c["similarita"] < 0.9]
    rilevanti = [c for c in cambi if c["capability_comparse"] or c["iniettivo_comparso"]]

    out = []
    def w(s=""):
        out.append(s)
        print(s.encode(sys.stdout.encoding or "utf-8", "replace")
               .decode(sys.stdout.encoding or "utf-8", "replace"))

    w("# Rug pull — tool description cambiate fra maggio e luglio 2026")
    w()
    w("Confronto degli inventari di tool salvati da `mcp-security-scan` e")
    w("`mcp-shield` nelle due analisi. Le descrizioni sono quelle che il server")
    w("dichiarava **interrogandolo dal vivo** (`tools/list`), non lette dal")
    w("sorgente: sono cio' che un client MCP avrebbe visto in quel momento.")
    w()
    w("| | |")
    w("|---|---:|")
    w(f"| server con inventario a maggio | {len(i1):,} |")
    w(f"| server con inventario a luglio | {len(i2):,} |")
    w(f"| **server confrontabili (in entrambe)** | **{len(comuni):,}** |")
    w(f"| coppie (server, tool) confrontate | {sum(len(set(i1[s])|set(i2[s])) for s in comuni):,} |")
    w(f"| **descrizioni cambiate** | **{len(cambi):,}** su {len({c['server'] for c in cambi}):,} server |")
    w(f"| di cui cambi sostanziali (similarita' <90%) | {len(sost):,} |")
    w(f"| **di cui con capability nuove dichiarate** | **{len(rilevanti):,}** |")
    w(f"| tool aggiunti | {len(aggiunti):,} |")
    w(f"| tool rimossi | {len(rimossi):,} |")
    w(f"| scartati (descrizione vuota da un lato) | {scartati_vuoti:,} |")
    w()

    conta = defaultdict(int)
    for c in rilevanti:
        for k in c["capability_comparse"]:
            conta[k] += 1
    if conta:
        w("## Capability comparse dove prima non c'erano")
        w()
        w("| capability | tool |")
        w("|---|---:|")
        for k, v in sorted(conta.items(), key=lambda x: -x[1]):
            w(f"| {k} | {v} |")
        w()

    iniett = [c for c in cambi if c["iniettivo_comparso"]]
    if iniett:
        w(f"## Linguaggio direttivo comparso nella descrizione ({len(iniett)})")
        w()
        for c in iniett:
            w(f"- `{c['server']}` :: `{c['tool']}`")
        w()

    w("## Casi con capability nuove — da validare a mano")
    w()
    for c in sorted(rilevanti, key=lambda c: c["similarita"])[:60]:
        w(f"### `{c['server']}` :: `{c['tool']}`")
        w(f"*similarita' {c['similarita']:.0%} · comparse: "
          f"{', '.join(c['capability_comparse']) or '—'}*")
        w()
        w(f"- **maggio**: {c['prima'][:300]}")
        w(f"- **luglio**: {c['dopo'][:300]}")
        w()

    if a.out:
        Path(a.out).write_text("\n".join(out), encoding="utf-8")
        print(f"\n-> {a.out}")
    if a.json:
        Path(a.json).write_text(json.dumps(cambi, ensure_ascii=False, indent=1),
                                encoding="utf-8")
        print(f"-> {a.json}")


if __name__ == "__main__":
    main()
