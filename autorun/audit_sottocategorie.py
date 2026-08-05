#!/usr/bin/env python3
"""
audit_sottocategorie.py — campiona le sotto-categorie non ancora validate.

Le 17 categorie del confronto (quelle della prima analisi) sono aggregati di piu'
sotto-categorie prodotte da tool diversi. L'audit fatto finora copre il 77% dei
VP; questo script prepara il campione per il 23% scoperto, mantenendo per ogni
record il legame esplicito con la **categoria madre** a cui va ricondotto.

Uso:
    python autorun/audit_sottocategorie.py --prepara
"""
import argparse
import json
import random
import re
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "autorun" / "manual_audit" / "lotti"

# (sotto-categoria, CATEGORIA MADRE fra le 17, glob dei vp.json)
SUB = [
    ("guard/dangerous-tool-handler", "Dangerous capabilities",
     "mcp_guard/postprocessing/dangerous-tool-handler-static/**/vp.json"),
    ("guard/path-traversal-fuzzing", "Path traversal",
     "mcp_guard/postprocessing/path-traversal-fuzzing/**/vp.json"),
    ("guard/command-injection-fuzzing", "Command injection",
     "mcp_guard/postprocessing/command-injection-fuzzing/**/vp.json"),
    ("guard/command-execution-fuzzing", "Command injection",
     "mcp_guard/postprocessing/command-execution-fuzzing/**/vp.json"),
    ("guard/information-disclosure-fuzzing", "Sensitive info disclosure",
     "mcp_guard/postprocessing/information-disclosure-fuzzing/**/vp.json"),
    ("guard/code-injection-fuzzing", "Code injection",
     "mcp_guard/postprocessing/code-injection-fuzzing/**/vp.json"),
    ("guard/prompt-injection-static", "Prompt injection",
     "mcp_guard/postprocessing/prompt-injection-static/**/vp.json"),
    ("shield/hidden-instructions", "Prompt injection",
     "mcp_shield/postprocessing/hidden-instructions/**/vp.json"),
    ("guard/protocol-*", "Protocol violation",
     "mcp_guard/postprocessing/protocol-*/**/vp.json"),
    ("fuzzing/tool-crash-dos", "Protocol violation",
     "fuzzing/postprocessing/tool-crash-dos/**/vp.json"),
    ("fuzzing/tool-error-disclosure", "Sensitive info disclosure",
     "fuzzing/postprocessing/tool-error-disclosure/**/vp.json"),
    ("scan/W017_npx", "Sensitive info disclosure", "mcp_scan/postprocessing/**/W017_npx/**/vp.json"),
    ("scan/W018_npx", "Sensitive info disclosure", "mcp_scan/postprocessing/**/W018_npx/**/vp.json"),
    ("scan/W019_npx", "Dangerous capabilities", "mcp_scan/postprocessing/**/W019_npx/**/vp.json"),
    ("scan/W020_npx", "Dangerous capabilities", "mcp_scan/postprocessing/**/W020_npx/**/vp.json"),
    ("security_scan/input-validation", "Input validation",
     "mcp_security_scan/postprocessing/input-validation/**/vp.json"),
    ("security_scan/path-traversal", "Path traversal",
     "mcp_security_scan/postprocessing/path-traversal/**/vp.json"),
    ("security_scan/sensitive-file-access", "Sensitive file access",
     "mcp_security_scan/postprocessing/sensitive-file-access/**/vp.json"),
    ("security_scan/remote-access-control", "Access control",
     "mcp_security_scan/postprocessing/remote-access-control/**/vp.json"),
]

N_PER_SUB = 15
# raggruppamento in lotti da dare ad analisti diversi
LOTTI = {
    "S1": ["guard/dangerous-tool-handler"],
    "S2": ["guard/path-traversal-fuzzing", "security_scan/path-traversal"],
    "S3": ["guard/command-injection-fuzzing", "guard/command-execution-fuzzing",
           "guard/code-injection-fuzzing"],
    "S4": ["guard/information-disclosure-fuzzing", "fuzzing/tool-error-disclosure"],
    "S5": ["scan/W017_npx", "scan/W018_npx"],
    "S6": ["scan/W019_npx", "scan/W020_npx"],
    "S7": ["guard/prompt-injection-static", "shield/hidden-instructions",
           "guard/protocol-*", "fuzzing/tool-crash-dos",
           "security_scan/input-validation", "security_scan/sensitive-file-access",
           "security_scan/remote-access-control"],
}


def items(d):
    return d if isinstance(d, list) else (d.get("findings") or d.get("entries") or [])


def repo_of(f):
    u = f.get("server_url") or f.get("github_url") or ""
    return re.sub(r"^https?://github\.com/", "", str(u)).rstrip("/")


def compatta(f):
    """Tiene solo i campi che servono a decidere, senza gonfiare il file."""
    out = {}
    for k in ("file", "line", "tool_name", "server_name", "severity", "id",
              "description", "evidence", "payload", "response", "message",
              "tool_description", "details", "extra_data"):
        v = f.get(k)
        if v not in (None, "", [], {}):
            out[k] = v if not isinstance(v, str) else v[:900]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prepara", action="store_true")
    ap.parse_args()

    random.seed(23)
    per_sub = {}
    for nome, madre, pat in SUB:
        tutti = []
        for p in REPO.glob(pat):
            tutti += items(json.load(open(p, encoding="utf-8")))
        if not tutti:
            continue
        # stratifica: max 2 per server, poi campiona
        per_srv = defaultdict(list)
        for f in tutti:
            per_srv[repo_of(f)].append(f)
        pool = []
        for giro in range(2):
            for s in sorted(per_srv):
                if len(per_srv[s]) > giro:
                    pool.append(per_srv[s][giro])
        random.shuffle(pool)
        sel = pool[:N_PER_SUB]
        per_sub[nome] = [{
            "sotto_categoria": nome,
            "categoria_madre": madre,
            "repo": repo_of(f),
            "verdetto_pipeline": "VP",
            "dati": compatta(f),
        } for f in sel]
        print(f"  {nome:<38} {len(tutti):>6,} VP -> campione {len(sel)}  [{madre}]")

    OUT.mkdir(parents=True, exist_ok=True)
    for lotto, subs in LOTTI.items():
        casi = []
        for s in subs:
            for i, r in enumerate(per_sub.get(s, [])):
                casi.append({**r, "n": len(casi) + 1})
        if not casi:
            continue
        p = OUT / f"lotto_{lotto}.json"
        json.dump(casi, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"\nlotto {lotto}: {len(casi)} casi -> {p.name}")


if __name__ == "__main__":
    main()
