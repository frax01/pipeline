#!/usr/bin/env python3
"""
disclosure_estensione.py — prepara l'estensione della campagna ai finding NON
di credenziali che una persona ha letto e confermato individualmente.

Perimetro: i soli verdetti **VP-C** dell'audit manuale, esclusi credenziali
(gia' coperte dalla campagna), `protocol-violation` e le sottocategorie di
`mcp-check` (conformita' al protocollo, non vulnerabilita').

Due filtri che non sono opzionali:

  * i repository gia' nel Tier 1/2 vengono tolti. Su quattro di essi il
    manutentore *e'* l'attaccante: avvisarlo che e' stato scoperto, prima che
    GitHub intervenga, e' esattamente il contrario di una disclosure;
  * i repository deliberatamente vulnerabili (demo, materiale didattico,
    CTF) vengono tolti. Il finding e' corretto ma non c'e' niente da
    segnalare a chi ha scritto la vulnerabilita' apposta.

Poi cerca un canale di contatto pubblico, con la stessa gerarchia della
campagna: `SECURITY.md`, email del profilo, email nel README. Non contatta
nessuno e non genera testi: produce il registro.

Uso:
    python autorun/disclosure_estensione.py
"""
import base64
import json
import os
import re
import time
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AUDIT = REPO / "autorun" / "manual_audit"
OUT = REPO / "docs" / "disclosure" / "estensione_registro.json"
CACHE = REPO / "autorun" / "_estensione_cache.json"

# gia' instradati altrove: vedi docs/disclosure/FASE2_testi.md §1-§5
TIER12 = {
    "heavenlycolle/mcp-trino", "illustriousj/kite-mcp-server",
    "optimisticdur/go-mcp-mysql", "FronNian/mpc-maven-security",
    "michaelguo1991/math-mcp-server-nodejs", "skdkfk8758/MCP-ProjectManager",
    "vincentmcleese/promtHire-mcp", "sentry-official/mcp-cap-internal",
    "letoribo/mcp-graphql-enhanced",
}

FUORI = {"protocol-violation", "Protocol violation", "credential-leak", "?"}

# repository vulnerabili di proposito: il finding e' vero, il destinatario no
DEMO = re.compile(r"\b(vulnerable|intentionally insecure|deliberately insecure|"
                  r"insecure by design|for (educational|training|demo|teaching)|"
                  r"security (training|exercise|workshop|lab)|ctf|"
                  r"capture[- ]the[- ]flag|playground|sandbox for testing|"
                  r"proof[- ]of[- ]concept attack|poc exploit|demo of)\b", re.I)
DEMO_NOME = re.compile(r"(^|[-_/])(vuln|vulnerable|insecure|dvwa|ctf|hackme|"
                       r"pwnable|exploit-demo)([-_]|$)", re.I)


def token():
    t = os.environ.get("GITHUB_TOKEN")
    if t:
        return t
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return winreg.QueryValueEx(k, "GITHUB_TOKEN")[0]
    except Exception:
        return None


TOK = token()
HDR = {"User-Agent": "academic-study", "Accept": "application/vnd.github+json"}
if TOK:
    HDR["Authorization"] = f"Bearer {TOK}"

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SCARTA = re.compile(r"(example|noreply|no-reply|your[_-]?e?mail|user@|test@|foo@|"
                    r"@company\.|@email\.|@domain\.|@yourdomain\.|"
                    r"\.png|\.jpg|\.svg|\.gif|@2x|@types|@babel|@angular|@vue|"
                    r"npmjs|schema\.org|w3\.org|sentry\.io)", re.I)


def get(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=HDR),
                                    timeout=15) as f:
            return json.loads(f.read().decode("utf-8", "replace"))
    except Exception:
        return None


def testo(d):
    if not d or "content" not in d:
        return ""
    try:
        return base64.b64decode(d["content"]).decode("utf-8", "replace")
    except Exception:
        return ""


def norm(u):
    return (u or "").replace("https://github.com/", "") \
                    .replace("http://github.com/", "").rstrip("/")


def candidati():
    """repo -> lista dei finding VP-C, con categoria, file, riga e nota."""
    out = defaultdict(list)
    for p in AUDIT.glob("verdetti_*.json"):
        if p.name == "verdetti_HC.json":
            continue
        try:
            dati = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(dati, list):
            continue
        for x in dati:
            c = x.get("categoria") or x.get("categoria_madre") or "?"
            if str(c).startswith("mcp-check/") or c in FUORI:
                continue
            if x.get("verdetto") != "VP-C":
                continue
            r = norm(x.get("repo") or x.get("server_url") or x.get("server"))
            if not r:
                continue
            out[r].append({"categoria": str(c), "file": x.get("file"),
                           "riga": x.get("line"), "nota": x.get("nota"),
                           "lotto": p.name})
    return out


def canale(repo, cache):
    """SECURITY.md > email del profilo > email nel README. Solo dati pubblici."""
    if repo in cache:
        return cache[repo]
    owner = repo.split("/")[0]
    info = {"canale": None, "email": None, "note": None,
            "descrizione": None, "stelle": None, "archiviato": None}

    meta = get(f"https://api.github.com/repos/{repo}")
    if not meta:
        info["canale"] = "repository non piu' disponibile"
        cache[repo] = info
        return info
    info["descrizione"] = meta.get("description")
    info["stelle"] = meta.get("stargazers_count")
    info["archiviato"] = bool(meta.get("archived"))

    if DEMO.search(meta.get("description") or "") or DEMO_NOME.search(repo):
        info["canale"] = "vulnerabile di proposito (escluso)"
        info["note"] = "descrizione o nome dichiarano un repository didattico"
        cache[repo] = info
        return info
    if info["archiviato"]:
        info["canale"] = "archiviato (nessuno interviene)"
        cache[repo] = info
        return info

    for p in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
        t = testo(get(f"https://api.github.com/repos/{repo}/contents/{p}"))
        if t:
            m = [x for x in EMAIL.findall(t) if not SCARTA.search(x)]
            info.update(canale="SECURITY.md", email=m[0] if m else None,
                        note="procedura dichiarata nel file, da leggere a mano")
            cache[repo] = info
            return info

    u = get(f"https://api.github.com/users/{owner}") or {}
    if u.get("email") and not SCARTA.search(u["email"]):
        info.update(canale="email pubblica", email=u["email"])
        cache[repo] = info
        return info

    t = testo(get(f"https://api.github.com/repos/{repo}/readme"))
    t += "\n" + testo(get(f"https://api.github.com/repos/{owner}/{owner}/readme"))
    m = [x for x in EMAIL.findall(t) if not SCARTA.search(x)]
    m = [x for x in m if not re.match(r"(info|support|contact|hello|admin|abuse)@",
                                      x, re.I)] or m
    if m:
        info.update(canale="email nel README", email=m[0])
    else:
        info["canale"] = "nessun canale utilizzabile"
    cache[repo] = info
    return info


def main():
    if not TOK:
        print("[!] GITHUB_TOKEN non trovato: senza token il limite e' 60/ora.")

    dati = candidati()
    print(f"repository con almeno un VP-C non-credenziale: {len(dati)}")

    gia = sorted(set(dati) & TIER12)
    for r in gia:
        del dati[r]
    print(f"  - {len(gia)} gia' instradati nel Tier 1/2, tolti:")
    for r in gia:
        print(f"      {r}")
    print(f"  = {len(dati)} da valutare\n")

    cache = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}
    reg = []
    for i, (r, f) in enumerate(sorted(dati.items()), 1):
        c = canale(r, cache)
        reg.append({"repo_github": r, "n_finding": len(f),
                    "categorie": sorted({x["categoria"] for x in f}),
                    "finding": f, **c, "stato": "da inviare",
                    "data_invio": None, "esito": None})
        if i % 10 == 0:
            print(f"   {i}/{len(dati)}")
            CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
        time.sleep(0.05)

    CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    OUT.write_text(json.dumps(reg, ensure_ascii=False, indent=1), encoding="utf-8")

    RAGG = {"SECURITY.md", "email pubblica", "email nel README"}
    c = Counter(x["canale"] for x in reg)
    n_r = sum(v for k, v in c.items() if k in RAGG)
    print(f"\n{'canale':<38}{'repo':>5}")
    for k, v in c.most_common():
        print(f"  {str(k):<36}{v:>5}")
    print(f"\nCONTATTABILI: {n_r}/{len(reg)} ({100*n_r/max(len(reg),1):.0f}%)")
    print(f"registro -> {OUT}")

    esclusi = [x for x in reg if x["canale"] == "vulnerabile di proposito (escluso)"]
    if esclusi:
        print(f"\nesclusi perche' vulnerabili di proposito ({len(esclusi)}):")
        for x in esclusi:
            print(f"   {x['repo_github']} — {(x['descrizione'] or '')[:70]}")


if __name__ == "__main__":
    main()
