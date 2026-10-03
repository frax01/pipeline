#!/usr/bin/env python3
"""
disclosure_canali.py — stabilisce, per ogni repository della campagna
credenziali, se esiste un canale utilizzabile per avvisare l'owner.

Non esiste un modo pulito via API per sapere se un repository di terzi ha
attivato il private vulnerability reporting: quel campo e' visibile solo a chi
ha permessi di amministrazione. Ci si basa quindi su tre segnali pubblici:

  * `SECURITY.md` (anche in `.github/` o `docs/`) — se c'e', il manutentore ha
    dichiarato lui stesso come vuole essere contattato: e' il canale migliore;
  * email pubblica sul profilo dell'owner — l'ha pubblicata di sua volonta';
  * data dell'ultimo push — un progetto fermo da anni non ha nessuno che legga.

Il token si legge da GITHUB_TOKEN, oppure dalle variabili utente di Windows se
la shell non le eredita. **Non viene mai stampato ne' scritto su file.**

Uso:
    python autorun/disclosure_canali.py
    python autorun/disclosure_canali.py --limite 50    # prova su pochi
"""
import argparse
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "docs" / "disclosure" / "campagna_credenziali.json"
CACHE = REPO / "autorun" / "_canali_cache.json"


def token():
    t = os.environ.get("GITHUB_TOKEN")
    if t:
        return t
    try:                                    # variabili utente di Windows
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return winreg.QueryValueEx(k, "GITHUB_TOKEN")[0]
    except Exception:
        return None


TOK = token()
HDR = {"User-Agent": "academic-study", "Accept": "application/vnd.github+json"}
if TOK:
    HDR["Authorization"] = f"Bearer {TOK}"


def api(url, attesa=0.0):
    if attesa:
        time.sleep(attesa)
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=HDR),
                                    timeout=20) as f:
            return json.loads(f.read().decode("utf-8", "replace")), 200
    except urllib.error.HTTPError as e:
        if e.code == 403 and "rate" in (e.headers.get("x-ratelimit-remaining") or ""):
            return None, 403
        return None, e.code
    except Exception:
        return None, 0


def esiste(url):
    try:
        req = urllib.request.Request(url, headers=HDR, method="HEAD")
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status == 200
    except Exception:
        return False


def analizza(repo, cache):
    if repo in cache:
        return cache[repo]
    owner = repo.split("/")[0]
    d, code = api(f"https://api.github.com/repos/{repo}")
    if d is None:
        r = {"esiste": False, "motivo": f"http {code}"}
        cache[repo] = r
        return r

    sec = None
    for p in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
        if esiste(f"https://api.github.com/repos/{repo}/contents/{p}"):
            sec = p
            break

    if owner not in cache:
        u, _ = api(f"https://api.github.com/users/{owner}")
        cache[owner] = {"email": (u or {}).get("email")}
    email = cache[owner]["email"]

    push = d.get("pushed_at")
    mesi = None
    if push:
        dt = datetime.fromisoformat(push.replace("Z", "+00:00"))
        mesi = round((datetime.now(timezone.utc) - dt).days / 30.4)

    r = {"esiste": True, "archiviato": bool(d.get("archived")),
         "security_md": sec, "email_owner": bool(email),
         "mesi_da_ultimo_push": mesi, "stelle": d.get("stargazers_count")}
    cache[repo] = r
    return r


def canale(r):
    if not r.get("esiste"):
        return "repository non piu' disponibile"
    if r.get("archiviato"):
        return "archiviato (nessuno interviene)"
    if r.get("security_md"):
        return "SECURITY.md"
    if r.get("email_owner"):
        return "email pubblica"
    if (r.get("mesi_da_ultimo_push") or 0) > 18:
        return "abbandonato (nessun canale)"
    return "nessun canale utilizzabile"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limite", type=int, default=None)
    a = ap.parse_args()

    if not TOK:
        print("[!] GITHUB_TOKEN non trovato: senza token il limite e' 60/ora.")
    reg = json.loads(REG.read_text(encoding="utf-8"))
    cache = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}
    da_fare = [r for r in reg if r["contattabile"]]
    if a.limite:
        da_fare = da_fare[:a.limite]

    print(f"analizzo {len(da_fare)} repository...")
    for i, r in enumerate(da_fare, 1):
        info = analizza(r["repo_github"], cache)
        r["canale"] = canale(info)
        r["info_canale"] = info
        if i % 50 == 0:
            print(f"   {i}/{len(da_fare)}")
            CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
        time.sleep(0.05)
    CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    REG.write_text(json.dumps(reg, ensure_ascii=False, indent=1), encoding="utf-8")

    from collections import Counter
    c = Counter(r.get("canale") for r in da_fare)
    print(f"\n{'canale':<34} {'repo':>5}")
    for k, v in c.most_common():
        print(f"  {k:<32} {v:>5}")
    ragg = sum(v for k, v in c.items() if k in ("SECURITY.md", "email pubblica"))
    print(f"\nraggiungibili : {ragg} su {len(da_fare)} "
          f"({100*ragg/max(len(da_fare),1):.0f}%)")
    print(f"registro aggiornato -> {REG}")


if __name__ == "__main__":
    main()
