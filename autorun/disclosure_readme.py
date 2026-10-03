#!/usr/bin/env python3
"""
disclosure_readme.py — recupera un contatto per i repository che l'analisi dei
canali aveva classificato come irraggiungibili.

Molti manutentori non compilano il campo `email` del profilo GitHub ma
pubblicano un indirizzo nel README del repository o in quello del profilo. E'
un contatto che hanno scelto di rendere pubblico in un file destinato ai
lettori: usarlo e' legittimo, a differenza degli indirizzi ricavati dalla
cronologia dei commit, che sarebbero dati personali raccolti per una finalita'
diversa da quella per cui sono li'.

Aggiorna `canale` nel registro della campagna. Non contatta nessuno.

Uso:
    python autorun/disclosure_readme.py
"""
import base64
import json
import os
import re
import time
import urllib.request
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "docs" / "disclosure" / "campagna_credenziali.json"
CACHE = REPO / "autorun" / "_readme_cache.json"


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
# scarti: segnaposto, indirizzi di servizio, falsi positivi da nomi di file
SCARTA = re.compile(r"(example|noreply|no-reply|your[_-]?e?mail|user@|test@|foo@|"
                    r"sentry\.io|\.png|\.jpg|\.svg|\.gif|@2x|@types|@babel|"
                    r"@angular|@vue|npmjs|schema\.org|w3\.org|"
                    # frammenti di stringhe di connessione: `user:password@host`
                    # nei README producono finti indirizzi. Ne e' partito uno
                    # (password@cluster.mongodb.net) prima che se ne accorgesse
                    # qualcuno: il messaggio non raggiunge nessuno e il
                    # repository risulta contattato quando non lo e'.
                    r"^(password|passwd|pwd|pass|user|username|host|db|dbname|"
                    r"token|secret|apikey|changeme)@|"
                    r"@(cluster|localhost|host|db|server)[.\-]|"
                    r"mongodb\.net|amazonaws\.com|\.rds\.|supabase\.co|"
                    r"neon\.tech|planetscale\.dev)", re.I)


def get(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=HDR),
                                    timeout=15) as f:
            return json.loads(f.read().decode("utf-8", "replace"))
    except Exception:
        return None


def testo_readme(d):
    if not d or "content" not in d:
        return ""
    try:
        return base64.b64decode(d["content"]).decode("utf-8", "replace")
    except Exception:
        return ""


def contatto(repo, cache):
    if repo in cache:
        return cache[repo]
    owner = repo.split("/")[0]
    t = testo_readme(get(f"https://api.github.com/repos/{repo}/readme"))
    if f"profilo:{owner}" in cache:
        t += "\n" + cache[f"profilo:{owner}"]
    else:
        pr = testo_readme(get(f"https://api.github.com/repos/{owner}/{owner}/readme"))
        cache[f"profilo:{owner}"] = pr
        t += "\n" + pr
    mail = [m for m in EMAIL.findall(t) if not SCARTA.search(m)]
    # scarta gli indirizzi che sono chiaramente di terzi (supporto, liste)
    mail = [m for m in mail if not re.match(r"(info|support|contact|hello|admin|"
                                            r"security|abuse)@", m, re.I)] or mail
    r = {"email_readme": mail[0] if mail else None, "quante": len(set(mail))}
    cache[repo] = r
    return r


def main():
    if not TOK:
        print("[!] GITHUB_TOKEN non trovato: senza token il limite e' 60/ora.")
    reg = json.loads(REG.read_text(encoding="utf-8"))
    cache = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}
    target = [r for r in reg if r.get("canale") == "nessun canale utilizzabile"]
    print(f"cerco un contatto nel README di {len(target)} repository...")

    rec = 0
    for i, r in enumerate(target, 1):
        c = contatto(r["repo_github"], cache)
        if c["email_readme"]:
            r["canale"] = "email nel README"
            r["email"] = c["email_readme"]
            rec += 1
        if i % 50 == 0:
            print(f"   {i}/{len(target)}  (recuperati finora: {rec})")
            CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
        time.sleep(0.05)

    CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    REG.write_text(json.dumps(reg, ensure_ascii=False, indent=1), encoding="utf-8")

    c = Counter(r.get("canale") for r in reg if r.get("canale"))
    ragg = {"SECURITY.md", "email pubblica", "email nel README"}
    n_r = sum(v for k, v in c.items() if k in ragg)
    cred_r = sum(r["n_credenziali"] for r in reg if r.get("canale") in ragg)
    cred_t = sum(r["n_credenziali"] for r in reg if r.get("canale"))
    print(f"\nrecuperati dal README: {rec}\n")
    print(f"{'canale':<34} {'repo':>5}")
    for k, v in c.most_common():
        print(f"  {k:<32} {v:>5}")
    tot = sum(c.values())
    print(f"\nraggiungibili : {n_r}/{tot} ({100*n_r/max(tot,1):.0f}%)")
    print(f"credenziali coperte: {cred_r}/{cred_t} ({100*cred_r/max(cred_t,1):.0f}%)")


if __name__ == "__main__":
    main()
