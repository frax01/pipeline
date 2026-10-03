#!/usr/bin/env python3
"""
disclosure_contatti.py — completa il registro con i contatti effettivi.

Due cose, entrambe in sola lettura su dati pubblici:

  1. per i repository con canale "email pubblica" recupera l'indirizzo dal
     profilo GitHub dell'owner (nel registro era salvato solo il fatto che
     esistesse, non il valore);
  2. per i repository con `SECURITY.md` ne estrae la procedura dichiarata —
     indirizzo, link o indicazione di usare il private reporting — e produce
     una tabella da seguire a mano, perche' ogni progetto dichiara una via
     diversa e non e' automatizzabile.

Uso:
    python autorun/disclosure_contatti.py
"""
import base64
import json
import os
import re
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "docs" / "disclosure" / "campagna_credenziali.json"
OUT = REPO / "docs" / "disclosure" / "SECURITY_MD.md"


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


HDR = {"User-Agent": "academic-study", "Accept": "application/vnd.github+json"}
if token():
    HDR["Authorization"] = f"Bearer {token()}"

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
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
LINK = re.compile(r"https?://[^\s)>\]]+", re.I)


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


def main():
    reg = json.loads(REG.read_text(encoding="utf-8"))

    # --- 1. indirizzi dal profilo ---
    da_risolvere = [r for r in reg
                    if r.get("canale") == "email pubblica" and not r.get("email")]
    print(f"recupero l'indirizzo dal profilo per {len(da_risolvere)} owner...")
    cache, ok = {}, 0
    for i, r in enumerate(da_risolvere, 1):
        owner = r["repo_github"].split("/")[0]
        if owner not in cache:
            u = get(f"https://api.github.com/users/{owner}")
            cache[owner] = (u or {}).get("email")
            time.sleep(0.05)
        if cache[owner] and not SCARTA.search(cache[owner]):
            r["email"] = cache[owner]
            ok += 1
        else:
            r["canale"] = "nessun canale utilizzabile"
            r["nota_canale"] = "email del profilo non recuperabile o segnaposto"
        if i % 25 == 0:
            print(f"   {i}/{len(da_risolvere)}")
    print(f"   risolti: {ok}, decaduti: {len(da_risolvere)-ok}")

    # --- 2. procedura dichiarata nei SECURITY.md ---
    sec = [r for r in reg if r.get("canale") == "SECURITY.md"]
    print(f"\nestraggo la procedura da {len(sec)} SECURITY.md...")
    righe = []
    for r in sec:
        repo = r["repo_github"]
        t = ""
        for p in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
            t = testo(get(f"https://api.github.com/repos/{repo}/contents/{p}"))
            if t:
                break
        mail = [m for m in EMAIL.findall(t) if not SCARTA.search(m)]
        link = [l for l in LINK.findall(t)
                if re.search(r"(security|advisor|report|vuln|contact|hackerone|"
                             r"bugcrowd)", l, re.I)]
        priv = bool(re.search(r"(private vulnerability reporting|security/advisories|"
                              r"report a vulnerability)", t, re.I))
        via = (f"email: {mail[0]}" if mail else
               (f"link: {link[0][:70]}" if link else
                ("private vulnerability reporting" if priv else
                 "procedura non chiara, leggere il file")))
        r["contatto_securitymd"] = via
        righe.append((repo, r["n_credenziali"], via))
        time.sleep(0.05)

    REG.write_text(json.dumps(reg, ensure_ascii=False, indent=1), encoding="utf-8")

    out = ["# I 29 repository con `SECURITY.md`", "",
           "Ognuno dichiara la propria procedura: vanno seguite a mano, non sono",
           "automatizzabili. Il messaggio da usare e' quello gia' generato in",
           "`messaggi/<owner>__<repo>.txt`.", "",
           "| repository | cred. | come segnalare | fatto |",
           "|---|---:|---|:--:|"]
    for repo, n, via in sorted(righe, key=lambda x: -x[1]):
        out.append(f"| `{repo}` | {n} | {via} | ☐ |")
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")

    from collections import Counter
    c = Counter(r.get("canale") for r in reg if r.get("canale"))
    pronti = sum(1 for r in reg if r.get("email"))
    print(f"\ndestinatari con indirizzo pronto: {pronti}")
    for k, v in c.most_common():
        print(f"   {k:<34} {v:>4}")
    print(f"\ntabella SECURITY.md -> {OUT}")


if __name__ == "__main__":
    main()
