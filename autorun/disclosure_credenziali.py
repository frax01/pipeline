#!/usr/bin/env python3
"""
disclosure_credenziali.py — prepara la campagna di notifica agli owner dei
repository che hanno credenziali esposte. NON INVIA NULLA.

Perimetro: la classe `hardcoded-credential` e' l'unica auditata **per intero**
e non a campione, e conferma al 95%. E' quindi l'unico gruppo su cui una
notifica di massa e' difendibile: sulle altre categorie la precisione pesata e'
del 49,7% e scrivere a tutti significherebbe sbagliare in meta' dei casi.

Cosa fa:
  1. raccoglie i finding di credenziali CONFERMATI dall'audit manuale;
  2. risolve i pacchetti npx al repository GitHub di origine, leggendo il campo
     `repository` del registry npm (lettura pubblica, senza autenticazione);
  3. genera un messaggio per repository, con file e riga specifici;
  4. scrive il registro per tracciare le risposte.

Il messaggio **non contiene mai il valore della chiave**: indica dove si trova.
Mandare la credenziale in chiaro in una issue pubblica la esporrebbe una
seconda volta.

Uso:
    python autorun/disclosure_credenziali.py               # tutto
    python autorun/disclosure_credenziali.py --no-npm      # salta la risoluzione
"""
import argparse
import json
import re
import textwrap
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "disclosure"
CACHE = REPO / "autorun" / "_npm_repo_cache.json"

PROVIDER = [
    ("Google", r"AIza|GOOGLE|GEMINI|FIREBASE|GCP|YOUTUBE|MAPS"),
    ("OpenAI", r"\bsk-|OPENAI"), ("GitHub", r"ghp_|gho_|GITHUB_(TOKEN|CLIENT_SECRET)"),
    ("Slack", r"xox[baprs]-|SLACK"), ("Groq", r"gsk_|GROQ"),
    ("Docker", r"dckr_pat_|DOCKER"), ("OpenWeather", r"OPENWEATHER|OWM_"),
    ("AWS", r"AKIA|AWS_(SECRET|ACCESS)"), ("Stripe", r"sk_live_|pk_live_|STRIPE"),
    ("Anthropic", r"ANTHROPIC|CLAUDE_API"), ("Telegram", r"TELEGRAM|BOT_TOKEN"),
    ("Supabase", r"SUPABASE"), ("Cerebras", r"\bcsk-|CEREBRAS"),
    ("HuggingFace", r"\bhf_|HUGGING"), ("Notion", r"NOTION"), ("Discord", r"DISCORD"),
]


def items(d):
    return d if isinstance(d, list) else (d.get("findings") or d.get("entries") or [])


def provider_di(testo):
    return next((n for n, p in PROVIDER if re.search(p, testo or "", re.I)), None)


def confermati():
    """(repo, file, riga, provider) dei soli finding confermati a mano."""
    out = defaultdict(list)

    # --- guard/hardcoded-credential: verdetto per (repo, file) ---
    hc = {(x["repo"], x["file"]): x["verdetto"]
          for x in json.loads((REPO / "autorun" / "manual_audit" /
                               "verdetti_HC.json").read_text(encoding="utf-8"))}
    for p in REPO.glob("mcp_guard/postprocessing/hardcoded-credential-static/**/vp.json"):
        for f in items(json.loads(p.read_text(encoding="utf-8"))):
            srv = (f.get("server_url") or "").replace("https://github.com/", "").rstrip("/")
            fil = f.get("file") or ""
            if hc.get((srv, fil)) not in ("VP-C", "VP-D"):
                continue
            desc = f.get("description") or ""
            m = re.search(r"in (.+?) at line (\d+)", desc)
            out[srv].append({"file": m.group(1) if m else fil,
                             "riga": int(m.group(2)) if m else None,
                             "provider": provider_di(desc),
                             "fonte": "hardcoded-credential"})

    # --- watch/credential-leak: verdetto per cluster ---
    base = REPO / "autorun" / "credleak_audit"
    if (base / "indice.json").exists():
        ver = {c["id"]: c["verdetto"]
               for c in json.loads((base / "verdetti_cluster.json").read_text(encoding="utf-8"))}
        for cid, lst in json.loads((base / "indice.json").read_text(encoding="utf-8")).items():
            if ver.get(cid) not in ("VP-C", "VP-D"):
                continue
            for x in lst:
                srv = (x.get("github_url") or "").replace("https://github.com/", "").rstrip("/")
                if not srv:
                    continue
                out[srv].append({"file": x.get("file"), "riga": x.get("line"),
                                 "provider": None, "fonte": "credential-leak"})
    # dedup per (file, riga)
    for s in out:
        visti, puliti = set(), []
        for f in out[s]:
            k = (f["file"], f["riga"])
            if k in visti:
                continue
            visti.add(k)
            puliti.append(f)
        out[s] = puliti
    return out


def risolvi_npm(pkg, cache):
    """pacchetto npm -> owner/repo GitHub, dal campo `repository` del registry."""
    if pkg in cache:
        return cache[pkg]
    url = "https://registry.npmjs.org/" + urllib.parse.quote(pkg, safe="@")
    val = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "academic-study"})
        with urllib.request.urlopen(req, timeout=20) as f:
            d = json.loads(f.read().decode("utf-8", "replace"))
        r = (d.get("repository") or {})
        u = r.get("url") if isinstance(r, dict) else r
        if u:
            m = re.search(r"github\.com[:/]+([^/]+/[^/.]+)", u)
            if m:
                val = m.group(1)
    except Exception:
        pass
    cache[pkg] = val
    return val


INTRO = """Subject: Responsible disclosure: hardcoded credential in {repo}

Hello,

My name is Francesco Martignoni. I am a former Master's student at Politecnico
di Milano, where, as part of my thesis project, I conducted a large-scale
analysis of the Model Context Protocol (MCP) ecosystem, with a particular focus
on identifying potential security vulnerabilities and misconfigurations in
publicly available MCP servers.

As part of this research, we analysed 69,104 publicly published MCP servers.
Your repository was identified during one of our security checks, and I am
contacting you as part of our responsible disclosure process to privately
report a potential issue that may warrant your attention.

{specifica}

{elenco}

I am deliberately not including the {valore} in this email. We have never used
the {credenziale}, attempted to authenticate with {pron}, invoked any associated
API, or otherwise tested whether {pron2} currently active. The {finding} initially
identified through static analysis and subsequently manually reviewed to reduce
the likelihood of a false positive.

{rimedio}

{placeholder}

This message is solely intended as a responsible disclosure of the finding. No
action or response is required from you within any particular timeframe, and we
are not requesting anything in return. The study is academic in nature, and your
repository is not individually identified in the resulting research.
"""

CHIUSURA = """
Should you require any further information or clarification regarding the study,
the methodology, or this disclosure, please feel free to contact any of the
researchers involved:

  * Francesco Martignoni - Former Master's Student, Politecnico di Milano -
    francesco.martignoni@mail.polimi.it
  * Michele Carminati - Associate Professor, Politecnico di Milano, DEIB -
    michele.carminati@polimi.it
  * Stefano Longari - Assistant Professor, Politecnico di Milano, DEIB -
    stefano.longari@polimi.it

Kind regards,
Francesco Martignoni
Politecnico di Milano
francesco.martignoni@mail.polimi.it
"""

RIMEDIO_SING = """If the value corresponds to a valid credential, removing it from the current
version of the source code would not, by itself, fully address the exposure, as
the value may remain accessible through the repository's Git history. In such
cases, the standard remediation would be to issue a new credential, update the
relevant configuration to use it, and subsequently revoke or retire the exposed
credential. More generally, credentials committed to a public repository should
be considered potentially compromised regardless of whether they are still
active, as publicly available source code may be continuously indexed and
scanned by automated systems."""

RIMEDIO_PLUR = """If these values correspond to valid credentials, removing them from the current
version of the source code would not, by itself, fully address the exposure, as
the values may remain accessible through the repository's Git history. In such
cases, the standard remediation would be to issue new credentials, update the
relevant configuration to use them, and subsequently revoke or retire the
exposed ones. More generally, credentials committed to a public repository
should be considered potentially compromised regardless of whether they are
still active, as publicly available source code may be continuously indexed and
scanned by automated systems."""

PH_SING = """If, on the other hand, the identified value is merely a placeholder, an example
credential, or a credential that has already been rotated or revoked, no further
action may be necessary, and I apologise for any unnecessary notification."""

PH_PLUR = """If, on the other hand, the identified values are merely placeholders, example
credentials, or credentials that have already been rotated or revoked, no
further action may be necessary, and I apologise for any unnecessary
notification."""


NL = chr(10)
SEP = NL * 2


def riavvolgi(testo, larghezza=78):
    """Riformatta i paragrafi di prosa a `larghezza` colonne.

    Le sostituzioni singolare/plurale cambiano la lunghezza delle frasi e
    lasciano righe di lunghezze irregolari: qui il testo viene riavvolto una
    volta sola, alla fine. Elenchi puntati, riga dell'oggetto e firma restano
    come sono.
    """
    fuori = ("  *", "    ", "Subject:", "Kind regards,", "Hello,",
             "Francesco Martignoni", "Politecnico di Milano",
             "francesco.martignoni@")
    out = []
    for par in testo.split(SEP):
        if any(r.startswith(fuori) for r in par.split(NL)):
            out.append(par)
        else:
            out.append(textwrap.fill(" ".join(par.split()), larghezza))
    return SEP.join(out)


def messaggio(repo, finding):
    """Genera il testo per un repository. Il valore della chiave non compare mai."""
    prov = sorted({f["provider"] for f in finding if f["provider"]})
    n = len(finding)
    if n == 1:
        cosa = "what appears to be a hardcoded credential in the following location"
        if prov:
            cosa = (f"what appears to be a hardcoded {prov[0]} credential in the "
                    "following location")
        campi = dict(cosa=cosa, valore="value", credenziale="credential",
                     pron="it", pron2="it is", finding="finding was",
                     rimedio=RIMEDIO_SING, placeholder=PH_SING)
    else:
        cosa = f"what appear to be {n} hardcoded credentials in the following locations"
        if prov:
            cosa += f" (including credentials for {', '.join(prov)})"
        campi = dict(cosa=cosa, valore="values", credenziale="credentials",
                     pron="them", pron2="they are", finding="findings were",
                     rimedio=RIMEDIO_PLUR, placeholder=PH_PLUR)

    righe = []
    for f in finding[:6]:
        loc = f["file"] + (f":{f['riga']}" if f["riga"] else "")
        righe.append(f"  * {loc}" + (f"   ({f['provider']})" if f["provider"] else ""))
    if n > 6:
        righe.append(f"  * ... and {n - 6} further locations, available on request")

    campi["specifica"] = "Specifically, we identified " + campi.pop("cosa") + ":"
    return riavvolgi(
        INTRO.format(repo=repo, elenco=chr(10).join(righe), **campi) + CHIUSURA)


def scrivi_messaggi(reg, msgdir):
    """Rigenera i .txt dal registro. Non tocca il registro stesso."""
    msgdir.mkdir(parents=True, exist_ok=True)
    n = 0
    for r in reg:
        if not r.get("repo_github"):
            continue
        prov = r.get("provider") or []
        f = [{"file": p["file"], "riga": p["riga"],
              "provider": prov[0] if prov else None} for p in r["posizioni"]]
        (msgdir / (r["repo_github"].replace("/", "__") + ".txt")).write_text(
            messaggio(r["repo_github"], f), encoding="utf-8")
        n += 1
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-npm", action="store_true")
    ap.add_argument("--solo-testi", action="store_true",
                    help="rigenera solo i .txt dal registro esistente, senza "
                         "ricostruirlo (il registro contiene i canali e gli "
                         "indirizzi risolti dopo, che verrebbero persi)")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    if a.solo_testi:
        reg = json.loads((OUT / "campagna_credenziali.json").read_text(encoding="utf-8"))
        n = scrivi_messaggi(reg, OUT / "messaggi")
        print(f"messaggi rigenerati: {n:,}  -> {OUT / 'messaggi'}")
        print("registro non toccato.")
        return

    dati = confermati()
    print(f"finding confermati: {sum(len(v) for v in dati.values()):,} "
          f"su {len(dati):,} server")

    cache = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}
    reg, non_risolti = [], 0
    pkg = [s for s in dati if "/" not in s or s.startswith("@")]
    if pkg and not a.no_npm:
        print(f"risolvo {len(pkg)} pacchetti npm al repository di origine...")
        for i, p in enumerate(pkg, 1):
            risolvi_npm(p, cache)
            if i % 50 == 0:
                print(f"   {i}/{len(pkg)}")
                CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
            time.sleep(0.15)
        CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")

    for s, f in sorted(dati.items()):
        gh = s if ("/" in s and not s.startswith("@")) else cache.get(s)
        if not gh:
            non_risolti += 1
        reg.append({"origine": s, "repo_github": gh, "n_credenziali": len(f),
                    "provider": sorted({x["provider"] for x in f if x["provider"]}),
                    "posizioni": [{"file": x["file"], "riga": x["riga"]} for x in f],
                    "contattabile": bool(gh), "stato": "da inviare",
                    "data_invio": None, "esito": None})

    (OUT / "campagna_credenziali.json").write_text(
        json.dumps(reg, ensure_ascii=False, indent=1), encoding="utf-8")

    msgdir = OUT / "messaggi"
    scritti = scrivi_messaggi(reg, msgdir)

    print(f"\ncontattabili        : {sum(1 for r in reg if r['contattabile']):,}")
    print(f"non risolti a un repo: {non_risolti:,}")
    print(f"messaggi generati   : {scritti:,}  -> {msgdir}")
    print(f"registro            : {OUT / 'campagna_credenziali.json'}")


if __name__ == "__main__":
    main()
