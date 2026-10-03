#!/usr/bin/env python3
"""
disclosure_invio.py — invia le notifiche via email ai manutentori raggiungibili.

**Di default NON invia**: stampa cosa manderebbe. Serve `--invia` esplicito.

Protezioni, che non sono formalita':
  * dry-run come comportamento predefinito;
  * `--max N` per limitare il lotto (i primi invii vanno fatti pochi alla volta
    e verificati, un errore nel modello si moltiplica per 167);
  * pausa fra un messaggio e l'altro: un server istituzionale blocca le raffiche
    e una sequenza di messaggi quasi identici a sconosciuti finisce in spam;
  * ripresa dal registro: chi ha gia' ricevuto non viene ricontattato;
  * ogni invio scrive data ed esito nel registro, che e' anche il materiale con
    cui si scrive la sezione sulla disclosure.

Le credenziali SMTP si leggono dall'ambiente e non vengono mai stampate:

    SMTP_HOST     es. smtp.polimi.it
    SMTP_PORT     es. 587
    SMTP_USER     il proprio indirizzo
    SMTP_PASS     password applicativa
    MITTENTE      nome e cognome, per la firma

Uso:
    python autorun/disclosure_invio.py                    # dry-run completo
    python autorun/disclosure_invio.py --max 5            # dry-run dei primi 5
    python autorun/disclosure_invio.py --invia --max 5    # invia i primi 5
    python autorun/disclosure_invio.py --invia --max 25   # lotto successivo
"""
import argparse
import json
import os
import smtplib
import ssl
import sys
import time
from datetime import date
from email.message import EmailMessage
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REG = REPO / "docs" / "disclosure" / "campagna_credenziali.json"
MSG = REPO / "docs" / "disclosure" / "messaggi"

CANALI_EMAIL = {"email pubblica", "email nel README"}


def env(nome, obbligatorio=True):
    v = os.environ.get(nome)
    if not v:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
                v = winreg.QueryValueEx(k, nome)[0]
        except Exception:
            v = None
    if not v and obbligatorio:
        print(f"[!] variabile d'ambiente {nome} non impostata")
    return v


def corpo(repo, mittente, indirizzo_mittente):
    """Legge il messaggio gia' generato e vi sostituisce i segnaposto."""
    f = MSG / (repo.replace("/", "__") + ".txt")
    if not f.exists():
        return None, None
    t = f.read_text(encoding="utf-8")
    t = t.replace("[NOME]", mittente).replace("[EMAIL]", indirizzo_mittente)
    righe = t.split("\n")
    oggetto = righe[0].replace("Subject:", "").strip()
    return oggetto, "\n".join(righe[1:]).lstrip("\n")



def trasporto(via, utente_smtp):
    """Restituisce (manda, mittente, chiudi).

    `outlook` parla con l'Outlook classico gia' aperto e autenticato tramite
    COM: nessuna credenziale entra in gioco, il mittente e' l'account del
    profilo MAPI e i messaggi finiscono in Posta inviata come qualunque altra
    email. E' anche l'unica via praticabile su Microsoft 365, dove
    l'autenticazione di base per SMTP e' disattivata.
    """
    if via == "outlook":
        try:
            import win32com.client
        except ImportError:
            print("[!] pywin32 non installato: pip install pywin32")
            return None, None, lambda: None
        try:
            ol = win32com.client.Dispatch("Outlook.Application")
            ns = ol.GetNamespace("MAPI")
            if getattr(ns, "Offline", False):
                print("[!] Outlook e' in modalita' non in linea: i messaggi")
                print("    resterebbero in Posta in uscita. Rimetterlo in linea.")
                return None, None, lambda: None
            mittente = ns.Accounts.Item(1).SmtpAddress
        except Exception as e:
            print(f"[!] non riesco a parlare con Outlook: {type(e).__name__}: {e}")
            print("    Outlook classico deve essere aperto.")
            return None, None, lambda: None

        def manda(a, cc, oggetto, testo):
            m = ol.CreateItem(0)
            m.To = a
            if cc:
                m.CC = cc
            m.Subject = oggetto
            m.Body = testo
            m.Send()

        return manda, mittente, lambda: None

    host, porta = env("SMTP_HOST"), env("SMTP_PORT")
    pwd = env("SMTP_PASS")
    if not all([host, porta, utente_smtp, pwd]):
        print("[!] configurazione SMTP incompleta, non invio nulla.")
        return None, None, lambda: None
    s = smtplib.SMTP(host, int(porta), timeout=30)
    s.starttls(context=ssl.create_default_context())
    s.login(utente_smtp, pwd)

    def manda(a, cc, oggetto, testo):
        m = EmailMessage()
        m["From"] = utente_smtp
        m["To"] = a
        if cc:
            m["Cc"] = cc
        m["Subject"] = oggetto
        m.set_content(testo)
        s.send_message(m)

    return manda, utente_smtp, s.quit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--invia", action="store_true",
                    help="invia davvero; senza questo e' una prova a vuoto")
    ap.add_argument("--max", type=int, default=None, help="quanti al massimo")
    ap.add_argument("--pausa", type=float, default=20.0,
                    help="secondi fra un invio e l'altro (default 20)")
    ap.add_argument("--via", choices=("outlook", "smtp"), default="outlook",
                    help="come spedire: 'outlook' usa l'Outlook classico gia' "
                         "aperto e autenticato (nessuna credenziale, mittente "
                         "l'account del profilo); 'smtp' richiede SMTP_*")
    a = ap.parse_args()

    reg = json.loads(REG.read_text(encoding="utf-8"))
    coda = [r for r in reg
            if r.get("canale") in CANALI_EMAIL
            and r.get("stato") != "inviato"
            and (r.get("email") or r.get("info_canale", {}).get("email_owner"))]

    # per i 92 con email sul profilo l'indirizzo non e' nel registro: va risolto
    mancanti = [r for r in coda if not r.get("email")]
    if mancanti:
        print(f"[!] {len(mancanti)} destinatari hanno il canale 'email pubblica' ma")
        print("    l'indirizzo non e' nel registro: eseguire prima")
        print("    python autorun/disclosure_contatti.py")
        coda = [r for r in coda if r.get("email")]

    if a.max:
        coda = coda[:a.max]

    mitt = env("MITTENTE", False) or "[NOME]"
    utente = env("SMTP_USER", a.invia and a.via == "smtp") or "[EMAIL]"
    print(f"{'INVIO' if a.invia else 'PROVA A VUOTO (nessun messaggio parte)'}"
          f" — {len(coda)} destinatari, pausa {a.pausa}s\n")

    if not a.invia:
        for r in coda[:3]:
            og, co = corpo(r["repo_github"], mitt, utente)
            print(f"--- a: {r['email']}  ({r['repo_github']})")
            print(f"    oggetto: {og}")
            print("    " + "\n    ".join(co.split("\n")[:6]) + "\n    [...]\n")
        print(f"... e altri {max(0, len(coda)-3)} destinatari.")
        print("\nPer inviare davvero: aggiungere --invia (e cominciare con --max 5).")
        return

    manda, mittente_reale, chiudi = trasporto(a.via, utente)
    if not manda:
        sys.exit(1)
    print(f"mittente reale: {mittente_reale}")
    print()

    inviati = falliti = 0
    try:
        for i, r in enumerate(coda, 1):
            og, co = corpo(r["repo_github"], mitt, mittente_reale)
            if not og:
                continue
            try:
                manda(r["email"], None, og, co)
                r["stato"] = "inviato"
                r["data_invio"] = date.today().isoformat()
                r["esito"] = f"consegnato ({a.via})"
                inviati += 1
                print(f"  [{i}/{len(coda)}] -> {r['email']}  ({r['repo_github']})")
            except Exception as e:
                r["esito"] = f"errore: {type(e).__name__}"
                falliti += 1
                print(f"  [{i}/{len(coda)}] FALLITO {r['email']}: {type(e).__name__}")
            REG.write_text(json.dumps(reg, ensure_ascii=False, indent=1),
                           encoding="utf-8")
            if i < len(coda):
                time.sleep(a.pausa)
    finally:
        chiudi()

    print(f"\ninviati: {inviati} | falliti: {falliti}")
    print(f"registro aggiornato -> {REG}")


if __name__ == "__main__":
    main()
