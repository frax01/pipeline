#!/usr/bin/env python3
"""
disclosure_uno.py — invia UN singolo messaggio gia' scritto, con eventuale copia.

Serve per le comunicazioni che non stanno nella campagna di massa: i casi
singoli (§9a) e i 29 repository con `SECURITY.md`, che hanno ognuno un
destinatario diverso deciso a mano.

**Di default non invia**: stampa il messaggio e i destinatari. Serve `--invia`.

Il file deve avere `Subject: ...` sulla prima riga, come tutti i testi generati.

Credenziali SMTP dall'ambiente, mai stampate:
    SMTP_HOST  SMTP_PORT  SMTP_USER  SMTP_PASS

Uso:
    python autorun/disclosure_uno.py --file docs/disclosure/messaggi_estensione/x.txt \\
        --a tizio@example.com --cc caio@example.com
    ... e la stessa riga con --invia per mandarlo davvero.
"""
import argparse
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def env(nome):
    v = os.environ.get(nome)
    if v:
        return v
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return winreg.QueryValueEx(k, nome)[0]
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="file del messaggio")
    ap.add_argument("--a", required=True, help="destinatario")
    ap.add_argument("--cc", default=None, help="copia (facoltativa)")
    ap.add_argument("--invia", action="store_true",
                    help="invia davvero; senza questo e' una prova a vuoto")
    ap.add_argument("--via", choices=("outlook", "smtp"), default="outlook",
                    help="come spedire (default outlook)")
    a = ap.parse_args()

    f = Path(a.file)
    if not f.is_absolute():
        f = REPO / a.file
    if not f.exists():
        print(f"[!] file non trovato: {f}")
        sys.exit(1)

    righe = f.read_text(encoding="utf-8").split("\n")
    if not righe[0].startswith("Subject:"):
        print("[!] la prima riga del file non e' 'Subject: ...'")
        sys.exit(1)
    oggetto = righe[0].replace("Subject:", "").strip()
    corpo = "\n".join(righe[1:]).lstrip("\n")

    resti = [s for s in ("[NOME]", "[EMAIL]", "[DATA]", "[CHIUSURA]",
                         "[CATEGORIE]", "[ELENCO]", "[CATEGORIA]") if s in corpo]
    if resti:
        print(f"[!] il testo contiene ancora segnaposto: {', '.join(resti)}")
        print("    sostituirli prima di inviare.")
        sys.exit(1)

    print(f"file    : {f}")
    print(f"a       : {a.a}")
    print(f"cc      : {a.cc or '(nessuna)'}")
    print(f"oggetto : {oggetto}")
    print(f"corpo   : {len(corpo.split(chr(10)))} righe, {len(corpo)} caratteri")

    if not a.invia:
        print("\n" + "-" * 70)
        print(corpo)
        print("-" * 70)
        print("\nPROVA A VUOTO: non e' partito niente.")
        print("Per inviare davvero, ripetere il comando con --invia.")
        return

    if a.via == "outlook":
        import win32com.client
        ol = win32com.client.Dispatch("Outlook.Application")
        ns = ol.GetNamespace("MAPI")
        if getattr(ns, "Offline", False):
            print("[!] Outlook e' non in linea: il messaggio resterebbe in")
            print("    Posta in uscita. Rimetterlo in linea.")
            sys.exit(1)
        print("mittente:", ns.Accounts.Item(1).SmtpAddress)
        m = ol.CreateItem(0)
        m.To = a.a
        if a.cc:
            m.CC = a.cc
        m.Subject = oggetto
        m.Body = corpo
        m.Send()
    else:
        host, porta = env("SMTP_HOST"), env("SMTP_PORT")
        utente, pwd = env("SMTP_USER"), env("SMTP_PASS")
        if not all([host, porta, utente, pwd]):
            print("[!] configurazione SMTP incompleta, non invio nulla.")
            print("    servono SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS")
            sys.exit(1)
        m = EmailMessage()
        m["From"] = utente
        m["To"] = a.a
        if a.cc:
            m["Cc"] = a.cc
        m["Subject"] = oggetto
        m.set_content(corpo)
        with smtplib.SMTP(host, int(porta), timeout=30) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(utente, pwd)
            s.send_message(m)

    print(f"\nINVIATO a {a.a}" + (f" (cc {a.cc})" if a.cc else ""))
    print("Annotare data ed esito in docs/disclosure/FASE3.md.")


if __name__ == "__main__":
    main()
