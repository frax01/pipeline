#!/usr/bin/env python3
"""
aggregato_finale.py — confronto definitivo fra prima analisi e rirun, sulle
STESSE 17 categorie.

Le 17 categorie della prima analisi sono aggregati di piu' sotto-categorie
prodotte da tool diversi. La mappatura e' stata ricostruita verificando che la
somma dei VP per categoria riproduca esattamente i totali dichiarati nella prima
analisi (27.958 in totale, riga per riga).

Il tasso di conferma di ogni categoria e' la media dei tassi delle sue
sotto-categorie, **pesata sui VP di ciascuna**: una sotto-categoria che vale
1.155 VP non puo' contare quanto una che ne vale 5.

"Confermato" = VP-C + VP-D (sfruttabile, anche se con impatto limitato).
I VP-L (capability dichiarata, non sfruttabile) contano come NON confermati,
coerentemente con la convenzione della prima analisi.

Uso:
    python autorun/aggregato_finale.py
    python autorun/aggregato_finale.py --out docs/rirun/CONFRONTO_FINALE.md
"""
import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AUD = REPO / "autorun" / "manual_audit"

# categoria delle 17 -> [(etichetta sotto-categoria, glob dei vp.json)]
MAPPA = {
    "Untrusted content": [("scan/W015", "mcp_scan/postprocessing/**/W015/**/vp.json")],
    "Sensitive info disclosure": [
        ("scan/W017_npx", "mcp_scan/postprocessing/**/W017_npx/**/vp.json"),
        ("scan/W018_npx", "mcp_scan/postprocessing/**/W018_npx/**/vp.json"),
        ("guard/information-disclosure-fuzzing", "mcp_guard/postprocessing/information-disclosure-fuzzing/**/vp.json"),
        ("fuzzing/tool-error-disclosure", "fuzzing/postprocessing/tool-error-disclosure/**/vp.json"),
        ("guard/sensitive-info-disclosed", "mcp_guard/postprocessing/sensitive-info-disclosed-fuzzing/**/vp.json")],
    "Credential leak": [
        ("watch/credential-leak", "mcp_watch/postprocessing/credential-leak/**/vp.json"),
        ("guard/hardcoded-credential", "mcp_guard/postprocessing/hardcoded-credential-static/**/vp.json")],
    "Dangerous capabilities": [
        ("security_scan/dangerous-capabilities", "mcp_security_scan/postprocessing/dangerous-capabilities/**/vp.json"),
        ("guard/dangerous-tool-handler", "mcp_guard/postprocessing/dangerous-tool-handler-static/**/vp.json"),
        ("scan/W019_npx", "mcp_scan/postprocessing/**/W019_npx/**/vp.json"),
        ("scan/W020_npx", "mcp_scan/postprocessing/**/W020_npx/**/vp.json")],
    "Protocol violation": [
        ("check (tutto)", "mcp_check/postprocessing/**/vp.json"),
        ("watch/protocol-violation", "mcp_watch/postprocessing/protocol-violation/**/vp.json"),
        ("guard/protocol-*", "mcp_guard/postprocessing/protocol-*/**/vp.json"),
        ("fuzzing/tool-crash-dos", "fuzzing/postprocessing/tool-crash-dos/**/vp.json")],
    "SQL injection": [("guard/sql-injection-static", "mcp_guard/postprocessing/sql-injection-static/**/vp.json")],
    "SSRF": [("guard/ssrf-static", "mcp_guard/postprocessing/ssrf-static/**/vp.json")],
    "Code injection": [
        ("guard/code-injection-static", "mcp_guard/postprocessing/code-injection-static/**/vp.json"),
        ("guard/code-injection-fuzzing", "mcp_guard/postprocessing/code-injection-fuzzing/**/vp.json")],
    "Input validation": [
        ("watch/input-validation", "mcp_watch/postprocessing/input-validation/**/vp.json"),
        ("security_scan/input-validation", "mcp_security_scan/postprocessing/input-validation/**/vp.json")],
    "Path traversal": [
        ("guard/path-traversal-fuzzing", "mcp_guard/postprocessing/path-traversal-fuzzing/**/vp.json"),
        ("guard/path-traversal-static", "mcp_guard/postprocessing/path-traversal-static/**/vp.json"),
        ("security_scan/path-traversal", "mcp_security_scan/postprocessing/path-traversal/**/vp.json")],
    "Command injection": [
        ("guard/command-injection-fuzzing", "mcp_guard/postprocessing/command-injection-fuzzing/**/vp.json"),
        ("guard/command-injection-static", "mcp_guard/postprocessing/command-injection-static/**/vp.json"),
        ("guard/command-execution-fuzzing", "mcp_guard/postprocessing/command-execution-fuzzing/**/vp.json")],
    "Prompt injection": [
        ("scan/E001", "mcp_scan/postprocessing/**/E001/**/vp.json"),
        ("guard/prompt-injection-static", "mcp_guard/postprocessing/prompt-injection-static/**/vp.json"),
        ("shield/hidden-instructions", "mcp_shield/postprocessing/hidden-instructions/**/vp.json")],
    "Insecure deserialization": [("guard/insecure-deserialization", "mcp_guard/postprocessing/insecure-deserialization-static/**/vp.json")],
    "Sensitive file access": [
        ("shield/sensitive-file-access", "mcp_shield/postprocessing/sensitive-file-access/**/vp.json"),
        ("security_scan/sensitive-file-access", "mcp_security_scan/postprocessing/sensitive-file-access/**/vp.json")],
    "Access control": [
        ("watch/access-control", "mcp_watch/postprocessing/access-control/**/vp.json"),
        ("security_scan/remote-access-control", "mcp_security_scan/postprocessing/remote-access-control/**/vp.json")],
    "Data exfiltration": [("watch/data-exfiltration", "mcp_watch/postprocessing/data-exfiltration/**/vp.json")],
    "Tool shadowing": [("shield/shadowing-detected", "mcp_shield/postprocessing/shadowing-detected/**/vp.json")],
}

# prima analisi: (VP totali, analizzati, confermati)
PRIMA = {
    "Untrusted content": (952, 15, 15), "Sensitive info disclosure": (1873, 15, 15),
    "Data exfiltration": (2, 2, 2), "Tool shadowing": (1, 1, 1),
    "Credential leak": (1342, 1342, 1258), "Insecure deserialization": (31, 15, 14),
    "Prompt injection": (118, 16, 13), "Dangerous capabilities": (3745, 15, 10),
    "Protocol violation": (15436, 15, 9), "SQL injection": (2406, 30, 16),
    "SSRF": (741, 15, 8), "Code injection": (220, 23, 10),
    "Input validation": (254, 19, 8), "Sensitive file access": (18, 18, 7),
    "Path traversal": (537, 15, 5), "Command injection": (274, 15, 4),
    "Access control": (8, 8, 2),
}

# etichette usate nei file di verdetto delle categorie auditate per prime
ALIAS = {
    "sql-injection": "guard/sql-injection-static", "ssrf": "guard/ssrf-static",
    "path-traversal-static": "guard/path-traversal-static",
    "command-injection-static": "guard/command-injection-static",
    "code-injection-static": "guard/code-injection-static",
    "input-validation": "watch/input-validation",
    "protocol-violation": "watch/protocol-violation",
    "insecure-deserialization": "guard/insecure-deserialization",
    "sensitive-file-access": "shield/sensitive-file-access",
    "sensitive-info-disclosure": "guard/sensitive-info-disclosed",
    "access-control": "watch/access-control",
    "data-exfiltration": "watch/data-exfiltration",
    "tool-shadowing": "shield/shadowing-detected",
    "dangerous-capabilities": "security_scan/dangerous-capabilities",
    "untrusted-content": "scan/W015", "prompt-injection": "scan/E001",
    "credential-leak": "watch/credential-leak",
}


def items(d):
    return d if isinstance(d, list) else (d.get("findings") or d.get("entries") or [])


def _chiave(f):
    """Identita' di un finding, ignorando i campi aggiunti dal post-processing."""
    o = {k: v for k, v in f.items()
         if not k.startswith("_") and k not in
         ("llm_verdict", "llm_reason", "verdict_source", "final_verdict",
          "final_reason", "bucket_reason", "llm_bucket", "hc_bucket", "hc_reason")}
    return hashlib.sha1(json.dumps(o, sort_keys=True, ensure_ascii=False)
                        .encode("utf-8", "replace")).hexdigest()


def n_vp(pat):
    """VP DISTINTI. I worker di watch sono stati riavviati piu' volte su range
    sovrapposti, quindi il merge dei 50 shard contiene lo stesso finding piu'
    volte (39% di duplicati in watch, ~0% negli altri tool)."""
    s = set()
    for p in REPO.glob(pat):
        try:
            for f in items(json.load(open(p, encoding="utf-8"))):
                s.add(_chiave(f))
        except Exception:
            pass
    return len(s)


def tassi():
    """etichetta sotto-categoria -> (confermati, esaminati)"""
    t = defaultdict(lambda: [0, 0])
    for p in AUD.glob("verdetti_*.json"):
        for r in json.load(open(p, encoding="utf-8")):
            et = r.get("sotto_categoria") or ALIAS.get(r.get("categoria", ""), None)
            if et is None:
                cat = r.get("categoria", "")
                et = ALIAS.get(cat.replace("mcp-check/", "").split("/")[0], "check (tutto)") \
                    if cat.startswith("mcp-check/") else None
            if et is None:
                continue
            t[et][1] += 1
            if r.get("verdetto") in ("VP-C", "VP-D"):
                t[et][0] += 1
    # credential-leak: audit integrale per cluster, non campionario.
    # Va deduplicato come i VP: `n_finding` conta anche le ripetizioni dovute ai
    # riavvii dei worker di watch, e i duplicati non sono distribuiti in modo
    # uniforme fra i cluster (36,7% con duplicati -> 38,3% senza).
    cl = AUD.parent / "credleak_audit" / "verdetti_cluster.json"
    ix = AUD.parent / "credleak_audit" / "indice.json"
    if cl.exists() and ix.exists():
        ver = {c["id"]: c["verdetto"] for c in json.load(open(cl, encoding="utf-8"))}
        idx = json.load(open(ix, encoding="utf-8"))
        seen, tot, conf = set(), 0, 0
        for cid, lst in idx.items():
            for f in lst:
                k = (f.get("github_url"), f.get("file"), f.get("line"))
                if k in seen:
                    continue
                seen.add(k)
                tot += 1
                if ver.get(cid) in ("VP-C", "VP-D"):
                    conf += 1
        t["watch/credential-leak"] = [conf, tot]
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    T = tassi()
    righe, note = [], []
    NUM = DEN = 0
    NUM0 = DEN0 = 0
    for cat, subs in MAPPA.items():
        vp_tot = 0
        num = 0
        scoperti = []
        for et, pat in subs:
            v = n_vp(pat)
            if not v:
                continue
            vp_tot += v
            c, e = T.get(et, (0, 0))
            if e:
                num += v * (c / e)
            else:
                scoperti.append(f"{et} ({v:,} VP)")
        tasso = num / vp_tot if vp_tot else 0
        pn, pa, pc = PRIMA[cat]
        righe.append((cat, pn, pc / pa, vp_tot, tasso, scoperti))
        NUM += vp_tot * tasso; DEN += vp_tot
        NUM0 += pn * (pc / pa); DEN0 += pn

    out = []
    def w(s=""):
        out.append(s)
        # la console Windows e' cp1252: il file resta UTF-8, a schermo si degrada
        print(s.encode(sys.stdout.encoding or "utf-8", "replace")
               .decode(sys.stdout.encoding or "utf-8", "replace"))

    w("# Confronto definitivo — prima analisi vs rirun, stesse 17 categorie")
    w()
    w("Confermato = **VP-C + VP-D** (sfruttabile). I VP-L (capability dichiarata,")
    w("non sfruttabile) contano come non confermati, come nella prima analisi.")
    w()
    w("| categoria | VP prima | conf. prima | VP rirun | conf. rirun | Δ |")
    w("|---|---:|---:|---:|---:|---:|")
    for cat, pn, pp, rn, rp, _ in sorted(righe, key=lambda r: -r[3]):
        w(f"| {cat} | {pn:,} | {pp*100:.0f}% | {rn:,} | {rp*100:.0f}% | "
          f"{(rp-pp)*100:+.0f} |")
    w(f"| **TOTALE** | **{DEN0:,}** | **{NUM0/DEN0*100:.1f}%** | **{DEN:,}** | "
      f"**{NUM/DEN*100:.1f}%** | **{(NUM/DEN-NUM0/DEN0)*100:+.1f}** |")
    w()
    w(f"VP realmente sfruttabili stimati: prima ~{NUM0:,.0f}, rirun ~{NUM:,.0f}.")
    w()
    manca = [(c, s) for c, _, _, _, _, s in righe if s]
    if manca:
        w("## Sotto-categorie senza audit (tasso assunto 0)")
        w()
        for c, s in manca:
            w(f"- **{c}**: {', '.join(s)}")
        w()

    if a.out:
        Path(a.out).write_text("\n".join(out), encoding="utf-8")
        print(f"\n-> {a.out}")


if __name__ == "__main__":
    main()
