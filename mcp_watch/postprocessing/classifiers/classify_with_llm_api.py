"""
Stage 2B — Classificatore automatico via Ollama (llama3) per i finding UNCERTAIN.

Uso:
    python _classify_with_llm_api.py --category credential-leak
    python _classify_with_llm_api.py --category data-exfiltration
    python _classify_with_llm_api.py --category all

Prerequisiti:
    Ollama installato e in esecuzione: https://ollama.com
    ollama pull llama3          # oppure llama3.1, llama3.2, ecc.

Il script:
  1. Legge uncertain.json dalla cartella llm_analysis/ della categoria
  2. Per ogni finding, invia una richiesta a Ollama (POST /api/chat)
  3. Salva i risultati in cache su disco (non si paga due volte)
  4. Produce classified_uncertain.json con i verdetti
  5. (Opzionale) Merge con hc_fp.json e hc_vp.json per produrre vp.json/fp.json finali

Parametri opzionali:
    --model         modello Ollama da usare (default: llama3)
    --ollama-url    URL base di Ollama (default: http://localhost:11434)
    --no-cache      ignora la cache esistente e riclassifica tutto
    --merge         esegue il merge con i bucket HC dopo la classificazione
    --dry-run       mostra i prompt senza chiamare l'API
"""

from __future__ import annotations

import argparse
import io
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent

CATEGORIES = [
    "credential-leak",
    "data-exfiltration",
    # Aggiungi altre categorie qui man mano che vengono analizzate
]

CLASSIFICATION_PROMPT = """\
Sei un esperto di sicurezza informatica che analizza finding di vulnerabilita di MCP server (Model Context Protocol).

Devi classificare il seguente finding come:
- VP (Vero Positivo): il finding indica una vera vulnerabilita di sicurezza
- FP (Falso Positivo): il finding e un errore dello scanner, codice di test, pattern legittimo

FINDING DA ANALIZZARE:
- ID vulnerabilita: {vid}
- Categoria: {category}
- Server: {server_name}
- File: {file}
- Confidence filtro: {filter_confidence}
- Evidence (riga di codice rilevante):
  {evidence}

ISTRUZIONI PER LA CLASSIFICAZIONE:

Per HARDCODED_CREDENTIALS -> VP se la stringa sembra una vera chiave/token, FP se:
  - e commentata (inizia con #, //, /*)
  - e un placeholder/demo (abc123, your_, changeme, placeholder, example)
  - e un token di test evidente (ruolo "anon" in JWT Supabase)

Per PLAINTEXT_STORAGE -> VP se credenziali vengono scritte su disco/log, FP se:
  - e solo un output su stdout di un LLM token (streaming)
  - e una definizione di funzione/metodo, non una scrittura effettiva
  - riguarda file JSON di dati, non file di configurazione

Per DATA_EXFILTRATION -> VP se dati utente/sessione vengono inviati a server esterno, FP se:
  - e una chiamata API a Ollama/embedding locale
  - e un parametro Python interno (non nel schema MCP)
  - e un metodo di caching o wrapper interno
  - e codice bundled/minificato

Per INSECURE_CREDENTIAL_PERMISSIONS -> VP se permessi davvero troppo permissivi, FP se:
  - il file e package.json (script di build)
  - il chmod imposta permessi sicuri (600, 644, 400)

RISPONDI SOLO con questo JSON (nient'altro, nessun testo prima o dopo):
{{"verdict": "VP" o "FP", "reason": "breve spiegazione in italiano (max 20 parole)"}}"""


def build_prompt(f: dict) -> str:
    ev = (f.get("evidence") or "")[:500]  # Tronca evidence molto lunga
    return CLASSIFICATION_PROMPT.format(
        vid=f.get("id", ""),
        category=f.get("category", ""),
        server_name=f.get("server_name", ""),
        file=f.get("file", ""),
        filter_confidence=f.get("filter_confidence", ""),
        evidence=ev,
    )


def call_ollama(ollama_url: str, model: str, prompt: str) -> dict:
    """Chiama Ollama via /api/chat e restituisce il JSON parsato."""
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0},
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{ollama_url}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = json.loads(resp.read().decode("utf-8"))

    text = body.get("message", {}).get("content", "").strip()

    # Estrai il JSON dalla risposta (gestisce markdown code block e testo extra)
    m = re.search(r'\{[^{}]+\}', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"verdict": "UNCERTAIN", "reason": f"parse_error: {text[:100]}"}


def check_ollama(ollama_url: str, model: str) -> bool:
    """Verifica che Ollama sia raggiungibile e che il modello esista."""
    try:
        req = urllib.request.Request(f"{ollama_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            tags = json.loads(resp.read().decode("utf-8"))
        available = [m["name"].split(":")[0] for m in tags.get("models", [])]
        model_base = model.split(":")[0]
        if model_base not in available:
            print(f"ATTENZIONE: modello '{model}' non trovato in Ollama.")
            print(f"  Modelli disponibili: {', '.join(available) or 'nessuno'}")
            print(f"  Esegui: ollama pull {model}")
            return False
        return True
    except urllib.error.URLError as e:
        print(f"ERRORE: impossibile connettersi a Ollama su {ollama_url}")
        print(f"  Dettaglio: {e}")
        print("  Assicurati che Ollama sia in esecuzione (ollama serve)")
        return False


def get_cache_path(cat_dir: Path) -> Path:
    return cat_dir / "llm_analysis" / "_llm_api_cache.json"


def load_cache(cat_dir: Path) -> dict:
    p = get_cache_path(cat_dir)
    if p.exists():
        try:
            with io.open(p, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass
    return {}


def save_cache(cat_dir: Path, cache: dict) -> None:
    p = get_cache_path(cat_dir)
    with io.open(p, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, ensure_ascii=False, indent=2)


def make_cache_key(f: dict) -> str:
    """Chiave univoca per un finding nel cache."""
    return f"{f.get('server_name','')}/{f.get('file','')}/{f.get('line',0)}/{f.get('id','')}"


def classify_category(cat: str, args) -> dict:
    cat_dir = HERE / cat / "filtered"
    uncertain_path = cat_dir / "llm_analysis" / "uncertain.json"

    if not uncertain_path.exists():
        print(f"[{cat}] uncertain.json non trovato: {uncertain_path}")
        print(f"[{cat}] Esegui prima _classify_3bucket.py nella cartella {cat_dir}")
        return {"category": cat, "error": "uncertain.json not found"}

    with io.open(uncertain_path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = data.get("findings", [])
    print(f"\n[{cat}] {len(findings)} finding UNCERTAIN da classificare")

    cache = {} if args.no_cache else load_cache(cat_dir)
    results = []
    new_calls = 0

    for i, f in enumerate(findings):
        key = make_cache_key(f)
        if key in cache and not args.no_cache:
            verdict_data = cache[key]
            print(f"  [{i+1}/{len(findings)}] CACHED  {f['server_name'][:30]:30s}  → {verdict_data['verdict']}")
        else:
            prompt = build_prompt(f)
            if args.dry_run:
                print(f"\n  [{i+1}/{len(findings)}] DRY-RUN: {f['server_name']}")
                print(f"  PROMPT (primi 400 char):\n  {prompt[:400]}\n  ...\n")
                verdict_data = {"verdict": "DRY_RUN", "reason": "dry_run"}
            else:
                try:
                    verdict_data = call_ollama(args.ollama_url, args.model, prompt)
                    new_calls += 1
                    cache[key] = verdict_data
                    save_cache(cat_dir, cache)
                    print(f"  [{i+1}/{len(findings)}] OLLAMA  {f['server_name'][:30]:30s}  → {verdict_data.get('verdict','?'):2s}  {verdict_data.get('reason','')[:60]}")
                except Exception as e:
                    print(f"  [{i+1}/{len(findings)}] ERRORE  {f['server_name']}: {e}")
                    verdict_data = {"verdict": "ERROR", "reason": str(e)[:100]}

        enriched = dict(f,
                        llm_api_verdict=verdict_data.get("verdict"),
                        llm_api_reason=verdict_data.get("reason"),
                        verdict_source=f"ollama:{args.model}")
        results.append(enriched)

    # Salva classified_uncertain.json
    out_path = cat_dir / "llm_analysis" / "classified_uncertain.json"
    with io.open(out_path, "w", encoding="utf-8") as fh:
        json.dump({
            "category": cat,
            "model": args.model,
            "ollama_url": args.ollama_url,
            "total": len(results),
            "new_calls": new_calls,
            "findings": results,
        }, fh, ensure_ascii=False, indent=2)
    print(f"[{cat}] → salvato: {out_path.name}  ({new_calls} nuove chiamate Ollama)")

    from collections import Counter
    counts = Counter(r["llm_api_verdict"] for r in results)
    print(f"[{cat}] Verdetti: {dict(counts)}")

    if args.merge and not args.dry_run:
        merge_results(cat, cat_dir, results)

    return {"category": cat, "results": len(results), "new_calls": new_calls}


def merge_results(cat: str, cat_dir: Path, uncertain_classified: list) -> None:
    """Merge con HC bucket per produrre vp.json / fp.json / audit.json."""
    llm_dir = cat_dir / "llm_analysis"

    def load_json(name: str) -> list:
        p = llm_dir / name
        if not p.exists():
            return []
        with io.open(p, encoding="utf-8") as fh:
            return json.load(fh).get("findings", [])

    hc_vp = load_json("hc_vp.json")
    hc_fp = load_json("hc_fp.json")

    vp_final, fp_final, audit = [], [], []

    for f in hc_vp:
        rec = dict(f, final_verdict="VP", verdict_source="hc_rule",
                   final_reason=f.get("bucket_reason", ""))
        vp_final.append(rec); audit.append(rec)

    for f in hc_fp:
        rec = dict(f, final_verdict="FP", verdict_source="hc_rule",
                   final_reason=f.get("bucket_reason", ""))
        fp_final.append(rec); audit.append(rec)

    for f in uncertain_classified:
        v = f.get("llm_api_verdict", "")
        if v not in ("VP", "FP"):
            v = "FP"  # default conservativo: se errore → FP
        rec = dict(f, final_verdict=v, final_reason=f.get("llm_api_reason", ""))
        (vp_final if v == "VP" else fp_final).append(rec)
        audit.append(rec)

    src_meta_path = cat_dir / f"{cat.replace('-', '_')}_filtered.json"
    src_meta = {}
    if src_meta_path.exists():
        with io.open(src_meta_path, encoding="utf-8") as fh:
            src_meta = json.load(fh)

    def dump(path: Path, items: list, verdict: str) -> None:
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "category": cat,
                "pipeline_stage": "llm_ollama_analysis",
                "verdict": verdict,
                "original_total": src_meta.get("original_total"),
                "filter_kept_total": src_meta.get("kept_total"),
                "llm_total": len(items),
                "findings": items,
            }, fh, ensure_ascii=False, indent=2)

    dump(llm_dir / "vp.json",    vp_final, "true_positive")
    dump(llm_dir / "fp.json",    fp_final, "false_positive")
    with io.open(llm_dir / "audit.json", "w", encoding="utf-8") as fh:
        json.dump({"total": len(audit), "findings": audit},
                  fh, ensure_ascii=False, indent=2)

    total = len(vp_final) + len(fp_final)
    print(f"[{cat}] MERGE: {total} totali → "
          f"{len(vp_final)} VP ({len(vp_final)/total*100:.1f}%) / "
          f"{len(fp_final)} FP ({len(fp_final)/total*100:.1f}%)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stage 2B — Classificatore Ollama per finding UNCERTAIN di mcp-watch"
    )
    parser.add_argument("--category", default="all",
                        help=f"Categoria: {', '.join(CATEGORIES)}, o 'all' (default: all)")
    parser.add_argument("--model", default="llama3",
                        help="Modello Ollama (default: llama3). Es: llama3.1, llama3.2, mistral")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="URL base di Ollama (default: http://localhost:11434)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Ignora la cache e riclassifica tutto da zero")
    parser.add_argument("--merge", action="store_true",
                        help="Dopo la classificazione, merge con HC bucket → vp.json/fp.json")
    parser.add_argument("--dry-run", action="store_true",
                        help="Mostra i prompt senza chiamare Ollama")
    args = parser.parse_args()

    # Selezione categorie
    if args.category == "all":
        cats = CATEGORIES
    elif args.category in CATEGORIES:
        cats = [args.category]
    else:
        print(f"Categoria non valida: '{args.category}'")
        print(f"Categorie disponibili: {', '.join(CATEGORIES)}")
        return

    print(f"\n{'='*60}")
    print(f"  Stage 2B — Classificazione Ollama")
    print(f"  Categorie: {cats}")
    print(f"  Modello:   {args.model}  ({args.ollama_url})")
    print(f"  Cache:     {'disabilitata' if args.no_cache else 'abilitata'}")
    print(f"  Merge:     {'si' if args.merge else 'no'}")
    print(f"{'='*60}")

    # Verifica Ollama prima di iniziare (skip in dry-run)
    if not args.dry_run:
        if not check_ollama(args.ollama_url, args.model):
            return

    for cat in cats:
        classify_category(cat, args)

    print("\nFatto.")


if __name__ == "__main__":
    main()
