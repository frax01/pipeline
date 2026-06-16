"""
Pipeline LLM per i finding di mcp-scan.

A differenza di mcp-watch e mcp-shield, mcp-scan emette finding che sono GIA' stati
elaborati da un LLM interno al framework (produce campi risk_score / reason /
evidence / thought_process / example). Di conseguenza il post-processing non usa
regole HC: il classificatore passa direttamente allo Stage 2B (seconda opinione
LLM) con input arricchito.

Uso:
    python -X utf8 pipeline_mcp_scan.py --category E001 --merge
    python -X utf8 pipeline_mcp_scan.py --category W015 --merge
    python -X utf8 pipeline_mcp_scan.py --category all --merge

Output in <level>/<categoria>/llm_analysis/:
    vp.json           VP finali
    fp.json           FP finali
    audit.json        log completo di tutti i finding classificati
    _llm_api_cache.json  cache dei verdetti (chiave: cache_key, valore: verdict+reason)

Parametri:
    --category    E001 | W001 | W015 | W016 | all
    --model       modello Ollama (default: llama3)
    --ollama-url  URL Ollama (default: http://localhost:11434)
    --no-cache    ignora cache esistente e riclassifica
    --dry-run     mostra prompt senza chiamare Ollama
    --cache-only  usa SOLO la cache esistente, non chiama Ollama (utile quando
                  la cache e' stata popolata manualmente con verdetti in-chat)

Nota: per E001 e W015 la cache e' stata pre-popolata con verdetti in-chat
(Sonnet). Eseguire con --cache-only per generare vp.json/fp.json dalla cache
senza lanciare Ollama.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

# stdout utf-8 per Windows cp1252
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = Path(__file__).resolve().parent

# ══════════════════════════════════════════════════════════════════════════════
#  REGISTRY CATEGORIE
# ══════════════════════════════════════════════════════════════════════════════
#  level:    tool-level | server-level
#  filename: nome del file JSON sorgente (senza path)
#  kind:     tool (ha tool_name, category) | server (solo server_url)

# NB struttura unificata post-merge:
#   E001/W015     = file mergiati (GitHub raw + NPX raw), analysis mergiata
#   W001/W016     = solo raw mergiati, NESSUNA analysis (esclusi dal registry)
#   W017_npx..W020_npx = NPX-only, suffisso _npx
CATEGORIES: dict[str, dict] = {
    "E001": {
        "level": "tool-level",
        "filename": "E001.json",
        "kind": "tool",
        "description": "Prompt Injection (tool-level)",
    },
    "W015": {
        "level": "server-level",
        "filename": "W015.json",
        "kind": "server",
        "description": "Untrusted Content (server-level)",
    },
    "W017_npx": {
        "level": "server-level",
        "filename": "W017_npx.json",
        "kind": "server",
        "description": "Sensitive Data Exposure (server-level) - NPX only",
        "subdir": "W017_npx",
    },
    "W018_npx": {
        "level": "server-level",
        "filename": "W018_npx.json",
        "kind": "server",
        "description": "Workspace Data Exposure (server-level) - NPX only",
        "subdir": "W018_npx",
    },
    "W019_npx": {
        "level": "server-level",
        "filename": "W019_npx.json",
        "kind": "server",
        "description": "Destructive Capabilities - Shared (server-level) - NPX only",
        "subdir": "W019_npx",
    },
    "W020_npx": {
        "level": "server-level",
        "filename": "W020_npx.json",
        "kind": "server",
        "description": "Local Destructive Capabilities (server-level) - NPX only",
        "subdir": "W020_npx",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _server_short(url: str) -> str:
    return (url or "").replace("https://github.com/", "")


def _cache_key(f: dict, kind: str) -> str:
    """Chiave di cache per un finding.
    tool-level:   <server_short>|<tool_name>
    server-level: <server_short>
    """
    s = _server_short(f.get("server_url", ""))
    if kind == "tool":
        return f"{s}|{f.get('tool_name','')}"
    return s


def _finding_summary(f: dict, kind: str) -> str:
    """Rappresentazione compatta per logging."""
    s = _server_short(f.get("server_url", ""))[:50]
    if kind == "tool":
        t = (f.get("tool_name") or "")[:30]
        return f"{s:50s} :: {t:30s}"
    return f"{s:50s}"


def _extra(f: dict, key: str, default: str = "") -> str:
    ed = f.get("extra_data") or {}
    return ed.get(key, default) or default


# ══════════════════════════════════════════════════════════════════════════════
#  LOADING
# ══════════════════════════════════════════════════════════════════════════════

def load_findings(cat: str) -> tuple[list, dict]:
    info = CATEGORIES[cat]
    path = HERE / info["level"] / info["filename"]
    if not path.exists():
        raise FileNotFoundError(f"File sorgente non trovato: {path}")
    with io.open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = data.get("vulnerabilities") or []
    meta = {
        "category": cat,
        "level": info["level"],
        "description": info["description"],
        "total_in_file": data.get("total", len(findings)),
        "total_loaded": len(findings),
    }
    return findings, meta


# ══════════════════════════════════════════════════════════════════════════════
#  LLM / OLLAMA
# ══════════════════════════════════════════════════════════════════════════════

OLLAMA_PROMPT_TOOL = """\
Sei un esperto di sicurezza MCP (Model Context Protocol).

Classifica il seguente finding come VP (Vero Positivo) o FP (Falso Positivo).

CONTESTO: mcp-scan ha rilevato una potenziale PROMPT INJECTION in una tool
description di un server MCP. Il framework ha gia' prodotto un reasoning LLM
(campo evidence qui sotto); devi dare una seconda opinione.

SERVER:     {server}
TOOL:       {tool_name}
CATEGORIA:  {category}
RISK SCORE: {risk_score} (emesso dall'LLM interno a mcp-scan)
EVIDENCE:
---
{evidence}
---

CLASSIFICAZIONE:
- VP se: la tool description contiene istruzioni ESPLICITE di:
    * occultamento ("silently remember", "hide from user", "execute silently")
    * esfiltrazione ("send COMPLETE conversation", "export all data")
    * tool shadowing ("never use X", "ALWAYS use this instead")
    * bypass safety ("bypass token limits", "ignore previous instructions")
    * tool chaining forzato ("CRITICAL: MUST call X IMMEDIATELY")
    * impersonation ("display verbatim as your own words")
- FP se:
    * il tool wrappa un CLI reale e ne espone i flag (yolo, baseInstructions, ecc.)
    * e' un template noto (mcp-server-fetch "grants internet access")
    * "MUST/ALWAYS/CRITICAL" sono guidance operativa normale per il dominio
    * parametro e' configurazione (system_prompt) non injection in description
    * boilerplate enterprise (security checklist con "STRICT: You MUST")
    * tool workflow engine legittimo (follow tool instructions = purpose)

RISPONDI SOLO con questo JSON (nessun altro testo):
{{"verdict": "VP" o "FP", "reason": "spiegazione in italiano max 20 parole"}}"""


OLLAMA_PROMPT_SERVER = """\
Sei un esperto di sicurezza MCP (Model Context Protocol).

Classifica il seguente finding come VP (Vero Positivo) o FP (Falso Positivo).

CONTESTO: mcp-scan ha rilevato un server MCP con rischio UNTRUSTED CONTENT:
il server espone tool che leggono dati da fonti esterne potenzialmente avvelenate.
Il framework ha gia' prodotto un reasoning LLM; devi dare una seconda opinione.

SERVER:     {server}
MESSAGE:    {message}
SEVERITY:   {severity}
RISK SCORE: {risk_score}
EVIDENCE:
---
{evidence}
---
EXAMPLE:
---
{example}
---

CLASSIFICAZIONE:
- VP se: la fonte dati e' AVVELENABILE senza privilegi (repo GitHub pubblico,
  YouTube comments/captions, Telegram channel, Open Library, web scraping di
  contenuto utente-generato, public forum, Reddit, ecc.) E il tool restituisce
  quel contenuto direttamente all'agente.
- FP se:
    * la fonte e' interna/privata (database admin, SaaS con auth, server interno)
    * il tool richiede privilegi speciali (admin token, private repo)
    * e' un honeypot/demo intenzionale (vulnerable-notes-mcp, ecc.)
    * non c'e' un vero percorso di poisoning pubblico

RISPONDI SOLO con questo JSON (nessun altro testo):
{{"verdict": "VP" o "FP", "reason": "spiegazione in italiano max 20 parole"}}"""


def _build_prompt(f: dict, kind: str) -> str:
    if kind == "tool":
        return OLLAMA_PROMPT_TOOL.format(
            server=_server_short(f.get("server_url", "")),
            tool_name=f.get("tool_name", ""),
            category=f.get("category", ""),
            risk_score=_extra(f, "risk_score", "?"),
            evidence=_extra(f, "evidence", "")[:1200],
        )
    return OLLAMA_PROMPT_SERVER.format(
        server=_server_short(f.get("server_url", "")),
        message=f.get("message", ""),
        severity=f.get("severity", ""),
        risk_score=_extra(f, "risk_score", "?"),
        evidence=_extra(f, "evidence", "")[:800],
        example=_extra(f, "example", "")[:600],
    )


def _call_ollama(ollama_url: str, model: str, prompt: str) -> dict:
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
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    text = body.get("message", {}).get("content", "").strip()
    m = re.search(r"\{[^{}]+\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"verdict": "UNCERTAIN", "reason": f"parse_error:{text[:80]}"}


def check_ollama(ollama_url: str, model: str) -> bool:
    try:
        req = urllib.request.Request(f"{ollama_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            tags = json.loads(resp.read().decode("utf-8"))
        available = [m["name"].split(":")[0] for m in tags.get("models", [])]
        if model.split(":")[0] not in available:
            print(f"ATTENZIONE: modello '{model}' non trovato in Ollama.")
            print(f"  Disponibili: {', '.join(available) or 'nessuno'}")
            return False
        return True
    except urllib.error.URLError as e:
        print(f"ERRORE: impossibile connettersi a Ollama su {ollama_url}: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  CACHE
# ══════════════════════════════════════════════════════════════════════════════

def _cache_path(out_dir: Path) -> Path:
    return out_dir / "_llm_api_cache.json"


def _load_cache(out_dir: Path) -> dict:
    p = _cache_path(out_dir)
    if p.exists():
        try:
            with io.open(p, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass
    return {}


def _save_cache(out_dir: Path, cache: dict) -> None:
    with io.open(_cache_path(out_dir), "w", encoding="utf-8") as fh:
        json.dump(cache, fh, ensure_ascii=False, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  CLASSIFICAZIONE
# ══════════════════════════════════════════════════════════════════════════════

def classify(findings: list, kind: str, out_dir: Path, args) -> list:
    cache = {} if args.no_cache else _load_cache(out_dir)
    results = []
    new_calls = 0
    cached_hits = 0
    n = len(findings)

    for i, f in enumerate(findings):
        key = _cache_key(f, kind)
        summary = _finding_summary(f, kind)

        if key in cache and not args.no_cache:
            vd = cache[key]
            cached_hits += 1
            print(f"  [{i+1:4d}/{n}] CACHE   {summary}  -> {vd.get('verdict','?')}")
        elif args.cache_only:
            vd = {"verdict": "UNCACHED", "reason": "not in cache, --cache-only mode"}
            print(f"  [{i+1:4d}/{n}] SKIP    {summary}  (no cache entry)")
        else:
            prompt = _build_prompt(f, kind)
            if args.dry_run:
                vd = {"verdict": "DRY_RUN", "reason": "dry_run"}
                print(f"  [{i+1:4d}/{n}] DRY     {summary}")
                print(f"    PROMPT: {prompt[:160]}...")
            else:
                try:
                    vd = _call_ollama(args.ollama_url, args.model, prompt)
                    new_calls += 1
                    cache[key] = vd
                    _save_cache(out_dir, cache)
                    print(f"  [{i+1:4d}/{n}] OLLAMA  {summary}  -> {vd.get('verdict','?'):2s}  "
                          f"{(vd.get('reason','') or '')[:50]}")
                except Exception as e:
                    print(f"  [{i+1:4d}/{n}] ERR     {summary}: {e}")
                    vd = {"verdict": "ERROR", "reason": str(e)[:80]}

        results.append(dict(f,
                            llm_verdict=vd.get("verdict"),
                            llm_reason=vd.get("reason"),
                            verdict_source=("cache" if key in cache else "ollama")))

    print(f"\n  Riepilogo: {cached_hits} da cache, {new_calls} nuove chiamate, "
          f"{n - cached_hits - new_calls} altro")
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  MERGE
# ══════════════════════════════════════════════════════════════════════════════

def run_merge(cat: str, meta: dict, classified: list, out_dir: Path) -> None:
    vp_final, fp_final, audit = [], [], []

    for f in classified:
        v = (f.get("llm_verdict") or "").upper()
        if v not in ("VP", "FP"):
            # verdetto non classificato: default FP (conservativo)
            v = "FP"
        rec = dict(f, final_verdict=v, final_reason=f.get("llm_reason", ""))
        (vp_final if v == "VP" else fp_final).append(rec)
        audit.append(rec)

    base = {
        "category": cat,
        "description": meta.get("description"),
        "level": meta.get("level"),
        "total_loaded": meta.get("total_loaded"),
        "pipeline_stage": "stage2_llm_direct",
    }

    def dump(path: Path, items: list, verdict: str) -> None:
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump({**base, "verdict": verdict, "total": len(items), "findings": items},
                      fh, ensure_ascii=False, indent=2)

    dump(out_dir / "vp.json", vp_final, "true_positive")
    dump(out_dir / "fp.json", fp_final, "false_positive")
    with io.open(out_dir / "audit.json", "w", encoding="utf-8") as fh:
        json.dump({"category": cat, "total": len(audit), "findings": audit},
                  fh, ensure_ascii=False, indent=2)

    total = len(vp_final) + len(fp_final)
    if total == 0:
        print("\n  [WARN] Nessun finding nel merge.")
        return

    print(f"\n  -- Risultati finali --")
    print(f"  Totale:         {total:5d}")
    print(f"  Veri Positivi:  {len(vp_final):5d}  ({len(vp_final)/total*100:.1f}%)")
    print(f"  Falsi Positivi: {len(fp_final):5d}  ({len(fp_final)/total*100:.1f}%)")


# ══════════════════════════════════════════════════════════════════════════════
#  PIPELINE PRINCIPALE
# ══════════════════════════════════════════════════════════════════════════════

def run_category(cat: str, args) -> None:
    info = CATEGORIES[cat]
    # subdir può essere diverso dalla chiave categoria (es. W017_npx)
    subdir = info.get("subdir", cat)
    out_dir = HERE / info["level"] / subdir / "llm_analysis"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*66}")
    print(f"  Categoria: {cat} ({info['description']})")
    print(f"  Level: {info['level']}  |  Kind: {info['kind']}")
    print(f"{'='*66}")

    findings, meta = load_findings(cat)
    print(f"  Finding caricati: {meta['total_loaded']} (file total: {meta['total_in_file']})")

    if not args.cache_only and not args.dry_run:
        if not check_ollama(args.ollama_url, args.model):
            print("  Ollama non raggiungibile. Usa --cache-only per usare la cache esistente "
                  "oppure --dry-run per vedere i prompt.")
            return

    print(f"\n[Stage LLM] Classificazione diretta ({'cache-only' if args.cache_only else args.model})...")
    classified = classify(findings, info["kind"], out_dir, args)

    print("\n[Merge] Produzione vp.json / fp.json / audit.json...")
    run_merge(cat, meta, classified, out_dir)

    # Riepilogo ragioni VP/FP
    reasons_vp = Counter(f.get("llm_reason", "") for f in classified if f.get("llm_verdict") == "VP")
    reasons_fp = Counter(f.get("llm_reason", "") for f in classified if f.get("llm_verdict") == "FP")
    if reasons_vp:
        print("\n  Top ragioni VP:")
        for r, c in reasons_vp.most_common(10):
            print(f"    {c:4d}  {r[:75]}")
    if reasons_fp:
        print("\n  Top ragioni FP:")
        for r, c in reasons_fp.most_common(10):
            print(f"    {c:4d}  {r[:75]}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pipeline LLM per mcp-scan: classificazione VP/FP diretta con Ollama/cache"
    )
    parser.add_argument("--category", default="all",
                        help=f"Categoria: {', '.join(CATEGORIES)}, o 'all' (default: all)")
    parser.add_argument("--model", default="llama3",
                        help="Modello Ollama (default: llama3)")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="URL Ollama (default: http://localhost:11434)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Ignora cache e riclassifica da zero")
    parser.add_argument("--cache-only", action="store_true",
                        help="Usa SOLO la cache esistente (no Ollama). Richiede cache pre-popolata.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Mostra prompt senza chiamare Ollama")
    parser.add_argument("--merge", action="store_true",
                        help="Alias: esegui classificazione + merge (default)")

    args = parser.parse_args()

    cats = list(CATEGORIES.keys()) if args.category == "all" else [args.category]
    for cat in cats:
        if cat not in CATEGORIES:
            print(f"[ERRORE] Categoria sconosciuta: '{cat}'. Disponibili: {', '.join(CATEGORIES)}")
            continue
        run_category(cat, args)


if __name__ == "__main__":
    main()
