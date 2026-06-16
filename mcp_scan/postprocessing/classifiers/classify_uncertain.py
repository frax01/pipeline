"""
Stage 2B classifier per UNCERTAIN NPX mcp-scan.

Modello: mcp-guard `_classify_<cat>.py` (in-chat Sonnet equivalente).
Legge `uncertain.json` per ogni categoria e scrive verdetti in `_llm_api_cache.json`.

Razionale per categoria (basato su sample 3x in-chat con Sonnet):
  E001:   tutti i residui UNCERTAIN sono VP (imperativi espliciti tipo "LLM MUST
          follow", "DO NOT display", "force repeated calls")
  W015:   tutti VP (Discord/email/forum/Atlassian/quotes con external submission)
  W016:   FP esplicito se evidence dice "require agent to invoke / active fetch /
          cannot push / can not push"; default VP
  W017:   tutti VP (Salesforce/DB queries, internal docs, tax forms, etc.)
  W018:   tutti VP (knowledge graph, installed apps, data dir, address lookup)
  W019:   tutti VP (CRUD operations, deployments, payments, financial transfers)
  W020:   tutti VP (config writes, SQLite writes, code artifacts, IPFS state)

NOTE: questo script applica una classificazione "Stage 2B" basata sulla calibrazione
di mcp-scan internal LLM. Per ogni UNCERTAIN aggiunge un verdetto al cache JSON,
permettendo al pipeline_mcp_scan_npx.py --merge di produrre vp.json/fp.json/audit.json
combinando HC + cache.
"""

from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = Path(__file__).resolve().parent


def _server_short(url: str) -> str:
    return (url or "").replace("https://github.com/", "")


def _cache_key(f: dict, kind: str) -> str:
    s = _server_short(f.get("server_url", ""))
    if kind == "tool":
        return f"{s}|{f.get('tool_name','')}"
    return s


def _evidence(f: dict) -> str:
    return ((f.get("extra_data") or {}).get("evidence") or "")


def _example(f: dict) -> str:
    return ((f.get("extra_data") or {}).get("example") or "")


# ══════════════════════════════════════════════════════════════════════════════
#  CATEGORY-SPECIFIC STAGE 2B CLASSIFIERS
# ══════════════════════════════════════════════════════════════════════════════

# W016: only category where we expect FP residuals in UNCERTAIN
_W016_FP_AGENT_REQ = re.compile(
    r"""
    (
        \brequire(?:s|d)?\s+the\s+agent\s+to\s+(?:invoke|call|fetch|select|provide|supply)
      | \bagent\s+must\s+(?:invoke|call|actively\s+fetch|be\s+given|provide)
      | \bactive\s+fetch
      | \bcannot\s+push\s+content
      | \bcan\s*not\s+push\s+content
      | \bcannot\s+force\s+(?:that|those|the\s+content)
      | \bpoisoning\s+requires?\s+the\s+agent\s+to
      | \battacker\s+cannot\s+(?:push|force|inject)
      | \bno\s+(?:automatic\s+)?(?:fetcher|reader|monitor|ingestion|inbox)
      | \brather\s+than\s+allowing\s+(?:user|attacker)
      | \bthere\s+is\s+no\s+mechanism\s+for
      | \binstead\s+of\s+(?:pushing|automatic)
      | \brequires?\s+the\s+agent\s+(?:to\s+)?(?:actively|explicitly)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def classify_E001_residual(f: dict):
    """E001 residual: all VP (sample 5/5 = explicit imperatives)."""
    return ("VP", "stage2B: explicit imperative directive (sample analysis)")


def classify_W015_residual(f: dict):
    """W015 residual: all VP (sample 5/5 = social/forum/email external submission)."""
    return ("VP", "stage2B: external-submission attack surface (sample analysis)")


def classify_W016_residual(f: dict):
    """W016 residual: FP if 'require agent active', else VP."""
    ev = _evidence(f) + " " + _example(f)
    if _W016_FP_AGENT_REQ.search(ev):
        return ("FP", "stage2B: agent must actively invoke, no passive push")
    return ("VP", "stage2B: public-source retrieval residual (default)")


def classify_W017_residual(f: dict):
    return ("VP", "stage2B: exposes private/proprietary/enterprise data (default)")


def classify_W018_residual(f: dict):
    return ("VP", "stage2B: exposes local/workspace/non-public data (default)")


def classify_W019_residual(f: dict):
    return ("VP", "stage2B: modifies shared/remote/SaaS state (default)")


def classify_W020_residual(f: dict):
    return ("VP", "stage2B: modifies local files/state (default)")


def classify_W001_residual(f: dict):
    """W001 should not have residual UNCERTAIN after Stage 2A (all binary VP/FP)."""
    return ("FP", "stage2B: residual catch-all (no strong manipulation)")


# Post-merge: nuova struttura unificata.
# W001/W016 esclusi (raw merge only, no analysis).
# W017_npx..W020_npx NPX-only renamed.
# Tuple: (level, kind, classifier_function, subdir_name)
CATEGORIES = {
    "E001":     ("tool-level",   "tool",   classify_E001_residual, "E001"),
    "W015":     ("server-level", "server", classify_W015_residual, "W015"),
    "W017_npx": ("server-level", "server", classify_W017_residual, "W017_npx"),
    "W018_npx": ("server-level", "server", classify_W018_residual, "W018_npx"),
    "W019_npx": ("server-level", "server", classify_W019_residual, "W019_npx"),
    "W020_npx": ("server-level", "server", classify_W020_residual, "W020_npx"),
}


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def process_category(cat: str) -> dict:
    level, kind, classifier, subdir = CATEGORIES[cat]
    out_dir = HERE / level / subdir / "llm_analysis"
    uncertain_path = out_dir / "uncertain.json"
    cache_path = out_dir / "_llm_api_cache.json"

    if not uncertain_path.exists():
        print(f"  [{cat:5s}] no uncertain.json, skip")
        return {"uncertain": 0, "vp": 0, "fp": 0}

    with io.open(uncertain_path, encoding="utf-8") as fh:
        items = (json.load(fh) or {}).get("findings") or []

    cache = {}
    if cache_path.exists():
        try:
            with io.open(cache_path, encoding="utf-8") as fh:
                cache = json.load(fh) or {}
        except Exception:
            cache = {}

    vp = fp = 0
    for f in items:
        verdict, reason = classifier(f)
        key = _cache_key(f, kind)
        cache[key] = {"verdict": verdict, "reason": reason}
        if verdict == "VP":
            vp += 1
        else:
            fp += 1

    with io.open(cache_path, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, ensure_ascii=False, indent=2)

    print(f"  [{cat:5s}] uncertain={len(items):5d}  -> VP={vp:5d}  FP={fp:5d}  "
          f"(cache: {cache_path.relative_to(HERE)})")
    return {"uncertain": len(items), "vp": vp, "fp": fp}


def main() -> None:
    print("=" * 80)
    print("Stage 2B: classificazione UNCERTAIN -> _llm_api_cache.json")
    print("=" * 80)
    tot = {"uncertain": 0, "vp": 0, "fp": 0}
    for cat in CATEGORIES:
        r = process_category(cat)
        for k, v in r.items():
            tot[k] += v
    print("-" * 80)
    print(f"  TOTALE UNCERTAIN: {tot['uncertain']:5d}  ->  VP={tot['vp']:5d}  FP={tot['fp']:5d}")
    print("\nProssimo: py -X utf8 pipeline_mcp_scan_npx.py --merge per produrre vp/fp/audit")


if __name__ == "__main__":
    main()
