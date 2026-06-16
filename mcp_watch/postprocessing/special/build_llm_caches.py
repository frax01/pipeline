"""
Build _llm_api_cache.json for every mcp-watch category.

For frameworks that use Ollama at runtime (mcp-shield, mcp-scan,
mcp-check, mcp-security-scan) Stage 2B writes its verdicts into a
per-category file:

    <cat>/filtered/llm_analysis/_llm_api_cache.json

mcp-watch instead runs hand-codified rules (_classify_3bucket.py and
_classify_vp_fp.py) and writes vp.json / fp.json directly, with no
cache artifact. This script rebuilds the equivalent cache from the
existing outputs so that all frameworks expose the same artifact set
in the repository.

Cache format (identical to pipeline_mcp_watch.py::_cache_key):

    {
      "<server_name>/<file>/<line>/<id>": {
        "verdict": "VP" | "FP",
        "reason":  "rule_based:<category>"
      },
      ...
    }

Run from this directory:
    python -X utf8 _build_llm_caches.py
"""
from __future__ import annotations

import io
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

CATEGORIES = [
    "credential-leak",
    "data-exfiltration",
    "input-validation",
    "steganographic-attack",
    "protocol-violation",
    "tool-poisoning",
    "prompt-injection",
    "tool-mutation",
    "access-control",
]


def cache_key(f: dict) -> str:
    """Same format used by pipeline_mcp_watch.py::_cache_key."""
    return f"{f.get('server_name','')}/{f.get('file','')}/{f.get('line',0)}/{f.get('id','')}"


def load_findings(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with io.open(path, "r", encoding="utf-8") as fp:
        data = json.load(fp)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data["findings"]
    return []


def build_cache(category: str) -> tuple[int, int, int]:
    """Return (uncertain_total, vp_matched, fp_matched)."""
    base = HERE / category / "filtered" / "llm_analysis"
    unc = load_findings(base / "uncertain.json")
    vp  = load_findings(base / "vp.json")
    fp  = load_findings(base / "fp.json")

    vp_keys = {cache_key(f) for f in vp}
    fp_keys = {cache_key(f) for f in fp}

    cache: dict[str, dict[str, str]] = {}
    vp_matched = fp_matched = 0
    for f in unc:
        k = cache_key(f)
        if k in vp_keys:
            cache[k] = {"verdict": "VP", "reason": f"rule_based:{category}"}
            vp_matched += 1
        elif k in fp_keys:
            cache[k] = {"verdict": "FP", "reason": f"rule_based:{category}"}
            fp_matched += 1
        # else: orphan -- the UNCERTAIN finding was not classified into VP/FP;
        # this can happen if the classifier was re-run on a different sample.

    out = base / "_llm_api_cache.json"
    with io.open(out, "w", encoding="utf-8") as fp_out:
        json.dump(cache, fp_out, indent=2, ensure_ascii=False)

    return len(unc), vp_matched, fp_matched


def main() -> None:
    print(f"{'category':<26} {'uncertain':>10} {'VP':>8} {'FP':>8}  cache_file")
    print("-" * 90)
    for cat in CATEGORIES:
        try:
            unc, vp, fp = build_cache(cat)
            print(f"{cat:<26} {unc:>10} {vp:>8} {fp:>8}  {cat}/filtered/llm_analysis/_llm_api_cache.json")
        except Exception as e:
            print(f"{cat:<26}   ERROR: {e}")


if __name__ == "__main__":
    main()
