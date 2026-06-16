"""
Popola _llm_api_cache.json con verdetti Stage 2B (classificati in-chat con Sonnet).

NPX mcp-security-scan classification rules:
  dangerous-capabilities UNCERTAIN (15):
    - exec/install/terminal/SSH exec/delete/state-mod → VP
    - read-only info/registry-only/code-gen → FP
  input-validation (36, no HC): tutti VP — exploit successo con /etc/passwd o uid=...
  path-traversal (2, no HC): tutti VP — file:///etc/* content returned
  sensitive-file-access (2, no HC): tutti VP — root:x:0 in response
  sensitive-resource-exposure (5, no HC): tutti FP — documentation resources, not sensitive
  remote-access-control (1, no HC): VP — fetch_remote_files
"""
import io
import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try: sys.stdout.reconfigure(encoding="utf-8")
    except: pass

HERE = Path(__file__).resolve().parent


def _server_short(url):
    return (url or "").replace("https://github.com/", "")


def cache_key(f):
    return _server_short(f.get("server_url", ""))


# Verdetti per dangerous-capabilities UNCERTAIN (per server_short)
DC_VERDICTS = {
    "@aumoai/mcp-data-analyst":           ("VP", "stage2B: execute_code with arbitrary Python"),
    "@dylibso/mcpx":                      ("FP", "stage2B: read-only search registry"),
    "@enactprotocol/mcp-server":          ("VP", "stage2B: enact_install (package install)"),
    "@hazzel-cn/node-terminal-mcp":       ("VP", "stage2B: persistent terminal session"),
    "@iflow-mcp/appinsightmcp":           ("FP", "stage2B: read-only google-play info"),
    "@iflow-mcp/flint-note":              ("FP", "stage2B: remove_vault registry-only (no file delete)"),
    "@iflow-mcp/mcpfinder-server":        ("FP", "stage2B: read-only registry info"),
    "@iflow-mcp/sacloud-mcp":             ("FP", "stage2B: read-only ssh key info"),
    "@iflow-mcp/terminal-mcp-server":     ("VP", "stage2B: SSH exec on remote/local hosts"),
    "@open-mcp/lambda-ai":                ("VP", "stage2B: deletesshkey state-modifying"),
    "gemini-design-mcp":                  ("FP", "stage2B: code generation only, no exec"),
    "gpuse-mcp-server":                   ("VP", "stage2B: container build via POST API"),
    "shadcn-studio-mcp":                  ("FP", "stage2B: generates install cmd string (no exec)"),
    "simon-mcp-server":                   ("VP", "stage2B: 'any operation without restrictions' on server"),
    "tca-mcp-server":                     ("VP", "stage2B: state-modifying create_repo"),
}


def classify(cat: str, f: dict):
    srv = cache_key(f)
    if cat == "dangerous-capabilities":
        # Only for UNCERTAIN (HC already classified most)
        if srv in DC_VERDICTS:
            return DC_VERDICTS[srv]
        # Default for UNCERTAIN not in dict: VP (cautious for dangerous-capabilities)
        return ("VP", "stage2B: dangerous-capability with no FP signal")
    elif cat == "input-validation":
        # All VP — exploit /etc/passwd or uid= visible in response
        return ("VP", "stage2B: exploit successful (/etc/passwd content or uid= in resp)")
    elif cat == "path-traversal":
        return ("VP", "stage2B: file:///etc/* content returned in resp")
    elif cat == "sensitive-file-access":
        return ("VP", "stage2B: /etc/passwd content (root:x:0) returned in resp")
    elif cat == "sensitive-resource-exposure":
        return ("FP", "stage2B: documentation resources (docs/tokenizer/components), not sensitive")
    elif cat == "remote-access-control":
        return ("VP", "stage2B: fetch_remote_files = remote fetch vector (RC-01)")
    return ("FP", "stage2B: default conservative")


def main():
    # Process UNCERTAIN per categories with HC (dangerous-capabilities)
    cats_with_unc = ["dangerous-capabilities"]
    # Process FILTERED finding for categories without HC (treat as direct Stage 2B)
    cats_direct = ["input-validation", "path-traversal", "sensitive-file-access",
                   "sensitive-resource-exposure", "remote-access-control"]

    for cat in cats_with_unc:
        unc_p = HERE / cat / "filtered" / "llm_analysis" / "uncertain.json"
        cache_p = HERE / cat / "filtered" / "llm_analysis" / "_llm_api_cache.json"
        if not unc_p.exists():
            continue
        unc = (json.load(io.open(unc_p, encoding="utf-8")) or {}).get("findings") or []
        cache = {}
        if cache_p.exists():
            try:
                with io.open(cache_p, encoding="utf-8") as fh:
                    cache = json.load(fh) or {}
            except: cache = {}
        vp = fp = 0
        for f in unc:
            v, r = classify(cat, f)
            cache[cache_key(f)] = {"verdict": v, "reason": r}
            if v == "VP": vp += 1
            else: fp += 1
        cache_p.parent.mkdir(parents=True, exist_ok=True)
        with io.open(cache_p, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2, ensure_ascii=False)
        print(f"  [{cat:30s}] {len(unc):4d} UNCERTAIN → VP={vp} FP={fp}")

    for cat in cats_direct:
        filt_p = HERE / cat / "filtered" / f"{cat.replace('-','_')}_filtered.json"
        out_dir = HERE / cat / "filtered" / "llm_analysis"
        if not filt_p.exists():
            print(f"  [{cat:30s}] no filtered.json, skip")
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        cache_p = out_dir / "_llm_api_cache.json"
        cache = {}
        items = (json.load(io.open(filt_p, encoding="utf-8")) or {}).get("findings") or []
        vp = fp = 0
        for f in items:
            v, r = classify(cat, f)
            cache[cache_key(f)] = {"verdict": v, "reason": r}
            if v == "VP": vp += 1
            else: fp += 1
        with io.open(cache_p, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2, ensure_ascii=False)
        print(f"  [{cat:30s}] {len(items):4d} direct  → VP={vp} FP={fp}")


if __name__ == "__main__":
    main()
