"""
Popola _ollama_cache.json con i verdetti Stage 2B (classificati in-chat con Sonnet).

UNCERTAIN classificati:
  credential-leak:    20 → 15 VP + 5 FP
  data-exfiltration:   3 → 0 VP + 3 FP
  input-validation:    3 → 0 VP + 3 FP
  protocol-violation:  6 → 0 VP + 6 FP

Cache key format: server_name/file/line/id
"""
import io
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def cache_key(f):
    return f"{f.get('server_name','')}/{f.get('file','')}/{f.get('line',0)}/{f.get('id','')}"


# Verdetti per categoria — keyed by (server_name, file_starts_with) per ridurre noise
VERDICTS = {
    "credential-leak": {
        # All HARDCODED_CREDENTIALS finding ID with real API keys/tokens = VP
        # PLAINTEXT_STORAGE in writer.write(product,'token',token) = VP
        # CLI help docs (process.stdout.write) and minified bundles = FP
        "rules": [
            ("@leeguoo/zentao-mcp",        "src/cli/help.js",      "FP", "stage2B: CLI help docs, not actual credential storage"),
            ("@leeguoo/zentao-mcp",        "src/commands/login.js","FP", "stage2B: CLI help docs, not actual credential storage"),
            ("n8n-nodes-jenna-mcp",        "nodes/JennaMcp",       "FP", "stage2B: minified Axios bundle, not real credential"),
            ("n8n-nodes-jenna-mcp",        "nodes/Wajs",           "FP", "stage2B: minified Axios bundle, not real credential"),
            ("@atlassian-dc-mcp/common",   "src/setup-cli.ts",     "VP", "stage2B: writer.write(product,'token',token) = plaintext token storage"),
            # All others (HARDCODED_CREDENTIALS) = VP
        ],
        "default": ("VP", "stage2B: hardcoded API key/JWT/token in source code"),
    },
    "data-exfiltration": {
        "rules": [
            ("line-desktop-mcp", "", "FP", "stage2B: legitimate user-controlled LINE chat extraction, not malicious exfil ('ENTIRE conversation' missing)"),
        ],
        "default": ("FP", "stage2B: targeted user-feature, not exfiltration"),
    },
    "input-validation": {
        "rules": [
            ("codeguard-mcp",     "", "FP", "stage2B: advice string in scanner, not actual exec call"),
            ("securitylens-mcp",  "", "FP", "stage2B: scanner self-pattern (example code in security scanner), not vulnerable"),
        ],
        "default": ("FP", "stage2B: scanner/example code, not real vulnerability"),
    },
    "protocol-violation": {
        "rules": [
            ("smart-mcp", "demos", "FP", "stage2B: placeholder/demo address (http://www.), incomplete URL in demo files"),
        ],
        "default": ("FP", "stage2B: placeholder/demo"),
    },
}


def classify_finding(cat: str, f: dict) -> tuple[str, str]:
    cfg = VERDICTS[cat]
    server_name = f.get("server_name", "") or ""
    file_path = f.get("file", "") or ""
    for srv_match, file_match, verdict, reason in cfg["rules"]:
        if srv_match in server_name and file_match in file_path:
            return verdict, reason
    return cfg["default"]


def main():
    for cat in VERDICTS:
        unc_path = HERE / cat / "filtered" / "llm_analysis" / "uncertain.json"
        cache_path = HERE / cat / "filtered" / "llm_analysis" / "_ollama_cache.json"
        if not unc_path.exists():
            print(f"  [SKIP] {cat}: no uncertain.json")
            continue
        with io.open(unc_path, encoding="utf-8") as fh:
            unc = json.load(fh).get("findings") or []
        cache = {}
        if cache_path.exists():
            try:
                with io.open(cache_path, encoding="utf-8") as fh:
                    cache = json.load(fh) or {}
            except Exception:
                cache = {}
        vp = fp = 0
        for f in unc:
            verdict, reason = classify_finding(cat, f)
            cache[cache_key(f)] = {"verdict": verdict, "reason": reason}
            if verdict == "VP": vp += 1
            else: fp += 1
        with io.open(cache_path, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2, ensure_ascii=False)
        print(f"  [{cat:30s}] {len(unc):4d} UNCERTAIN → VP={vp} FP={fp}")


if __name__ == "__main__":
    main()
