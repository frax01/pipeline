"""
Merge dei verdetti LLM (analisi manuale Claude Sonnet) con i bucket HC.

Legge hc_fp.json, hc_vp.json, uncertain.json e applica i verdetti LLM
per i 190 finding uncertain, producendo:
  llm_analysis/vp.json   — tutti i veri positivi finali
  llm_analysis/fp.json   — tutti i falsi positivi finali
  llm_analysis/audit.json — log completo per ogni finding
"""

from __future__ import annotations
import io, json, re
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT  = HERE / "llm_analysis"

# ─── LLM verdetti per i finding UNCERTAIN ────────────────────────────────────
# Struttura: (server_name, file_fragment, evidence_fragment) -> ("FP"|"VP", motivo)
# Usiamo substring match su file ed evidence per robustezza.

LLM_VERDICTS: list[tuple[str, str, str, str, str]] = [
    # server_name, file_frag, evidence_frag, verdict, reason

    # ── PLAINTEXT uncertain ──
    ("mcp-console-automation", "SSHAdapter",  "stdin!.write",          "FP", "ssh_stdin_passthrough"),
    ("zentao-mcp",    "help.js",    "zentao login",                     "FP", "cli_help_text_stdout"),
    ("zentao-mcp",    "help.js",    "zentao self-test",                 "FP", "cli_help_text_stdout"),
    ("zentao-mcp",    "login.js",   "zentao login",                     "FP", "cli_help_text_stdout"),
    ("SmartDB_MCP",   "index-",     "getSetCookie",                     "FP", "minified_js_library"),
    ("ARIES",         "telnet.py",  "self.writer.write",                "FP", "telnet_passthrough"),
    ("mcp-server",    "create_initial_admin", "self.stdout.write",      "FP", "django_mgmt_cmd_stdout"),
    ("django-mcp-inspector", "mcp_oauth_admin", "Client Secret:",       "FP", "django_mgmt_cmd_stdout"),
    ("django-mcp-inspector", "mcp_oauth_admin", "Token URL:",           "FP", "django_mgmt_cmd_stdout"),
    ("Codex-MCP-Bridge", "index.ts", "--auth <auto",                    "FP", "cli_help_text_stdout"),

    # ── JWT uncertain ──
    ("PeoplestrongMCPServerSecured", "",      "//   const accessToken", "FP", "commented_out_code"),
    ("remote-mcp-server",  "schema.gen",  "access_token",               "FP", "jsdoc_example"),
    ("learnflowpro", "simpleTokenManager", "eyJ",                       "FP", "hardcoded_test_token_userId1"),
    ("learnflowpro", "tokenManager.ts",   "eyJ",                        "FP", "hardcoded_test_token_userId1"),
    ("learnflowpro", "my-day-network",    "eyJ",                        "FP", "hardcoded_test_token_userId1"),
    ("telnyx-node",  "actions.ts",        "eyJ",                        "FP", "jsdoc_example"),
    ("mm-mcp",       "api-client",        "// this.token",              "FP", "commented_out_code"),

    # ── Generic API Key uncertain ──
    ("MCP",            "checkerlat",  "OTM_API_KEY",                    "FP", "commented_out_code"),
    ("apify-mcp",      "const.ts",    "search only (public)",           "FP", "explicitly_public_key"),
    ("actors-mcp-server", "const.ts", "search only (public)",           "FP", "explicitly_public_key"),
    ("tsap_mcp_server","patterns.py", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "FP", "sequential_test_value"),
    ("Zerodha-Trade-GPT", "trade.ts", "// const apiSecret",            "FP", "commented_out_code"),
    ("Trip_planner_agent_mcp_server", "weather.py", "#     api_key",   "FP", "commented_out_code"),
    ("Mcp_trade",      "trade.ts",    "// const apiSecret",            "FP", "commented_out_code"),
    ("lobe-chat-arkaios", "error.ts",  "InvalidProviderAPIKey",        "FP", "typescript_enum_definition"),
    ("lobe-chat-arkaios", "asyncTask", "InvalidProviderAPIKey",        "FP", "typescript_enum_definition"),
    ("lobe-chat",      "error.ts",    "InvalidProviderAPIKey",         "FP", "typescript_enum_definition"),
    ("lobe-chat",      "asyncTask",   "InvalidProviderAPIKey",         "FP", "typescript_enum_definition"),
    ("storybook-npm",  "registry-custom", "*   apiKey=",               "FP", "jsdoc_example"),
    ("storybook-npm",  "registry.ts", "*   apiKey=",                   "FP", "jsdoc_example"),
]


def match_verdict(f: dict) -> tuple[str, str] | None:
    """Prova a matchare un finding con la tabella LLM_VERDICTS."""
    name = f.get("server_name", "")
    path = f.get("file", "")
    ev   = f.get("evidence", "")
    for sname, file_frag, ev_frag, verdict, reason in LLM_VERDICTS:
        if name == sname and file_frag in path and ev_frag in ev:
            return verdict, f"llm_sonnet:{reason}"
    return None


def main() -> None:
    def load(fname: str) -> list[dict]:
        with io.open(OUT / fname, encoding="utf-8") as fh:
            return json.load(fh)["findings"]

    hc_vp  = load("hc_vp.json")
    hc_fp  = load("hc_fp.json")
    unc    = load("uncertain.json")

    src_meta = json.load(io.open(
        HERE / "credential_leak_filtered.json", encoding="utf-8"))

    vp_final, fp_final, audit = [], [], []

    # HC findings — già classificati
    for f in hc_vp:
        rec = dict(f, final_verdict="VP", verdict_source="hc_rule",
                   final_reason=f.get("bucket_reason",""))
        vp_final.append(rec); audit.append(rec)

    for f in hc_fp:
        rec = dict(f, final_verdict="FP", verdict_source="hc_rule",
                   final_reason=f.get("bucket_reason",""))
        fp_final.append(rec); audit.append(rec)

    # Uncertain — applica verdetti LLM
    llm_matched = 0
    for f in unc:
        result = match_verdict(f)
        if result:
            verdict, reason = result
            llm_matched += 1
        else:
            # Non matchato esplicitamente → default VP
            # (tutto ciò che non è in tabella FP è stato giudicato VP)
            verdict, reason = "VP", "llm_sonnet:default_vp"

        rec = dict(f, final_verdict=verdict, verdict_source="llm_claude_sonnet",
                   final_reason=reason)
        (vp_final if verdict == "VP" else fp_final).append(rec)
        audit.append(rec)

    def dump(path: Path, items: list, verdict: str) -> None:
        payload = {
            "category": src_meta["category"],
            "pipeline_stage": "llm_analysis",
            "verdict": verdict,
            "original_total": src_meta.get("original_total"),
            "filter_kept_total": src_meta.get("kept_total"),
            "llm_total": len(items),
            "findings": items,
        }
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)

    dump(OUT / "vp.json",    vp_final, "true_positive")
    dump(OUT / "fp.json",    fp_final, "false_positive")

    with io.open(OUT / "audit.json", "w", encoding="utf-8") as fh:
        json.dump({"total": len(audit), "findings": audit},
                  fh, ensure_ascii=False, indent=2)

    total = len(vp_final) + len(fp_final)
    print(f"{'─'*50}")
    print(f"  Finding totali:          {total:4d}")
    print(f"  Veri Positivi   (VP):    {len(vp_final):4d}  ({len(vp_final)/total*100:.1f}%)")
    print(f"  Falsi Positivi  (FP):    {len(fp_final):4d}  ({len(fp_final)/total*100:.1f}%)")
    print(f"  LLM verdetti applicati:  {llm_matched:4d}  (su 190 uncertain)")
    print(f"{'─'*50}")
    from collections import Counter
    print("\nFP per source:")
    for r,c in Counter(x["final_reason"] for x in fp_final).most_common():
        print(f"  {c:3d}  {r}")


if __name__ == "__main__":
    main()
