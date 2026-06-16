"""
Merge dei verdetti LLM (analisi manuale Claude Sonnet) con i bucket HC.

Legge hc_fp.json, hc_vp.json, uncertain.json e applica i verdetti LLM
per i 5 finding uncertain, producendo:
  llm_analysis/vp.json   — tutti i veri positivi finali
  llm_analysis/fp.json   — tutti i falsi positivi finali
  llm_analysis/audit.json — log completo per ogni finding

Verdetti UNCERTAIN (5 finding):
  1. MCP / static/app.js
     → FP: il frontend chiama la propria API backend (/api.prompt è un path
       interno), non esfiltrazione verso terzi.

  2. classifier_mcp_server / mcp_client/client.py
     → FP: il server è un classificatore che chiama BASE_URL (Ollama/LLM
       locale). La keyword "prompt" nel payload è il formato standard
       dell'API Ollama, non indica esfiltrzione.

  3-5. line-desktop-mcp / src/server.js (3 finding)
     → FP: il server è un client MCP per l'app di messaggistica LINE.
       "Extract conversation history" si riferisce alle chat LINE dell'utente
       (funzione dichiarata del tool), non alla conversazione con l'LLM.
       Il tool serve legittimamente a leggere lo storico chat LINE.
"""

from __future__ import annotations
import io, json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT  = HERE / "llm_analysis"

# ─── LLM verdetti per i finding UNCERTAIN ─────────────────────────────────────
# Struttura: (server_name, file_fragment, evidence_fragment) -> ("FP"|"VP", motivo)

LLM_VERDICTS: list[tuple[str, str, str, str, str]] = [
    # server_name, file_frag, evidence_frag, verdict, reason

    # MCP / static/app.js — frontend che chiama la propria API backend
    ("MCP", "static/app.js", "fetch(api.prompt",
     "FP", "frontend_calling_own_backend_not_external_exfiltration"),

    # classifier_mcp_server — chiamata Ollama/LLM locale
    ("classifier_mcp_server", "client.py", '"prompt": prompt',
     "FP", "llm_classifier_api_call_not_exfiltration"),

    # line-desktop-mcp — client MCP per l'app di messaggistica LINE (legittimo)
    ("line-desktop-mcp", "server.js", "Extract conversation history",
     "FP", "line_messaging_app_reads_own_chat_history_legitimate"),
]


def match_verdict(f: dict) -> tuple[str, str] | None:
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

    hc_vp = load("hc_vp.json")
    hc_fp = load("hc_fp.json")
    unc   = load("uncertain.json")

    src_meta = json.load(io.open(
        HERE / "data_exfiltration_filtered.json", encoding="utf-8"))

    vp_final, fp_final, audit = [], [], []

    for f in hc_vp:
        rec = dict(f, final_verdict="VP", verdict_source="hc_rule",
                   final_reason=f.get("bucket_reason", ""))
        vp_final.append(rec); audit.append(rec)

    for f in hc_fp:
        rec = dict(f, final_verdict="FP", verdict_source="hc_rule",
                   final_reason=f.get("bucket_reason", ""))
        fp_final.append(rec); audit.append(rec)

    llm_matched = 0
    for f in unc:
        result = match_verdict(f)
        if result:
            verdict, reason = result
            llm_matched += 1
        else:
            # Fallback: tutto ciò che non è in tabella FP → VP
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

    dump(OUT / "vp.json", vp_final, "true_positive")
    dump(OUT / "fp.json", fp_final, "false_positive")

    with io.open(OUT / "audit.json", "w", encoding="utf-8") as fh:
        json.dump({"total": len(audit), "findings": audit},
                  fh, ensure_ascii=False, indent=2)

    total = len(vp_final) + len(fp_final)
    print(f"{'─'*55}")
    print(f"  Finding totali:          {total:4d}")
    print(f"  Veri Positivi   (VP):    {len(vp_final):4d}  ({len(vp_final)/total*100:.1f}%)")
    print(f"  Falsi Positivi  (FP):    {len(fp_final):4d}  ({len(fp_final)/total*100:.1f}%)")
    print(f"  LLM verdetti applicati:  {llm_matched:4d}  (su {len(unc)} uncertain)")
    print(f"{'─'*55}")

    from collections import Counter
    print("\nFP per source:")
    for r, c in Counter(x["final_reason"] for x in fp_final).most_common():
        print(f"  {c:3d}  {r}")
    print("\nVP finding:")
    for x in vp_final:
        print(f"  {x['server_name']:40s}  {x.get('final_reason','')}")


if __name__ == "__main__":
    main()
