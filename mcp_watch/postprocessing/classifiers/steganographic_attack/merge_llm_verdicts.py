"""
Merge dei verdetti LLM (analisi in-chat Claude Sonnet) con i bucket HC.

Legge hc_fp.json, hc_vp.json, uncertain.json e applica i verdetti LLM
per i 46 finding uncertain, producendo:
  llm_analysis/vp.json   — tutti i veri positivi finali
  llm_analysis/fp.json   — tutti i falsi positivi finali
  llm_analysis/audit.json — log completo per ogni finding

━━━ Verdetti UNCERTAIN (46 finding) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Tutti i 46 UNCERTAIN sono HC-FP dopo analisi in-chat:

1. Spek-template / analyzer/enterprise/compliance/iso27001.py (41 finding)
   Whitespace 304-336 chars.
   → FP: codice Python di analisi compliance con annidamento abnorme ma
     legittimo (metodi async annidati con dict di risultati). Il contenuto
     è chiaramente sintassi Python (dict key-value, def, async def), non
     testo nascosto. L'indentazione estrema è un difetto di stile del
     template, non steganografia.

2. mcp_sofia_voice- / src/configs/config.py (1 finding)
   Whitespace 552 chars su: SHIFTS_INDEX_NAME = os.getenv("SHIFTS_INDEX_NAME")
   → FP: file di configurazione Python. Una semplice assegnazione os.getenv
     con 552 spazi prima è un artefatto di formattazione (probabilmente
     generato o riformattato). Non è una tool description che raggiunge
     l'LLM, quindi non steganografica.

3. mcp-mesh / mcp-garmin/server.py (4 finding)
   Whitespace 302-399 chars su: app = FastAPI(...), raise HTTPException(...)
   → FP: codice infrastruttura FastAPI con indentazione anomala. Nessuna
     di queste righe è in una tool description o annotation MCP — sono
     route handler e inizializzazione del server. Non raggiungono l'LLM
     come input, quindi non steganografiche.

━━━ HC-VP confermati (3 finding) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

exa-mcp-server / src/tools/*.ts:
  - companyResearch.ts: 1152 whitespace su "}"
  - crawling.ts: 2304 whitespace su "}"
  - webSearch.ts: 86016 whitespace su "}"
  → VP confermato: whitespace count impossibile come indentazione reale.
    Le tool definition TypeScript di exa-mcp-server contengono whitespace
    steganografico embedded nelle definizioni dei tool che vengono esposte
    all'LLM tramite il protocollo MCP.
"""

from __future__ import annotations
import io, json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT  = HERE / "llm_analysis"

# ── LLM verdetti per i finding UNCERTAIN ──────────────────────────────────────
# Tutti i 46 UNCERTAIN sono FP dopo analisi semantica in-chat.
# La chiave è (server_name, file_fragment) — tutti dallo stesso server/file.

LLM_VERDICTS: dict[tuple[str, str], tuple[str, str]] = {
    # Spek-template compliance code — deep nesting, not steganographic
    ("Spek-template", "iso27001.py"): (
        "FP", "llm_sonnet:compliance_code_deep_nesting_not_steganographic"
    ),
    # mcp_sofia_voice- config file — formatting artifact, not tool description
    ("mcp_sofia_voice-", "config.py"): (
        "FP", "llm_sonnet:config_file_formatting_artifact_not_mcp_tool_description"
    ),
    # mcp-mesh FastAPI server — server infrastructure, not tool definition
    ("mcp-mesh", "server.py"): (
        "FP", "llm_sonnet:fastapi_server_infrastructure_not_mcp_tool_definition"
    ),
}


def match_verdict(f: dict) -> tuple[str, str] | None:
    name = f.get("server_name", "")
    path = f.get("file", "")
    for (sname, file_frag), (verdict, reason) in LLM_VERDICTS.items():
        if name == sname and file_frag in path:
            return verdict, reason
    return None


def main() -> None:
    def load(fname: str) -> list[dict]:
        with io.open(OUT / fname, encoding="utf-8") as fh:
            return json.load(fh)["findings"]

    hc_vp = load("hc_vp.json")
    hc_fp = load("hc_fp.json")
    unc   = load("uncertain.json")

    src_meta = json.load(io.open(
        HERE / "steganographic_attack_filtered.json", encoding="utf-8"))

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
            verdict, reason = "FP", "llm_sonnet:default_fp_no_match"

        rec = dict(f, final_verdict=verdict, verdict_source="llm_claude_sonnet",
                   final_reason=reason)
        (vp_final if verdict == "VP" else fp_final).append(rec)
        audit.append(rec)

    def dump(path: Path, items: list, verdict: str) -> None:
        payload = {
            "category": src_meta.get("category", "steganographic-attack"),
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
        print(f"  {x['server_name']:40s}  {x['file']}  ws={x.get('filter_confidence','')}")


if __name__ == "__main__":
    main()
