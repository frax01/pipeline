#!/usr/bin/env python3
"""
Stage 2A (HC rules) + merge per il re-run tool_fuzzing (con risposte).

Per ogni categoria legge <cat>/filtered/<cat>_filtered.json e produce
<cat>/filtered/llm_analysis/{hc_vp,hc_fp,uncertain,vp,fp,audit}.json

HC rules basate sulle RISPOSTE del re-run (assenti nel run vecchio):
  tool-crash-dos       VP se crash runtime reale (panic Go / traceback Python)
                       FP se solo TransportFailure (env/transport noise)
  tool-error-disclosure VP se stack trace con path sorgente (info disclosure)
                       FP altrimenti (errori interni env/runtime/API)
  tool-input-accepted  VP se result mostra exploitation reale (file/cmd/secret)
                       FP se rifiutato (isError) o nessun effetto
  protocol-fuzzing     FP: metodi validi gestiti o response vuota (no processing)

Uso:
  py -X utf8 pipeline_fuzzing.py --category all
  py -X utf8 pipeline_fuzzing.py --category tool-crash-dos
"""
import argparse
import json
import os
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
CATEGORIES = ["tool-input-accepted", "tool-error-disclosure", "tool-crash-dos", "protocol-fuzzing"]

# metodi MCP legittimi: accettarli/gestirli NON e' una vulnerabilita'
_VALID_METHODS = {
    "PingRequest", "PingResult", "InitializeRequest", "InitializeResult",
    "ListResourcesRequest", "ListResourcesResult", "ListPromptsRequest", "ListPromptsResult",
    "ListResourceTemplatesRequest", "ListResourceTemplatesResult", "ListToolsResult",
    "ReadResourceRequest", "ReadResourceResult", "GetPromptRequest", "GetPromptResult",
    "CompleteRequest", "CompleteResult", "SetLevelRequest", "SubscribeRequest",
    "UnsubscribeRequest", "ListRootsRequest", "ListRootsResult", "Resource", "ResourceTemplate",
    "Tool", "TextContent", "ImageContent", "AudioContent", "BlobResourceContents",
    "TextResourceContents", "SamplingMessage",
}


def hc_input_accepted(f):
    if f.get("exploit_marker"):
        return "VP", "result_shows_real_exploitation"
    if f.get("result_is_error"):
        return "FP", "tool_rejected_payload_iserror"
    return "FP", "payload_accepted_no_security_effect"


def hc_error_disclosure(f):
    if f.get("disclosure_marker"):
        return "VP", "stack_trace_source_path_disclosure"
    return "FP", "generic_internal_or_env_error"


def hc_crash_dos(f):
    ct = f.get("crash_type")
    if ct in ("go_panic", "py_traceback"):
        # Discriminante VP/FP = TIPO di panic (non DoS: recover() tiene su il processo;
        # il valore e' come bug di robustezza input-handling CWE-476 attacker-triggerable):
        #  - "interface conversion: interface {} is nil, not <type>" = type assertion NON
        #    controllata su un valore di INPUT -> il payload fuzzato causa direttamente il
        #    panic -> INPUT-TRIGGERED -> VP
        #  - "invalid memory address or nil pointer dereference" = tipicamente client/SDK nil
        #    da config/backend assente (panic ~100% su OGNI tool, input-independent) -> FP
        if f.get("input_assertion") or ct == "py_traceback":
            return "VP", "input_triggered_handler_panic_recovered"
        return "FP", "nil_pointer_input_independent_config_recovered"
    # solo TransportFailure / pycrash legacy
    if f.get("pycrash", 0):
        return "VP", "python_crash"
    return "FP", "transport_failure_env_or_timeout"


def hc_protocol(f):
    pt = f.get("protocol_type", "")
    # tutti i finding protocol: o metodo valido gestito o response vuota -> FP
    # (l'analisi ha mostrato server_response vuoto o handling di metodi validi)
    if pt in _VALID_METHODS:
        return "FP", "valid_mcp_method_handled"
    return "FP", "malformed_msg_no_processing_empty_response"


HC = {
    "tool-input-accepted": hc_input_accepted,
    "tool-error-disclosure": hc_error_disclosure,
    "tool-crash-dos": hc_crash_dos,
    "protocol-fuzzing": hc_protocol,
}


def run_category(cat):
    src = os.path.join(HERE, cat, "filtered", f"{cat}_filtered.json")
    if not os.path.exists(src):
        print(f"  SKIP {cat}: no filtered file")
        return None
    findings = json.load(open(src, encoding="utf-8")).get("findings", [])
    out_dir = os.path.join(HERE, cat, "filtered", "llm_analysis")
    os.makedirs(out_dir, exist_ok=True)
    # Annotazione VP: severita' + CWE + nota (i crash recuperati NON sono DoS)
    VP_META = {
        "tool-crash-dos": {
            "severity": "low",
            "cwe": "CWE-20 (Improper Input Validation) -> type-assertion panic (CWE-248)",
            "vp_class": "robustness_input_validation",
            "note": "panic recuperato (recover()): NON e' un DoS pieno del processo; "
                    "e' un bug di robustezza/input-handling attacker-triggerable.",
        },
        "tool-error-disclosure": {
            "severity": "low",
            "cwe": "CWE-209 (Generation of Error Message Containing Sensitive Information)",
            "vp_class": "information_disclosure",
            "note": "stack trace con path sorgente interni esposti al client.",
        },
    }
    hc = HC[cat]
    vp, fp = [], []
    reasons = Counter()
    for f in findings:
        verdict, reason = hc(f)
        rec = dict(f, final_verdict=verdict, final_reason=reason, verdict_source="hc_rule")
        if verdict == "VP" and cat in VP_META:
            rec.update(VP_META[cat])
        (vp if verdict == "VP" else fp).append(rec)
        reasons[f"{verdict}:{reason}"] += 1

    def dump(name, items, extra=None):
        d = {"category": cat, "total": len(items)}
        if extra:
            d.update(extra)
        d["findings"] = items
        json.dump(d, open(os.path.join(out_dir, name), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)

    dump("vp.json", vp, {"verdict": "true_positive"})
    dump("fp.json", fp, {"verdict": "false_positive"})
    dump("hc_vp.json", vp); dump("hc_fp.json", fp); dump("uncertain.json", [])
    dump("audit.json", vp + fp)

    vp_org = Counter(x["_origin"] for x in vp)
    print(f"  {cat:24s} total={len(findings):5d}  VP={len(vp):4d} (gh={vp_org.get('github',0)} npx={vp_org.get('npx',0)})  FP={len(fp):5d}")
    for r, c in reasons.most_common():
        print(f"       {c:5d}  {r}")
    return {"cat": cat, "vp": len(vp), "fp": len(fp),
            "vp_servers": len(set(x["server_url"] for x in vp))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--category", default="all")
    args = ap.parse_args()
    cats = CATEGORIES if args.category == "all" else [args.category]
    summary = []
    for c in cats:
        r = run_category(c)
        if r:
            summary.append(r)
    if len(summary) > 1:
        tv = sum(s["vp"] for s in summary); tf = sum(s["fp"] for s in summary)
        print(f"\n  TOTALE  VP={tv}  FP={tf}")
        print("  VP per categoria (server distinti):")
        for s in summary:
            print(f"    {s['cat']:24s} VP={s['vp']:4d}  server_distinti={s['vp_servers']}")


if __name__ == "__main__":
    main()
