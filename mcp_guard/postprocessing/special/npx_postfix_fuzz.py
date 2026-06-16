#!/usr/bin/env python3
"""
Post-fix NPX per 2 categorie fuzzing dove le HC GitHub-tuned lasciano passare FP:

- command-execution-fuzzing: la response e' "Command failed: <comando DEL TOOL>"
  (ollama/git/python script del tool che fallisce), NON l'esecuzione del payload
  dell'attaccante. VP solo se la response mostra output di exec reale (uid=, /etc/passwd).
- code-injection-fuzzing: server e' un esecutore di codice by-design (mcp-pyodide,
  sandbox WASM) o la response e' "Command failed: <script .py del tool>". Eseguire
  codice in un interprete sandbox dichiarato NON e' una injection.

Sposta i finding leaky da vp.json a fp.json e riscrive audit.json.
"""
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent

# evidenza di exec/disclosure REALE nella response (solo marker decisivi:
# NON /bin/sh che compare nei messaggi d'errore "Syntax error" della shell che
# RIFIUTA il comando malformato = FP)
_REAL = re.compile(
    r"uid=\d+\([a-z]|gid=\d+\([a-z]|root:x:0:0:|"
    r"\[boot loader\]|\[fonts\]|BEGIN [A-Z ]*PRIVATE KEY|ssh-rsa AAAA",
    re.M,
)
# esecutore di codice dichiarato / script proprio del tool che fallisce
_SANDBOX_OR_OWN = re.compile(
    r"_pyodide|pyodide|Command failed:\s*(python|node|ollama|git|npm|npx|sh|bash)\b|"
    r"Traceback \(most recent call last\)",
    re.I,
)


def fix_category(cat, fp_rule):
    d = HERE / cat / "filtered" / "llm_analysis"
    vp = json.load(open(d / "vp.json", encoding="utf-8"))
    fp = json.load(open(d / "fp.json", encoding="utf-8"))
    moved = 0
    keep_vp = []
    for f in vp["findings"]:
        verdict, reason = fp_rule(f)
        if verdict == "FP":
            f = dict(f, final_verdict="FP", final_reason=reason,
                     verdict_source="npx_postfix")
            fp["findings"].append(f)
            moved += 1
        else:
            keep_vp.append(f)
    vp["findings"] = keep_vp
    vp["total"] = len(keep_vp)
    fp["total"] = len(fp["findings"])
    json.dump(vp, open(d / "vp.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump(fp, open(d / "fp.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    # audit = vp + fp
    audit = {"category": cat, "total": vp["total"] + fp["total"],
             "findings": keep_vp + fp["findings"]}
    json.dump(audit, open(d / "audit.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"  {cat:28s} spostati VP->FP: {moved:3d}  | VP rimasti: {vp['total']}")


def rule_command_execution(f):
    resp = str(f.get("response", ""))
    if _REAL.search(resp):
        return "VP", f.get("final_reason", "real_exec_output")
    return "FP", "tool_own_command_failed_no_real_exec"


def rule_code_injection(f):
    resp = str(f.get("response", ""))
    if _REAL.search(resp):
        return "VP", f.get("final_reason", "real_injection_evidence")
    if _SANDBOX_OR_OWN.search(resp) or "pyodide" in str(f.get("server_name", "")).lower():
        return "FP", "sandbox_executor_or_tool_own_script"
    return "VP", f.get("final_reason", "kept")


if __name__ == "__main__":
    print("=== Post-fix NPX fuzzing categorie leaky ===")
    fix_category("command-execution-fuzzing", rule_command_execution)
    fix_category("code-injection-fuzzing", rule_code_injection)
