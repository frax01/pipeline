#!/usr/bin/env python3
"""
Stage 1 filter per il re-run tool_fuzzing (GitHub+NPX combinato, CON risposte).

Legge i dati aggregati (exceptions/*.json + protocol_accepted.json) e produce
4 categorie normalizzate in <category>/filtered/<category>_filtered.json.

Categorie (sfruttano le risposte del re-run, assenti nel run vecchio):
  1. tool-input-accepted   - payload fuzz ACCETTATO dal tool (inputs_successful + result)
  2. tool-error-disclosure - server_error_response/result con potenziale disclosure
                             (esclude -32602 validation = rifiuto corretto)
  3. tool-crash-dos        - TransportFailure (server non risponde) + crash Python
  4. protocol-fuzzing      - messaggi protocol malformati accettati (non-notification)

Ogni finding mantiene _origin (github|npx).
"""
import json
import glob
import os
import re
import hashlib
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
EXC_DIR = os.path.join(HERE, "exceptions")
PROTO = os.path.join(HERE, "protocol_accepted.json")

# messaggi che indicano un RIFIUTO CORRETTO (validation) o problema ambientale → noise
_VALIDATION_NOISE = re.compile(
    r"invalid request parameters|invalid params|invalid parameters|"
    r"parameter parsing not fully implemented|validating \"?arguments\"?|"
    r"method \"?tools/call\"? is invalid during session init|"
    r"unknown method|server not initialized|missing required|"
    r"required (parameter|argument|property)|must be a valid|must be one of",
    re.I,
)
_ENV_NOISE = re.compile(
    r"api key not set|api[_ ]?key.*(not set|required|missing)|token not found|"
    r"not configured|credentials.*(not|could not)|authentication failed|"
    r"auth_error|executable file not found|exec: \"[^\"]+\": executable|"
    r"connection.*(not established|refused)|not running|env(ironment)? var|"
    r"no such file or directory|folder has not been set|kubeconfig|"
    r"\.kube/config|token\.tkn|not been set as a root",
    re.I,
)
# crash runtime reale (panic Go / traceback Python) triggerato da input fuzzato
_CRASH = re.compile(
    r"panic recovered|panic:|interface conversion: interface \{\} is nil|"
    r"invalid memory address or nil pointer dereference|"
    r"runtime error:|index out of range|goroutine \d+ \[|"
    r"Traceback \(most recent call last\)|object has no attribute|"
    r"unhandledRejection|maximum call stack|RangeError: Maximum",
    re.I,
)
# disclosure reale: stack trace / source path con riga / secret
_DISCLOSURE = re.compile(
    r"Traceback \(most recent call last\)|"
    r"\bat [A-Za-z0-9_$.<>]+ \(.*:\d+:\d+\)|"          # node stack
    r"\.(py|js|ts|go|rb|java):\d+|"                      # source:line
    r"File \"[^\"]+\", line \d+|"                        # python file/line
    r"goroutine \d+ \[|panic:|"                          # go panic
    r"BEGIN [A-Z ]*PRIVATE KEY|ssh-rsa AAAA|AKIA[0-9A-Z]{16}|"
    r"ENOENT.*\.\./|EACCES",
    re.I,
)
# exploitation reale nel result (path traversal / command exec / data leak)
_EXPLOIT = re.compile(
    r"root:x:0:0:|uid=\d+\([a-z]|gid=\d+\([a-z]|"
    r"\bdrwx[r-][w-][x-]|^total \d+$|"
    r"BEGIN [A-Z ]*PRIVATE KEY|ssh-rsa AAAA|AKIA[0-9A-Z]{16}",
    re.M,
)
# pattern d'attacco negli ARGOMENTI fuzzati
_ATTACK_ARG = re.compile(
    r"\.\./|/etc/passwd|\.\.\.\.\.\.|%2e%2e|"
    r"__proto__|constructor.*prototype|isAdmin|"
    r"<script|javascript:|onerror=|"
    r"' OR |UNION SELECT|DROP TABLE|1=1|"
    r"\$\(|&&|; rm |; cat |; ls |"
    r"http://evil|169\.254|file://",
    re.I,
)


def origin_of(url):
    u = url or ""
    return "github" if u.startswith("http://github.com/") or u.startswith("https://github.com/") else "npx"


def _hash(*parts):
    return hashlib.md5("|".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()[:12]


def save_cat(cat, findings, meta):
    out = {"category": cat, "original_total": meta.get("orig", len(findings)),
           "kept_total": len(findings), "findings": findings}
    d = os.path.join(HERE, cat, "filtered")
    os.makedirs(d, exist_ok=True)
    json.dump(out, open(os.path.join(d, f"{cat}_filtered.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print(f"  {cat:24s} orig={meta.get('orig','?'):>6} kept={len(findings)}")


def main():
    exc_files = glob.glob(os.path.join(EXC_DIR, "*.json"))

    input_accepted = []
    error_disclosure = []
    crash_dos = {}     # (server,tool) -> aggregato
    orig_succ = orig_err = 0

    for fn in exc_files:
        d = json.load(open(fn, encoding="utf-8"))
        for s in d.get("servers", []):
            url = s.get("server_url"); name = s.get("server_name")
            tool = s.get("tool_name"); orig = origin_of(url)
            etype = None

            # --- inputs_successful -> tool-input-accepted ---
            for ins in s.get("inputs_successful", []):
                r = ins.get("result")
                if r is None:
                    continue
                orig_succ += 1
                rtxt = json.dumps(r, ensure_ascii=False)
                args = ins.get("arguments", {})
                atxt = json.dumps(args, ensure_ascii=False)
                is_err = isinstance(r, dict) and r.get("isError") is True
                has_attack = bool(_ATTACK_ARG.search(atxt))
                # Stage1: tieni solo se il payload aveva un pattern d'attacco
                # (gli altri sono input random benigni accettati = irrilevante)
                if not has_attack:
                    continue
                input_accepted.append({
                    "server_url": url, "server_name": name, "tool_name": tool,
                    "category": "tool-input-accepted", "_origin": orig,
                    "arguments": args, "result_excerpt": rtxt[:1500],
                    "result_is_error": is_err,
                    "exploit_marker": bool(_EXPLOIT.search(rtxt)),
                    "id": _hash(url, tool, _hash(atxt)),
                })

            # --- inputs_causing_error -> error-disclosure / crash ---
            for ic in s.get("inputs_causing_error", []):
                orig_err += 1
                et = ic.get("exception_type")
                code = ic.get("exception_code")
                ser = ic.get("server_error_response") or {}
                msg = ser.get("message") or (ic.get("server_error") if isinstance(ic.get("server_error"), str) else "") or ""
                etype = et
                if et == "TransportFailure":
                    continue  # gestito sotto come crash aggregato
                # CRASH runtime (panic Go / traceback) -> crash-dos, NON disclosure
                if _CRASH.search(msg):
                    key = (url, tool, "panic")
                    prev = crash_dos.get(key)
                    if prev:
                        prev["crash_hits"] = prev.get("crash_hits", 1) + 1
                    else:
                        ctype = "go_panic" if re.search(r"panic|interface conversion|nil pointer|goroutine|runtime error", msg, re.I) else "py_traceback"
                        crash_dos[key] = {
                            "server_url": url, "server_name": name, "tool_name": tool,
                            "category": "tool-crash-dos", "_origin": orig,
                            "crash_type": ctype, "crash_hits": 1,
                            "runs": s.get("runs"),
                            "input_assertion": bool(re.search(r"interface conversion", msg, re.I)),
                            "exception_code": code,
                            "message_excerpt": msg[:500],
                            "sample_args": ic.get("arguments", {}),
                            "id": _hash(url, tool, "panic"),
                        }
                    continue
                # scarta validation/env noise
                if _VALIDATION_NOISE.search(msg) or _ENV_NOISE.search(msg):
                    continue
                if code == -32602:
                    continue  # validation corretta
                # tieni solo potenziale disclosure o internal error con contenuto
                if not msg.strip():
                    continue
                disclosure = bool(_DISCLOSURE.search(msg))
                if not (disclosure or code in (-32603, -32000, 0, None)):
                    continue
                error_disclosure.append({
                    "server_url": url, "server_name": name, "tool_name": tool,
                    "category": "tool-error-disclosure", "_origin": orig,
                    "exception_code": code, "exception_type": et,
                    "message_excerpt": msg[:1200],
                    "disclosure_marker": disclosure,
                    "arguments": ic.get("arguments", {}),
                    "id": _hash(url, tool, _hash(msg[:120])),
                })

            # --- crash/DoS: tool con TransportFailure ---
            if s.get("exceptions") and s.get("runs"):
                tf = [ic for ic in s.get("inputs_causing_error", [])
                      if ic.get("exception_type") == "TransportFailure"]
                pycrash = [ic for ic in s.get("inputs_causing_error", [])
                           if isinstance(ic.get("server_error"), str)
                           and ("object has no attribute" in ic.get("server_error", "")
                                or "Traceback" in ic.get("server_error", ""))]
                if tf or pycrash:
                    key = (url, tool)
                    prev = crash_dos.get(key, {"tf": 0, "pycrash": 0, "runs": 0, "exc": 0})
                    crash_dos[key] = {
                        "server_url": url, "server_name": name, "tool_name": tool,
                        "category": "tool-crash-dos", "_origin": orig,
                        "tf": prev["tf"] + len(tf),
                        "pycrash": prev["pycrash"] + len(pycrash),
                        "runs": s.get("runs"), "exc": s.get("exceptions"),
                        "success_rate": s.get("success_rate"),
                        "sample_args": (tf or pycrash)[0].get("arguments", {}),
                        "id": _hash(url, tool, "crash"),
                    }

    crash_list = list(crash_dos.values())

    # --- protocol-fuzzing ---
    proto_findings = []
    if os.path.exists(PROTO):
        pd = json.load(open(PROTO, encoding="utf-8"))
        for e in pd.get("entries", []):
            proto_findings.append({
                "server_url": e.get("server_url"), "server_name": e.get("server_name"),
                "tool_name": None, "category": "protocol-fuzzing",
                "_origin": e.get("_origin", origin_of(e.get("server_url"))),
                "protocol_type": e.get("protocol_type"),
                "successful": e.get("successful"), "runs": e.get("runs"),
                "success_details": e.get("success_details", [])[:3],
                "id": _hash(e.get("server_url"), e.get("protocol_type")),
            })

    save_cat("tool-input-accepted", input_accepted, {"orig": orig_succ})
    save_cat("tool-error-disclosure", error_disclosure, {"orig": orig_err})
    save_cat("tool-crash-dos", crash_list, {"orig": len(crash_list)})
    save_cat("protocol-fuzzing", proto_findings, {"orig": len(proto_findings)})

    print("\n  Origin split:")
    for cat, lst in [("input-accepted", input_accepted), ("error-disclosure", error_disclosure),
                     ("crash-dos", crash_list), ("protocol", proto_findings)]:
        c = Counter(f["_origin"] for f in lst)
        print(f"    {cat:18s} github={c.get('github',0):5d}  npx={c.get('npx',0):4d}")


if __name__ == "__main__":
    main()
