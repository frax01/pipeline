#!/usr/bin/env python3
"""
Pre-filtro protocol da eseguire SU OGNI VM prima del pull.

Riduce i ~1-2 GB di protocol/*.json tenendo SOLO i server-entry dove il server
ha ACCETTATO un messaggio protocol malformato (successful > 0). Scarta tutti i
run di errore (rejection corretta = noise).

Output: protocol_accepted.json (compatto) nella cwd.
"""
import json
import glob
import os
import sys

SRC = "protocol"
OUT = "protocol_accepted.json"


def main():
    entries = []
    by_type = {}
    notif_counts = {}          # *Notification: solo conteggio (FP by design, no response)
    files = sorted(glob.glob(os.path.join(SRC, "*.json")))
    for f in files:
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception as e:
            print(f"  ERR {f}: {e}", file=sys.stderr)
            continue
        ptype = d.get("protocol_type", os.path.basename(f).replace(".json", ""))
        is_notif = ptype.endswith("Notification")
        kept = 0
        for s in d.get("servers", []):
            if s.get("successful", 0) and s.get("successful", 0) > 0:
                kept += 1
                if is_notif:
                    # notification: nessun response body utile, tengo solo il conteggio
                    continue
                entries.append({
                    "server_url": s.get("server_url"),
                    "server_name": s.get("server_name"),
                    "protocol_type": ptype,
                    "runs": s.get("runs"),
                    "successful": s.get("successful"),
                    "errors": s.get("errors"),
                    "success_rate": s.get("success_rate"),
                    "success_details": s.get("success_details", []),
                })
        if kept:
            (notif_counts if is_notif else by_type)[ptype] = kept
    out = {
        "total_accepted_entries": len(entries),
        "notification_counts_fp_by_design": dict(sorted(notif_counts.items(), key=lambda x: -x[1])),
        "by_protocol_type": dict(sorted(by_type.items(), key=lambda x: -x[1])),
        "entries": entries,
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)
    print(f"  protocol accepted entries: {len(entries)}  -> {OUT} "
          f"({os.path.getsize(OUT)/1e6:.1f} MB)")


if __name__ == "__main__":
    main()
