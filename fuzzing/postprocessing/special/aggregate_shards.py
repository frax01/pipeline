#!/usr/bin/env python3
"""
Aggrega i 9 shard del re-run fuzzing (GitHub+NPX combinato) in fuzzing/.

Produce:
  exceptions/<msg>.json          -> tool-level merged (servers[] concatenati, _origin)
  protocol_accepted.json         -> protocol merged (entries[], _origin, notif counts)
  fuzzing_servers_merged.json    -> mappa server->status (con _origin)
  fuzzing_stats_merged.json      -> contatori sommati
  _coverage_report.json          -> S_tool, S_protocol_only, split github/npx
"""
import json
import glob
import os
from collections import defaultdict, Counter

HERE = os.path.dirname(os.path.abspath(__file__))
SHARDS = sorted(glob.glob(os.path.join(HERE, "_shards", "vm*")))

EXC_FILES = [
    "Server_returned_error.json",
    "Failed_to_receive_message_from_stdio_transport.json",
    "Failed_to_send_message_over_stdio_transport.json",
    "No_response_received_from_stdio_transport.json",
    "safety_blocked.json",
]


def origin_of(url):
    u = url or ""
    if u.startswith("https://github.com/") or u.startswith("http://github.com/"):
        return "github"
    return "npx"


def load(p):
    return json.load(open(p, encoding="utf-8"))


def save(p, d):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)


# ── 1. merge exceptions ──────────────────────────────────────────────────────
exc_merged = {}      # filename -> {exception_message, total, servers[]}
tool_servers = set()
for fn in EXC_FILES:
    msg = None
    servers = []
    for sh in SHARDS:
        p = os.path.join(sh, "exceptions", fn)
        if not os.path.exists(p):
            continue
        d = load(p)
        msg = d.get("exception_message", fn.replace(".json", "").replace("_", " "))
        for s in d.get("servers", []):
            s["_origin"] = origin_of(s.get("server_url"))
            servers.append(s)
            if s.get("tool_name"):
                tool_servers.add(s.get("server_url"))
    exc_merged[fn] = {"exception_message": msg, "total": len(servers), "servers": servers}
    save(os.path.join(HERE, "exceptions", fn), exc_merged[fn])

# ── 2. merge protocol_accepted ───────────────────────────────────────────────
proto_entries = []
notif = Counter()
by_type = Counter()
proto_servers = set()
for sh in SHARDS:
    p = os.path.join(sh, "protocol_accepted.json")
    if not os.path.exists(p):
        continue
    d = load(p)
    notif.update(d.get("notification_counts_fp_by_design", {}))
    by_type.update(d.get("by_protocol_type", {}))
    for e in d.get("entries", []):
        e["_origin"] = origin_of(e.get("server_url"))
        proto_entries.append(e)
        proto_servers.add(e.get("server_url"))
save(os.path.join(HERE, "protocol_accepted.json"), {
    "total_accepted_entries": len(proto_entries),
    "notification_counts_fp_by_design": dict(notif.most_common()),
    "by_protocol_type": dict(by_type.most_common()),
    "entries": proto_entries,
})

# ── 3. merge fuzzing_servers (status map) ────────────────────────────────────
servers_map = {}
status_counter = Counter()
origin_counter = Counter()
completed_servers = set()
for sh in SHARDS:
    p = os.path.join(sh, "fuzzing_servers.json")
    if not os.path.exists(p):
        continue
    d = load(p)
    for url, status in d.items():
        servers_map[url] = status
        status_counter[status] += 1
        origin_counter[origin_of(url)] += 1
        if isinstance(status, str) and "completed" in status:
            completed_servers.add(url)
save(os.path.join(HERE, "fuzzing_servers_merged.json"), servers_map)

# ── 4. merge fuzzing_stats (somma contatori) ─────────────────────────────────
agg = Counter()
exc_by_msg = Counter()
proto_runs = Counter()
for sh in SHARDS:
    p = os.path.join(sh, "fuzzing_stats.json")
    if not os.path.exists(p):
        continue
    f = load(p).get("fuzzing", {})
    for k in ("total_servers", "total_tools", "total_fuzzing_runs",
              "total_successful", "total_exceptions", "total_safety_blocked"):
        agg[k] += f.get(k, 0) or 0
    exc_by_msg.update(f.get("exceptions_by_message", {}))
    pt = f.get("protocol_types", {})
    for k in ("total_runs", "total_successful", "total_errors"):
        proto_runs[k] += pt.get(k, 0) or 0
save(os.path.join(HERE, "fuzzing_stats_merged.json"), {
    "fuzzing": dict(agg),
    "exceptions_by_message": dict(exc_by_msg),
    "protocol_runs": dict(proto_runs),
})

# ── 5. coverage report: S_tool vs S_protocol_only ────────────────────────────
tool_origin = Counter(origin_of(u) for u in tool_servers)
proto_only = proto_servers - tool_servers
completed_only_proto = completed_servers - tool_servers
report = {
    "shards": len(SHARDS),
    "servers_in_status_map": len(servers_map),
    "status_distribution": dict(status_counter.most_common()),
    "origin_distribution_all": dict(origin_counter),
    "completed_servers": len(completed_servers),
    "S_tool__servers_with_tool_fuzzing": len(tool_servers),
    "S_tool_by_origin": dict(tool_origin),
    "S_protocol_accepted_servers": len(proto_servers),
    "S_protocol_only_vs_tool": len(proto_only),
    "completed_but_no_tool_fuzzing": len(completed_only_proto),
    "exceptions_merged_totals": {fn: exc_merged[fn]["total"] for fn in EXC_FILES},
    "protocol_accepted_entries": len(proto_entries),
}
save(os.path.join(HERE, "_coverage_report.json"), report)

print(json.dumps(report, indent=2, ensure_ascii=False))
