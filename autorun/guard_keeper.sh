#!/bin/bash
# Keep-alive + periodic backup + disk guard for the sandboxed guard workers on VM1.
# - relaunches a worker whose unit died before finishing its shard
# - snapshots results to ~/pipeline_backups (outside the sandbox) keeping last 3
# - frees disk when the home filesystem gets tight (VM1 sandbox has no guardian.sh)
# Run from cron every ~15 min. Safe/idempotent.
set -u
LAUNCH=/home/tecnico/guard_sbx/sbx_launch.sh
BK=/home/tecnico/pipeline_backups
STAMP=$(date +%Y%m%d_%H%M%S)
LOG=/home/tecnico/guard_sbx/keeper.log

disk_pct() { df --output=pcent "$HOME" 2>/dev/null | tail -1 | tr -dc '0-9'; }

clean_disk() {
  local p; p=$(disk_pct); [ -z "$p" ] && return
  if [ "$p" -ge 85 ]; then
    echo "[$(date '+%F %T')] disk ${p}% -> cleanup" >> "$LOG"
    # stale caches in the REAL home (sandbox workers use ~/gsafe/wN/home/.cache)
    rm -rf ~/.cache/uv ~/.cache/puppeteer ~/.cache/ms-playwright ~/.cache/go-build 2>/dev/null
    # trim snapshots to the last 2 per tool
    for d in "$BK"/tool_*; do
      [ -d "$d" ] && ls -1t "$d"/*.tar.gz 2>/dev/null | tail -n +3 | xargs -r rm -f
    done
    # if still tight, prune sandbox package caches (workers re-fetch if needed)
    p=$(disk_pct)
    if [ "${p:-0}" -ge 90 ]; then
      for g in /home/tecnico/gsafe/w1 /home/tecnico/gsafe/w2; do
        rm -rf "$g/home/.npm/_cacache" "$g/home/.cache/uv" "$g/home/go/pkg/mod/cache/download" 2>/dev/null
      done
    fi
    echo "[$(date '+%F %T')] disk now $(disk_pct)%" >> "$LOG"
  fi
}

run_one() {
  local w="$1" tool="$2" end="$3"
  local g="/home/tecnico/gsafe/$w"
  local base="$g/work/Pipeline/$tool"
  local stats="$base/mcp_guard_stats.json"
  # ---- backup (best effort) ----
  mkdir -p "$BK/$tool"
  local items=""
  for x in mcp_guard_stats.json mcp_guard_servers.json static dynamic fuzzing protocol; do
    [ -e "$base/$x" ] && items="$items $tool/$x"
  done
  if [ -n "$items" ]; then
    ( cd "$g/work/Pipeline" && tar czf "$BK/$tool/$STAMP.tar.gz" $items 2>/dev/null ) || true
    ls -1t "$BK/$tool"/*.tar.gz 2>/dev/null | tail -n +4 | xargs -r rm -f
  fi
  # ---- keep-alive ----
  if [ "$(systemctl is-active guard_$w 2>/dev/null)" = "active" ]; then
    echo "[$(date '+%F %T')] guard_$w active" >> "$LOG"; return
  fi
  local li=0
  [ -f "$stats" ] && li=$(python3 -c "import json;print(json.load(open('$stats')).get('last_index',0))" 2>/dev/null || echo 0)
  if [ "${li:-0}" -ge "$end" ]; then
    echo "[$(date '+%F %T')] guard_$w DONE (last_index=$li >= $end)" >> "$LOG"; return
  fi
  echo "[$(date '+%F %T')] guard_$w down (last_index=$li) -> relaunch" >> "$LOG"
  bash "$LAUNCH" "guard_$w" "$g" "$tool" -1 "$end" >> "$LOG" 2>&1
}

clean_disk
run_one w1 tool_mcp_guard_w1 17276
run_one w2 tool_mcp_guard_w2 34552
