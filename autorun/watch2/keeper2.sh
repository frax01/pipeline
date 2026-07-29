#!/bin/bash
# keeper2.sh — keep-alive dei worker watch della SECONDA tranche ([33139,69104)).
#
# Legge ~/watch2/tasks.tsv (4 colonne: unit, gsafe_dir, tool_dir, end) e per ogni
# worker: se l'unit non e' attiva e last_index < end, lo rilancia in RESUME
# (--start -1 => riparte da last_index; MAI --reset, nessun dato perso).
# Fa anche uno snapshot rotante dei risultati e libera il disco se stretto.
#
# Da cron ogni 15 min. Idempotente.
set -u
VENV=/home/tecnico/pipeline-env/bin
TASKS=/home/tecnico/watch2/tasks.tsv
LOG=/home/tecnico/watch2/keeper2.log
BK=/home/tecnico/watch2/backups
STAMP=$(date +%Y%m%d_%H%M%S)
CATS="toxic-flow credential-leak data-exfiltration protocol-violation input-validation \
prompt-injection access-control tool-poisoning tool-mutation server-spoofing steganographic-attack"

[ -f "$TASKS" ] || exit 0

disk_pct() { df --output=pcent /home/tecnico 2>/dev/null | tail -1 | tr -dc '0-9'; }

clean_disk() {
  local p; p=$(disk_pct); [ -z "$p" ] && return
  [ "$p" -lt 88 ] && return
  echo "[$(date '+%F %T')] disk ${p}% -> cleanup" >> "$LOG"
  while IFS=$'\t' read -r unit g tool end; do
    [ -z "${unit:-}" ] && continue
    rm -rf "$g/home/.npm/_cacache" "$g/home/.cache/uv" "$g/home/.cache/go-build" 2>/dev/null
  done < "$TASKS"
  # tronca i log dei worker oltre 1GB (rumore stdout dei server analizzati)
  for lg in /home/tecnico/watch2/*.log; do
    [ -f "$lg" ] && [ "$(stat -c %s "$lg")" -gt 1073741824 ] && : > "$lg"
  done
  # tieni solo gli ultimi 2 snapshot per worker
  for d in "$BK"/*; do
    [ -d "$d" ] && ls -1t "$d"/*.tar.gz 2>/dev/null | tail -n +3 | xargs -r rm -f
  done
  echo "[$(date '+%F %T')] disk ora $(disk_pct)%" >> "$LOG"
}

clean_disk

while IFS=$'\t' read -r unit g tool end; do
  [ -z "${unit:-}" ] && continue
  wd="$g/work/Pipeline/$tool"
  stats="$wd/mcp_watch_stats.json"

  # ---- snapshot risultati (best effort) ----
  mkdir -p "$BK/$tool"
  items=""
  for x in mcp_watch_stats.json mcp_watch_servers.json $CATS; do
    [ -e "$wd/$x" ] && items="$items $tool/$x"
  done
  if [ -n "$items" ]; then
    ( cd "$g/work/Pipeline" && tar czf "$BK/$tool/$STAMP.tar.gz" $items 2>/dev/null ) || true
    ls -1t "$BK/$tool"/*.tar.gz 2>/dev/null | tail -n +4 | xargs -r rm -f
  fi

  # ---- keep-alive ----
  if [ "$(systemctl is-active "$unit" 2>/dev/null)" = active ]; then
    continue
  fi
  li=0
  [ -f "$stats" ] && li=$(python3 -c "import json;print(json.load(open('$stats')).get('last_index',0))" 2>/dev/null || echo 0)
  if [ "${li:-0}" -ge "$end" ]; then
    echo "[$(date '+%F %T')] $unit DONE ($li>=$end)" >> "$LOG"; continue
  fi
  echo "[$(date '+%F %T')] $unit giu' (li=$li) -> resume" >> "$LOG"
  sudo systemctl reset-failed "$unit" 2>/dev/null || true
  sudo systemd-run --unit="$unit" --collect \
    -p User=tecnico -p Group=tecnico -p ProtectSystem=strict \
    -p ReadWritePaths="$g" -p InaccessiblePaths=/home/tecnico/Desktop \
    -p PrivateTmp=yes -p NoNewPrivileges=yes \
    -p Restart=on-failure -p RestartSec=20 \
    -p WorkingDirectory="$wd" \
    -p "StandardOutput=append:/home/tecnico/watch2/$unit.log" \
    -p "StandardError=append:/home/tecnico/watch2/$unit.log" \
    --setenv=HOME="$g/home" --setenv=PIPELINE_BASE="$g/work/Pipeline" \
    --setenv=PATH="$VENV:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    --setenv=MCP_CONFIG="$wd/claude_desktop_config.json" \
    "$VENV/python" "$wd/run_watch.py" --start -1 --end "$end" >> "$LOG" 2>&1
done < "$TASKS"
