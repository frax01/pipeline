#!/bin/bash
# culprit_watch.sh — forensic canary watcher for the sandboxed guard workers (VM1).
#
# WHY: mcp-guard runs untrusted MCP servers (install/start/fuzz). One server in
# the shard executes a destructive command against ~/Desktop. The workers now run
# inside a systemd sandbox where ~/Desktop is a throwaway dir, so the wipe is
# contained. This watcher drops a canary in each sandbox's ~/Desktop (and ~/ root)
# and, the instant it vanishes, records WHICH server index was in-flight — turning
# the wipe into a precisely attributed finding instead of an unattributed incident.
#
# The stats file lives under work/Pipeline (PIPELINE_BASE), NOT under ~/Desktop, so
# it survives the wipe: last_index is readable at the moment of detection and the
# in-flight (culprit) server = last_index + 1.
#
# Runs OUTSIDE the sandbox as user tecnico. Idempotent; safe to relaunch.
set -u

GS=/home/tecnico/gsafe
EVID=/home/tecnico/guard_sbx/CULPRIT_EVIDENCE.log
TRACE=/home/tecnico/guard_sbx/index_trace.log
WORKERS=("w1:tool_mcp_guard_w1" "w2:tool_mcp_guard_w2")

ensure_canaries() {         # $1 = sandbox base dir
  local g="$1"
  mkdir -p "$g/home/Desktop" "$g/home" 2>/dev/null
  [ -e "$g/home/Desktop/CANARY_DESKTOP" ] || echo "forensic canary - do not delete - $(date '+%F %T')" > "$g/home/Desktop/CANARY_DESKTOP" 2>/dev/null
  [ -e "$g/home/CANARY_HOME" ]            || echo "forensic canary - do not delete - $(date '+%F %T')" > "$g/home/CANARY_HOME" 2>/dev/null
}

read_last_index() {         # $1 = sandbox base dir  $2 = tool dir name
  local s="$1/work/Pipeline/$2/mcp_guard_stats.json"
  if [ -f "$s" ]; then
    python3 -c "import json;print(json.load(open('$s')).get('last_index','?'))" 2>/dev/null || echo '?'
  else
    echo '?'
  fi
}

declare -A LASTSEEN
for pair in "${WORKERS[@]}"; do ensure_canaries "$GS/${pair%%:*}"; done
echo "[$(date '+%F %T')] culprit_watch started (pid $$)" >> "$EVID"

while true; do
  ts=$(date '+%F %T')
  for pair in "${WORKERS[@]}"; do
    w="${pair%%:*}"; tool="${pair##*:}"; g="$GS/$w"
    idx=$(read_last_index "$g" "$tool")

    # trace only on change -> compact per-server timeline
    if [ "${LASTSEEN[$w]:-}" != "$idx" ]; then
      echo "$ts $w last_index=$idx" >> "$TRACE"
      LASTSEEN[$w]="$idx"
    fi

    # canary check
    if [ ! -e "$g/home/Desktop/CANARY_DESKTOP" ] || [ ! -e "$g/home/CANARY_HOME" ]; then
      dgone=no; hgone=no
      [ -e "$g/home/Desktop/CANARY_DESKTOP" ] || dgone=yes
      [ -e "$g/home/CANARY_HOME" ]            || hgone=yes
      culprit='?'; [ "$idx" != '?' ] && culprit=$((idx+1))
      {
        echo "=================================================================="
        echo "[$ts] !!! DESTRUCTIVE EVENT CONTAINED on $w !!!"
        echo "  canary ~/Desktop deleted      : $dgone"
        echo "  canary ~/ (home root) deleted : $hgone   (yes => 'rm -rf ~', no => targeted ~/Desktop)"
        echo "  last completed index          : $idx"
        echo "  ==> CULPRIT in-flight index   : $culprit"
        echo "  --- last 35 log lines (guard_$w.log) ---"
        tail -35 "$g/guard_$w.log" 2>/dev/null | sed 's/^/    /'
        echo "  --- recent Server:/URL:/Index: markers (may lag: stdout buffered) ---"
        grep -aE '^(URL:|Index:|Server:|command:)' "$g/guard_$w.log" 2>/dev/null | tail -8 | sed 's/^/    /'
        echo "=================================================================="
        echo
      } >> "$EVID"
      ensure_canaries "$g"   # recreate for the next catch
    fi
  done
  sleep 8
done
