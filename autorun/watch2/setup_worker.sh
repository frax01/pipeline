#!/bin/bash
# setup_worker.sh — crea UNA sandbox watch della seconda tranche e la avvia.
# args: WORKER_ID START END
# Richiede /home/tecnico/watch2/template.tar.gz gia' presente sulla VM.
set -eu
WID="$1"; START="$2"; END="$3"
G=/home/tecnico/gsafe_watch2/$WID
TOOL=tool_mcp_watch_$WID
UNIT=watch2_$WID
VENV=/home/tecnico/pipeline-env/bin
TMPL=/home/tecnico/watch2/template.tar.gz

mkdir -p /home/tecnico/watch2

# ferma un'eventuale istanza precedente
sudo systemctl stop "$UNIT" 2>/dev/null || true
sudo systemctl reset-failed "$UNIT" 2>/dev/null || true

# ricrea la sandbox SOLO se non esiste gia' (idempotente: non distrugge risultati)
if [ ! -d "$G/work/Pipeline/$TOOL" ]; then
  mkdir -p "$G/home/Desktop" "$G/work/Pipeline"
  tar xzf "$TMPL" -C "$G" --strip-components=1   # template/{home,work} -> $G/{home,work}
  mv "$G/work/Pipeline/tool_mcp_watch_TMPL" "$G/work/Pipeline/$TOOL"
  echo '{}' > "$G/work/Pipeline/$TOOL/claude_desktop_config.json"
  # canary forensi: se un server analizzato cancella la home/Desktop lo si vede
  echo "forensic canary - do not delete" > "$G/home/Desktop/CANARY_DESKTOP"
  echo "forensic canary - do not delete" > "$G/home/CANARY_HOME"
fi

WD="$G/work/Pipeline/$TOOL"

# resume se ci sono gia' risultati, altrimenti parte da START
LI=0
[ -f "$WD/mcp_watch_stats.json" ] && LI=$(python3 -c "import json;print(json.load(open('$WD/mcp_watch_stats.json')).get('last_index',0))" 2>/dev/null || echo 0)
S="$START"
[ "${LI:-0}" -gt "$START" ] && S="$LI"
if [ "${LI:-0}" -ge "$END" ]; then
  echo "$WID GIA' COMPLETO (last_index=$LI >= $END)"; exit 0
fi

sudo systemd-run --unit="$UNIT" --collect \
  -p User=tecnico -p Group=tecnico -p ProtectSystem=strict \
  -p ReadWritePaths="$G" -p InaccessiblePaths=/home/tecnico/Desktop \
  -p PrivateTmp=yes -p NoNewPrivileges=yes \
  -p Restart=on-failure -p RestartSec=20 \
  -p WorkingDirectory="$WD" \
  -p "StandardOutput=append:/home/tecnico/watch2/$UNIT.log" \
  -p "StandardError=append:/home/tecnico/watch2/$UNIT.log" \
  --setenv=HOME="$G/home" --setenv=PIPELINE_BASE="$G/work/Pipeline" \
  --setenv=PATH="$VENV:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  --setenv=MCP_CONFIG="$WD/claude_desktop_config.json" \
  "$VENV/python" "$WD/run_watch.py" --start "$S" --end "$END"

echo "$WID avviato: start=$S end=$END (last_index precedente=$LI)"
