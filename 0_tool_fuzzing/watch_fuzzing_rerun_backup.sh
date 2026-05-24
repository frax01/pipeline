#!/bin/bash
# Backup watcher per il fuzzing rerun (0_tool_fuzzing/).
# Ogni volta che il fuzzer chiude un write su un .json -> rsync verso /opt/mcp_backups.
# Backuppa fuzzing_stats.json, fuzzing_servers.json, exceptions/, protocol/.

SRC_DIR="/home/tecnico/Desktop/Pipeline/0_tool_fuzzing"
DST_DIR="/opt/mcp_backups/0_tool_fuzzing"
LOG="/opt/mcp_backups/watch_fuzzing_rerun_backup.log"

mkdir -p "$DST_DIR"
echo "[$(date)] watcher started, watching $SRC_DIR" >> "$LOG"

# Attendi che la sorgente esista (pipeline puo' non essere ancora deployata)
while [ ! -d "$SRC_DIR" ]; do
  echo "[$(date)] waiting for $SRC_DIR..." >> "$LOG"
  sleep 30
done

# Watch su CLOSE_WRITE: evento emesso quando python fa close() dopo json.dump
# -r: ricorsivo, cosi' include anche exceptions/ e protocol/ (sottocartelle)
inotifywait -m -r -e close_write -e moved_to --format '%w%f' \
  "$SRC_DIR" 2>/dev/null | while read FILE; do
    case "$FILE" in
      *.json|*.json.tmp)
        rsync -a --no-links --delete-after "$SRC_DIR/" "$DST_DIR/" 2>/dev/null
        IDX=$(grep -oP '"last_index":\s*\K\d+' "$SRC_DIR/fuzzing_stats.json" 2>/dev/null || echo "?")
        echo "[$(date)] backup done (idx=$IDX, trigger=$(basename $FILE))" >> "$LOG"
        ;;
    esac
done
