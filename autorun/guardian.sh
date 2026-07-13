#!/usr/bin/env bash
# guardian.sh — sorveglia i tool di analisi su UNA VM.
#
# Legge ~/pipeline_rerun/guardian_tasks.tsv (generato da autorun.py) con colonne
# separate da TAB:
#   name  pgrep_pattern  cwd  stats_file  floor  end  script  log
#
# Attende GRACE secondi (i tool sono già stati avviati da autorun launch), poi
# ogni ciclo (60s):
#   - integrità: se lo stats è assente/corrotto -> lo RIPRISTINA dall'ultimo
#     snapshot buono (così il calcolo dell'indice non riparte da 0).
#   - se un task non è completo (last_index < end) e il suo processo non gira
#     -> lo RILANCIA in resume da start = max(last_index, floor), MAI --reset
#     (lo shard riparte dal punto giusto, nessuna perdita dati né sovrapposizione).
#   - se il disco supera la soglia -> pulisce le cache di build.
#   - ogni SNAP_EVERY cicli -> snapshot della cartella dei risultati di ogni task
#     (ne tiene NKEEP).
# Termina quando TUTTI i task sono completi.

set +e
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:$PATH"
DIR="$HOME/pipeline_rerun"
TASKS="$DIR/guardian_tasks.tsv"
BK="$HOME/pipeline_backups"
LOG() { echo "[$(date '+%F %T')] $*"; }

GRACE=${GUARDIAN_GRACE:-150}   # attesa iniziale prima del primo controllo
DISK_THRESHOLD=80              # % oltre il quale si pulisce
SNAP_EVERY=30                  # ogni ~30 cicli (~30 min) fa uno snapshot
NKEEP=3                        # snapshot da conservare per cartella
SLEEP=60

CACHE_DIRS=(
  "$HOME/.cache/uv" "$HOME/.cache/go-build" "$HOME/.cache/puppeteer"
  "$HOME/.cache/ms-playwright" "$HOME/.cache/electron" "$HOME/.cache/node-gyp"
  "$HOME/.cache/pnpm" "$HOME/.cache/pip" "$HOME/.cache/prisma"
  "$HOME/.npm/_cacache" "$HOME/.npm/_npx"
  "$HOME/go/pkg" "$HOME/go/pkg/mod"
  "$HOME/.local/share/pnpm/store" "$HOME/.bun/install/cache"
  "/tmp/node-compile-cache" "/tmp/safe"
)

clean_orphans() {
  # rimuove i repo clonati ORFANI (dir con .git non toccate da >15 min) nella
  # cwd di un worker: una scansione dura pochi minuti, quindi un clone fermo da
  # 15+ min è certamente residuo di un server andato in crash/timeout senza
  # cleanup. La cache Go è read-only -> chmod prima del rm.
  find "$1" -maxdepth 1 -mindepth 1 -type d -mmin +15 2>/dev/null | while read -r od; do
    if [ -d "$od/.git" ]; then
      chmod -R u+w "$od" 2>/dev/null; rm -rf "$od" 2>/dev/null
      LOG "clone orfano rimosso: $od"
    fi
  done
}

is_running() {
  # vivo solo se un processo che matcha il pattern è un python REALE
  # (non il wrapper 'bash -lc ... setsid nohup python ...' che resta appeso)
  local p c
  for p in $(pgrep -f "$1" 2>/dev/null); do
    c="$(ps -o comm= -p "$p" 2>/dev/null)"
    case "$c" in python|python3|python3.*) return 0 ;; esac
  done
  return 1
}

disk_pct() { df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9'; }

clean_caches() {
  LOG "disco alto ($(disk_pct)%) -> pulizia cache..."
  # la module cache di Go è READ-ONLY: senza chmod, rm -rf fallisce e ~/go
  # cresce fino a riempire il disco (causa radice della saturazione).
  chmod -R u+w "$HOME/go" "$HOME/.cache" 2>/dev/null
  for d in "${CACHE_DIRS[@]}"; do rm -rf "$d" 2>/dev/null; done
  rm -rf "$HOME/go/pkg" "$HOME/go/bin" /tmp/go-build* /tmp/gocache* 2>/dev/null
  # tronca i log di output troppo grandi (i tool verbosi arrivano a GB)
  for lg in "$HOME/Desktop/Pipeline"/*.log; do
    [ -f "$lg" ] && [ "$(stat -c%s "$lg" 2>/dev/null || echo 0)" -gt 524288000 ] && : > "$lg"
  done
  LOG "disco dopo pulizia: $(disk_pct)%"
}

last_index() {
  python3 - "$1" <<'PY' 2>/dev/null || echo 0
import json,sys
try: print(int(json.load(open(sys.argv[1])).get("last_index",0)))
except Exception: print(0)
PY
}

stats_ok() {
  python3 - "$1" <<'PY' 2>/dev/null
import json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if isinstance(d,dict) and d else 1)
PY
}

snapshot_dir() {
  local src="$1"; [ -d "$src" ] || return
  local base; base="$(basename "$src")"
  mkdir -p "$BK/$base"
  # ESCLUDI node_modules e i repo clonati (dir con .git): sono transitori e
  # gonfiavano gli snapshot fino a decine di GB (era il vero mangia-disco).
  # Si salvano solo i RISULTATI (stats, servers.json, cartelle finding).
  local ex="--exclude=*/node_modules --exclude=*/.git" d
  for d in "$src"/*/; do
    [ -d "${d}.git" ] && ex="$ex --exclude=$base/$(basename "$d")"
  done
  tar czf "$BK/$base/$(date '+%Y%m%d_%H%M%S').tar.gz" $ex -C "$(dirname "$src")" "$base" 2>/dev/null
  ls -1t "$BK/$base"/*.tar.gz 2>/dev/null | tail -n +$((NKEEP+1)) | xargs -r rm -f
}

restore_dir() {
  local src="$1"; local base; base="$(basename "$src")"
  local latest; latest="$(ls -1t "$BK/$base"/*.tar.gz 2>/dev/null | head -1)"
  [ -n "$latest" ] || { LOG "NESSUNO snapshot per $base"; return; }
  LOG "RIPRISTINO $base da $latest"
  tar xzf "$latest" -C "$(dirname "$src")" 2>/dev/null
}

if [ ! -f "$TASKS" ]; then LOG "manca $TASKS, esco"; exit 1; fi
LOG "guardian avviato. Attesa iniziale ${GRACE}s (i tool sono già stati lanciati). Task:"
cat "$TASKS" | sed 's/^/    /'
sleep "$GRACE"

cycle=0
while true; do
  cycle=$((cycle+1))
  all_done=1

  while IFS=$'\t' read -r name pat cwd stats floor end script log env; do
    [ -z "$name" ] && continue
    stats_e="$(eval echo "$stats")"; dir_e="$(dirname "$stats_e")"
    # pulizia cloni orfani, SOLO nelle cwd dei worker (tool_*_wN)
    cwd_e="$(eval echo "$cwd")"
    case "$cwd_e" in *tool_*_w[0-9]*) clean_orphans "$cwd_e" ;; esac
    # integrità: ripristina se la cartella/stats è SPARITA o corrotta.
    # (dopo il grace period, uno stats assente = cartella cancellata -> auto-restore
    #  dall'ultimo snapshot, così un incidente tipo-VM1 si ripara da solo).
    if [ ! -e "$stats_e" ]; then
      LOG "stats di '$name' ASSENTE (cartella sparita?) -> ripristino da snapshot"
      restore_dir "$dir_e"
    elif ! stats_ok "$stats_e"; then
      LOG "stats di '$name' corrotto -> ripristino"; restore_dir "$dir_e"
    fi
    li="$(last_index "$stats_e")"
    if [ "${li:-0}" -ge "${end:-0}" ] 2>/dev/null; then continue; fi
    all_done=0
    if ! is_running "$pat"; then
      st=$floor; [ "${li:-0}" -gt "${floor:-0}" ] 2>/dev/null && st=$li
      cwd_e="$(eval echo "$cwd")"; script_e="$(eval echo "$script")"; log_e="$(eval echo "$log")"
      env_e="$(eval echo "$env")"; exp=""; [ -n "$env_e" ] && exp="export $env_e && "
      LOG "task '$name' fermo (idx=$li, floor=$floor) -> RESUME da $st"
      bash -lc "cd '$cwd_e' && source \$HOME/pipeline-env/bin/activate && ${exp}setsid nohup python '$script_e' --start $st --end $end > '$log_e' 2>&1 < /dev/null &"
      sleep 3
    fi
  done < "$TASKS"

  pct="$(disk_pct)"
  if [ -n "$pct" ] && [ "$pct" -ge "$DISK_THRESHOLD" ] 2>/dev/null; then clean_caches; fi

  if [ $((cycle % SNAP_EVERY)) -eq 0 ]; then
    while IFS=$'\t' read -r name pat cwd stats floor end script log env; do
      [ -z "$name" ] && continue
      stats_e="$(eval echo "$stats")"
      [ -f "$stats_e" ] && stats_ok "$stats_e" && snapshot_dir "$(dirname "$stats_e")"
    done < "$TASKS"
  fi

  if [ "$all_done" -eq 1 ]; then
    LOG "TUTTI i task completi. Snapshot finale e uscita."
    while IFS=$'\t' read -r name pat cwd stats floor end script log env; do
      [ -z "$name" ] && continue
      stats_e="$(eval echo "$stats")"; snapshot_dir "$(dirname "$stats_e")"
    done < "$TASKS"
    break
  fi
  sleep "$SLEEP"
done
LOG "guardian terminato."
