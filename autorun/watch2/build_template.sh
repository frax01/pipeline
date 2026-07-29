#!/bin/bash
# build_template.sh — costruisce il template di sandbox watch da eseguire su VM2 (.133),
# che ha una sandbox watch funzionante e allineata al repo. Produce
# /home/tecnico/watch2/template.tar.gz con SOLO codice+framework+dataset (nessun risultato).
set -eu
SRC=/home/tecnico/gsafe_watch/w1
OUT=/home/tecnico/watch2/template.tar.gz
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

mkdir -p "$T/template/work/Pipeline/tool_mcp_watch_TMPL" "$T/template/home/Desktop/Frameworks"

# codice + dataset (niente risultati)
cp -a "$SRC/work/Pipeline/functions"   "$T/template/work/Pipeline/"
cp -a "$SRC/work/Pipeline/frameworks"  "$T/template/work/Pipeline/"
cp -a "$SRC/work/Pipeline/npm_runner"  "$T/template/work/Pipeline/"
cp -a "$SRC/work/Pipeline/"*.xlsx      "$T/template/work/Pipeline/"

# script del worker
cp -a "$SRC/work/Pipeline/tool_mcp_watch_w1/run_watch.py"   "$T/template/work/Pipeline/tool_mcp_watch_TMPL/"
cp -a "$SRC/work/Pipeline/tool_mcp_watch_w1/merge_stats.py" "$T/template/work/Pipeline/tool_mcp_watch_TMPL/" 2>/dev/null || true

# framework mcp-watch (progetto Node con node_modules)
cp -a "$SRC/home/Desktop/Frameworks/mcp-watch" "$T/template/home/Desktop/Frameworks/"

mkdir -p /home/tecnico/watch2
tar czf "$OUT" -C "$T" template
echo "template: $OUT ($(du -h "$OUT" | cut -f1))"
tar tzf "$OUT" | head -12
