#!/bin/bash
# Pull partial results from all VMs into a local folder and merge them
# Usage: bash pull_partial_results.sh [output_folder_name]
#   default output folder: partial_results_YYYYMMDD_HHMM

set -e

TIMESTAMP=$(date +%Y%m%d_%H%M)
OUTPUT_DIR="${1:-partial_results_${TIMESTAMP}}"
PIPELINE_REMOTE="~/Desktop/Pipeline"

# VM definitions: ip, label, shard_start, shard_end
VMS=(
  "10.79.6.132 vm1_132 0 6689"
  "10.79.6.133 vm2_133 6689 13378"
  "10.79.6.134 vm3_134 13378 20067"
  "10.79.6.136 vm4_136 20067 26756"
  "10.79.6.137 vm5_137 26756 33445"
  "10.79.6.138 vm6_138 33445 40134"
  "10.79.6.139 vm7_139 40134 46823"
  "10.79.6.141 vm8_141 46823 53512"
  "10.79.6.142 vm9_142 53512 60205"
)

# Tools to pull (remote_dir  local_name)
TOOLS=(
  "tool_mcp_guard    mcp_guard"
  "tool_mcp_check    mcp_check"
  "tool_mcp_shield   mcp_shield"
  "tool_mcp_scan     mcp_scan"
  "tool_mcp_security_scan mcp_security_scan"
  "tool_mcp_watch    mcp_watch"
)

echo "============================================"
echo "  Pull partial results from all VMs"
echo "  Output: $OUTPUT_DIR"
echo "============================================"

mkdir -p "$OUTPUT_DIR"

# ──────────────────────────────────────────────
# STEP 1: Pull data from each VM
# ──────────────────────────────────────────────
for vm_line in "${VMS[@]}"; do
  read -r IP LABEL SHARD_START SHARD_END <<< "$vm_line"
  echo ""
  echo "=== $LABEL ($IP) - shard $SHARD_START-$SHARD_END ==="

  # Test SSH connectivity
  if ! ssh -o ConnectTimeout=8 -o BatchMode=yes "tecnico@$IP" "echo ok" &>/dev/null; then
    echo "  SKIP: SSH connection failed"
    continue
  fi

  for tool_line in "${TOOLS[@]}"; do
    read -r TOOL_DIR TOOL_NAME <<< "$tool_line"
    LOCAL_DIR="$OUTPUT_DIR/$TOOL_NAME/$LABEL"
    mkdir -p "$LOCAL_DIR"

    echo "  Pulling $TOOL_NAME..."

    # Pull servers.json and stats.json
    scp -o ConnectTimeout=8 -q \
      "tecnico@$IP:$PIPELINE_REMOTE/$TOOL_DIR/${TOOL_NAME}_servers.json" \
      "$LOCAL_DIR/" 2>/dev/null || echo "    warn: ${TOOL_NAME}_servers.json not found"

    scp -o ConnectTimeout=8 -q \
      "tecnico@$IP:$PIPELINE_REMOTE/$TOOL_DIR/${TOOL_NAME}_stats.json" \
      "$LOCAL_DIR/" 2>/dev/null || echo "    warn: ${TOOL_NAME}_stats.json not found"

    # Discover and pull ALL subdirectories with JSON files
    SUBDIRS=$(ssh -o ConnectTimeout=8 "tecnico@$IP" \
      "find $PIPELINE_REMOTE/$TOOL_DIR -mindepth 1 -maxdepth 1 -type d -exec basename {} \;" 2>/dev/null || echo "")

    for subdir in $SUBDIRS; do
      case "$subdir" in
        __pycache__|.git|node_modules) continue ;;
      esac

      FILE_COUNT=$(ssh -o ConnectTimeout=8 "tecnico@$IP" \
        "ls $PIPELINE_REMOTE/$TOOL_DIR/$subdir/*.json 2>/dev/null | wc -l" 2>/dev/null || echo "0")

      if [ "$FILE_COUNT" -gt 0 ]; then
        mkdir -p "$LOCAL_DIR/$subdir"
        echo "    $subdir: $FILE_COUNT files"
        scp -o ConnectTimeout=8 -q \
          "tecnico@$IP:$PIPELINE_REMOTE/$TOOL_DIR/$subdir/*.json" \
          "$LOCAL_DIR/$subdir/" 2>/dev/null || echo "    warn: $subdir copy failed"
      fi
    done
  done

  echo "  Done."
done

# ──────────────────────────────────────────────
# STEP 2: Merge all VM data per tool
# ──────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Merging results..."
echo "============================================"

python3 - "$OUTPUT_DIR" <<'MERGE_SCRIPT'
import json, sys, os
from pathlib import Path
from collections import defaultdict

output_dir = Path(sys.argv[1])

# Find all tool directories
tool_dirs = sorted([d for d in output_dir.iterdir() if d.is_dir()])

for tool_dir in tool_dirs:
    tool_name = tool_dir.name
    merged_dir = tool_dir / "merged"
    merged_dir.mkdir(exist_ok=True)

    vm_dirs = sorted([d for d in tool_dir.iterdir() if d.is_dir() and d.name.startswith("vm")])
    if not vm_dirs:
        continue

    print(f"\n--- Merging {tool_name} ({len(vm_dirs)} VMs) ---")

    # ── Merge servers.json (dict {url: result}) ──
    merged_servers = {}
    for vm_dir in vm_dirs:
        servers_file = vm_dir / f"{tool_name}_servers.json"
        if servers_file.exists():
            try:
                data = json.loads(servers_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    merged_servers.update(data)
            except Exception as e:
                print(f"  warn: {servers_file}: {e}")

    if merged_servers:
        out = merged_dir / f"{tool_name}_servers_merged.json"
        out.write_text(json.dumps(merged_servers, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  {out.name}: {len(merged_servers)} servers")

    # ── Merge stats.json (aggregate) ──
    merged_stats = {"last_index_per_vm": {}, "total": 0}
    for vm_dir in vm_dirs:
        stats_file = vm_dir / f"{tool_name}_stats.json"
        if stats_file.exists():
            try:
                data = json.loads(stats_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    merged_stats["last_index_per_vm"][vm_dir.name] = data.get("last_index", 0)
                    merged_stats["total"] += data.get("total", 0)
                    # Copy all other top-level keys (first vm wins for structure)
                    for k, v in data.items():
                        if k not in ("last_index", "total") and k not in merged_stats:
                            merged_stats[k] = v
            except Exception as e:
                print(f"  warn: {stats_file}: {e}")

    if merged_stats["total"] > 0 or merged_stats["last_index_per_vm"]:
        out = merged_dir / f"{tool_name}_stats_merged.json"
        out.write_text(json.dumps(merged_stats, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  {out.name}: total={merged_stats['total']}")

    # ── Merge vulnerability subdirectories ──
    # Collect all subdirectory names across all VMs
    all_subdirs = set()
    for vm_dir in vm_dirs:
        for sub in vm_dir.iterdir():
            if sub.is_dir():
                all_subdirs.add(sub.name)

    for subdir_name in sorted(all_subdirs):
        sub_merged_dir = merged_dir / subdir_name
        sub_merged_dir.mkdir(exist_ok=True)

        # Collect all JSON files in this subdir across VMs
        # Group by filename (e.g. hidden_instructions_HIGH.json)
        files_by_name = defaultdict(list)
        for vm_dir in vm_dirs:
            sub_path = vm_dir / subdir_name
            if sub_path.is_dir():
                for f in sub_path.glob("*.json"):
                    files_by_name[f.name].append(f)

        for filename, file_list in sorted(files_by_name.items()):
            # Merge: each file has {"total": N, "findings": [...]}
            merged_total = 0
            merged_findings = []

            for f in file_list:
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        merged_total += data.get("total", 0)
                        findings = data.get("findings", [])
                        if isinstance(findings, list):
                            merged_findings.extend(findings)
                    elif isinstance(data, list):
                        # Some files might be plain arrays
                        merged_findings.extend(data)
                        merged_total += len(data)
                except Exception as e:
                    print(f"    warn: {f}: {e}")

            merged_data = {
                "total": merged_total,
                "findings": merged_findings
            }

            out = sub_merged_dir / filename
            out.write_text(json.dumps(merged_data, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"  {subdir_name}/{filename}: {merged_total} findings")

print("\n============================================")
print("  Merge complete!")
print("============================================")
MERGE_SCRIPT

# ──────────────────────────────────────────────
# STEP 3: Quick summary
# ──────────────────────────────────────────────
echo ""
echo "=== Quick summary ==="
for tool_line in "${TOOLS[@]}"; do
  read -r TOOL_DIR TOOL_NAME <<< "$tool_line"
  echo ""
  echo "--- $TOOL_NAME ---"
  for vm_line in "${VMS[@]}"; do
    read -r IP LABEL SHARD_START SHARD_END <<< "$vm_line"
    STATS_FILE="$OUTPUT_DIR/$TOOL_NAME/$LABEL/${TOOL_NAME}_stats.json"
    if [ -f "$STATS_FILE" ]; then
      LAST_IDX=$(python3 -c "import json; d=json.load(open('$STATS_FILE')); print(d.get('last_index', '?'))" 2>/dev/null || echo "?")
      TOTAL=$(python3 -c "import json; d=json.load(open('$STATS_FILE')); print(d.get('total', '?'))" 2>/dev/null || echo "?")
      echo "  $LABEL: last_index=$LAST_IDX total=$TOTAL (shard $SHARD_START-$SHARD_END)"
    else
      echo "  $LABEL: no stats"
    fi
  done
done

echo ""
echo "Results in: $OUTPUT_DIR/"
echo "Merged data in: $OUTPUT_DIR/<tool>/merged/"
