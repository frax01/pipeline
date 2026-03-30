# MCP Guard Commands

## Deployment and Execution (All 9 VMs)
```bash
# Deploy essential files to all 9 VMs
python deploy.py --deploy-guard-all

# Launch on all VMs (ranges are handled by deploy.py)
python deploy.py --launch-guard-all
```

## Results Collection and Analysis
```bash
# Pull all results (including category folders) from all VMs
python deploy.py --pull-guard

# Merge all results into analysisAllData/0_tool_mcp_guard/
python deploy.py --merge-guard
```

## Monitoring
```bash
# Status summary across all VMs
python deploy.py --status-guard

# Tail logs from all VMs
python deploy.py --tail-guard

# Local monitoring of stats
watch -n 5 'cat analysis/0_tool_mcp_guard/mcp_guard_stats.json | python3 -m json.tool'
```