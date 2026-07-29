# Pipeline — Security Analysis of MCP Servers

Distributed pipeline for the security analysis of **69,104 MCP (Model Context
Protocol) servers** collected from GitHub (60,205) and npm/NPX (8,899). The
analysis is carried out with **7 tools** running in parallel on **9 VMs**,
followed by a triage and validation process that reduces millions of raw
findings to a set of actionable **true positives (TPs)**.

This repository contains the pipeline **code** (dataset collection, execution,
tool wrappers, post-processing, aggregation) and the
**documentation/results** in readable form. Raw datasets and heavy JSON outputs
(tens of GB) are archived separately — see [§ Data](#data).

## End-to-end pipeline

```
web_crawler/        collection of MCP server URLs from 17 public directories
      │
      ▼
hashAnalysis/       dedup by content hash  ──►  unified dataset (69,104)
      │
      ▼
deploy.py / launch.py    execution of the 7 tools on 9 VMs (one per VM)
      │                  (frameworks/ runs+parses, npm_runner/ builds the repos)
      ▼
<tool>/merge_stats.py    merge of the shards from the 9 VMs, for each tool
      │
      ▼
<tool>/postprocessing/   3-stage triage (regex filter → classifiers → merge)
      │
      ▼
cross_framework/    TP consensus across the 7 tools (Tier 1/2/3)
      │
      ▼
docs/               manual validation + final reports
```

## Documentation

| Document | Content |
|-----------|-----------|
| [docs/METHODOLOGY.md](docs/METHODOLOGY.md) | Architecture, the 7 tools, 3-stage triage workflow, cross-framework consensus |
| [docs/THREAT_ANALYSIS_REPORT.md](docs/THREAT_ANALYSIS_REPORT.md) | Full report of the results by threat category |
| [docs/MANUAL_AUDIT_REPORT.md](docs/MANUAL_AUDIT_REPORT.md) | Summary of the manual validation of the TPs against the real source code |
| [docs/MANUAL.md](docs/MANUAL.md) | Detailed manual verification tables by category (verdict for each server) |
| [docs/MANUAL_CHECKLIST.md](docs/MANUAL_CHECKLIST.md) | Checklist of the manual checks performed for each of the 17 categories |
| [docs/STATE_OF_THE_ART.md](docs/STATE_OF_THE_ART.md) | State of the art: academic papers reviewed for the thesis |
| [web_crawler/README.md](web_crawler/README.md) | Details of the dataset collection scrapers (17 sources) |

## Repository structure

```
pipeline/
├── README.md                     this file
├── deploy.py                     VM orchestrator (deploy / launch / pull / merge / status / tail)
├── launch.py                     local tool launcher (start / resume / status / kill)
├── pull_partial_results.sh       aggregation of partial results from the VMs
├── 0.0. All servers unified (69104).xlsx   unified input dataset
├── requirements.txt              Python dependencies
├── package.json / tsconfig.json  Node/TS project for the MCP SDK helper (frameworks/listTools.ts)
│
├── web_crawler/                  collection of MCP server URLs (17 scrapers + run_all.py) — see its README
├── hashAnalysis/                 dataset dedup by content hash
│   ├── hash_analyzer.py             clones each repo and computes the content hash
│   ├── remove_true_duplicates.py    removal of exact duplicates
│   ├── remove_from_excel.py         cleanup of the rows in the .xlsx dataset
│   ├── clean_slashes_and_git.py     URL normalization
│   └── vm/                          variants for execution on the VMs
│
├── functions/                    shared utilities
│   ├── config.py                    paths, commands, VMs, category maps (central config)
│   ├── helper.py                    process execution and generic helpers
│   ├── buildConfig.py               repo clone, MCP config build, ensure bun/npm
│   ├── hash.py / hashCache.py       content hashing (for the dedup)
│   ├── stats.py                     aggregation of the statistics per tool
│   └── recapFramework.py            per-server recap
│
├── frameworks/                   tool execution/parsing wrappers
│   ├── mcpGuard.py mcpWatch.py mcpScan.py mcpShield.py
│   ├── mcpSecurityScan.py mcpCheck.py fuzzing.py llmAnalysis.py
│   └── listTools.ts                 (TS) connects to an MCP server over stdio and lists its tools
│
├── npm_runner/                   build of the repos before the analysis (`npm run build`)
│   ├── npm_build.sh                 bash version (Linux/VM)
│   └── npm_build.ps1                PowerShell version (Windows)
│
├── monitorVM/                    monitor.py — terminal dashboard of the tool status on the 9 VMs
│
├── mcp_guard/             one tool — SAME structure for all 7:
│   ├── run_<tool>.py               execution (local or on VM)
│   ├── merge_stats.py              merge of the shards from the 9 VMs
│   ├── commands.md  howDoesItWork.md   tool docs (+ changes.md where present)
│   └── postprocessing/             results triage:
│       ├── stage1_filter.py            Stage 1 — regex filter
│       ├── stage2_pipeline.py          Stage 2A/2B + merge
│       ├── classifiers/                Stage 2B classifiers (per category)
│       └── special/                    scripts for specific purposes
├── mcp_watch/  fuzzing/  mcp_scan/  mcp_shield/  mcp_security_scan/  mcp_check/   (same)
│
├── cross_framework/      aggregation of the TPs across the 7 tools (Tier 1/2/3 consensus)
│   ├── cross_framework_consensus.py    main consensus
│   ├── _aggregate_threats.py           aggregation by threat category
│   ├── _verify_credleak.py             targeted verification of the credential leaks
│   ├── _find_missing.py                search for findings missing from the other tools
│   └── check_pt_fuzz.py                path-traversal vs fuzzing cross-check
│
└── docs/                 documentation and reports (see table above)
```

> The numeric prefix `NN_` of the scrapers in `web_crawler/` follows the
> numbering of the sources in the thesis. The scrapers are **17** but the sources
> are **18**: `17_npm.py` collects from the npm registry both the **npm** servers
> and the **npx-runnable** ones (they are npm packages, same scrape → sources 17
> and 18). `npm_runner/` is **not** a collection source: it is the build step
> (`npm run build`) used during the analysis phase.

## The 7 tools

| Tool | VM | What it detects |
|------|----|-------------|
| **mcp-guard** | VM1 | Path traversal, command/SQL/code injection, SSRF, credentials (SAST + fuzzing) |
| **mcp-watch** | VM2 | Hardcoded credentials, data exfiltration, protocol violations, tool poisoning |
| **tool_fuzzing** | VM3 | Crash/DoS, error disclosure, executed injection (malformed input) |
| **mcp-scan** | VM4 | Prompt injection, untrusted content, destructive capabilities |
| **mcp-shield** | VM5 | Hidden instructions / tool shadowing (LLM semantic analysis) |
| **mcp-security-scan** | VM6 | Dangerous capabilities, rug pull, access to sensitive files |
| **mcp-check** | VM7 | MCP protocol conformance |

VM8–VM9 host additional aggregation/validation roles (`scanorama`,
`validator`) — see the VM map in the docstring of [`deploy.py`](deploy.py).

## Quick start

```bash
pip install -r requirements.txt
npm install                 # only if the TypeScript helper frameworks/listTools.ts (MCP SDK) is needed
# The 7 scanning frameworks are installed separately (see the commands.md of each tool).
```

Every entry point supports `--help`. There is **no** single command that runs
the whole analysis (69,104 servers × 7 tools): it is distributed over 9 VMs per
project. Recommended path:

```bash
# 0. (optional) rebuild the dataset from the public MCP directories
python web_crawler/run_all.py             # --list, --only, --skip ; see web_crawler/README.md
#    then dedup to obtain the unified dataset (e.g.):
python hashAnalysis/hash_analyzer.py
python hashAnalysis/remove_true_duplicates.py

# 1. try ONE tool locally on a few servers (works anywhere, Windows included)
python launch.py scan --start 0           # or: python mcp_scan/run_scan.py --start 0 --end 20

# 2. full distributed execution, orchestrated by deploy.py
python deploy.py --help                   # deploy / launch / pull / merge / status / tail
python deploy.py --status                 # tool status on all the VMs
#    the exact commands for each tool are in <tool>/commands.md

# 3. monitor the progress on the VMs
python monitorVM/monitor.py

# 4. post-processing / 3-stage triage (for each tool)
python mcp_guard/postprocessing/stage1_filter.py
python mcp_guard/postprocessing/stage2_pipeline.py --category all --merge

# 5. cross-tool consensus of the TPs
python cross_framework/cross_framework_consensus.py
```

The configuration parameters (dataset path, framework directories, commands, VM
addresses) are centralized in
[`functions/config.py`](functions/config.py).

## Data

To keep the repository light and clean, the following are **not** versioned:
the raw pulls from the VMs, the scanner JSON outputs, the per-source `.xlsx`
files of `web_crawler/` and the post-processing intermediates (tens of GB). What
remains is the **code** that produces them and the readable **reports**. To
re-run the `stage2_pipeline.py` scripts in `*/postprocessing/` the raw data must
be restored.

> Note on the published data: the values of the third-party credentials that
> emerged as *findings* of the analysis are **masked** (placeholders) in the
> versioned reports and in the `.xlsx` dataset.

## Results in brief

After the 3-stage triage and the manual validation, the analysis produces the
set of true positives by threat category (SQL injection, credential leak, SSRF,
prompt injection, command/code injection, dangerous capabilities, untrusted
content, etc.). The full detail is in
[docs/THREAT_ANALYSIS_REPORT.md](docs/THREAT_ANALYSIS_REPORT.md), the summary of
the manual validation in [docs/MANUAL_AUDIT_REPORT.md](docs/MANUAL_AUDIT_REPORT.md)
and the detailed per-category tables in [docs/MANUAL.md](docs/MANUAL.md).
