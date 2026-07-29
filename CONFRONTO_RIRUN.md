# Confronto Veri Positivi — prima analisi vs rirun

- prima analisi : `C:\Users\francesco\Desktop\pipeline_DATI_BACKUP\analysisAllData`
- rirun         : `C:\Users\francesco\Desktop\pipeline` (*/postprocessing/)

> La prima analisi copriva 60.205 server GitHub + una run NPX separata poi unita;
> la rirun ha coperto i 69.104 del dataset unico in un'unica passata.

## Per tool

| tool | VP prima | VP rirun | delta | server prima | server rirun | delta |
|------|---------:|---------:|------:|-------------:|-------------:|------:|
| guard | 6,010 | 7,386 | +1,376 | 2,141 | 2,375 | +234 |
| watch | 1,166 | 2,011 | +845 | 650 | 674 | +24 |
| fuzzing | 13 | 47 | +34 | 4 | 9 | +5 |
| scan | 4,396 | 4,396 | +0 | 2,809 | 2,809 | +0 |
| shield | 16 | 21 | +5 | 7 | 11 | +4 |
| security_scan | 1,374 | 651 | -723 | 1,324 | 651 | -673 |
| check | 14,983 | 10,500 | -4,483 | 8,310 | 6,088 | -2,222 |
| **totale** | **27,958** | **25,012** | **-2,946** | **11,841** | **11,487** | **-354** |

## Per server (unione di tutti i tool)

- confermati in entrambe : **8,764**
- solo prima analisi     : **3,077**
- solo rirun             : **2,723**
- concordanza (Jaccard)  : 60.2%

Esempi di server trovati **solo dalla rirun** (primi 15):
  - 01koushal/skills-integrate-mcp-with-copilot
  - 0brym/mcp
  - 0xEVom/clarify-mcp
  - 0xHumban/perplexity-mcp
  - 0xMikeAdams/wpmcp
  - 0xdaef0f/job-searchoor
  - 0xgordian/mcp-github-client
  - 0xhackerfren/Pcap-Analysis-MCP
  - 0xikarus/linear-kanban-mcp
  - 0xintuition/research-mcp
  - 0xjcf/MCP_CodeAnalysis
  - 14ag/systeminternals-mcp
  - 15972289829/mcp
  - 167AliRaza/MCP-Demo
  - 18896101294/my-appflowy-mcp

Esempi di server trovati **solo dalla prima analisi** (primi 15):
  - 0nork/0nMCP
  - 0xCJT/TemplonixLite
  - 0xkoda/mcp-rust-docs
  - 0xquinto/rss-mcp
  - 1018053166/stock-mcp-server
  - 1049861657/MCP
  - 199-biotechnologies/engram
  - 199-mcp/mcp-autostarter
  - 1999AZZAR/wikipedia-mcp-server
  - 23021813/sample-mcp-server
  - 611711Dark/mcp_calculate_server
  - 7gugu/whistle-mcp
  - 8LWXpg/mcp-server-sqlite
  - 99byte/harmony-tools
  - @actionbookdev/mcp

## Per categoria

### guard

| categoria | VP prima | VP rirun | delta |
|-----------|---------:|---------:|------:|
| code-injection-fuzzing | 36 | 35 | -1 |
| code-injection-static | 184 | 222 | +38 |
| command-execution-fuzzing | 2 | 78 | +76 |
| command-injection-fuzzing | 246 | 267 | +21 |
| command-injection-static | 26 | 26 | +0 |
| dangerous-tool-handler-static | 1,017 | 1,155 | +138 |
| hardcoded-credential-static | 677 | 949 | +272 |
| information-disclosure-fuzzing | 7 | 279 | +272 |
| insecure-deserialization-static | 31 | 83 | +52 |
| path-traversal-fuzzing | 507 | 541 | +34 |
| path-traversal-static | 23 | 146 | +123 |
| prompt-injection-static | 16 | 17 | +1 |
| protocol-information-disclosure | 6 | 4 | -2 |
| protocol-invalid-jsonrpc-version | 77 | 4 | -73 |
| protocol-missing-id | 0 | 0 | +0 |
| protocol-path-traversal | 6 | 1 | -5 |
| sensitive-info-disclosed-fuzzing | 2 | 45 | +43 |
| sql-injection-static | 2,406 | 2,638 | +232 |
| ssrf-static | 741 | 896 | +155 |

### watch

| categoria | VP prima | VP rirun | delta |
|-----------|---------:|---------:|------:|
| access-control | 7 | 10 | +3 |
| credential-leak | 665 | 1,176 | +511 |
| data-exfiltration | 2 | 4 | +2 |
| input-validation | 135 | 318 | +183 |
| prompt-injection | 0 | 0 | +0 |
| protocol-violation | 357 | 499 | +142 |
| steganographic-attack | 0 | 4 | +4 |
| tool-mutation | 0 | 0 | +0 |
| tool-poisoning | 0 | 0 | +0 |

### fuzzing

| categoria | VP prima | VP rirun | delta |
|-----------|---------:|---------:|------:|
| protocol-fuzzing | 0 | 0 | +0 |
| tool-crash-dos | 7 | 5 | -2 |
| tool-error-disclosure | 6 | 42 | +36 |
| tool-input-accepted | 0 | 0 | +0 |

### scan

| categoria | VP prima | VP rirun | delta |
|-----------|---------:|---------:|------:|
| server-level/W015 | 952 | 952 | +0 |
| server-level/W017_npx | 976 | 976 | +0 |
| server-level/W018_npx | 882 | 882 | +0 |
| server-level/W019_npx | 682 | 682 | +0 |
| server-level/W020_npx | 806 | 806 | +0 |
| tool-level/E001 | 98 | 98 | +0 |

### shield

| categoria | VP prima | VP rirun | delta |
|-----------|---------:|---------:|------:|
| hidden-instructions | 4 | 14 | +10 |
| potential-exfiltration | 0 | 0 | +0 |
| sensitive-file-access | 11 | 5 | -6 |
| shadowing-detected | 1 | 2 | +1 |

### security_scan

| categoria | VP prima | VP rirun | delta |
|-----------|---------:|---------:|------:|
| dangerous-capabilities | 1,240 | 651 | -589 |
| data-leak | 0 | 0 | +0 |
| indirect-prompt-injection | 0 | 0 | +0 |
| input-validation | 119 | 0 | -119 |
| path-traversal | 7 | 0 | -7 |
| prompt-injection | 0 | 0 | +0 |
| remote-access-control | 1 | 0 | -1 |
| rug-pull | 0 | 0 | +0 |
| sensitive-file-access | 7 | 0 | -7 |
| sensitive-resource-exposure | 0 | 0 | +0 |

### check

| categoria | VP prima | VP rirun | delta |
|-----------|---------:|---------:|------:|
| handshake/invalid_arguments | 2 | 0 | -2 |
| handshake/method_not_found | 449 | 327 | -122 |
| handshake/other_errors | 138 | 96 | -42 |
| handshake/schema_violation | 103 | 51 | -52 |
| handshake/unauthorized_or_auth_missing | 0 | 0 | +0 |
| tool_discovery/method_not_found | 67 | 54 | -13 |
| tool_discovery/other_errors | 42 | 44 | +2 |
| tool_discovery/schema_violation | 313 | 275 | -38 |
| tool_discovery/warnings | 649 | 435 | -214 |
| tool_invocation/invalid_arguments | 92 | 46 | -46 |
| tool_invocation/method_not_found | 77 | 70 | -7 |
| tool_invocation/other_errors | 5,546 | 3,689 | -1,857 |
| tool_invocation/panic_or_crash | 4 | 0 | -4 |
| tool_invocation/schema_violation | 7,501 | 5,413 | -2,088 |
| tool_invocation/unauthorized_or_auth_missing | 0 | 0 | +0 |
| tool_invocation/warnings | 0 | 0 | +0 |
