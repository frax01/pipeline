# Confronto definitivo — prima analisi vs rirun, stesse 17 categorie

Confermato = **VP-C + VP-D** (sfruttabile). I VP-L (capability dichiarata,
non sfruttabile) contano come non confermati, come nella prima analisi.

| categoria | VP prima | conf. prima | VP rirun | conf. rirun | Δ |
|---|---:|---:|---:|---:|---:|
| Protocol violation | 15,436 | 60% | 10,900 | 63% | +3 |
| Dangerous capabilities | 3,745 | 67% | 3,294 | 28% | -39 |
| SQL injection | 2,406 | 53% | 2,638 | 7% | -47 |
| Sensitive info disclosure | 1,873 | 100% | 2,224 | 42% | -58 |
| Credential leak | 1,342 | 94% | 1,601 | 72% | -22 |
| Untrusted content | 952 | 100% | 952 | 93% | -7 |
| SSRF | 741 | 53% | 896 | 33% | -20 |
| Path traversal | 537 | 33% | 687 | 56% | +23 |
| Command injection | 274 | 27% | 371 | 68% | +41 |
| Code injection | 220 | 43% | 257 | 19% | -24 |
| Input validation | 254 | 42% | 171 | 20% | -22 |
| Prompt injection | 118 | 81% | 129 | 54% | -27 |
| Insecure deserialization | 31 | 93% | 83 | 40% | -53 |
| Access control | 8 | 25% | 9 | 29% | +4 |
| Sensitive file access | 18 | 39% | 5 | 0% | -39 |
| Data exfiltration | 2 | 100% | 2 | 100% | +0 |
| Tool shadowing | 1 | 100% | 2 | 50% | -50 |
| **TOTALE** | **27,958** | **64.8%** | **24,221** | **49.7%** | **-15.1** |

VP realmente sfruttabili stimati: prima ~18,111, rirun ~12,042.
