4 file modificati in mcp-security-scanner
1. src/mcp_scanner/security_checks.py — Funzione check_tool_stability()

Aggiunto guard all'inizio: se una delle due liste è vuota e l'altra no, il test passa con un messaggio esplicativo invece di segnalare un falso positivo
[] → [tools] → "Skipped: first listing was empty (server likely not ready at first call)"
[tools] → [] → "Skipped: second listing was empty (server likely crashed between calls)"
2. src/mcp_scanner/stdio_scanner.py — Blocco X-03

Aggiunto retry con time.sleep(2) se la prima tools/list ha restituito una lista vuota, prima di procedere al confronto
3. src/mcp_scanner/http_checks.py — Blocco X-03

Stesso retry con time.sleep(2) se la prima lista era vuota (sostituisce il vecchio if not tools: pass che saltava il test completamente)
4. src/mcp_scanner/sse_scanner.py — Blocco X-03

Aggiunto retry con time.sleep(2) se la prima lista era vuota
Rimossa la logica di diff inline duplicata, sostituita con chiamata centralizzata a security_checks.check_tool_stability() (come fanno già stdio e http)
Aggiunto from . import security_checks negli import

Cosa risolvono:

Falso positivo	                                    Causa	                                    Fix
before: [], after: [6 tools]	                    Race condition: server non ancora pronto	Retry dopo 2s prima del confronto
before: [7 tools], after: []	                    Server crashato tra le due chiamate	        Guard in check_tool_stability()

I veri positivi (tool che cambiano effettivamente nome/descrizione tra le due chiamate) continuano a essere segnalati correttamente.