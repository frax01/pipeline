Riepilogo delle 3 fix:

1. Initialize con params corretti (stdio_scanner.py + sse_scanner.py)
# Prima: params vuoti
client.send_recv("initialize", {})

# Dopo: params completi secondo spec MCP
client.send_recv("initialize", {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "mcp-security-scanner", "version": "1.0.0"}
})

Questo elimina i falsi initialization-error dai server "strict" che rifiutavano la connessione per mancanza di protocolVersion.

2. PYTHONUNBUFFERED=1 nel subprocess (stdio_scanner.py)
I server Python scrivevano la risposta ma restava nel buffer stdout della pipe. Il client riceveva EOF → no_response → initialization-error falso.

3. shlex.split(posix=False) su Windows (stdio_scanner.py)
shlex.split mangiava i backslash nei path Windows, il file non veniva trovato e il processo moriva subito → initialization-error falso.

4. Non contare initialization-error come "completed" (pipeline mcpSecurityScan.py)
Se il server fallisce l'init, restituisce failure() invece di contare come server scansionato.

Le fix 2 e 3 riducono il numero reale di initialization-error (falsi positivi causati dal client). La fix 1 elimina i rifiuti dai server strict. La fix 4 rende oneste le statistiche escludendo i server che non si sono inizializzati.