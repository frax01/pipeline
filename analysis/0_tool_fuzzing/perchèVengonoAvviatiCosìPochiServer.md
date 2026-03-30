Perché il Fuzzer Ha Avviato Così Pochi Server Rispetto a mcp-check e mcp-scan (o altri)
I numeri a confronto
Tool	Server testati	% su 60.200	Node.js	Python	Go
mcp-check	34.404	57,14%	20.303	13.017	1.084
mcp-scan	10.710	17,79%	7.566	2.493	418
mcp-fuzzer	6.035	10,02%	5.686	35	314
Il dato più eclatante: Python — mcp-check testa 13.017 server Python, mcp-fuzzer ne fuzza solo 35. Ma anche Node.js ha un gap enorme: 20.303 vs 5.686 (28% di quanto raggiunge mcp-check).

Causa 1: Architettura di Lancio Radicalmente Diversa
Le tre tool hanno la stessa fase di preparazione (clone → detect language → build_mcp_config()) ma divergono completamente nel modo in cui avviano e comunicano con il server MCP.

mcp-check: tool esterna che gestisce tutto internamente
Il pipeline genera un test-config.json con comando e argomenti separati, poi delega tutto a mcp-check (tool Node.js esterna):

# mcpCheck.py:108-141
def generate_mcp_check_config(repo_path, command, main_file):
    config = {
        "target": {
            "type": "stdio",
            "command": target_command,      # "node"
            "args": target_args             # ["/full/path/to/file.js"]
        },
        "reporting": {
            "formats": ["json"],
            "outputDir": str(MCP_CHECK_DIR / "reports")
        }
    }
    # Scrive test-config.json

# mcpCheck.py:244-259
cmd = [
    "node",
    str(MCP_CHECK_DIR / "bin" / "mcp-check.js"),
    "test",
    "--config", str(config_path)
]
stdout, stderr, elapsed, code = run_process(
    cmd=cmd, cwd=MCP_CHECK_DIR, timeout=TIMEOUT_SECONDS, ...
)

mcp-check internamente usa il @modelcontextprotocol/sdk ufficiale Node.js con StdioClientTransport. L'SDK gestisce:

Spawn del processo figlio con command + args separati (niente parsing di stringhe)
Handshake MCP initialize → initialized standard
Negoziazione capabilities
Gestione errori e timeout integrata
Il pipeline lancia un solo processo (node mcp-check.js) che a sua volta spawna il server. Struttura piatta.

mcp-fuzzer: trasporto custom Python con endpoint stringa singola
Il pipeline chiama mcp-fuzzer come subprocess, che a sua volta spawna il server MCP come sotto-sotto-processo:

# fuzzing.py:258-335
def execute_mcp_fuzzing(path, command, elem, mode="all"):
    endpoint = f"{command} {elem}"     # ← STRINGA UNICA: "node file.js"
    cmd = [
        "mcp-fuzzer",
        "--mode", mode,
        "--phase", "both",
        "--protocol", "stdio",
        "--endpoint", endpoint,        # ← passa come singolo argomento
        "--runs", "10",
        "--runs-per-type", "10",
        "--timeout", "60",
        "--watchdog-process-timeout", "45",
        "--watchdog-max-hang-time", "90",
        "--process-retry-count", "3",
    ]
    output = subprocess.run(cmd, cwd=str(path), timeout=300, ...)

All'interno del fuzzer, lo StdioDriver riceve l'endpoint come stringa singola e la parsa con shlex.split():

# stdio_driver.py:128-147
if isinstance(self.command, str):
    cmd_parts = shlex.split(self.command)   # "node file.js" → ["node", "file.js"]
else:
    cmd_parts = self.command

self.process = await asyncio.create_subprocess_exec(
    *cmd_parts,
    stdin=asyncio.subprocess.PIPE,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    env=sanitize_subprocess_env(),           # ← ambiente sanitizzato!
    ...
)

Struttura a tre livelli: pipeline → mcp-fuzzer (subprocess) → server MCP (async subprocess).

Causa 2: shlex.split() vs command + args separati
Questa è la differenza tecnica più critica.

mcp-check riceve dal config JSON:

{"command": "node", "args": ["/home/user/repos/server-name/dist/index.js"]}

L'SDK Node.js usa child_process.spawn("node", ["/home/user/repos/server-name/dist/index.js"]) — nessun parsing, argomenti esatti.

mcp-fuzzer riceve una stringa:

--endpoint "node /home/user/repos/server-name/dist/index.js"

E la parsa con shlex.split() (stdio_driver.py:130). Questo fallisce su:

Path con spazi: "node /home/user/my repos/server/index.js" → split errato
Comandi complessi: "uvx --from package-name server" → potenziale errore
Path Windows: "node C:\Users\user\server\index.js" → backslash problematici
Comandi con env vars: "NODE_ENV=production node server.js" → non gestito
Causa 3: sanitize_subprocess_env() vs ambiente nativo
Il fuzzer usa un ambiente sanitizzato per il processo figlio:

# stdio_driver.py:140
env=sanitize_subprocess_env(),

Questo rimuove o filtra variabili d'ambiente che potrebbero essere necessarie per far partire il server (PATH custom, NODE_PATH, PYTHONPATH, virtual env, Go module paths, ecc.).

mcp-check invece passa l'ambiente completo del processo padre, perché l'SDK Node.js non applica sanitizzazione dell'ambiente.

Per i server Python questo è devastante: molti server richiedono un virtual environment attivo (VIRTUAL_ENV, PATH modificato) o variabili come PYTHONPATH. Il fuzzer le rimuove → il server non parte → 35 su 14.790.

Causa 4: Budget di Timeout Completamente Diverso
Parametro	mcp-check	mcp-fuzzer
Timeout per server (pipeline)	600s (10 min)	300s (5 min)
Timeout subprocess (tool)	TIMEOUT_SECONDS	300s (mode all)
Operazioni per server	~20-30 test	10×N tools + 10×17 protocolli
Watchdog	Nessuno	45s process-timeout
mcp-check esegue ~20-30 test case (handshake, tool-discovery, tool-invocation). Il fuzzer deve completare potenzialmente centinaia di operazioni:

Se un server ha 10 tool: 10 tool × 10 run × 2 fasi = 200 run tool
Più: 17 tipi protocollo × 10 run = 170 run protocollo
Totale: ~370 operazioni da completare in 300 secondi
Il watchdog (--watchdog-process-timeout 45) è particolarmente aggressivo: se il server non risponde entro 45 secondi a una qualsiasi richiesta, viene killato e il fuzzing fallisce.

# stdio_driver.py:62-68
watchdog_config = WatchdogConfig(
    check_interval=1.0,
    process_timeout=self.timeout,         # 45s
    extra_buffer=5.0,
    max_hang_time=self.timeout + 10.0,    # 55s
    auto_kill=True,                       # ← kill automatico!
)

Causa 5: Il Fuzzer Distrugge i Propri Server
Differenza fondamentale: mcp-check osserva, il fuzzer attacca.

mcp-check invia messaggi MCP standard e ben formati. Se il server risponde, anche con errore, il test procede. Il server rimane stabile durante tutta la sessione.

Il fuzzer invia payload intenzionalmente distruttivi nella fase aggressive:

# aggressive/protocol_type_strategy.py:164-177
def fuzz_initialize_request_aggressive():
    malicious_versions = [
        None, "", "999.999.999", "-1.0.0",
        "' OR '1'='1",                      # SQL injection
        "<script>alert('xss')</script>",     # XSS
        "../../../etc/passwd",               # Path traversal
        "A" * 1000,                          # Buffer overflow
        "\x00\x01\x02",                      # Null bytes
    ]

Questi payload possono crashare il processo server (specialmente buffer overflow e null bytes). Quando il server muore:

Lo StdioDriver rileva la pipe rotta
Tenta un restart con backoff (stdio_driver.py:117)
Ma il server ri-crasherà subito al prossimo payload aggressivo
Dopo N fallimenti, il fuzzer marca il server come fallito
Un server che sopravvive alle 20 test case di mcp-check può legittimamente crashare dopo 50 payload aggressivi del fuzzer.

Causa 6: Prerequisiti di Inizializzazione Diversi
mcp-check conta un server come "testato" se riesce a produrre qualsiasi risultato, anche se tutti i test falliscono. Se il handshake fallisce (32.343 pass su 59.806 = 54%), il server è comunque contato come testato.

mcp-fuzzer conta un server come "fuzzato" solo se:

Il processo parte con successo (StdioDriver init)
L'handshake MCP completa (initialize + initialized)
La chiamata tools/list restituisce almeno un tool (rpc_adapter.py:55)
Il fuzzing produce un report JSON valido
# rpc_adapter.py:55-87
async def get_tools(self):
    response = await self._transport.send_request("tools/list")
    if "tools" in response:
        tools = response["tools"]
    else:
        return []    # ← server contato come fallito, nessun tool = nessun fuzzing

Se tools/list fallisce o restituisce lista vuota, il server non ha nulla da fuzzare e non viene contato.

# fuzzing.py:344-348
report_path = find_latest_fuzzing_report(path)
if report_path is None:
    result["mcp-fuzzing"]["status"] = "skipped"    # ← non contato
    return result

Causa 7: Nesting dei Processi e Signal Handling
Pipeline (run_fuzzing.py)
  └─ subprocess.run(timeout=300)
      └─ mcp-fuzzer (processo Python asincrono)
          └─ asyncio.create_subprocess_exec()
              └─ server MCP (node/python/go)

Tre livelli di processi. Quando il timeout della pipeline scatta:

# run_fuzzing.py:342-343
if use_alarm:
    signal.alarm(SERVER_TIMEOUT)     # 300s SIGALRM

Il SIGALRM uccide mcp-fuzzer, che potrebbe non avere tempo di uccidere il server figlio (zombie processes). Il cleanup deve poi cercare e killare i processi orfani:

# fuzzing.py:8-77
def _kill_server_processes(server_command):
    # pgrep -f server_command → kill matching PIDs
    result = subprocess.run(["pgrep", "-f", server_command], ...)
    for pid in result.stdout.strip().split("\n"):
        os.kill(pid, 9)

Con mcp-check il nesting è di soli due livelli (pipeline → mcp-check, che gestisce il server internamente), e l'SDK Node.js ha gestione nativa del cleanup dei processi figli.

Sintesi: Tabella Comparativa Completa
Aspetto	mcp-check	mcp-fuzzer
Avvio server	SDK MCP Node.js (StdioClientTransport)	Custom Python StdioDriver
Formato comando	command + args[] separati (JSON)	Stringa singola parsata con shlex.split()
Ambiente processo	Ereditato dal padre (completo)	sanitize_subprocess_env() (filtrato)
Nesting processi	2 livelli	3 livelli
Timeout per server	600s	300s
Operazioni per server	~20-30 test	~250-400 run fuzzing
Watchdog	Nessuno	45s auto-kill
Tipo di input	Messaggi MCP validi	Payload distruttivi (SQL inj, XSS, overflow)
Criterio "testato"	Qualsiasi output prodotto	Report fuzzing completo con risultati
Effetto sul server	Non distruttivo	Può crashare il processo
Python servers	13.017 testati	35 fuzzati
Risultato	57,14% raggiungibilità	10,02% raggiungibilità
La differenza di fondo è architetturale: mcp-check è un osservatore gentile con trasporto battle-tested; mcp-fuzzer è un attaccante con trasporto custom che deve sopravvivere ai propri attacchi. Il gap del 47% tra i due è il costo combinato di un trasporto meno robusto, un ambiente sanitizzato troppo aggressivo, timeout più stretti, e la natura autodistruttiva del fuzzing aggressivo.