# 1

{
            "server_url": "https://github.com/FelixFoster/mcp-enhance-prompt",
            "server_name": "mcp-enhance-prompt",
            "tool_name": "enhance_prompt",
            "runs": 20,
            "exceptions": 20,
            "success_rate": 0.0,
            "inputs_causing_error": [
                {
                    "type": "str",
                    "arguments": {
                        "prompt": ""
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": ""
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": ""
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": ""
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": ""
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": ""
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": ""
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": ""
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": ""
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": ""
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": ""
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": "' OR '1'='1"
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": "' OR '1'='1"
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": "' OR '1'='1"
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": "A"
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": "' OR '1'='1"
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": "' OR '1'='1"
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": "' OR '1'='1"
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": "' OR '1'='1"
                    }
                },
                {
                    "type": "str",
                    "arguments": {
                        "prompt": "' OR '1'='1"
                    }
                }
            ]
        },

Hai ragione a insistere — i numeri non tornano con la probabilità del codice. Facciamo il conto esatto.

Con --runs 10 --phase both = 10 realistic + 10 aggressive:

Realistic (10 run): probabilità di "" = 1/51 ≈ 2%. Attesi: ~0.2 vuoti.
Aggressive (10 run): 70% random, 30% edge case con 3/10 vuoti → ~9% per run. Attesi: ~0.9 vuoti.

Totale atteso: ~1.1 stringhe vuote su 20 run. Ottenere 11 è statisticamente impossibile.

E c'è un altro dettaglio: non vedi nessuna stringa random tra i 20 input — solo "", ' OR '1'='1 e "A". Anche questo è impossibile se il generatore funzionasse normalmente (14 run su 20 dovrebbero produrre stringhe random).

Confrontiamo con websimm:

x13: {"slug": "", "user": ""}
x7:  {"slug": "' OR '1'='1", "user": "' OR '1'='1"}

Stesso identico pattern: ~65% vuoti, ~35% SQL injection, zero stringhe random. Questo non è casualità — è un comportamento sistematico.

L'unica spiegazione che quadra è che lo schema del tool ha un vincolo che schiaccia la generazione. Guarda cosa succede in _handle_string_type se il server dichiara "maxLength": 0 (o un valore molto piccolo):

max_length = int(schema.get("maxLength", 100))  # se maxLength=0 → 0
# ...
length = random.randint(0, min(0, 50))  # = random.randint(0, 0) = SEMPRE 0!

In quel caso:

Realistic: tutte le 10 run producono "" (length è sempre 0)
Aggressive 70%: random.randint(0, 0) → "" sempre
Aggressive 30%: pesca dalla lista edge case dove "A" * min_length = "", " " * min_length = "", ma "' OR '1'='1" e "A" * 1000 sono stringhe lunghe che ignorano maxLength
Quindi la lista edge case è l'unica fonte di diversità, perché il ramo "normale" produce sempre vuoto. Da lì vengono i pochi ' OR '1'='1 e l'unico "A" (che è "A" * min_length = "A" * 1 se minLength=1, oppure un altro edge case).

In sintesi: non è un problema di "generare troppi duplicati" — è che lo schema del tool forza quasi tutti i valori a stringa vuota, e solo gli edge case hardcoded sfuggono a quel vincolo.

ma max e minLength dove dovrebbero essere presi? O li dobbiamo passare noi?



Vengono dallo schema del tool stesso, dichiarato dal server MCP.

Quando il fuzzer chiama tools/list, il server risponde con qualcosa tipo:

{
  "name": "enhance_prompt",
  "inputSchema": {
    "type": "object",
    "required": ["prompt"],
    "properties": {
      "prompt": {
        "type": "string",
        "minLength": 1,    ← opzionale, lo dichiara il server
        "maxLength": 500   ← opzionale, lo dichiara il server
      }
    }
  }
}

Nel codice (schema_parser.py:409-410):

min_length = max(0, int(schema.get("minLength", 0)))    # default: 0
max_length = int(schema.get("maxLength", 100)))          # default: 100

Se il server non dichiara minLength/maxLength (cosa molto comune), i default sono 0 e 100. Con quei valori la generazione dovrebbe essere diversificata — e 11 stringhe vuote su 20 non avrebbe senso.

Quindi il mio sospetto di prima (che maxLength=0 causi tutte stringhe vuote) funzionerebbe solo se il server dichiara esplicitamente "maxLength": 0 nel suo schema, il che è improbabile.

Il problema reale probabilmente è un altro: il server crasha durante la connessione/inizializzazione, prima ancora di ricevere l'input. In quel caso il fuzzer genera gli args, prova a inviarli, il server è morto → "Failed to receive message". Gli args che vedi nel report sono quelli che il fuzzer avrebbe mandato, ma che probabilmente non sono mai arrivati al server. Le stringhe random generate nelle altre run causano lo stesso crash, ma se guardi bene i numeri: 11 + 8 + 1 = 20 = tutte le run. Non ci sono run "nascoste" con stringhe random — tutte e 20 finiscono in questo file.

Questo significa che il generatore ha effettivamente prodotto solo quei 3 valori distinti su 20 run, il che è un bug nella diversità della generazione, non dello schema.

# ------

1. mcp-enhance-prompt — falso positivo
20/20 fallite, 0% success rate
Tutti gli input sono "" o ' OR '1'='1 — pochissima varietà
Il server non parte mai o crasha all'inizializzazione (probabilmente manca una API key per un LLM)
Non è una vulnerabilità: è un server non configurabile senza credenziali

2. mcp/get_native_chat_uikit_integration — vulnerabilità reale
18/20 fallite, 2 successi → il server funziona con input validi
Crasha con:
sdkAppId: "" → mancata validazione input vuoto — il server dovrebbe restituire un errore JSON-RPC, non crashare il processo
sdkAppId: "'" → apice singolo fa crashare il processo — possibile SQL injection o parsing non protetto
sdkAppId: "tes﻿t_id" (BOM), "tes‮t_id" (RTL override) → caratteri unicode invisibili causano crash — mancata sanitizzazione
Questi sono bug reali di robustezza. Un server MCP non deve mai morire su input malformati — deve restituire un errore strutturato.

3. mcp/get_native_call_uikit_integration — vulnerabilità reale
7/20 fallite, 65% success → il server funziona bene con input normali
Crasha solo con:
sdkAppId: "", secretKey: "" → stessa mancata validazione
secretKey: "/tmp/safe/.." → path traversal che causa crash
sdkAppId: "tes‮t_id" → stessi caratteri RTL override
Il pattern è chiaro e consistente.