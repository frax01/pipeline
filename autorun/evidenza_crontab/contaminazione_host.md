# Contaminazione dell'host di analisi da parte dei server MCP

Misure raccolte il 2026-08-05 sulle 9 VM di analisi, **dopo** la fine della
rirun. Nessuna di queste tracce e' stata creata dalla pipeline: sono tutte
prodotte dai server MCP sotto esame durante l'analisi dinamica.

## 1. Voci di cron persistenti (payload degli scanner)

Alcuni server espongono un tool di scheduling. Gli analizzatori vi hanno
iniettato i propri payload di probe, e il server li ha scritti nel **crontab
dell'host**, dove sono rimasti a eseguire ogni minuto per nove giorni.

| VM | tool in esecuzione | righe di payload |
|---|---|---:|
| .138 | security_scan | 8 |
| .139 | check | 13 |
| .137 | shield | 4 |
| .142 | shield | 1 |
| **totale** | **4 VM su 9** | **26** |

Contenuto tipico: `; id`, `$(whoami)`, `` `uname -a` ``,
`../../../../etc/passwd`, `<img src=x onerror=ale`, `/tmp/safe/<random>`.
Crontab originali conservati in questa cartella (`vm_*.crontab`).

## 2. Scrittura nel file di avvio della shell

| VM | `.bashrc` (byte) | righe |
|---|---:|---:|
| .138 | 251.310 | 13.128 |
| .136 | 232.741 | |
| .141 | 186.227 | |
| .134 | 148.581 | |
| .137 | 140.809 | |
| .132 | 112.717 | |
| .142 | 100.601 | |
| .133 | 77.527 | |
| .139 | 4.699 | (non contaminato) |

Un `.bashrc` di default pesa ~4 KB. Su `.138` il 96% del file e' **la stessa
tripletta ripetuta 3.251 volte**:

```
# bun
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"
```

L'installer di `bun`, invocato da migliaia di server durante l'analisi,
riappende il proprio blocco a ogni esecuzione senza controllare se c'e' gia'.
Presente anche un blocco `hive-mcp-cli managed - START/END` che imposta
variabili d'ambiente puntando a una directory creata dal server.

## 3. Directory di stato create nella home

| VM | dot-directory | voci in `/tmp` |
|---|---:|---:|
| .136 | 608 | 14.347 |
| .138 | 476 | 14.628 |
| .139 | 454 | 2.341 |
| .134 | 389 | 12.604 |
| .137 | 379 | 1.179 |
| .141 | 368 | 18.342 |
| .142 | 319 | 748 |
| .132 | 222 | 4.496 |
| .133 | 176 | 34 |

Esempi: `.ableton-copilot-mcp`, `.algorand-mcp`, `.arxiv-mcp-server`,
`.bitcoin-mcp`, `.agent-wallet`, `.agent365-bridge`, `.appium`, `.arcade`.
Ogni server che si avvia lascia stato persistente nella home dell'utente.

## 4. Perche' conta

1. **Nessuno dei sette framework analizzati rileva nulla di tutto questo.**
   Tutti osservano cosa il server *risponde*; nessuno osserva cosa il server
   *fa al sistema* mentre gira.
2. E' il terzo incidente indipendente della stessa classe, dopo la
   cancellazione di `~/Desktop` su VM1 e le voci di cron.
3. Ha un **impatto operativo misurabile**: la saturazione del disco che ne
   deriva (82-88 GB su 96 GB) fa fallire l'avvio dei server successivi,
   contaminando la misura stessa.

## 5. Avvertenza metodologica

Un ambiente di analisi non bonificato fra una passata e l'altra **non misura
l'ecosistema, misura se stesso**. Nella terza passata di questo lavoro il
tasso di avvio e' sceso dall'81% al 45% sulle VM con il disco piu' pieno: se
non fosse stato notato, sarebbe stato riportato come "mortalita' dei server".
