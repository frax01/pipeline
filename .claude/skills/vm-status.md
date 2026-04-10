---
name: vm-status
description: Mostra una tabella con lo stato di tutti i framework/tool che runnano sulle 9 VM remote. Per ogni tool mostra la VM, l'indice corrente, la percentuale di completamento, e se il processo e' attivo, finito o morto.
user_invocable: true
---

# VM Status - Stato dei framework sulle VM

Quando l'utente invoca questa skill, devi connetterti via SSH a tutte e 9 le VM remote e mostrare una tabella con lo stato di ogni tool/framework.

## Informazioni da raccogliere

Per ogni VM, devi:

1. **Leggere il file stats JSON** del tool per ottenere `last_index`, `total`, `range_start`, `range_end`
2. **Controllare se il processo e' attivo** con `pgrep -af 'python.*run_'`

## Le 9 VM e i 7 tool

Ci sono 9 VM ma solo 7 tool attivi. Ogni tool gira su tutte le 9 VM (ognuna processa il suo chunk).

| Tool | Stats path (remoto) | Script |
|------|---------------------|--------|
| guard | tool_mcp_guard/mcp_guard_stats.json | run_guard.py |
| watch | tool_mcp_watch/mcp_watch_stats.json | run_watch.py |
| fuzzing | tool_fuzzing/fuzzing_stats.json | run_fuzzing.py |
| scan | tool_mcp_scan/mcp_scan_stats.json | run_scan.py |
| shield | tool_mcp_shield/mcp_shield_stats.json | run_shield.py |
| security_scan | tool_mcp_security_scan/mcp_security_scan_stats.json | run_security_scan.py |
| check | tool_mcp_check/mcp_check_stats.json | run_check.py |

Le 9 VM:

| VM | Indirizzo SSH |
|-----|---------------|
| VM1 | tecnico@10.79.6.132 |
| VM2 | tecnico@10.79.6.133 |
| VM3 | tecnico@10.79.6.134 |
| VM4 | tecnico@10.79.6.136 |
| VM5 | tecnico@10.79.6.137 |
| VM6 | tecnico@10.79.6.138 |
| VM7 | tecnico@10.79.6.139 |
| VM8 | tecnico@10.79.6.141 |
| VM9 | tecnico@10.79.6.142 |

**Path base remoto**: `/home/tecnico/Desktop/Pipeline/`
**Totale server**: 60.205
**Chunk per VM**: 6.689 (ultima VM: 6.693)

## Come eseguire

Esegui i comandi SSH in parallelo (lancia tutti i comandi bash in parallelo).

Per ogni VM e per ogni tool, esegui due comandi SSH:

### 1. Leggi stats
```bash
ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no tecnico@<IP> "python3 -c \"import json; d=json.load(open('/home/tecnico/Desktop/Pipeline/<stats_path>')); print(json.dumps({'last_index':d.get('last_index',0),'total':d.get('total',0),'range_start':d.get('range_start',0),'range_end':d.get('range_end',0)}))\" 2>/dev/null"
```

### 2. Controlla processo (una volta per VM, copre tutti i tool)
```bash
ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no tecnico@<IP> "pgrep -af 'python.*run_' 2>/dev/null"
```

## Output

Mostra una tabella markdown per ogni tool, con una riga per VM:

```
### guard

| VM  | IP            | Processati | Chunk  | Progresso | Stato        |
|-----|---------------|------------|--------|-----------|--------------|
| VM1 | 10.79.6.132   | 5234       | 6689   | 78.2%     | RUNNING      |
| VM2 | 10.79.6.133   | 6689       | 6689   | 100.0%    | COMPLETATO   |
| VM3 | 10.79.6.134   | 1200       | 6689   | 17.9%     | MORTO        |
| ...                                                                   |
```

### Regole per lo stato:
- **RUNNING**: Il processo `run_<tool>.py` e' attivo (trovato da pgrep)
- **COMPLETATO**: `total >= chunk` (ha finito tutti i server del suo range)
- **MORTO**: Il processo NON e' attivo E `total < chunk` (non ha finito ma il processo non c'e' piu')
- **NON AVVIATO**: Non esiste il file stats o total = 0 e il processo non e' attivo
- **ERRORE SSH**: SSH fallito o timeout

### Alla fine di tutte le tabelle aggiungi un riepilogo:

```
### Riepilogo

| Tool           | VM completate | VM running | VM morte | Progresso globale |
|----------------|---------------|------------|----------|-------------------|
| guard          | 7/9           | 2/9        | 0/9      | 89.3%             |
| watch          | 9/9           | 0/9        | 0/9      | 100.0%            |
| ...            |               |            |          |                   |
```

## Note importanti
- Lancia TUTTI i comandi SSH in parallelo (non uno alla volta) per velocita
- Timeout SSH: 10 secondi
- Se una VM non risponde, segna "ERRORE SSH" e vai avanti
- Usa il tool Bash per eseguire i comandi SSH
