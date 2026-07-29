# sensitive-file-access (R-02) - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Descrizione del check

Probe attivo con file:///etc/passwd. Il filtro tiene solo risposte con contenuto REALE di /etc/passwd o chiavi private.

## Statistiche filtro

| Metrica | Valore |
|---------|--------|
| Finding originali | 88 |
| Finding filtrati (tenuti) | 4 |
| Rimossi | 84 |
| Tasso di riduzione | 95.5% |

## Motivi di filtraggio

| Motivo | Count |
|--------|-------|
| `REJECTED:server_rejected_access` | 48 |
| `REJECTED:result_empty_no_file_read` | 26 |
| `REJECTED:result_no_file_content` | 10 |
| `KEPT:real_passwd_content` | 4 |

## Server unici con vulnerabilita' reali: 4

## Esempi di finding tenuti (max 15)

### 1. [-worksona-mcp-server](https://github.com/worksona/-worksona-mcp-server)

- **ID**: `R-02`
- **Severity**: `high`
- **Filter reason**: `real_passwd_content`
- **Details**: ```{"jsonrpc": "2.0", "id": 1, "result": {"contents": [{"type": "text", "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/ru... [troncato]```

### 2. [video-transcriber-mcp](https://github.com/nhatvu148/video-transcriber-mcp)

- **ID**: `R-02`
- **Severity**: `high`
- **Filter reason**: `real_passwd_content`
- **Details**: ```{"result": {"contents": [{"uri": "file:///etc/passwd", "mimeType": "text/plain", "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39... [troncato]```

### 3. [mcp-document-server](https://github.com/danielitus/mcp-document-server)

- **ID**: `R-02`
- **Severity**: `high`
- **Filter reason**: `real_passwd_content`
- **Details**: ```{"result": {"contents": [{"uri": "file:///etc/passwd", "mimeType": "text/plain", "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39... [troncato]```

### 4. [spec-workflow-mcp](https://github.com/uniswap/spec-workflow-mcp)

- **ID**: `R-02`
- **Severity**: `high`
- **Filter reason**: `real_passwd_content`
- **Details**: ```{"result": {"contents": [{"uri": "file:///etc/passwd", "mimeType": "text/markdown", "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x... [troncato]```

## Interpretazione

I finding tenuti mostrano server dove la lettura di file sensibili (file:///etc/passwd) ha restituito contenuto reale. Vulnerabilita' confermata.

## Lista completa server vulnerabili

- https://github.com/danielitus/mcp-document-server
- https://github.com/nhatvu148/video-transcriber-mcp
- https://github.com/uniswap/spec-workflow-mcp
- https://github.com/worksona/-worksona-mcp-server
