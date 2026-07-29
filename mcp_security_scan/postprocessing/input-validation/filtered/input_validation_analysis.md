# input-validation (X-02) - Analisi Finding Filtrati

**Data analisi**: 2026-07-27 12:30

## Descrizione del check

Injection fuzzing con 5 payload ('; id', '$(whoami)', '`uname -a`', '../../../../etc/passwd', 'http://169.254.169.254/...'). Lo scanner cerca indicatori generici ('linux', 'insecure', 'stdout') nel response. Il filtro tiene SOLO risposte dove l'injection e' stata REALMENTE eseguita (output di 'id', 'uname', contenuto di /etc/passwd, etc.) e scarta tutte le risposte con isError=true o payload echoing.

## Statistiche filtro

| Metrica | Valore |
|---------|--------|
| Finding originali | 2868 |
| Finding filtrati (tenuti) | 63 |
| Rimossi | 2805 |
| Tasso di riduzione | 97.8% |

## Motivi di filtraggio

| Motivo | Count |
|--------|-------|
| `REJECTED:all_injections_rejected` | 2805 |
| `KEPT:kept_1_of_1` | 6 |
| `KEPT:kept_1_of_2` | 6 |
| `KEPT:kept_1_of_3` | 3 |
| `KEPT:kept_1_of_4` | 3 |
| `KEPT:kept_2_of_4` | 3 |
| `KEPT:kept_2_of_6` | 2 |
| `KEPT:kept_2_of_7` | 2 |
| `KEPT:kept_4_of_4` | 2 |
| `KEPT:kept_1_of_7` | 2 |
| `KEPT:kept_9_of_9` | 2 |
| `KEPT:kept_1_of_5` | 2 |
| `KEPT:kept_2_of_3` | 2 |
| `KEPT:kept_4_of_28` | 1 |
| `KEPT:kept_1_of_6` | 1 |
| `KEPT:kept_7_of_13` | 1 |
| `KEPT:kept_5_of_6` | 1 |
| `KEPT:kept_4_of_6` | 1 |
| `KEPT:kept_4_of_18` | 1 |
| `KEPT:kept_20_of_34` | 1 |
| `KEPT:kept_2_of_14` | 1 |
| `KEPT:kept_1_of_15` | 1 |
| `KEPT:kept_3_of_9` | 1 |
| `KEPT:kept_7_of_9` | 1 |
| `KEPT:kept_1_of_10` | 1 |
| `KEPT:kept_19_of_66` | 1 |
| `KEPT:kept_2_of_9` | 1 |
| `KEPT:kept_1_of_9` | 1 |
| `KEPT:kept_5_of_29` | 1 |
| `KEPT:kept_3_of_23` | 1 |
| `KEPT:kept_3_of_14` | 1 |
| `KEPT:kept_1_of_16` | 1 |
| `KEPT:kept_4_of_23` | 1 |
| `KEPT:kept_1_of_8` | 1 |
| `KEPT:kept_5_of_11` | 1 |
| `KEPT:kept_4_of_13` | 1 |
| `KEPT:kept_1_of_20` | 1 |
| `KEPT:kept_7_of_7` | 1 |
| `KEPT:kept_3_of_18` | 1 |
| `KEPT:kept_19_of_19` | 1 |
| `KEPT:kept_3_of_3` | 1 |

## Server unici con vulnerabilita' reali: 63

## Esempi di finding tenuti (max 15)

### 1. [github-mcp-server](https://github.com/0xshariq/github-mcp-server)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_4_of_28`
- **Details**: ```[{"tool": "git_branch", "payload": "`uname -a`", "resp": {"result": {"content": [{"type": "text", "text": "{\"content\":[{\"type\":\"text\",\"text\":\"Error: Command failed: git branch \\\"`uname -a`\\\"\\nfatal: 'Linux martignoni-carminati-6 6.8.0-124-generic #124-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 13:00:45 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux' is not a valid branch name\\n\"}],\"isError\":true,\"metadata\":{\"operation\":\"git-branch\",\"duration\":8,\"timestamp\":\"2026-07-10T09:44:09.319Z\",\"workingDirectory\":\"/home/tecnico/Desktop/Pipeline/tool_mcp_security_scan_w1/github-mcp-server\"}}"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:Linux\\s+\\S+\\s+\\d+\\.\\d+\\.\\d+"}, {"tool": "git_checkout", "payload": "`uname -a`", "resp": {"result": {"content": [{"ty... [troncato]```

### 2. [Remote-Command-MCP](https://github.com/deepsuthar496/Remote-Command-MCP)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_1_of_1`
- **Details**: ```[{"tool": "execute_remote_command", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}]```

### 3. [Project-MCP-Server](https://github.com/riskiilyas/Project-MCP-Server)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_1_of_6`
- **Details**: ```[{"tool": "read_file", "payload": "../../../../etc/passwd", "resp": {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "{\n  \"file_path\": \"../../../../etc/passwd\",\n  \"full_path\": \"/home/tecnico/etc/passwd/../../../../etc/passwd\",\n  \"content\": \"root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\\nsync:x:4:65534:sync:/bin:/bin/sync\\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\\nproxy:x:13:13:proxy:... [troncato]```

### 4. [Repo-context](https://github.com/pablo-peek/Repo-context)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_2_of_6`
- **Details**: ```[{"tool": "getFileContent", "payload": "../../../../etc/passwd", "resp": {"result": {"content": [{"type": "text", "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var... [troncato]```

### 5. [mcp-perforce](https://github.com/Cocoon-AI/mcp-perforce)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_7_of_13`
- **Details**: ```[{"tool": "p4_stream_list", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)\n"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}, {"tool": "p4_stream_info", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)\n"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}, {"tool": "p4_stream_edit", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "Current stream spec for ; id:\n\nuid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm... [troncato]```

### 6. [Windows-Command-Line-MCP-Server](https://github.com/alxspiker/Windows-Command-Line-MCP-Server)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_2_of_7`
- **Details**: ```[{"tool": "list_running_processes", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)\n"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}, {"tool": "get_network_info", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n    inet6 ::1/128 scope host noprefixroute \n       valid_lft forever preferred_lft forever\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdis... [troncato]```

### 7. [tmux-mcp](https://github.com/MediocreTriumph/tmux-mcp)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_5_of_6`
- **Details**: ```[{"tool": "tmux_capture_pane", "payload": "`uname -a`", "resp": {"result": {"content": [{"type": "text", "text": "Error: Failed to capture pane: Command failed: tmux capture-pane -t \"`uname -a`:0\" -p\ncan't find session: Linux martignoni-carminati-6 6.8.0-124-generic #124-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 13\n"}], "isError": true}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:Linux\\s+\\S+\\s+\\d+\\.\\d+\\.\\d+"}, {"tool": "tmux_kill_session", "payload": "`uname -a`", "resp": {"result": {"content": [{"type": "text", "text": "Error: Failed to kill session: Command failed: tmux kill-session -t \"`uname -a`\"\ncan't find session: Linux martignoni-carminati-6 6.8.0-124-generic #124-Ubuntu SMP PREEMPT_DYNAMIC Tue May 26 13\n"}], "isError": true}, "jsonrpc": "2.0", "id": 1... [troncato]```

### 8. [mcp-git](https://github.com/markheramis/mcp-git)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_2_of_7`
- **Details**: ```[{"tool": "git_clone", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}, {"tool": "git_init", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "Reinitialized existing Git repository in /home/tecnico/Desktop/Pipeline/tool_mcp_security_scan_w1/mcp-git/.git/\nuid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}]```

### 9. [garmin-health-mcp-server](https://github.com/eversonl/garmin-health-mcp-server)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_1_of_2`
- **Details**: ```[{"tool": "get_sleep_data", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "{\n  \"output\": \"uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)\"\n}"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}]```

### 10. [local-logs-mcp-server](https://github.com/mariosss/local-logs-mcp-server)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_1_of_3`
- **Details**: ```[{"tool": "tail_log", "payload": "../../../../etc/passwd", "resp": {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "{\n  \"content\": \"root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\\nsync:x:4:65534:sync:/bin:/bin/sync\\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\\nbackup:x:34:34:backup:/var/backups:/us... [troncato]```

### 11. [docker-mcp](https://github.com/suvarchal/docker-mcp)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_4_of_4`
- **Details**: ```[{"tool": "run_container", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}, {"tool": "stop_container", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}, {"tool": "remove_container", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd... [troncato]```

### 12. [back-agent-mcp](https://github.com/ZUENS2020/back-agent-mcp)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_1_of_7`
- **Details**: ```[{"tool": "execute-task", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "## Task Completed Successfully\n\n### Output:\n```\nuid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)\n```\n\nExit Code: 0"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}]```

### 13. [ddev-mcp](https://github.com/AkibaAT/ddev-mcp)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_1_of_2`
- **Details**: ```[{"tool": "ddev_composer_command", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "Composer command executed successfully:\n\nuid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)\n"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}]```

### 14. [Ollama-mcp](https://github.com/NightTrek/Ollama-mcp)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_4_of_6`
- **Details**: ```[{"tool": "show", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)\n"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}, {"tool": "pull", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)\n"}]}, "jsonrpc": "2.0", "id": 1}, "_filter_reason": "real_injection:uid=\\d+\\("}, {"tool": "push", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "uid=1000(tecnico) gid=1000(tecnico) groups=1000(tecnico),4(adm),24(cdrom),27(sudo),30(dip),105(lxd),988(ollama)\n"}]}, "jsonr... [troncato]```

### 15. [mcp-server-qiita](https://github.com/Selenium39/mcp-server-qiita)

- **ID**: `X-02`
- **Severity**: `critical`
- **Filter reason**: `kept_1_of_2`
- **Details**: ```[{"tool": "get_items", "payload": "; id", "resp": {"result": {"content": [{"type": "text", "text": "[\n  {\n    \"rendered_body\": \"<blockquote data-sourcepos=\\\"1:1-2:127\\\">\\n<p data-sourcepos=\\\"1:3-2:127\\\"><strong>連載</strong>: <a href=\\\"https://qiita.com/singula/stocks/abadbf2d5d6211276c97\\\">AIに仕事を奪われる不安から始めるハーネス作成入門</a><br>\\n<strong>第13回</strong> ← <a href=\\\"https://qiita.com/singula/items/5d2756f639d08136ad70\\\" id=\\\"reference-563cd673eb397d60fd2e\\\">前回（第12回）: モデルルーターの設計</a></p>\\n</blockquote>\\n<h2 data-sourcepos=\\\"4:1-4:68\\\">\\n<span id=\\\"はじめにaiエージェントの暴走が怖い方へ\\\" class=\\\"fragment\\\"></span><a href=\\\"#%E3%81%AF%E3%81%98%E3%82%81%E3%81%ABai%E3%82%A8%E3%83%BC%E3%82%B8%E3%82%A7%E3%83%B3%E3%83%88%E3%81%AE%E6%9A%B4%E8%B5%B0%E3%81%8C%E6%80%96%E3%81%84%E6%96%B... [troncato]```


*... e altri 48 finding*

## Interpretazione

I finding tenuti mostrano server dove i payload di injection sono stati **realmente eseguiti** dal sistema operativo sottostante. Ad esempio, il payload `; id` ha prodotto output `uid=1000(tecnico)...` o il payload `\`uname -a\`` ha prodotto la versione del kernel. Questi sono **command injection confermati** e rappresentano vulnerabilita' critiche.

I finding scartati sono server che hanno rifiutato l'input (isError=true), o che hanno semplicemente echato il payload nel messaggio di errore senza eseguirlo.

## Lista completa server vulnerabili

- https://github.com/0xshariq/github-mcp-server
- https://github.com/AkibaAT/ddev-mcp
- https://github.com/Anansitrading/sprite-mcp-server
- https://github.com/Cocoon-AI/mcp-perforce
- https://github.com/ExpertVagabond/raycast-mcp-server
- https://github.com/GaryWenneker/jira-mcp-server
- https://github.com/GitJuhb/zellij-mcp-server
- https://github.com/MediocreTriumph/tmux-mcp
- https://github.com/MikeyBeez/mcp-kaggle-tool
- https://github.com/NightTrek/Ollama-mcp
- https://github.com/RuneLind/mcp-maven-test-runner
- https://github.com/Selenium39/mcp-server-qiita
- https://github.com/Shreesha4994/sap-btp-cf-mcp-server
- https://github.com/TauqeerAhmad5201/docker-mcp-extension
- https://github.com/TerminalGravity/video-mcp
- https://github.com/ZUENS2020/back-agent-mcp
- https://github.com/adriyansyah-mf/mcp-pentest
- https://github.com/aledlie/doppler-mcp
- https://github.com/alxspiker/Windows-Command-Line-MCP-Server
- https://github.com/aroglahcim/magick-mcp
- https://github.com/c3budiman/mcp-ping
- https://github.com/camiloafernandez/mcp-server-kubernetes
- https://github.com/codingsasi/ddev-mcp
- https://github.com/d3lta02/sepolia-prover-mcp
- https://github.com/deepsuthar496/Remote-Command-MCP
- https://github.com/eddie-rembrandt/MCP-CodeV
- https://github.com/eddyv73/azure-mcp
- https://github.com/ekdh600/build-mcp
- https://github.com/eversonl/garmin-health-mcp-server
- https://github.com/garthdb/act-testing-mcp
- https://github.com/gufao/mcp-server-fabric-ai
- https://github.com/hemichaeli/windows-mcp-server
- https://github.com/iptton-ai/wxcloud-mcp
- https://github.com/jungchihoon/github-mcp-server
- https://github.com/kdemarest/jeesty-mcp
- https://github.com/mamounalzyoud/django-mcp-server
- https://github.com/manalejandro/mcp-proc
- https://github.com/mariosss/local-logs-mcp-server
- https://github.com/markahope-aag/wp-audit-mcp
- https://github.com/markheramis/mcp-git
- https://github.com/matt-chlorophyll/claude-code-saver-mcp
- https://github.com/mckinleymedia/mcflow-mcp
- https://github.com/mjrestivo16/mcp-kubernetes
- https://github.com/nibesh0/NetSecmcp
- https://github.com/nobiehl/codeweaver-mcp
- https://github.com/pablo-peek/Repo-context
- https://github.com/portfolio-jaime/mcp-server-k8s
- https://github.com/raihan0824/mcp-server-kubernetes
- https://github.com/rangta10/kali-mcp-server
- https://github.com/riskiilyas/Project-MCP-Server
- https://github.com/sarva-20/heimdall-mcp
- https://github.com/solon07/mcp-devops-assistant
- https://github.com/storypixel/mcp-taskwarrior-ai
- https://github.com/suvarchal/docker-mcp
- https://github.com/talentedmrweb/local-dev-bridge-mcp
- https://github.com/thedotmack/the-dev-server-mcp
- https://github.com/thekaranpargaie/kube-mcp
- https://github.com/tiendung2k03/mcp-adb
- https://github.com/trickv/claude-squared-code
- https://github.com/vanisoul/rundeck-mcp-server
- https://github.com/volkan-m/vnc-mcp-server
- https://github.com/vyomjain6904/pentest-mcp-server
- https://github.com/xu1211/demo-mcp-server
