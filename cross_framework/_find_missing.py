import json, os, re

def load(path):
    if not os.path.exists(path):
        return None
    return json.load(open(path, encoding='utf-8')).get('findings', [])

def short(u):
    return (u or '').replace('https://github.com/', '')

def dump(title, path, already, fields):
    print('\n==== %s ====' % title)
    fs = load(path)
    if fs is None:
        print('  [MISSING FILE]', path); return
    print('  total VP:', len(fs))
    for f in fs:
        s = short(f.get('server_url') or f.get('server_name') or '')
        name = (f.get('server_name') or s or '').lower()
        present = any(a.lower() in name or a.lower() in s.lower() for a in already)
        tag = 'HAVE' if present else '>>>> MISSING'
        vals = []
        for k in fields:
            v = f.get(k)
            if k == 'description' and v:
                m = re.search(r'Code:\s*(.*)$', str(v), re.S)
                v = m.group(1).strip() if m else v
            if v: vals.append('%s=%s' % (k, str(v).replace(chr(10), ' ')[:120]))
        print('  [%s] %s | %s' % (tag, s, ' | '.join(vals)))

base = '.'
# 1) access-control missing -> mcp-security-scan remote-access-control
dump('access-control extra (mcp-security-scan/remote-access-control)',
     'mcp_security_scan/postprocessing/remote-access-control/filtered/llm_analysis/vp.json',
     ['aws-pentest', 'durandal'],
     ['server_url', 'id', 'title', 'details'])

# 2) sensitive-file-access missing -> mcp-security-scan sensitive-file-access
dump('sensitive-file-access (mcp-security-scan/sensitive-file-access)',
     'mcp_security_scan/postprocessing/sensitive-file-access/filtered/llm_analysis/vp.json',
     ['worksona', 'video-transcriber', 'my-docs', 'mcp-document-server', 'spec-workflow'],
     ['server_url', 'id', 'title', '_origin', 'details'])

# 3) sensitive-info-disclosure small sources
dump('info-disclosure-fuzzing (mcp-guard)',
     'mcp_guard/postprocessing/information-disclosure-fuzzing/filtered/llm_analysis/vp.json',
     ['simple-mcp-server', 'code-mcp'],
     ['server_url', 'file', '_origin', 'response'])
dump('sensitive-info-disclosed-fuzzing (mcp-guard)',
     'mcp_guard/postprocessing/sensitive-info-disclosed-fuzzing/filtered/llm_analysis/vp.json',
     ['mulmoscript'],
     ['server_url', 'file', '_origin', 'response', 'description'])
dump('tool-error-disclosure (tool_fuzzing)',
     'fuzzing/postprocessing/tool-error-disclosure/filtered/llm_analysis/vp.json',
     [],
     ['server_url', 'tool_name', '_origin', 'message_excerpt', 'final_reason'])
