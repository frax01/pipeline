import json, re
from collections import Counter

def load(path, guard=False):
    d = json.load(open(path, encoding='utf-8'))
    out = []
    for f in d.get('findings', []):
        if guard:
            desc = str(f.get('description', ''))
            m = re.search(r'Code:\s*(.*)$', desc, re.S)
            ev = m.group(1).strip() if m else desc
        else:
            ev = str(f.get('evidence', ''))
        out.append({'server': f.get('server_name') or f.get('server_url'),
                    'file': f.get('file'), 'ev': ev, 'id': f.get('id', '')})
    return out

W = load('mcp_watch/postprocessing/credential-leak/filtered/llm_analysis/vp.json')
G = load('mcp_guard/postprocessing/hardcoded-credential-static/filtered/llm_analysis/vp.json', guard=True)

REAL = [
 ('google_api', r'AIza[0-9A-Za-z_\-]{35}'),
 ('openai_anthropic', r'sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}'),
 ('github_pat', r'gh[posu]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}'),
 ('aws_akia', r'A(?:KIA|SIA)[0-9A-Z]{16}'),
 ('slack', r'xox[baprs]-[A-Za-z0-9\-]{10,}'),
 ('stripe', r'(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}'),
 ('google_oauth_secret', r'GOCSPX-[A-Za-z0-9_\-]{10,}'),
 ('sendgrid', r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
 ('hf', r'hf_[A-Za-z0-9]{30,}'),
 ('npm', r'npm_[A-Za-z0-9]{36}'),
 ('private_key', r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
 ('jwt', r'eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}'),
 ('conn_creds', r'(?:mongodb|postgres|postgresql|mysql|redis|amqps?)(?:\+srv)?://[^\s:@/]+:[^\s@/]{3,}@'),
 ('telegram', r'\b\d{8,10}:[A-Za-z0-9_\-]{35}\b'),
 ('twilio_sk', r'\bSK[0-9a-f]{32}\b'),
]
REAL = [(n, re.compile(p)) for n, p in REAL]

CRED_KEY = r'(?:api[_\-]?key|secret|token|password|passwd|pwd|auth|client[_\-]?secret|access[_\-]?key|private[_\-]?key|bearer)'
GEN_HEX = re.compile(CRED_KEY + r'["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-+/.=]{16,})["\']', re.I)
GEN_ENVLINE = re.compile(r'^[A-Z0-9_]*(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|AUTH|ACCESS_?KEY)[A-Z0-9_]*\s*=\s*["\']?([A-Za-z0-9_\-+/.=]{16,})', re.I)

PLACEHOLDER = re.compile(r'your[_\-]?|<[^>]{2,}>|x{4,}|change[_\-]?me|example|sample|dummy|fake|placeholder|replace[_\-]?|insert[_\-]?|todo|redacted|\.\.\.|\*{3,}|put[_\-]?your|enter[_\-]?your|my[_\-]?(?:api[_\-]?)?key|test[_\-]?(?:key|token|secret)|123456|abcdef|xxxxxx|sk-xxx', re.I)
ENVREF = re.compile(r'process\.env|os\.getenv|os\.environ|getenv\(|import\.meta\.env|Deno\.env|System\.getenv|\bENV\[|\$\{?[A-Za-z_]+\}?|settings\.[A-Za-z_]|config\.get|configservice|conf\[|secret[s]?\.get|vault|keyvault|getsecret', re.I)
EMPTY = re.compile(r'[:=]\s*["\']\s*["\']')
PUBLIC = re.compile(r'chromeuxreport|firebase|authdomain|messagingsenderid|storagebucket|measurementid', re.I)

def has_real(ev):
    return any(r.search(ev) for _, r in REAL)

def value_eq_key(ev):
    m = re.search(r'([A-Za-z_][A-Za-z0-9_\-]{1,30})["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{1,30})["\']', ev)
    if m:
        a = m.group(1).lower().replace('_', '').replace('-', '')
        b = m.group(2).lower().replace('_', '').replace('-', '')
        if a == b:
            return True
    return False

def classify(ev):
    if not ev.strip():
        return ('FP', 'empty')
    if PUBLIC.search(ev):
        return ('FP', 'public_web_key')
    if EMPTY.search(ev) and not has_real(ev):
        return ('FP', 'empty_value')
    if value_eq_key(ev):
        return ('FP', 'varname==value')
    if PLACEHOLDER.search(ev) and not has_real(ev):
        return ('FP', 'placeholder')
    if ENVREF.search(ev) and not has_real(ev):
        return ('FP', 'env_reference')
    for n, r in REAL:
        if r.search(ev):
            return ('VP-strong', n)
    if GEN_HEX.search(ev) or GEN_ENVLINE.search(ev):
        return ('VP-generic', 'high_entropy_literal')
    return ('VP-weak', 'cred_assignment_no_pattern')

def run(name, data):
    res = [classify(d['ev']) for d in data]
    cls = Counter(v for v, _ in res)
    reasons = Counter(r for _, r in res)
    vp = sum(1 for v, _ in res if v.startswith('VP'))
    fp = sum(1 for v, _ in res if v == 'FP')
    print('\n===== %s: %d entries  ->  VP=%d  FP=%d =====' % (name, len(data), vp, fp))
    print('  buckets:', dict(cls))
    print('  reasons:', dict(reasons))
    print('  -- FP examples --')
    shown = 0
    for d, (v, rsn) in zip(data, res):
        if v == 'FP' and shown < 10:
            print('    [%s] %s | %s' % (rsn, d['server'], str(d['ev'])[:90]))
            shown += 1
    print('  -- VP-weak examples --')
    shown = 0
    for d, (v, rsn) in zip(data, res):
        if v == 'VP-weak' and shown < 8:
            print('    %s | %s' % (d['server'], str(d['ev'])[:90]))
            shown += 1
    return vp, fp

vw, fw = run('mcp-watch credential-leak', W)
vg, fg = run('mcp-guard hardcoded-credential-static', G)
tot = len(W) + len(G)
print('\n################ COMBINED ################')
print('TOTAL entries: %d  ->  VP=%d  FP=%d' % (tot, vw + vg, fw + fg))
print('VP rate: %.1f%%' % ((vw + vg) / tot * 100))
