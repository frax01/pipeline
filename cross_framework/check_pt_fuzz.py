"""Sample 20 path-traversal-fuzzing VP, classify manually by content check."""
import json, re, random
random.seed(13)

d = json.load(open('mcp_guard/postprocessing/path-traversal-fuzzing/filtered/llm_analysis/vp.json', encoding='utf-8'))
fs = [f for f in d['findings'] if f.get('_hc_reason') == 'filesystem_content_in_response_etc_passwd']
sample = random.sample(fs, 20)

# Real /etc/passwd content patterns (multi-line)
REAL_LEAK = re.compile(r"root:x:0:0:[^:]*:/(?:root|home).*?:/bin/(?:bash|sh)|"
                       r"daemon:x:1:1:.*?nologin|"
                       r"(?:root|daemon|bin|sys):x:\d+:\d+:[^:]*:[^:]*:/(?:bin|usr|sbin)",
                       re.I | re.S)

real_count = 0
echo_count = 0
for i, f in enumerate(sample, 1):
    resp = f.get('response', '')
    if REAL_LEAK.search(resp):
        verdict = 'VP'
        real_count += 1
    else:
        verdict = 'FP'
        echo_count += 1
    print(f'{i}. {verdict} | {f.get("server_url","")[:50]}')

print(f'\nReal VP: {real_count}/20, Likely FP: {echo_count}/20')
print(f'FP rate stim: {echo_count/20*100:.0f}%')
