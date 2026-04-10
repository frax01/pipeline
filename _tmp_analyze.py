import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import json
from collections import Counter

with open('analysisAlldata/0_tool_mcp_watch/input-validation/filtered/input_validation_filtered.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

findings = data['findings']

##############################################
# COMMAND INJECTION classification
##############################################
ci = [f for f in findings if f['id'] == 'COMMAND_INJECTION_RISK']

tp_ci = []
fp_ci = []
for f in ci:
    ev = f['evidence']
    file = f['file']
    server = f['server_name']

    # FP: jQuery / minified JS
    if 'jquery' in file.lower() or '.min.js' in file.lower():
        fp_ci.append(('minified_js', f)); continue
    # FP: regex .exec()
    if 'rx.exec(' in ev or '.exec(input.text)' in ev:
        fp_ci.append(('regex_exec', f)); continue
    # FP: mongoose/ORM .exec()
    if 'lean().exec()' in ev or 'session.exec(' in ev:
        fp_ci.append(('orm_exec', f)); continue
    # FP: Commented out code
    if ev.strip().startswith('#') or ev.strip().startswith('//'):
        fp_ci.append(('commented', f)); continue
    # FP: Demo/example/vulnerable example files
    if any(x in file.lower() for x in ['demo', 'example', 'vulnerable', 'remediation', 'guidance', 'security_reminder', 'security-guidance']):
        fp_ci.append(('demo_or_docs', f)); continue
    # FP: Scanner test patterns
    if any(x in file.lower() for x in ['vulnerability-patterns', 'self-validation', 'benchmark-daemon']):
        fp_ci.append(('test_pattern', f)); continue
    # FP: Security linter test data
    if server in ['scan-mcp', 'fonCki_mcp-security-linter', 'agent-security-scanner-mcp']:
        if 'Should be' in ev or 'analyzers' in file:
            fp_ci.append(('test_pattern', f)); continue
    # FP: Documentation strings
    if 'NEVER use eval' in ev or 'directive' in ev:
        fp_ci.append(('doc_string', f)); continue
    # FP: Minified plugin code
    if '!function' in ev and 'plugin' in file.lower():
        fp_ci.append(('minified_js', f)); continue
    # FP: clickhouse DB exec
    if 'clickhouse' in ev.lower() or 'clickhouse' in file.lower():
        fp_ci.append(('db_exec', f)); continue
    # FP: Static exec (hardcoded path, os.system('clear'))
    if "os.system('clear'" in ev or 'os.system("clear"' in ev:
        fp_ci.append(('static_exec', f)); continue
    if "exec(open(r'" in ev:
        fp_ci.append(('static_exec', f)); continue
    # FP: scorecard args.system() - method call not OS
    if 'args.system(' in ev:
        fp_ci.append(('method_call', f)); continue
    # FP: DefinitelyTyped type definitions
    if 'DefinitelyTyped' in server or '.d.ts' in file:
        fp_ci.append(('type_def', f)); continue
    # FP: URL regex exec
    if 'exec = /^http' in ev:
        fp_ci.append(('regex_exec', f)); continue
    # FP: Browser adapter method calls
    if "this.exec([" in ev:
        fp_ci.append(('method_call', f)); continue
    # FP: console.log showing vuln pattern (string literal)
    if 'console.log' in ev and 'userInput' in ev:
        fp_ci.append(('string_literal', f)); continue
    # FP: string literal patterns in scanner/linter source
    if "'exec(" in ev or '"exec(' in ev:
        fp_ci.append(('string_literal', f)); continue
    # FP: os.system with static hardcoded rm
    if 'os.system(f"rm -f' in ev and 'ENZYGEN_PATH' in ev:
        fp_ci.append(('static_exec', f)); continue
    # FP: codex-hookify / claude-plugins security hook
    if 'security_reminder_hook' in file:
        fp_ci.append(('doc_string', f)); continue
    # FP: socket.io minified
    if 'socket.io' in file:
        fp_ci.append(('minified_js', f)); continue

    tp_ci.append(f)

print(f"=== COMMAND_INJECTION_RISK: {len(tp_ci)} TP, {len(fp_ci)} FP (of {len(ci)} total) ===")
print()
print("--- TRUE POSITIVES ---")
for f in tp_ci:
    print(f"  {f['server_name']:40s} | {f['file']}")
    print(f"    evidence: {f['evidence'][:120]}")
print()
print("--- FALSE POSITIVE REASONS ---")
fp_reasons = Counter(r for r,_ in fp_ci)
for r,c in fp_reasons.most_common():
    print(f"  {r}: {c}")
    for reason, f in fp_ci:
        if reason == r:
            print(f"    {f['server_name']:35s} | {f['file'][:55]}")

##############################################
# SSRF classification
##############################################
print("\n\n")
ssrf = [f for f in findings if f['id'] == 'SSRF_VULNERABILITY']

tp_ssrf = []
fp_ssrf = []
for f in ssrf:
    ev = f['evidence']
    file = f['file']
    server = f['server_name']

    # FP: Discord SDK .fetch()
    if 'guild.' in ev or 'Events.fetch' in ev or 'scheduledEvents' in ev:
        fp_ssrf.append(('discord_sdk', f)); continue
    # FP: prefetch (cache/preload, not HTTP)
    if '.prefetch(' in ev and 'fetch(' not in ev:
        fp_ssrf.append(('prefetch_method', f)); continue
    # FP: GraphQL client.request
    if 'graphqlClient.request' in ev or 'graphql' in file.lower():
        fp_ssrf.append(('graphql_client', f)); continue
    # FP: Not actually HTTP - approval request persistence
    if '_persist_approval_request' in ev:
        fp_ssrf.append(('not_http', f)); continue
    # FP: handle_mcp_request
    if 'handle_mcp_request' in ev:
        fp_ssrf.append(('not_http', f)); continue
    # FP: Sentinel proxy filter check
    if 'filter.is_llm_request' in ev:
        fp_ssrf.append(('not_http', f)); continue
    # FP: transform_request
    if 'transform_request' in ev:
        fp_ssrf.append(('not_http', f)); continue
    # FP: GitHub model_dump for PR creation
    if 'model_dump' in ev or 'merge_pull_request' in ev:
        fp_ssrf.append(('not_http', f)); continue
    # FP: env.GITHUB_DO fetch (Durable Object)
    if 'GITHUB_DO' in ev:
        fp_ssrf.append(('not_http', f)); continue
    # FP: transport.request (MCP transport)
    if 'transport.request' in ev:
        fp_ssrf.append(('not_http', f)); continue
    # FP: ctx.http.get (SDK wrapper)
    if 'ctx.http.get' in ev:
        fp_ssrf.append(('sdk_wrapper', f)); continue
    # FP: code-mode-mcp this.fetch(params.arguments) - internal method
    if 'this.fetch(params.arguments)' in ev:
        fp_ssrf.append(('sdk_wrapper', f)); continue
    # FP: docspace-mcp this.c.fetch(req.v) - SDK client
    if 'this.c.fetch(req.v)' in ev or 'this.fetch(req.v)' in ev:
        fp_ssrf.append(('sdk_client', f)); continue
    # FP: _build_upstream_test_request (gateway building)
    if '_build_upstream_test_request' in ev:
        fp_ssrf.append(('not_http', f)); continue
    # FP: _make_vector_store_request (internal function)
    if '_make_vector_store_request' in ev:
        fp_ssrf.append(('not_http', f)); continue
    # FP: discord message fetch
    if '.fetch(input.messageId)' in ev or '.fetch(input.eventId)' in ev:
        fp_ssrf.append(('discord_sdk', f)); continue

    tp_ssrf.append(f)

print(f"=== SSRF_VULNERABILITY: {len(tp_ssrf)} TP, {len(fp_ssrf)} FP (of {len(ssrf)} total) ===")
print()
print("--- TRUE POSITIVES (sample) ---")
for f in tp_ssrf[:10]:
    print(f"  {f['server_name']:40s} | {f['file']}")
    print(f"    evidence: {f['evidence'][:120]}")
print(f"  ... and {len(tp_ssrf)-10} more" if len(tp_ssrf) > 10 else "")
print()
print("--- FALSE POSITIVE REASONS ---")
fp_ssrf_reasons = Counter(r for r,_ in fp_ssrf)
for r,c in fp_ssrf_reasons.most_common():
    print(f"  {r}: {c}")
    for reason, f in fp_ssrf:
        if reason == r:
            print(f"    {f['server_name']:35s} | {f['file'][:55]}")

##############################################
# PATH TRAVERSAL classification
##############################################
print("\n\n")
pt = [f for f in findings if f['id'] == 'PATH_TRAVERSAL']

tp_pt = []
fp_pt = []
for f in pt:
    ev = f['evidence']
    file = f['file']
    server = f['server_name']

    # FP: path.join(...args.parts) - just joining user parts, unclear context
    if 'path.join(...args.parts)' in ev:
        tp_pt.append(f); continue  # Actually could be TP - joins arbitrary parts
    # FP: params.path in OpenAPI spec builders
    if 'params.path, restPath' in ev and 'openapi' in ev.lower():
        fp_pt.append(('openapi_spec', f)); continue
    # FP: npath.join for URL building (not filesystem)
    if 'npath.join(this.url' in ev:
        fp_pt.append(('url_building', f)); continue
    # FP: Huge minified JS blob
    if len(ev) > 500 and ('svelte' in ev or 'function' in ev):
        fp_pt.append(('minified_js', f)); continue
    # FP: Static dataset path
    if 'locomo10.json' in ev:
        fp_pt.append(('static_path', f)); continue

    tp_pt.append(f)

print(f"=== PATH_TRAVERSAL: {len(tp_pt)} TP, {len(fp_pt)} FP (of {len(pt)} total) ===")
print()
print("--- TRUE POSITIVES ---")
for f in tp_pt:
    print(f"  {f['server_name']:40s} | {f['file']}")
    print(f"    evidence: {f['evidence'][:120]}")
print()
print("--- FALSE POSITIVE REASONS ---")
fp_pt_reasons = Counter(r for r,_ in fp_pt)
for r,c in fp_pt_reasons.most_common():
    print(f"  {r}: {c}")
    for reason, f in fp_pt:
        if reason == r:
            print(f"    {f['server_name']:35s} | {f['file'][:55]}")

##############################################
# OVERALL SUMMARY
##############################################
print("\n\n=== OVERALL SUMMARY ===")
total_tp = len(tp_ci) + len(tp_ssrf) + len(tp_pt)
total_fp = len(fp_ci) + len(fp_ssrf) + len(fp_pt)
print(f"Total TP: {total_tp}")
print(f"Total FP: {total_fp}")
print(f"Total: {total_tp + total_fp}")
print(f"TP Rate: {total_tp / (total_tp + total_fp) * 100:.1f}%")
print(f"FP Rate: {total_fp / (total_tp + total_fp) * 100:.1f}%")
