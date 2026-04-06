import json
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

# ── Style ─────────────────────────────────────────────────────────────────
plt.rcParams.update({
    'figure.facecolor': '#FAFAFA',
    'axes.facecolor': '#FAFAFA',
    'axes.edgecolor': '#CCCCCC',
    'axes.grid': True,
    'grid.alpha': 0.3,
    'font.family': 'sans-serif',
    'font.size': 11,
    'axes.titlesize': 14,
    'axes.titleweight': 'bold',
    'figure.dpi': 150,
})

COLORS = ['#4C72B0', '#DD8452', '#55A868', '#C44E52', '#8172B3',
          '#937860', '#DA8BC3', '#8C8C8C', '#CCB974', '#64B5CD',
          '#E07B54', '#76B7B2', '#B07AA1', '#FF9DA7', '#9C755F']
SEVERITY_COLORS = {'critical': '#C44E52', 'high': '#DD8452', 'medium': '#CCB974',
                   'low': '#55A868', 'info': '#8C8C8C'}

BASE = r"C:\Users\francesco\Desktop\pipeline\analysis"

TOTAL_SERVERS = 60205


def save(fig, folder, name):
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{name}.png")
    fig.savefig(path, bbox_inches='tight', pad_inches=0.3)
    plt.close(fig)
    print(f"  OK {path}")


def load(tool_dir, filename):
    p = os.path.join(BASE, tool_dir, filename)
    with open(p, encoding='utf-8') as f:
        return json.load(f)


def pie_chart(labels, sizes, title, folder, fname, threshold_pct=3):
    """Pie chart that groups tiny slices into 'Other'."""
    total = sum(sizes)
    if total == 0:
        return
    main_l, main_s, other = [], [], 0
    for l, s in sorted(zip(labels, sizes), key=lambda x: -x[1]):
        if (s / total * 100) >= threshold_pct:
            main_l.append(l)
            main_s.append(s)
        else:
            other += s
    if other > 0:
        main_l.append('Other')
        main_s.append(other)
    fig, ax = plt.subplots(figsize=(8, 6))
    wedges, texts, autotexts = ax.pie(
        main_s, labels=None, autopct='%1.1f%%', colors=COLORS[:len(main_s)],
        startangle=140, pctdistance=0.8,
        wedgeprops=dict(edgecolor='white', linewidth=1.5))
    for t in autotexts:
        t.set_fontsize(9)
    ax.legend(main_l, loc='center left', bbox_to_anchor=(1, 0.5), fontsize=9)
    ax.set_title(title)
    save(fig, folder, fname)


def hbar_chart(labels, values, title, folder, fname, xlabel='Count', max_bars=12, color=None):
    """Horizontal bar chart, top N bars."""
    if not values:
        return
    pairs = sorted(zip(labels, values), key=lambda x: x[1], reverse=True)[:max_bars]
    pairs.reverse()
    lbls = [p[0][:55] for p in pairs]
    vals = [p[1] for p in pairs]
    fig, ax = plt.subplots(figsize=(10, max(4, len(lbls) * 0.45)))
    c = color if color else COLORS[0]
    ax.barh(range(len(lbls)), vals, color=c, edgecolor='white', height=0.6)
    ax.set_yticks(range(len(lbls)))
    ax.set_yticklabels(lbls, fontsize=9)
    ax.set_xlabel(xlabel)
    ax.set_title(title)
    for i, v in enumerate(vals):
        ax.text(v + max(vals) * 0.01, i, f'{v:,.0f}', va='center', fontsize=8)
    save(fig, folder, fname)


def severity_bar(counts, title, folder, fname):
    """Stacked or grouped severity bar."""
    order = ['critical', 'high', 'medium', 'low', 'info']
    labels = [k for k in order if k in counts]
    vals = [counts[k] for k in labels]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, vals, color=[SEVERITY_COLORS.get(l, '#8C8C8C') for l in labels],
                  edgecolor='white', linewidth=1.2)
    ax.set_title(title)
    ax.set_ylabel('Count')
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(vals) * 0.01,
                f'{v:,}', ha='center', va='bottom', fontsize=10, fontweight='bold')
    save(fig, folder, fname)


def lang_chart(langs, title, folder, fname):
    """Language distribution pie."""
    labels = list(langs.keys())
    sizes = list(langs.values())
    pie_chart(labels, sizes, title, folder, fname, threshold_pct=2)


# ═══════════════════════════════════════════════════════════════════════════
# 0) CROSS-TOOL COMPARISON (saved once in common_tables/)
# ═══════════════════════════════════════════════════════════════════════════
COMMON = os.path.join(BASE, 'common_tables')
print("=" * 60)
print("CROSS-TOOL COMPARISON CHARTS")
print("=" * 60)

tool_names = ['MCP Guard', 'MCP Check', 'MCP Scan\n(Snyk)', 'MCP Security\nScan', 'MCP Shield', 'MCP Watch', 'Fuzzing']
tool_totals = [56407, 34404, 10710, 54973, 11456, 46982, 6035]
tool_pcts = [t / TOTAL_SERVERS * 100 for t in tool_totals]

# Coverage comparison
fig, ax = plt.subplots(figsize=(12, 6))
bars = ax.bar(range(len(tool_names)), tool_pcts, color=COLORS[:len(tool_names)],
              edgecolor='white', linewidth=1.2)
ax.set_xticks(range(len(tool_names)))
ax.set_xticklabels(tool_names, fontsize=10)
ax.set_ylabel('Coverage (%)')
ax.set_title(f'Server Coverage per Tool (out of {TOTAL_SERVERS:,} total servers)')
ax.set_ylim(0, 105)
for bar, pct, total in zip(bars, tool_pcts, tool_totals):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
            f'{pct:.1f}%\n({total:,})', ha='center', va='bottom', fontsize=9)

save(fig, COMMON, '00_cross_tool_coverage')

# Vulnerability volume comparison (log scale) — ALL 7 TOOLS
# MCP Check: 100,926 failed tests as proxy; Fuzzing: 181,745 exceptions as proxy
vuln_totals = [561632, 100926, 5352, 61800, 6832, 9911265, 181745]
vuln_labels = ['Vulnerabilities', 'Failed Tests', 'Vulnerabilities', 'Vulnerabilities',
               'Vulnerabilities', 'Vulnerabilities', 'Exceptions']

fig, ax = plt.subplots(figsize=(13, 6))
bars = ax.bar(range(len(tool_names)), vuln_totals,
              color=COLORS[:len(tool_names)], edgecolor='white', linewidth=1.2)
ax.set_yscale('log')
ax.set_xticks(range(len(tool_names)))
ax.set_xticklabels(tool_names, fontsize=10)
ax.set_ylabel('Total Issues Found (log scale)')
ax.set_title('Total Issues Reported per Tool (all 7 tools)')
for bar, v, lbl in zip(bars, vuln_totals, vuln_labels):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.4,
            f'{v:,}', ha='center', va='bottom', fontsize=9, fontweight='bold')
# Add footnote
ax.annotate('* MCP Check counts failed tests; Fuzzing counts exceptions (not vulnerability classifications)',
            xy=(0.5, -0.12), xycoords='axes fraction', ha='center', fontsize=8, fontstyle='italic', color='#666666')

save(fig, COMMON, '00_cross_tool_vulnerabilities')

# Average issues per server comparison — ALL 7 TOOLS
# MCP Check: 100926/34404=2.93; Fuzzing: 181745/6035=30.12
avg_vulns = [9.96, 2.93, 0.5, 1.12, 0.6, 210.96, 30.12]
avg_labels = ['vulns/server', 'fails/server', 'vulns/server', 'vulns/server',
              'vulns/server', 'vulns/server', 'exceptions/server']

fig, ax = plt.subplots(figsize=(13, 6))
bars = ax.bar(range(len(tool_names)), avg_vulns,
              color=COLORS[:len(tool_names)], edgecolor='white', linewidth=1.2)
ax.set_yscale('log')
ax.set_xticks(range(len(tool_names)))
ax.set_xticklabels(tool_names, fontsize=10)
ax.set_ylabel('Avg Issues per Server (log scale)')
ax.set_title('Average Issues per Server — Tool Comparison (all 7 tools)')
for bar, v in zip(bars, avg_vulns):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.4,
            f'{v:.2f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
ax.annotate('* MCP Check = failed tests/server; Fuzzing = exceptions/server',
            xy=(0.5, -0.12), xycoords='axes fraction', ha='center', fontsize=8, fontstyle='italic', color='#666666')

save(fig, COMMON, '00_cross_tool_avg_vulns')

# Estimated false positive rate comparison — ALL 7 TOOLS
# Fuzzing: N/A conceptually, but shown as 0 with a special annotation
fp_names = ['MCP Guard', 'MCP Check', 'MCP Scan\n(Snyk)', 'MCP Security\nScan', 'MCP Shield', 'MCP Watch', 'Fuzzing']
fp_rates = [75, 7.5, 20, 27.5, 65, 95, 0]
fp_colors = COLORS[:7]

fig, ax = plt.subplots(figsize=(13, 6))
bars = ax.bar(range(len(fp_names)), fp_rates, color=fp_colors,
              edgecolor='white', linewidth=1.2)
ax.set_xticks(range(len(fp_names)))
ax.set_xticklabels(fp_names, fontsize=10)
ax.set_ylabel('Estimated False Positive Rate (%)')
ax.set_title('Estimated False Positive Rate per Tool (all 7 tools)')
ax.set_ylim(0, 115)
ax.axhline(y=50, color='red', linestyle='--', alpha=0.5, label='50% threshold')
ax.legend()
for i, (bar, v) in enumerate(zip(bars, fp_rates)):
    if i == 6:  # Fuzzing — N/A
        ax.text(bar.get_x() + bar.get_width() / 2, 3,
                'N/A', ha='center', va='bottom', fontsize=11, fontweight='bold', color='#666666')
    else:
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                f'{v}%', ha='center', va='bottom', fontsize=11, fontweight='bold')
ax.annotate('* Fuzzing does not classify vulnerabilities, so false positive rate is not applicable',
            xy=(0.5, -0.10), xycoords='axes fraction', ha='center', fontsize=8, fontstyle='italic', color='#666666')

save(fig, COMMON, '00_cross_tool_false_positives')


# ═══════════════════════════════════════════════════════════════════════════
# 1) MCP GUARD
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("MCP GUARD")
print("=" * 60)

d = load('0_tool_mcp_guard', 'mcp_guard_stats.json')
g = d['mcp-guard']
out = os.path.join(BASE, '0_tool_mcp_guard', 'tables')

# Language distribution
lang_chart(g['languages'], 'MCP Guard — Language Distribution of Analyzed Servers', out, '01_languages')

# Severity distribution
severity_bar(g['vulnerabilities']['counts'], 'MCP Guard — Vulnerability Severity Distribution', out, '02_severity')

# Top vulnerability categories (grouped)
cats_grouped = g['percentage_of_vulnerability_grouped']
top_cats = {k: v for k, v in sorted(cats_grouped.items(), key=lambda x: -x[1])[:15]}
labels_clean = [k.replace('---', ' - ').replace('-', ' ').replace(':', ': ').title()[:55] for k in top_cats.keys()]
hbar_chart(labels_clean, list(top_cats.values()),
           'MCP Guard — Top 15 Vulnerability Categories (%)',
           out, '03_top_categories', xlabel='Percentage (%)', max_bars=15, color=COLORS[0])

# Analysis type breakdown
at = g['analysis_types']
fig, ax = plt.subplots(figsize=(8, 5))
types = ['Static', 'Dynamic\n(simulated)', 'Fuzzing', 'Protocol']
vals = [at.get('static', {}).get('total', 0), at.get('dynamic', {}).get('total', 0),
        at.get('fuzzing', {}).get('total', 0), at.get('protocol', {}).get('total', 0)]
bars = ax.bar(types, vals, color=[COLORS[0], COLORS[1], COLORS[2], COLORS[3]], edgecolor='white')
ax.set_title('MCP Guard — Servers per Analysis Type')
ax.set_ylabel('Servers')
for bar, v in zip(bars, vals):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 500,
            f'{v:,}', ha='center', fontsize=10, fontweight='bold')
save(fig, out, '04_analysis_types')

# Static vs Dynamic vs Fuzzing categories (top 8 each)
cats_s = g.get('categories_static', {})
cats_d = g.get('categories_dynamic', {})
cats_rf = g.get('categories_fuzzing', {})

for label, cats, idx in [('Static', cats_s, 5), ('Dynamic (Simulated)', cats_d, 6), ('Fuzzing', cats_rf, 7)]:
    top = dict(sorted(cats.items(), key=lambda x: -x[1])[:10])
    clean = [k.replace('---', ' - ').replace('-', ' ').title()[:50] for k in top.keys()]
    hbar_chart(clean, list(top.values()),
               f'MCP Guard — {label} Analysis: Top Categories',
               out, f'0{idx}_{label.lower().replace(" ", "_").replace("(","").replace(")","")}', max_bars=10)

# Failure reasons
fr = g['failure_reasons']['counts']
pie_chart(list(fr.keys()), list(fr.values()), 'MCP Guard — Failure Reasons', out, '08_failure_reasons', threshold_pct=1)


# ═══════════════════════════════════════════════════════════════════════════
# 2) MCP CHECK
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("MCP CHECK")
print("=" * 60)

d = load('0_tool_mcp_check', 'mcp_check_stats.json')
c = d['mcp-check']
out = os.path.join(BASE, '0_tool_mcp_check', 'tables')

# Language distribution
lang_chart(c['languages'], 'MCP Check — Language Distribution of Analyzed Servers', out, '01_languages')

# Suite results (grouped bar)
suites = c['suites']
fig, ax = plt.subplots(figsize=(10, 6))
suite_names = list(suites.keys())
x = np.arange(len(suite_names))
w = 0.25
passed_vals = [suites[s]['passed'] for s in suite_names]
failed_vals = [suites[s]['failed'] for s in suite_names]
warning_vals = [suites[s]['warnings'] for s in suite_names]

ax.bar(x - w, passed_vals, w, label='Passed', color='#55A868', edgecolor='white')
ax.bar(x, failed_vals, w, label='Failed', color='#C44E52', edgecolor='white')
ax.bar(x + w, warning_vals, w, label='Warnings', color='#CCB974', edgecolor='white')
ax.set_xticks(x)
ax.set_xticklabels([s.replace('-', ' ').title() for s in suite_names], fontsize=10)
ax.set_ylabel('Count')
ax.set_title('MCP Check — Test Results by Suite')
ax.legend()
save(fig, out, '02_suite_results')

# Overall test results pie
tests = c['tests']
pie_chart(['Passed', 'Failed', 'Skipped', 'Warnings'],
          [tests['passed'], tests['failed'], tests['skipped'], tests['warnings']],
          f'MCP Check — Overall Test Results (n={tests["total"]:,})',
          out, '03_test_results_pie', threshold_pct=0.5)

# Top error types
errors = c['errors']
top_errs = dict(sorted(errors.items(), key=lambda x: -x[1])[:12])
labels_e = [k[:60] for k in top_errs.keys()]
hbar_chart(labels_e, list(top_errs.values()),
           'MCP Check — Top 12 Error Types',
           out, '04_top_errors', max_bars=12, color=COLORS[1])

# Pass rate gauge
fig, ax = plt.subplots(figsize=(6, 4))
rate = tests['success_rate']
ax.barh(0, rate, color='#55A868', height=0.5, edgecolor='white')
ax.barh(0, 100 - rate, left=rate, color='#C44E52', height=0.5, edgecolor='white')
ax.set_xlim(0, 100)
ax.set_yticks([])
ax.set_xlabel('Success Rate (%)')
ax.set_title(f'MCP Check — Overall Success Rate: {rate:.1f}%')
ax.axvline(x=50, color='gray', linestyle='--', alpha=0.5)
save(fig, out, '05_success_rate')


# ═══════════════════════════════════════════════════════════════════════════
# 3) MCP SCAN (Snyk)
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("MCP SCAN (Snyk)")
print("=" * 60)

d = load('0_tool_mcp_scan', 'mcp_scan_stats.json')
s = d['mcp-scan']
out = os.path.join(BASE, '0_tool_mcp_scan', 'tables')

# Language distribution
lang_chart(s['languages'], 'MCP Scan (Snyk) — Language Distribution', out, '01_languages')

# Overall severity
severity_bar(s['vulnerabilities']['counts'], 'MCP Scan (Snyk) — Vulnerability Severity Distribution', out, '02_severity')

# Server vs Tool vulnerabilities comparison
fig, ax = plt.subplots(figsize=(8, 5))
sv = s['server_vulnerabilities']
tv = s['tool_vulnerabilities']
x = np.arange(2)
w = 0.35
sv_vals = [sv['counts'].get('medium', 0), sv['counts'].get('low', 0)]
tv_vals = [tv['counts'].get('critical', 0), tv['counts'].get('low', 0)]

# Stacked bars for server and tool
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# Server vulnerabilities
sv_cats = sv['categories']
ax1.pie(list(sv_cats.values()), labels=[k.replace('-', ' ').title() for k in sv_cats.keys()],
        autopct='%1.1f%%', colors=[COLORS[1], COLORS[2]], startangle=140,
        wedgeprops=dict(edgecolor='white', linewidth=1.5))
ax1.set_title(f'Server-Level Vulnerabilities\n(n={sv["total"]:,})')

# Tool vulnerabilities
tv_cats = tv['categories']
ax2.pie(list(tv_cats.values()), labels=[k.replace('-', ' ').title() for k in tv_cats.keys()],
        autopct='%1.1f%%', colors=[COLORS[3], COLORS[4]], startangle=140,
        wedgeprops=dict(edgecolor='white', linewidth=1.5))
ax2.set_title(f'Tool-Level Vulnerabilities\n(n={tv["total"]:,})')

fig.suptitle('MCP Scan (Snyk) — Server vs Tool Vulnerabilities', fontsize=14, fontweight='bold', y=1.02)
save(fig, out, '03_server_vs_tool')

# Trigger words
tw = tv.get('trigger_words', {})
if tw:
    fig, ax = plt.subplots(figsize=(8, 5))
    sorted_tw = sorted(tw.items(), key=lambda x: -x[1])
    ax.bar([t[0] for t in sorted_tw], [t[1] for t in sorted_tw],
           color=COLORS[:len(sorted_tw)], edgecolor='white')
    ax.set_title('MCP Scan (Snyk) — W001 Trigger Words Distribution')
    ax.set_ylabel('Occurrences')
    for i, (word, count) in enumerate(sorted_tw):
        ax.text(i, count + 10, str(count), ha='center', fontsize=9, fontweight='bold')
    save(fig, out, '04_trigger_words')

# Safe vs vulnerable tools
tools = s['tools']
fig, ax = plt.subplots(figsize=(7, 5))
ax.pie([tools['safe'], tools['vulnerable']],
       labels=['Safe', 'Vulnerable'], autopct='%1.1f%%',
       colors=['#55A868', '#C44E52'], startangle=140,
       wedgeprops=dict(edgecolor='white', linewidth=2))
ax.set_title(f'MCP Scan (Snyk) — Tool Safety (n={tools["total"]:,})')
save(fig, out, '05_tools_safe_vulnerable')

# Issue codes
fig, ax = plt.subplots(figsize=(8, 5))
sv_codes = sv.get('issue_codes', {})
tv_codes = tv.get('issue_codes', {})
all_codes = {}
for k, v in sv_codes.items():
    all_codes[k] = all_codes.get(k, 0) + v
for k, v in tv_codes.items():
    all_codes[k] = all_codes.get(k, 0) + v
sorted_codes = sorted(all_codes.items(), key=lambda x: -x[1])
ax.bar([c[0] for c in sorted_codes], [c[1] for c in sorted_codes],
       color=COLORS[:len(sorted_codes)], edgecolor='white')
ax.set_title('MCP Scan (Snyk) — Finding Codes Distribution')
ax.set_ylabel('Count')
for i, (code, count) in enumerate(sorted_codes):
    ax.text(i, count + 30, f'{count:,}', ha='center', fontsize=10, fontweight='bold')
save(fig, out, '06_issue_codes')


# ═══════════════════════════════════════════════════════════════════════════
# 4) MCP SECURITY SCAN
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("MCP SECURITY SCAN")
print("=" * 60)

d = load('0_tool_mcp_security_scan', 'mcp_security_scan_stats.json')
ss = d['mcp-security-scan']
out = os.path.join(BASE, '0_tool_mcp_security_scan', 'tables')

# Language distribution
lang_chart(ss['languages'], 'MCP Security Scan — Language Distribution', out, '01_languages')

# Severity distribution
severity_bar(ss['vulnerabilities']['counts'], 'MCP Security Scan — Vulnerability Severity', out, '02_severity')

# Categories: passed vs failed (side by side)
cats_fail = ss['categories']
cats_pass = ss['categories_passed']
all_cats = sorted(set(list(cats_fail.keys()) + list(cats_pass.keys())))
# Remove init error for readability
security_cats = [c for c in all_cats if c != 'initialization-error']

fig, ax = plt.subplots(figsize=(12, 6))
x = np.arange(len(security_cats))
w = 0.35
p_vals = [cats_pass.get(c, 0) for c in security_cats]
f_vals = [cats_fail.get(c, 0) for c in security_cats]
ax.bar(x - w/2, p_vals, w, label='Passed', color='#55A868', edgecolor='white')
ax.bar(x + w/2, f_vals, w, label='Failed', color='#C44E52', edgecolor='white')
ax.set_xticks(x)
ax.set_xticklabels([c.replace('-', ' ').title() for c in security_cats], rotation=45, ha='right', fontsize=9)
ax.set_ylabel('Count')
ax.set_title('MCP Security Scan — Passed vs Failed by Category (excl. init errors)')
ax.legend()
save(fig, out, '03_categories_pass_fail')

# Categories distribution (excl init error)
cats_no_init = {k: v for k, v in cats_fail.items() if k != 'initialization-error'}
pie_chart([k.replace('-', ' ').title() for k in cats_no_init.keys()],
          list(cats_no_init.values()),
          'MCP Security Scan — Vulnerability Categories\n(excl. initialization errors)',
          out, '04_categories_pie', threshold_pct=2)

# Findings overview
findings = ss['findings']
fig, ax = plt.subplots(figsize=(7, 5))
ax.pie([findings['passed'], findings['failed']],
       labels=['Passed', 'Failed'], autopct='%1.1f%%',
       colors=['#55A868', '#C44E52'], startangle=140,
       wedgeprops=dict(edgecolor='white', linewidth=2))
ax.set_title(f'MCP Security Scan — Overall Findings (n={findings["total"]:,})')
save(fig, out, '05_findings_overview')


# ═══════════════════════════════════════════════════════════════════════════
# 5) MCP SHIELD
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("MCP SHIELD")
print("=" * 60)

d = load('0_tool_mcp_shield', 'mcp_shield_stats.json')
sh = d['mcp-shield']
out = os.path.join(BASE, '0_tool_mcp_shield', 'tables')

# Language distribution
lang_chart(sh['languages'], 'MCP Shield — Language Distribution', out, '01_languages')

# Safe vs vulnerable tools
tools = sh['tools']
fig, ax = plt.subplots(figsize=(7, 5))
ax.pie([tools['safe'], tools['vulnerable']['total']],
       labels=['Safe', 'Vulnerable'], autopct='%1.1f%%',
       colors=['#55A868', '#C44E52'], startangle=140,
       wedgeprops=dict(edgecolor='white', linewidth=2))
ax.set_title(f'MCP Shield — Tool Safety (n={tools["total"]:,})')
save(fig, out, '02_tools_safe_vulnerable')

# Static analysis categories
sa = tools['vulnerable']['static-analysis']
sa_cats = sa['categories']
# Filter out noise entries
sa_cats_clean = {k: v for k, v in sa_cats.items() if v > 5}
pie_chart([k.replace('-', ' ').title() for k in sa_cats_clean.keys()],
          list(sa_cats_clean.values()),
          'MCP Shield — Static Analysis: Vulnerability Categories',
          out, '03_static_categories', threshold_pct=3)

# Static analysis severity
sa_sev = sa['counts']
severity_bar(sa_sev, 'MCP Shield — Static Analysis Severity', out, '04_static_severity')

# LLM description analysis
llm = tools['vulnerable']['llm-description-analysis']
fig, ax = plt.subplots(figsize=(7, 5))
llm_labels = list(llm.keys())
llm_vals = list(llm.values())
llm_colors = [SEVERITY_COLORS.get(l.lower(), '#8C8C8C') for l in llm_labels]
ax.bar(llm_labels, llm_vals, color=llm_colors, edgecolor='white', linewidth=1.2)
ax.set_title('MCP Shield — LLM Description Analysis Results')
ax.set_ylabel('Count')
for i, v in enumerate(llm_vals):
    ax.text(i, v + 50, f'{v:,}', ha='center', fontsize=11, fontweight='bold')
save(fig, out, '05_llm_analysis')


# ═══════════════════════════════════════════════════════════════════════════
# 6) MCP WATCH
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("MCP WATCH")
print("=" * 60)

d = load('0_tool_mcp_watch', 'mcp_watch_stats.json')
w = d['mcp-watch']
out = os.path.join(BASE, '0_tool_mcp_watch', 'tables')

# Language distribution
lang_chart(w['languages'], 'MCP Watch — Language Distribution', out, '01_languages')

# Severity distribution
severity_bar(w['vulnerabilities']['counts'], 'MCP Watch — Vulnerability Severity', out, '02_severity')

# Categories distribution
cats = w['categories']
pie_chart([k.replace('-', ' ').title() for k in cats.keys()],
          list(cats.values()),
          'MCP Watch — Vulnerability Categories',
          out, '03_categories_pie', threshold_pct=2)

# Categories bar chart (log scale due to extreme variance)
sorted_cats = sorted(cats.items(), key=lambda x: -x[1])
fig, ax = plt.subplots(figsize=(12, 6))
cat_labels = [k.replace('-', ' ').title() for k, v in sorted_cats]
cat_vals = [v for k, v in sorted_cats]
bars = ax.bar(range(len(cat_labels)), cat_vals, color=COLORS[:len(cat_labels)], edgecolor='white')
ax.set_yscale('log')
ax.set_xticks(range(len(cat_labels)))
ax.set_xticklabels(cat_labels, rotation=45, ha='right', fontsize=9)
ax.set_ylabel('Count (log scale)')
ax.set_title('MCP Watch — Vulnerability Categories (log scale)')
for bar, v in zip(bars, cat_vals):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.3,
            f'{v:,}', ha='center', va='bottom', fontsize=7, rotation=45)
save(fig, out, '04_categories_bar_log')

# Failure reasons
fr = w['failure_reasons']['counts']
pie_chart(list(fr.keys()), list(fr.values()),
          f'MCP Watch — Failure Reasons (n={w["failure_reasons"]["total"]:,})',
          out, '05_failure_reasons', threshold_pct=1)


# ═══════════════════════════════════════════════════════════════════════════
# 7) FUZZING
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("FUZZING")
print("=" * 60)

d = load('0_tool_fuzzing', 'fuzzing_stats.json')
fz = d['fuzzing']
out = os.path.join(BASE, '0_tool_fuzzing', 'tables')

# Language distribution
lang_chart(fz['languages'], 'Fuzzing — Language Distribution', out, '01_languages')

# Tool fuzzing: success vs exceptions
fig, ax = plt.subplots(figsize=(7, 5))
ax.pie([fz['total_successful'], fz['total_exceptions']],
       labels=['Successful', 'Exceptions'], autopct='%1.1f%%',
       colors=['#55A868', '#C44E52'], startangle=140,
       wedgeprops=dict(edgecolor='white', linewidth=2))
ax.set_title(f'Fuzzing — Tool Invocation Results\n(n={fz["total_fuzzing_runs"]:,} runs)')
save(fig, out, '02_tool_fuzzing_results')

# Exception types
exc = fz['exceptions_by_message']
pie_chart(list(exc.keys()), list(exc.values()),
          'Fuzzing — Exception Types', out, '03_exception_types', threshold_pct=2)

# Protocol fuzzing success rates
proto = fz['protocol_types']['by_type']
proto_names = list(proto.keys())
proto_rates = [proto[p]['success_rate'] for p in proto_names]

fig, ax = plt.subplots(figsize=(10, 7))
y = np.arange(len(proto_names))
colors_p = ['#55A868' if r > 0 else '#C44E52' for r in proto_rates]
ax.barh(y, proto_rates, color=colors_p, edgecolor='white', height=0.6)
ax.set_yticks(y)
ax.set_yticklabels([p.replace('Request', '').replace('Notification', ' (Notif)') for p in proto_names], fontsize=9)
ax.set_xlabel('Success Rate (%)')
ax.set_title('Fuzzing — Protocol Message Type Success Rates')
for i, r in enumerate(proto_rates):
    if r > 0:
        ax.text(r + 0.3, i, f'{r:.1f}%', va='center', fontsize=9, fontweight='bold')
save(fig, out, '04_protocol_success_rates')

# Overall stats summary
fig, ax = plt.subplots(figsize=(8, 4))
ax.axis('off')
summary_data = [
    ['Total Servers', f'{fz["total_servers"]:,}'],
    ['Total Tools', f'{fz["total_tools"]:,}'],
    ['Total Fuzzing Runs', f'{fz["total_fuzzing_runs"]:,}'],
    ['Tool Fuzzing Success Rate', f'{fz["success_rate"]*100:.1f}%'],
    ['Protocol Fuzzing Success Rate', f'{fz["protocol_types"]["success_rate"]:.1f}%'],
    ['Safety Blocked', f'{fz["total_safety_blocked"]}'],
]
table = ax.table(cellText=summary_data, colLabels=['Metric', 'Value'],
                 loc='center', cellLoc='center')
table.auto_set_font_size(False)
table.set_fontsize(11)
table.scale(1, 1.8)
for (row, col), cell in table.get_celld().items():
    if row == 0:
        cell.set_facecolor('#4C72B0')
        cell.set_text_props(color='white', fontweight='bold')
    else:
        cell.set_facecolor('#F0F0F0' if row % 2 == 0 else 'white')
ax.set_title('Fuzzing — Summary Statistics', fontsize=14, fontweight='bold', pad=20)
save(fig, out, '05_summary_table')


print("\n" + "=" * 60)
print("ALL CHARTS GENERATED SUCCESSFULLY!")
print("=" * 60)
