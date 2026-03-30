import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch
from matplotlib.ticker import FuncFormatter
from .utils.style_utils import setup_theme, save_plot, clean_spines, FRAMEWORK_COLORS, TEXT_COLOR

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

def guard_watch_vuln_table(data, OUT_DIR, FRAMEWORKS):
    setup_theme()
    rows = []

    for sev in SEVERITY_ORDER:
        rows.append({
            "Severity": sev,
            "mcp-guard": data.get("mcp-guard", {})
                                .get("vulnerabilities", {})
                                .get("counts", {})
                                .get(sev, 0),
            "mcp-watch": data.get("mcp-watch", {})
                                .get("vulnerabilities", {})
                                .get("counts", {})
                                .get(sev, 0),
        })

    df = pd.DataFrame(rows)

    # rimuove severity completamente vuote
    df = df[(df["mcp-guard"] > 0) | (df["mcp-watch"] > 0)]
    df.reset_index(drop=True, inplace=True)

    # Colors
    colors = {
        "mcp-guard": FRAMEWORK_COLORS["mcp-guard"],
        "mcp-watch": FRAMEWORK_COLORS["mcp-watch"],
    }

    # Plot
    severities = df["Severity"].tolist()
    guard_vals = df["mcp-guard"].tolist()
    watch_vals = df["mcp-watch"].tolist()

    x = np.arange(len(severities))
    bar_width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))

    for i, (g, w) in enumerate(zip(guard_vals, watch_vals)):
        bars = []

        if g > 0 and w > 0:
            bars.append(ax.bar(x[i] - bar_width / 2, g, bar_width, color=colors["mcp-guard"], edgecolor=None))
            bars.append(ax.bar(x[i] + bar_width / 2, w, bar_width, color=colors["mcp-watch"], edgecolor=None))
        elif g > 0:
            bars.append(ax.bar(x[i], g, bar_width, color=colors["mcp-guard"], edgecolor=None))
        elif w > 0:
            bars.append(ax.bar(x[i], w, bar_width, color=colors["mcp-watch"], edgecolor=None))

        # Labels
        for group in bars:
            if isinstance(group, list):
                # Should not happen with direct append logic above unless ax.bar returns list?
                # ax.bar returns BarContainer which is iterable
                group = [group]
            
            # bar is a Patch or container
            # Actually ax.bar returns a Container object
            for bar in group: # Iterating over the BarContainer
                 if hasattr(bar, 'get_height'): # It's a single bar if iterated like this? No, container is a list of rects
                     pass
            
            # Correct iteration:
            for rect in group: 
                h = rect.get_height()
                ax.text(
                    rect.get_x() + rect.get_width() / 2,
                    h + (h * 0.01),
                    f"{int(h):,}",
                    ha="center",
                    va="bottom",
                    fontsize=11,
                    fontweight="bold",
                    color=TEXT_COLOR
                )

    ax.set_xticks(x)
    ax.set_xticklabels([s.capitalize() for s in severities], fontsize=12, fontweight="bold")

    clean_spines(ax)
    ax.grid(False, axis="x")

    ax.set_title(
        f"Guard vs Watch Vulnerabilities",
        pad=20
    )

    y_max = max(max(guard_vals), max(watch_vals))
    ax.set_ylim(0, y_max * 1.15)

    # Legend
    legend_handles = [
        Patch(facecolor=colors["mcp-guard"], label="mcp-guard"),
        Patch(facecolor=colors["mcp-watch"], label="mcp-watch"),
    ]

    ax.legend(
        handles=legend_handles,
        loc="upper right",
        frameon=False,
        fontsize=11
    )

    save_plot("5. guard_watch_severity_counts.png", OUT_DIR)
