import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch
from .utils.style_utils import setup_theme, save_plot, clean_spines, FRAMEWORK_COLORS, SEVERITY_COLORS, TEXT_COLOR, CAT_PALETTE

def scan_shield_tools_table(data, OUT_DIR, FRAMEWORKS):
    setup_theme()
    rows = []

    for fw in FRAMEWORKS:
        tools = data.get(fw, {}).get("tools", {})

        if fw == "mcp-shield":
            vulnerable = tools.get("vulnerable", {}).get("total", 0)
        else:
            vulnerable = tools.get("vulnerable", 0)

        rows.append({
            "Framework": fw,
            "Total": tools.get("total", 0),
            "Safe": tools.get("safe", 0),
            "Vulnerable": vulnerable,
        })

    df = pd.DataFrame(rows)

    # Standard colors for status
    colors = {
        "Total": CAT_PALETTE[0],       # Blue
        "Safe": CAT_PALETTE[1],        # Green
        "Vulnerable": CAT_PALETTE[7]   # Red (using index 7 which is Red in style_utils list)
    }
    metrics = ["Total", "Safe", "Vulnerable"]

    x = np.arange(len(df))
    bar_width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))

    for i, metric in enumerate(metrics):
        bars = ax.bar(
            x + (i - 1) * bar_width,
            df[metric],
            width=bar_width,
            color=colors[metric],
            label=metric,
            edgecolor=None
        )

        # Label formatting
        for bar in bars:
            h = bar.get_height()
            if h > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    h + (h * 0.01), # Slight offset
                    f"{int(h)}",
                    ha="center",
                    va="bottom",
                    fontsize=11,
                    fontweight="bold",
                    color=TEXT_COLOR
                )

    ax.set_xticks(x)
    ax.set_xticklabels(df["Framework"])
    clean_spines(ax)
    
    ax.set_title("Scan Shield tools", pad=20)
    ax.grid(False, axis="x")

    # Custom Legend
    legend_handles = [Patch(facecolor=colors[m], label=m) for m in metrics]
    ax.legend(
        handles=legend_handles,
        loc="upper right",
        frameon=False,
        fontsize=11
    )

    save_plot("6. scan_shield_tools_summary.png", OUT_DIR)
