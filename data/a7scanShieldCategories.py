import re
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter
from .utils.style_utils import setup_theme, save_plot, clean_spines, FRAMEWORK_COLORS, TEXT_COLOR, CAT_PALETTE

def normalize_category_two_words(cat: str) -> str:
    cat = cat.lower()
    cat = cat.replace("_", " ").replace("-", " ")
    cat = re.sub(r"[^a-z0-9 ]+", " ", cat)
    cat = re.sub(r"\s+", " ", cat).strip()

    words = cat.split()
    if not words:
        return "unknown"
    return " ".join(words[:2])

def scan_shield_single_framework_cat_table(data, OUT_DIR, framework):
    setup_theme()
    
    if framework == "mcp-scan":
        raw_categories = data.get("mcp-scan", {}).get("categories", {})
    elif framework == "mcp-shield":
        raw_categories = (
            data.get("mcp-shield", {})
            .get("tools", {})
            .get("vulnerable", {})
            .get("static-analysis", {})
            .get("categories", {})
        )
    else:
        return

    if not raw_categories:
        return

    aggregated = {}

    # Normalizzazione
    for cat, count in raw_categories.items():
        key = normalize_category_two_words(cat)
        aggregated[key] = aggregated.get(key, 0) + int(count)

    # DataFrame
    df = (
        pd.DataFrame(
            [{"Category": k, "Count": v} for k, v in aggregated.items()]
        )
        .sort_values("Count", ascending=False)
        .reset_index(drop=True)
    )

    categories = df["Category"].tolist()
    values = df["Count"].tolist()

    # Plot
    x = np.arange(len(categories))
    bar_width = 0.5

    fig, ax = plt.subplots(
        figsize=(max(10, len(categories) * 0.8), 6)
    )

    clean_spines(ax)
    ax.grid(False, axis="x")

    bars = ax.bar(
        x,
        values,
        width=bar_width,
        color=CAT_PALETTE[0],
        edgecolor=None
    )

    # Labels
    for bar in bars:
        h = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            h + (h * 0.01),
            f"{int(h)}",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
            color=TEXT_COLOR
        )

    # Assi
    ax.set_xticks(x)
    ax.set_xticklabels(
        categories,
        rotation=45,
        ha="right",
        fontsize=11,
        fontweight="bold"
    )

    # REMOVED LOG SCALE for consistency unless values are wildly different.
    # If log scale is needed, uncomment below lines
    # ax.set_yscale("log")
    # ax.yaxis.set_major_formatter(
    #    FuncFormatter(lambda y, _: f"{int(y):,}" if y >= 1 else "")
    # )

    y_max = max(values)
    ax.set_ylim(0, y_max * 1.15) if y_max > 0 else ax.set_ylim(0, 1)

    ax.set_title(
        f"{framework} vulnerabilities",
        pad=20
    )

    save_plot(f"7. {framework}_categories.png", OUT_DIR)
