import pandas as pd
import matplotlib.pyplot as plt
from .utils.style_utils import setup_theme, save_plot, clean_spines, CAT_PALETTE, TEXT_COLOR

def hash_table(data, out_dir):
    setup_theme()
    
    hash_data = data.get("hash", {})

    total = hash_data.get("total", 0)
    unique = hash_data.get("unique", 0)
    duplicate = hash_data.get("duplicate", {}).get("total", 0)

    # Build DataFrame
    df = pd.DataFrame([
        {"Type": "Total", "Count": total},
        {"Type": "Unique", "Count": unique},
        {"Type": "Duplicate", "Count": duplicate},
    ])

    # Colors
    colors = {
        "Total": CAT_PALETTE[0],       # Blue
        "Unique": CAT_PALETTE[1],      # Green
        "Duplicate": CAT_PALETTE[7]    # Red
    }

    # Plot
    fig, ax = plt.subplots(figsize=(8, 6))

    bars = ax.bar(
        df["Type"],
        df["Count"],
        color=[colors[t] for t in df["Type"]],
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
            fontsize=12,
            fontweight="bold",
            color=TEXT_COLOR
        )

    clean_spines(ax)
    ax.set_title("Hash summary", pad=20)
    ax.grid(False, axis="x")
    ax.set_ylabel("Count", labelpad=10)

    # Adjust limits
    ax.set_ylim(0, max(1, total) * 1.15)

    save_plot("9. hash_summary.png", out_dir)
