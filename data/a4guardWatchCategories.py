import json
import re
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
from matplotlib.patches import Patch
from .utils.style_utils import setup_theme, save_plot, clean_spines, FRAMEWORK_COLORS, TEXT_COLOR, CAT_PALETTE

def normalize_category_two_words(cat: str) -> str:
    """
    Normalizza una categoria:
    - lowercase
    - '_' e '-' → spazio
    - rimuove simboli strani
    - restituisce SOLO le prime due parole
    """
    cat = cat.lower()
    cat = cat.replace("_", " ")
    cat = cat.replace("-", " ")
    cat = re.sub(r"[^a-z0-9 ]+", " ", cat)
    cat = re.sub(r"\s+", " ", cat).strip()

    words = cat.split()
    if not words:
        return "unknown"
    return " ".join(words[:2])

def single_framework_cat_table(data, OUT_DIR, framework):
    setup_theme()
    
    raw_categories = data.get(framework, {}).get("categories", {})
    aggregated = {}

    # Normalizzazione categorie
    for cat, count in raw_categories.items():
        key = normalize_category_two_words(cat)
        aggregated[key] = aggregated.get(key, 0) + int(count)

    # --- CORREZIONE: Controllo se ci sono dati ---
    if not aggregated:
        print(f"Skipping plot for {framework}: No categories found.")
        return
    # ---------------------------------------------

    # DataFrame (ora siamo sicuri che 'aggregated' non è vuoto)
    df = (
        pd.DataFrame(
            [{"Category": k, "Count": v} for k, v in aggregated.items()]
        )
        .sort_values("Count", ascending=False)
        .reset_index(drop=True)
    )

    categories = df["Category"].tolist()
    values = df["Count"].tolist()

    x = np.arange(len(categories))
    bar_width = 0.6

    # Dynamic width based on category count
    fig, ax = plt.subplots(
        figsize=(max(10, len(categories) * 0.8), 6)
    )

    clean_spines(ax)
    ax.grid(False, axis="x")

    bars = ax.bar(
        x,
        values,
        width=bar_width,
        color=CAT_PALETTE[0], # Blue (palette index 0) forced
        edgecolor=None
    )

    # Labels sopra le barre
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

    # Explicitly remove/hide labels as requested
    ax.set_xlabel("")
    ax.set_ylabel("")

    # Y lineare + margine sopra
    y_max = max(values)
    ax.set_ylim(0, y_max * 1.15)

    ax.set_title(
        f"{framework} vulnerability categories",
        pad=20
    )

    save_plot(f"4. {framework}_categories.png", OUT_DIR)
