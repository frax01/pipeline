import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch
from .utils.style_utils import setup_theme, save_plot, clean_spines, CAT_PALETTE, TEXT_COLOR

def framework_languages_table(data, OUT_DIR):
    setup_theme()
    
    # 1. Costruzione DataFrame
    rows = []
    frameworks = ["mcp-guard", "mcp-watch", "fuzzing", "mcp-scan", "mcp-shield"]
    
    for fw in frameworks:
        langs = data.get(fw, {}).get("languages", {})
        for lang, count in langs.items():
            # Trasforma 'docker' in 'unknown'
            display_lang = "unknown" if lang.lower() == "docker" else lang
            rows.append({
                "Framework": fw,
                "Language": display_lang,
                "Servers": count
            })
    
    df = pd.DataFrame(rows)
    
    # 2. Pivot
    pivot_df = df.pivot_table(
        index="Framework",
        columns="Language",
        values="Servers",
        fill_value=0
    )

    desired_order = ["mcp-guard", "mcp-watch", "fuzzing", "mcp-scan", "mcp-shield"]
    pivot_df = pivot_df.reindex(desired_order).fillna(0)

    # ordine linguaggi per frequenza globale
    languages = (
        pivot_df.sum()
        .sort_values(ascending=False)
        .index
        .tolist()
    )
    
    pivot_df = pivot_df[languages]
    
    # 3. Colors from consistent category palette
    colors = {lang: CAT_PALETTE[i % len(CAT_PALETTE)] for i, lang in enumerate(languages)}
    
    # 4. Grouped bar chart
    framework_labels = pivot_df.index.tolist()
    x = np.arange(len(framework_labels))
    bar_width = 0.2
    
    plt.figure(figsize=(10, 6))
    ax = plt.gca()
    
    clean_spines(ax)
    ax.grid(False, axis="x")

    for fw_idx, fw in enumerate(framework_labels):
        fw_values = pivot_df.loc[fw]
        active_langs = fw_values[fw_values > 0]
    
        n = len(active_langs)
        if n == 0:
            continue
        
        offsets = np.linspace(
            -bar_width * (n - 1) / 2,
            bar_width * (n - 1) / 2,
            n
        )
    
        for offset, (lang, value) in zip(offsets, active_langs.items()):
            ax.bar(
                x[fw_idx] + offset,
                value,
                width=bar_width,
                color=colors[lang],
                edgecolor=None
            )
    
            ax.text(
                x[fw_idx] + offset,
                value,
                f"{int(value)}",
                ha="center",
                va="bottom",
                fontsize=9,
                fontweight='bold',
                color=TEXT_COLOR
            )
    
    # Space above highest bar
    max_value = pivot_df.values.max()
    padding = max(1, max_value * 0.1)
    ax.set_ylim(0, max_value + padding)

    # 5. Axis and Title
    ax.set_xticks(x)
    ax.set_xticklabels(framework_labels)

    total_servers = data.get("total", sum(data["languages"].values()))

    ax.set_title(
        f"Languages per Framework (Total: {total_servers})",
        pad=20
    )
    
    # 6. Legend
    legend_handles = [
        Patch(facecolor=colors[lang], label=lang)
        for lang in languages
    ]
    
    ax.legend(
        handles=legend_handles,
        title="Languages",
        bbox_to_anchor=(1.02, 1),
        loc="upper left",
        frameon=False,
        fontsize=10,
        title_fontsize=11
    )
    
    save_plot("3. framework_languages.png", OUT_DIR)
