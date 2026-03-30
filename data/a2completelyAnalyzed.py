import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from .utils.style_utils import setup_theme, adaptive_figsize, save_plot, add_bar_labels, clean_spines, CAT_PALETTE, TEXT_COLOR

def completely_analyzed_table(data, OUT_DIR):    
    setup_theme()
    
    # Trasforma 'docker' in 'unknown'
    languages_data = {}
    for lang, count in data["completely-analyzed-servers"]["languages"].items():
        display_lang = "unknown" if lang.lower() == "docker" else lang
        languages_data[display_lang] = languages_data.get(display_lang, 0) + count
    
    lang_df = (
        pd.Series(languages_data)
        .reset_index()
        .rename(columns={"index": "Language", 0: "Servers"})
        .sort_values("Servers", ascending=False)
    )

    plt.figure(figsize=adaptive_figsize(len(lang_df), height=6, min_width=8))
    
    ax = sns.barplot(
        data=lang_df, 
        x="Language", 
        y="Servers", 
        color=CAT_PALETTE[0],
        edgecolor=None
    )
    
    clean_spines(ax)
    add_bar_labels(ax, fontsize=12, color=TEXT_COLOR)

    total_servers = data.get("total", sum(data["completely-analyzed-servers"]["languages"].values()))
    ax.set_title(f"Completely Analyzed Servers (Total: {total_servers})", pad=20)
    
    save_plot("2. completely-analyzed.png", OUT_DIR)
