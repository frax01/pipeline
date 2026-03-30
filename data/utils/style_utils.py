import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from typing import Tuple, Optional, List

# Global Constants for Consistent Coloring
BACKGROUND_COLOR = "#FFFFFF"
TEXT_COLOR = "#333333"
GRID_COLOR = "#E0E0E0"

# Standard Framework Colors
FRAMEWORK_COLORS = {
    "mcp-guard": "#2196F3",  # Blue
    "mcp-watch": "#4CAF50",  # Green
    "mcp-scan": "#FF9800",   # Orange
    "mcp-shield": "#9C27B0", # Purple
    "fuzzing": "#E91E63",    # Pink
}

# Standard Severity Colors
SEVERITY_COLORS = {
    "low": "#9E9E9E",       # Grey
    "medium": "#FFC107",    # Amber
    "high": "#FF5722",      # Deep Orange
    "critical": "#D32F2F",  # Red
}

CAT_PALETTE = [
    "#2196F3", # Blue
    "#4CAF50", # Green
    "#FF9800", # Orange
    "#9C27B0", # Purple
    "#E91E63", # Pink
    "#00BCD4", # Cyan
    "#FFC107", # Amber
    "#F44336", # Red
    "#3F51B5", # Indigo
    "#009688", # Teal
]

def setup_theme():
    """Applies the global light theme."""
    sns.set_theme(style="whitegrid", context="talk")
    plt.rcParams.update({
        "figure.figsize": (10, 6),
        "figure.facecolor": BACKGROUND_COLOR,
        "axes.facecolor": BACKGROUND_COLOR,
        "axes.edgecolor": TEXT_COLOR,
        "axes.labelcolor": TEXT_COLOR,
        "xtick.color": TEXT_COLOR,
        "ytick.color": TEXT_COLOR,
        "text.color": TEXT_COLOR,
        "grid.color": GRID_COLOR,
        "grid.linestyle": "--",
        "grid.alpha": 0.7,
        "font.family": "sans-serif",
        "font.sans-serif": ["Segoe UI", "Roboto", "Arial", "sans-serif"],
        "font.weight": "bold",
        "axes.titleweight": "bold",
        "axes.titlesize": 16,
        "axes.labelsize": 12,
        "savefig.facecolor": BACKGROUND_COLOR,
        "savefig.edgecolor": BACKGROUND_COLOR,
    })

def adaptive_figsize(n_items: int, height: int = 6, min_width: int = 8, per_item: float = 0.5) -> Tuple[float, float]:
    """Calculates figure size based on number of items."""
    width = max(min_width, n_items * per_item)
    return (width, height)

def save_plot(filename: str, out_dir: str):
    """Saves the current plot with high quality settings."""
    plt.tight_layout()
    plt.savefig(f"{out_dir}/{filename}", dpi=300, bbox_inches="tight")
    plt.close()

def add_bar_labels(ax, fontsize=10, color=TEXT_COLOR):
    """Adds value labels to bar charts."""
    for container in ax.containers:
        labels = [f'{v.get_height():.0f}' if v.get_height() > 0 else '' for v in container]
        ax.bar_label(container, labels=labels, label_type='edge', padding=3, fontsize=fontsize, color=color, fontweight='bold')

def clean_spines(ax):
    """Removes top and right spines, colors others."""
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color(TEXT_COLOR)
    ax.spines['bottom'].set_color(TEXT_COLOR)
