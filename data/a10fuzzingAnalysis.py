import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from .utils.style_utils import setup_theme, save_plot, clean_spines, FRAMEWORK_COLORS, TEXT_COLOR

def fuzzing_success_table(data, out_dir):
    setup_theme()
    fuzz_data = data.get("fuzzing", {})
    
    # 1. Outcome Distribution (Pie/Donut)
    successful = fuzz_data.get("total_successful", 0)
    exceptions = fuzz_data.get("total_exceptions", 0)
    # safety_blocked = fuzz_data.get("total_safety_blocked", 0) # Usually 0 based on JSON
    
    total_runs = fuzz_data.get("total_fuzzing_runs", 0)
    
    # Skip if no fuzzing data
    if total_runs == 0 or (successful == 0 and exceptions == 0):
        print("Skipping fuzzing pie chart: No fuzzing runs recorded.")
        return
    
    labels = ["Successful", "Exceptions"]
    sizes = [successful, exceptions]
    colors = ["#4CAF50", "#F44336"] # Green/Red Standard
    
    fig, ax = plt.subplots(figsize=(8, 6))
    
    wedges, texts, autotexts = ax.pie(
        sizes, 
        labels=labels, 
        autopct='%1.1f%%', 
        startangle=90, 
        colors=colors,
        wedgeprops=dict(width=0.5, edgecolor=None), # Donut
        textprops=dict(color=TEXT_COLOR, fontsize=12, fontweight='bold')
    )
    
    ax.set_title("Fuzzing Run Outcomes", pad=20)
    
    # Make labels nicer
    for text in texts:
        text.set_color(TEXT_COLOR)
        
    save_plot("10. fuzzing_outcomes.png", out_dir)

def fuzzing_analysis_tables(data, out_dir):
    fuzzing_success_table(data, out_dir)

