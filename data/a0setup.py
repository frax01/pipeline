from .a1languagesTable import languages_table_setup
from .a2completelyAnalyzed import completely_analyzed_table
from .a3frameworkLanguages import framework_languages_table
from .a4guardWatchCategories import single_framework_cat_table
from .a5guardWatchVulnerabilities import guard_watch_vuln_table
from .a6scanShieldTool import scan_shield_tools_table
from .a7scanShieldCategories import scan_shield_single_framework_cat_table
from .a8vulnerabilityOverview import vulnerability_overview_table
from .a9hashFile import hash_table
from .a10fuzzingAnalysis import fuzzing_analysis_tables
import seaborn as sns
sns.set_theme(
    style="whitegrid", 
    context="talk",
    palette="deep"
)

def generate_all_tables(data, out_dir):
    languages_table_setup(data, out_dir)
    completely_analyzed_table(data, out_dir)
    framework_languages_table(data, out_dir)
    single_framework_cat_table(data, out_dir, "mcp-guard")
    single_framework_cat_table(data, out_dir, "mcp-watch") 
    guard_watch_vuln_table(data, out_dir, FRAMEWORKS=["mcp-guard", "mcp-watch"])
    scan_shield_tools_table(data, out_dir, FRAMEWORKS=["mcp-scan", "mcp-shield"])
    scan_shield_single_framework_cat_table(data, out_dir, "mcp-scan")
    scan_shield_single_framework_cat_table(data, out_dir, "mcp-shield")
    hash_table(data, out_dir)
    fuzzing_analysis_tables(data, out_dir)
    vulnerability_overview_table(data, out_dir)

#from pathlib import Path
#import os
#BASE_DIR = Path.home() / "Desktop/Pipeline"
#FRAMEWORKS = BASE_DIR / "frameworks.json"
#TABLE_DIR = BASE_DIR / "data/tables"
#os.makedirs(TABLE_DIR, exist_ok=True)
#import json
#def load_summary(path: Path) -> dict:
#    with open(path, "r") as f:
#        return json.load(f)
#generate_all_tables(load_summary(FRAMEWORKS), TABLE_DIR)