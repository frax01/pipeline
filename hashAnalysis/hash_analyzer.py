import pandas as pd
import json
from pathlib import Path
import sys
import os

# Add parent directory to path to allow importing from functions
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from functions.config import EXCEL_PATH_HASH_ANALYSIS
from functions.buildConfig import clone_repo
from functions.hash import compute_server_hash
from functions.helper import force_delete, extract_server_name

# Configuration
OUTPUT_FILE = Path("hashAnalysis.json")

def load_existing_results():
    if OUTPUT_FILE.exists():
        try:
            return json.loads(OUTPUT_FILE.read_text(encoding="utf-8"))
        except:
            return []
    return []

def save_result(result):
    current_results = load_existing_results()
    current_results.append(result)
    OUTPUT_FILE.write_text(json.dumps(current_results, indent=4, ensure_ascii=False), encoding="utf-8")

def main():
    print(f"Loading Excel from: {EXCEL_PATH_HASH_ANALYSIS}")
    df = pd.read_excel(EXCEL_PATH_HASH_ANALYSIS)
    
    # Local cache for this run: hash -> {"url": url, "name": name}
    # We want to find duplicates within the provided list.
    seen_hashes = {} 
    
    print(f"Found {len(df)} servers to process.")
    
    for idx, row in df.iterrows():
        server_url = row["Link"]
        server_name = extract_server_name(server_url)
        
        print(f"\n[{idx+1}/{len(df)}] Processing: {server_name}")
        print(f"URL: {server_url}")
        
        repo_path = Path.cwd() / "temp_hash_analysis" / server_name
        
        try:
            # Clone
            if repo_path.exists():
                force_delete(repo_path)
            
            # Using clone_repo from buildConfig which clones to a specific base
            # We'll use a temp dir for this analysis to avoid conflicts
            cloned_path = clone_repo(server_url, repo_path.parent)
            
            # Compute Hash
            server_hash = compute_server_hash(cloned_path)
            print(f"Hash: {server_hash}")
            
            # Check Duplicate
            if server_hash in seen_hashes:
                original = seen_hashes[server_hash]
                print(f"!!! DUPLICATE FOUND !!!")
                print(f"Original: {original['url']}")
                print(f"Duplicate: {server_url}")
                
                # Requested format: "urlServer:urlDuplicato"
                # Saving as an object for better structure, but fulfilling the requirements
                # User asked: "salva per ogni elemento ... in questo modo urlServer:urlDuplicato"
                # Interpreting as a JSON list of objects with this structure or a string
                # I will save as an object with specific keys as per previous thought, or explicitly mapping the string requirement.
                # "in cui salva per ogni elemento l'url del primo server, l'url del secondo server duplicato in questo modo urlServer:urlDuplicato"
                # This suggests the content of the "saved element" should be that string/structure.
                # Let's create a record that contains the pair.
                
                record = {
                    "original_url": original['url'],
                    "duplicate_url": server_url,
                    "hash": server_hash
                }
                save_result(record)
                
            else:
                seen_hashes[server_hash] = {
                    "url": server_url,
                    "name": server_name
                }
                
        except Exception as e:
            print(f"Error processing {server_name}: {e}")
            
        finally:
            # Cleanup
            if repo_path.exists():
                force_delete(repo_path)
                
if __name__ == "__main__":
    main()
