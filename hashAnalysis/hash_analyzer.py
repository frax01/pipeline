import pandas as pd
import json
from pathlib import Path
import sys
import os

# Add parent directory to path to allow importing from functions
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from functions.config import EXCEL_PATH
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
    print(f"Loading Excel from: {EXCEL_PATH}")
    df = pd.read_excel(EXCEL_PATH)
    
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
            
            # clone_repo (da buildConfig) clona in una temp dir per evitare conflitti
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
                
                # Record con la coppia originale/duplicato (urlServer:urlDuplicato).
                
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
