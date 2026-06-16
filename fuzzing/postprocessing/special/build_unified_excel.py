"""Build the unified 69104-row Excel for the 2026-05-21 fuzzing rerun.

Reads the GitHub (60205) and NPX (8899) Excels, adds a `Type` column,
concatenates, and writes the unified file. Run once locally before
deploying to the VMs.

    py -X utf8 fuzzing/build_unified_excel.py
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

import pandas as pd
from functions.config import EXCEL_PATH, EXCEL_PATH_NPX, EXCEL_PATH_UNIFIED


def main() -> None:
    print(f"GitHub: {EXCEL_PATH}")
    print(f"NPX:    {EXCEL_PATH_NPX}")
    print(f"Out:    {EXCEL_PATH_UNIFIED}")

    gh = pd.read_excel(EXCEL_PATH)
    npx = pd.read_excel(EXCEL_PATH_NPX)
    print(f"GitHub rows: {len(gh)}")
    print(f"NPX rows:    {len(npx)}")

    gh = gh[["Link"]].copy()
    gh["Type"] = "github"
    npx = npx[["Link"]].copy()
    npx["Type"] = "npx"

    unified = pd.concat([gh, npx], ignore_index=True)
    print(f"Unified rows: {len(unified)}")
    assert len(unified) == len(gh) + len(npx)

    EXCEL_PATH_UNIFIED.parent.mkdir(parents=True, exist_ok=True)
    unified.to_excel(EXCEL_PATH_UNIFIED, index=False)
    print(f"Wrote {EXCEL_PATH_UNIFIED}")


if __name__ == "__main__":
    main()
