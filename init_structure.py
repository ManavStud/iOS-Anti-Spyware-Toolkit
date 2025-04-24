#!/usr/bin/env python3
import os

BASE_DIR = "sysdiag_app"
MODULE_FILES = [
    "extraction.py",
    "metadata.py",
    "ai_summary.py",
    "main.py",
    "constants.py",
]
VIEW_FILES = [
    "sidebar.py",
    "file_viewer.py",
    "timeline.py",
]

def create_structure():
    # Create base and views directories
    os.makedirs(BASE_DIR, exist_ok=True)
    views_dir = os.path.join(BASE_DIR, "views")
    os.makedirs(views_dir, exist_ok=True)

    # Create top‑level module stubs
    for fname in MODULE_FILES:
        path = os.path.join(BASE_DIR, fname)
        with open(path, "w") as f:
            f.write(f"# Stub for {fname}\n")

    # Create views/ stubs
    for fname in VIEW_FILES:
        path = os.path.join(views_dir, fname)
        with open(path, "w") as f:
            f.write(f"# Stub for views/{fname}\n")

    print(f"Created folder structure under ./{BASE_DIR}/")

if __name__ == "__main__":
    create_structure()
