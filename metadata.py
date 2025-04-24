import os
import pandas as pd
from datetime import datetime
from pathlib import Path

from constants import categorize, CATEGORY_PATTERNS  # CATEGORY_PATTERNS if needed for sidebar


def scan_files(root_dir: str) -> pd.DataFrame:
    """
    Walk the extracted sysdiagnose directory, categorize each file via constants.categorize(),
    and return a DataFrame of metadata sorted by creation time.
    """
    metadata = []
    for dp, _, files in os.walk(root_dir):
        for fname in files:
            path = os.path.join(dp, fname)
            relpath = os.path.relpath(path, root_dir)

            # Try reading a snippet of text for content-based categorization
            raw_snippet = None
            ext = Path(path).suffix.lower()
            if ext in ['.txt', '.log', '.ips', '.crash']:
                try:
                    raw_snippet = Path(path).read_text(errors='ignore')[:1024]
                except Exception:
                    raw_snippet = None

            # Determine category
            category = categorize(path, raw_snippet)

            # File timestamps and size
            stt = os.stat(path)
            metadata.append({
                'full_path': path,
                'relpath': relpath,
                'category': category,
                'ctime': datetime.fromtimestamp(stt.st_ctime),
                'mtime': datetime.fromtimestamp(stt.st_mtime),
                'atime': datetime.fromtimestamp(stt.st_atime),
                'size_bytes': stt.st_size
            })

    df = pd.DataFrame(metadata)
    return df.sort_values('ctime').reset_index(drop=True)
