# Stub for extraction.py
import os, tarfile, tempfile
from typing import Optional

def extract_sysdiagnose(uploaded) -> Optional[str]:
    tmpdir = tempfile.mkdtemp()
    with tarfile.open(fileobj=uploaded, mode='r:gz') as tar:
        tar.extractall(tmpdir)
    # return first directory
    for entry in os.listdir(tmpdir):
        path = os.path.join(tmpdir, entry)
        if os.path.isdir(path):
            return path
    return None
