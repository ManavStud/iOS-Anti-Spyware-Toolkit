# views/log_parsers.py

import os
import re
import pandas as pd

def parse_launchd(path: str) -> pd.DataFrame:
    records = []
    pattern = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*pid=(?P<pid>\d+).*label=(?P<label>\S+)"
    )
    if path and os.path.exists(path):
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    records.append(m.groupdict())
    return pd.DataFrame(records)

def parse_netstats(path: str) -> pd.DataFrame:
    records = []
    pattern = re.compile(
        r"(?P<timestamp>\d{2}:\d{2}:\d{2}).*?(?P<local>\S+)->(?P<remote>\S+)\s+(?P<bytes_in>\d+)\s+(?P<bytes_out>\d+)"
    )
    if path and os.path.exists(path):
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    rec = m.groupdict()
                    ip, port = rec['remote'].rsplit('.', 1)
                    rec['remote_ip']   = ip
                    rec['remote_port'] = port
                    records.append(rec)
    return pd.DataFrame(records)

def parse_powerstats(path: str) -> pd.DataFrame:
    records = []
    pattern = re.compile(
        r"(?P<timestamp>\d{2}:\d{2}:\d{2}).*pid=(?P<pid>\d+).*cpu=(?P<cpu_pct>[0-9.]+)%"
    )
    if path and os.path.exists(path):
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    records.append(m.groupdict())
    return pd.DataFrame(records)
