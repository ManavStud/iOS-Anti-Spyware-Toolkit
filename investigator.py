# investigate_process.py

import os
import re
import pandas as pd
from datetime import datetime
from pathlib import Path

from views.log_parsers import parse_launchd, parse_netstats, parse_powerstats


def find_file(root: str, name: str) -> str | None:
    """Recursively search for a filename under root."""
    for dp, _, files in os.walk(root):
        if name in files:
            return os.path.join(dp, name)
    return None

def parse_spindump(path: str) -> pd.DataFrame:
    """
    Extract total CPU time and duration from spindump-nosymbols.txt
    """
    records = []
    txt = Path(path).read_text(errors='ignore')
    m_dur  = re.search(r'Duration:\s+([\d\.]+)s', txt)
    m_cpu  = re.search(r'Total CPU Time:\s+([\d\.]+)s', txt)
    m_end  = re.search(r'End time:\s+([\d\-]+ [\d:\.]+)', txt)

    if m_end:
        end_ts = pd.to_datetime(m_end.group(1))
    else:
        end_ts = None

    records.append({
        'end_time': end_ts,
        'duration_s': float(m_dur.group(1)) if m_dur else None,
        'cpu_time_s': float(m_cpu.group(1)) if m_cpu else None
    })
    return pd.DataFrame(records)

def parse_vm_stat(path: str) -> pd.DataFrame:
    """
    Grabs active & wired memory from vm_stat.txt
    """
    txt = Path(path).read_text(errors='ignore').splitlines()
    # find the line after "free"
    idx = next((i for i,l in enumerate(txt) if l.strip().startswith('free')), None)
    if idx is None or idx+1 >= len(txt):
        return pd.DataFrame()
    nums = list(map(int, re.findall(r"\d+", txt[idx+1])))
    # each page is 16 384 bytes on iOS
    page = 16384
    return pd.DataFrame([{
        'active_bytes': nums[1] * page,
        'wired_bytes':  nums[5] * page,
        'timestamp':    datetime.fromtimestamp(os.path.getmtime(path))
    }])

def find_crash_reports(root: str, process_label: str, pid: str|None=None) -> list[str]:
    """
    Return a list of crash/log files under root that mention either
    the bundle-id or the PID.
    """
    matches = []
    for dp, _, files in os.walk(root):
        for fn in files:
            if fn.lower().endswith(('.ips','.crash','.jsonl')):
                p = os.path.join(dp, fn)
                try:
                    text = Path(p).read_text(errors='ignore')
                except Exception:
                    continue
                if process_label in text or (pid and pid in text):
                    matches.append(p)
    return matches

def investigate_process(root_sysdiagnose_dir: str,
                        pid: int = None,
                        timestamp: str = None,
                        process_name: str = None
                       ) -> dict[str, pd.DataFrame]:
    """
    Deep‐dive on a given PID/timestamp *and* (additionally) on process_name.
    Returns a dict of DataFrames keyed by section name.
    """
    results = {}

    # 1) By PID & timestamp (existing logic)
    ld = parse_launchd(os.path.join(root_sysdiagnose_dir, "system_logs/launchd_output.log"))
    ns = parse_netstats(os.path.join(root_sysdiagnose_dir, "netstats.txt"))
    ps = parse_powerstats(os.path.join(root_sysdiagnose_dir, "powerstats.txt"))

    if pid is not None and timestamp:
        # filter for that pid+timestamp
        results["Launchd Events"]    = ld[(ld["pid"].astype(int)==pid) & (ld["timestamp"]==timestamp)]
        results["Network Sessions"]  = ns[(ns["timestamp"]==timestamp) & (ns["remote_ip"].notnull())]
        results["CPU Snapshots"]     = ps[(ps["pid"].astype(int)==pid) & (ps["timestamp"]==timestamp)]

    # 2) By process name across all system logs
    if process_name:
        proc_matches = []
        syslog_dir = os.path.join(root_sysdiagnose_dir, "system_logs")
        pattern = re.compile(re.escape(process_name), re.IGNORECASE)
        for root, _, files in os.walk(syslog_dir):
            for fn in files:
                path = os.path.join(root, fn)
                try:
                    with open(path, "r", errors="ignore") as f:
                        for lineno, line in enumerate(f, start=1):
                            if pattern.search(line):
                                proc_matches.append({
                                    "log_file": fn,
                                    "lineno":   lineno,
                                    "entry":    line.strip()
                                })
                except IOError:
                    continue
        results["Process Log Matches"] = pd.DataFrame(proc_matches)

    return results