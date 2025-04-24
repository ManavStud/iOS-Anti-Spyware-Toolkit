import streamlit as st
import pandas as pd
import os
import re
from datetime import datetime
from pathlib import Path

from extraction import extract_sysdiagnose
from metadata import scan_files
from views.sidebar import render_sidebar
from views.file_viewer import render_file
from views.timeline import render_timeline
from views.charts import render_dashboard
from ai_summary import get_summary
from constants import CATEGORY_PATTERNS
import os
import pandas as pd
from pathlib import Path
from datetime import datetime
from constants import categorize


def scan_files(root_dir: str) -> pd.DataFrame:
    """
    Walk the extracted sysdiagnose directory, classify each file,
    and return a DataFrame with file metadata and categories.
    """
    metadata = []
    for dp, _, files in os.walk(root_dir):
        for fname in files:
            path = os.path.join(dp, fname)
            relpath = os.path.relpath(path, root_dir)

            # Read a snippet for content-based classification
            raw_snippet = None
            try:
                with open(path, 'r', errors='ignore') as f:
                    raw_snippet = f.read(1024)
            except Exception:
                pass

            # Determine category using the multi-step logic
            category = categorize(path, raw_snippet)

            # File stats
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

# Page layout
st.set_page_config(layout='wide')
st.title("Sysdiagnose Analysis")

# --- Sidebar Inputs ---
api_key = st.sidebar.text_input("API Key", type="password")
upload  = st.sidebar.file_uploader("Upload .tar.gz", type=["tar.gz"])
if not upload:
    st.sidebar.info("Upload to begin.")
    st.stop()

# --- Extract & Scan ---
root_dir = extract_sysdiagnose(upload)
df_tl = scan_files(root_dir)
glob_files = df_tl['full_path'].tolist()

# Utility: find file by name under root

def find_file(root: str, name: str) -> str | None:
    for dp, _, fn in os.walk(root):
        if name in fn:
            return os.path.join(dp, name)
    return None

# --- Parsers for metrics ---
def parse_vm_stat(path: str) -> pd.DataFrame:
    try:
        text = Path(path).read_text().splitlines()
        idx = next(i for i,l in enumerate(text) if l.strip().startswith('free'))
        nums = list(map(int, re.findall(r"\d+", text[idx+1])))
        page_size = 16384
        active = nums[1] * page_size
        wired  = nums[5] * page_size
        ctime = datetime.fromtimestamp(os.path.getmtime(path))
        return pd.DataFrame([{'ctime': ctime, 'active': active, 'wired': wired}])
    except Exception:
        return pd.DataFrame()


def parse_spindump(path: str) -> pd.DataFrame:
    try:
        txt = Path(path).read_text()
        m_dur = re.search(r'Duration:\s+([\d\.]+)s', txt)
        m_cpu = re.search(r'Total CPU Time:\s+([\d\.]+)s', txt)
        m_end = re.search(r'End time:\s+([\d\-]+ [\d:\.]+)', txt)
        duration      = float(m_dur.group(1)) if m_dur else None
        total_cpu_time= float(m_cpu.group(1)) if m_cpu else None
        end_ts        = pd.to_datetime(m_end.group(1)) if m_end else None
        return pd.DataFrame([{'ctime': end_ts,'duration': duration,'total_cpu_time': total_cpu_time}])
    except Exception:
        return pd.DataFrame()


def parse_net_events(root: str) -> pd.DataFrame:
    records = []
    mapping = [
        ('netstat_PRE','netstat-PRE.txt'),
        ('netstat_POST','netstat-POST.txt'),
        ('ifconfig','ifconfig.txt'),
        ('arp','arp.txt')
    ]
    for key,name in mapping:
        path = find_file(root, name)
        if not path:
            continue
        try:
            txt = Path(path).read_text()
            m = re.search(r'BEGIN:\s*([\d:\.]+)', txt)
            if m:
                date = datetime.fromtimestamp(os.path.getmtime(path)).date()
                hh   = m.group(1).split('.')[0]
                ctime = pd.to_datetime(f"{date} {hh}")
                records.append({'ctime': ctime, 'interface': 'all', 'event': key})
        except Exception:
            continue
    return pd.DataFrame(records)

# --- Merge Metrics into timeline DF ---
df_tl['hour'] = pd.to_datetime(df_tl['ctime']).dt.floor('H')
vm_path = find_file(root_dir, 'vm_stat.txt')
cpu_path= find_file(root_dir, 'spindump-nosymbols.txt')
vm_df  = parse_vm_stat(vm_path) if vm_path else pd.DataFrame()
cpu_df = parse_spindump(cpu_path) if cpu_path else pd.DataFrame()
net_df = parse_net_events(root_dir)

def hourly_merge(main: pd.DataFrame, aux: pd.DataFrame, cols: list) -> pd.DataFrame:
    if aux.empty:
        return main
    aux['hour'] = aux['ctime'].dt.floor('H')
    agg = aux.groupby('hour')[cols].agg('mean' if 'active' in cols else 'sum').reset_index()
    return main.merge(agg, on='hour', how='left')

if not vm_df.empty:
    df_tl = hourly_merge(df_tl, vm_df, ['active','wired'])
if not cpu_df.empty:
    df_tl = hourly_merge(df_tl, cpu_df, ['duration','total_cpu_time'])
if not net_df.empty:
    net_df['hour'] = net_df['ctime'].dt.floor('H')
    df_tl = df_tl.merge(net_df[['hour','interface','event']], on='hour', how='left')

# --- Sidebar Explorer ---
if 'selected' not in st.session_state:
    st.session_state.selected = None
render_sidebar(glob_files, CATEGORY_PATTERNS, root_dir, st.session_state)

# --- File Viewer & AI ---
if st.session_state.selected:
    render_file(st.session_state.selected)
    if api_key and st.button("Generate Summary"):
        st.write(get_summary(st.session_state.selected, api_key))

# --- Tabs ---
tab1, tab2, tab3 = st.tabs(["Explorer", "Timeline", "Charts"])
with tab1:
    st.write("(Use sidebar)")
with tab2:
    render_timeline(df_tl)
with tab3:
    render_dashboard(df_tl)
