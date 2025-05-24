# --- UPDATED main.py ---

import streamlit as st
from dotenv import load_dotenv
import os
import random
import pandas as pd
import re
from datetime import datetime
from pathlib import Path
import uuid
import base64

# Load environment variables
load_dotenv()

st.set_page_config(layout='wide', page_title="Sysdiagnose Analyzer", page_icon="🫠")

st.markdown("""
    <style>
        .stApp { background-color: #f0f2f6; }
    </style>
""", unsafe_allow_html=True)

st.title("🩺 Sysdiagnose Analysis")

from auth import login_signup_page
query_params = st.query_params if hasattr(st, "query_params") else st.experimental_get_query_params()

if "user_email" in query_params:
    user_email = query_params["user_email"][0]
    st.session_state.authenticated = True
    st.session_state.user = user_email
    st.session_state.google_login = True

    from db import users_collection
    existing_user = users_collection.find_one({"email": user_email})
    if not existing_user:
        users_collection.insert_one({
            "first_name": "",
            "last_name": "",
            "email": user_email,
            "password": None,
            "oauth": "google"
        })
        st.info("Signed up successfully using Google!")

    user = users_collection.find_one({"email": user_email})
    st.session_state.scan_id = str(user.get("_id"))
    st.success(f"Welcome, {user_email}!")
    st.experimental_set_query_params()

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    login_signup_page()
    st.stop()
else:
    st.sidebar.success(f"Logged in as: {st.session_state.user}")
    st.sidebar.info(f"User ID: {st.session_state.get('scan_id', 'N/A')}")

from extraction import extract_sysdiagnose
from metadata import scan_files
from views.sidebar import render_sidebar
from views.file_viewer import render_file
from views.timeline import render_timeline
from views.charts import render_charts
from ai_summary import get_summary
from constants import CATEGORY_PATTERNS
from views.dashboard import render_dashboard
from db import scan_history_collection

# === SCAN HISTORY ===
user_scan_id = st.session_state.get("scan_id")
history = list(scan_history_collection.find({"user_id": user_scan_id}).sort("timestamp", -1))

with st.sidebar.expander("📁 Scan History", expanded=False):
    if history:
        df_hist = pd.DataFrame(history)[["scan_id", "file_name", "folder_link", "timestamp"]]
        df_hist["timestamp"] = pd.to_datetime(df_hist["timestamp"])

        start_date = st.date_input("From", df_hist["timestamp"].min().date())
        end_date = st.date_input("To", df_hist["timestamp"].max().date())

        filtered = df_hist[
            (df_hist["timestamp"].dt.date >= start_date) &
            (df_hist["timestamp"].dt.date <= end_date)
        ]
        st.dataframe(filtered, use_container_width=True, height=300)
        st.download_button("Download CSV", data=filtered.to_csv(index=False), file_name="scan_history.csv")
    else:
        st.info("No scan history found.")

if history:
    st.subheader("Recent Scans")
    for entry in history:
        st.markdown("---")
        st.markdown(f"**File Name:** `{entry['file_name']}`")
        st.markdown(f"**Folder Link:** `{entry['folder_link']}`")
        st.markdown(f"**Timestamp:** `{entry['timestamp']}`")
        st.markdown(f"**Scan ID:** `{entry['scan_id']}`")

# === API Key ===
keys_env = os.getenv("OPENROUTER_API_KEYS", "")
key_list = [k.strip() for k in keys_env.split(",") if k.strip()]
api_key = random.choice(key_list) if key_list else None

if not api_key:
    api_key = st.sidebar.text_input("API Key", type="password")

# === File Upload ===
upload = st.sidebar.file_uploader("Upload .tar.gz", type=["tar.gz"])
if not upload:
    st.sidebar.info("Upload to begin.")
    st.stop()

# === Generate short scan_id ===
def generate_short_scan_id():
    return base64.b32encode(os.urandom(4)).decode("utf-8").strip("=").lower()

scan_id = generate_short_scan_id()
timestamp = datetime.now()

# === Extract & Scan ===
root_dir = extract_sysdiagnose(upload)
df_tl = scan_files(root_dir)
glob_files = df_tl['full_path'].tolist()

# === Save to DB ===
scan_history_collection.insert_one({
    "scan_id": scan_id,
    "user_id": st.session_state.get("scan_id"),
    "file_name": upload.name,
    "folder_link": root_dir,
    "timestamp": timestamp
})

# === Utility Functions ===
def find_file(root: str, name: str) -> str | None:
    for dp, _, fn in os.walk(root):
        if name in fn:
            return os.path.join(dp, name)
    return None

def parse_vm_stat(path: str) -> pd.DataFrame:
    try:
        text = Path(path).read_text().splitlines()
        idx = next(i for i, l in enumerate(text) if l.strip().startswith('free'))
        nums = list(map(int, re.findall(r"\d+", text[idx + 1])))
        page_size = 16384
        active = nums[1] * page_size
        wired = nums[5] * page_size
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
        duration = float(m_dur.group(1)) if m_dur else None
        total_cpu_time = float(m_cpu.group(1)) if m_cpu else None
        end_ts = pd.to_datetime(m_end.group(1)) if m_end else None
        return pd.DataFrame([{'ctime': end_ts, 'duration': duration, 'total_cpu_time': total_cpu_time}])
    except Exception:
        return pd.DataFrame()

def parse_net_events(root: str) -> pd.DataFrame:
    records = []
    mapping = [
        ('netstat_PRE', 'netstat-PRE.txt'),
        ('netstat_POST', 'netstat-POST.txt'),
        ('ifconfig', 'ifconfig.txt'),
        ('arp', 'arp.txt')
    ]
    for key, name in mapping:
        path = find_file(root, name)
        if not path:
            continue
        try:
            txt = Path(path).read_text()
            m = re.search(r'BEGIN:\s*([\d:\.]+)', txt)
            if m:
                date = datetime.fromtimestamp(os.path.getmtime(path)).date()
                hh = m.group(1).split('.')[0]
                ctime = pd.to_datetime(f"{date} {hh}")
                records.append({'ctime': ctime, 'interface': 'all', 'event': key})
        except Exception:
            continue
    return pd.DataFrame(records)

# === Merge Timelines ===
df_tl['hour'] = pd.to_datetime(df_tl['ctime']).dt.floor('H')
vm_path = find_file(root_dir, 'vm_stat.txt')
cpu_path = find_file(root_dir, 'spindump-nosymbols.txt')
vm_df = parse_vm_stat(vm_path) if vm_path else pd.DataFrame()
cpu_df = parse_spindump(cpu_path) if cpu_path else pd.DataFrame()
net_df = parse_net_events(root_dir)

def hourly_merge(main: pd.DataFrame, aux: pd.DataFrame, cols: list) -> pd.DataFrame:
    if aux.empty:
        return main
    aux['hour'] = aux['ctime'].dt.floor('H')
    agg = aux.groupby('hour')[cols].agg('mean' if 'active' in cols else 'sum').reset_index()
    return main.merge(agg, on='hour', how='left')

if not vm_df.empty:
    df_tl = hourly_merge(df_tl, vm_df, ['active', 'wired'])
if not cpu_df.empty:
    df_tl = hourly_merge(df_tl, cpu_df, ['duration', 'total_cpu_time'])
if not net_df.empty:
    net_df['hour'] = net_df['ctime'].dt.floor('H')
    df_tl = df_tl.merge(net_df[['hour', 'interface', 'event']], on='hour', how='left')

# === UI Tabs ===
if 'selected' not in st.session_state:
    st.session_state.selected = None
render_sidebar(glob_files, CATEGORY_PATTERNS, root_dir, st.session_state)

tab1, tab2, tab3, tab4 = st.tabs(["Explorer", "Timeline", "Charts", "Ios Forensic Dashboard"])

with tab1:
    if st.session_state.selected:
        render_file(st.session_state.selected)
        if api_key:
            if st.button("Generate Summary", key="gen_sum"):
                with st.spinner("Generating AI summary…"):
                    summary = get_summary(
                        path=st.session_state.selected,
                        api_key=api_key
                    )
                st.subheader("AI-Generated Summary")
                st.write(summary)
        else:
            st.info("Enter your API key to enable AI summaries.")

with tab2:
    render_timeline(df_tl)

with tab3:
    render_charts(df_tl)

with tab4:
    render_dashboard()
