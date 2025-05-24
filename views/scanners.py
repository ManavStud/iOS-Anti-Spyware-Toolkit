# views/scanners.py

import os
import glob
import tempfile
import re
import streamlit as st
import pandas as pd
import altair as alt
from dotenv import load_dotenv

from indicator_engine import load_indicators, scan_path
from ai_summary import summarize_indicators

# Initialize environment
load_dotenv()

# Severity badge mapping
SEVERITY_BADGES = {
    "Low": "🟢 Low",
    "Medium": "🟠 Medium",
    "High": "🔴 High",
    "Extreme": "⚫ Extreme"
}

# Combined indicator rules for correlated alerts
COMBINED_INDICATORS = [
    {
        "names": ["Public Outbound Connection", "Unauthorized Port Listening"],
        "message": "Multiple public outbound connections along with unauthorized listening ports indicate potential data exfiltration."
    }
]

@st.cache_data
def parse_launchd(log_path: str) -> pd.DataFrame:
    """
    Parse launchd_output.log to extract timestamp, pid, and process label.
    """
    records = []
    pattern = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*pid=(?P<pid>\d+).*label=(?P<label>\S+)"
    )
    try:
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    records.append(m.groupdict())
    except FileNotFoundError:
        return pd.DataFrame()
    return pd.DataFrame(records)

@st.cache_data
def parse_netstats(file_path: str) -> pd.DataFrame:
    """
    Parse netstats.txt to extract timestamps, remote IP/port, and byte counts.
    """
    records = []
    pattern = re.compile(
        r"(?P<timestamp>\d{2}:\d{2}:\d{2}).*?(?P<local>\S+)->(?P<remote>\S+)\s+(?P<bytes_in>\d+)\s+(?P<bytes_out>\d+)"
    )
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    rec = m.groupdict()
                    ip, port = rec['remote'].rsplit('.', 1)
                    rec['remote_ip'] = ip
                    rec['remote_port'] = port
                    records.append(rec)
    except FileNotFoundError:
        return pd.DataFrame()
    return pd.DataFrame(records)

@st.cache_data
def parse_powerstats(file_path: str) -> pd.DataFrame:
    """
    Parse powerstats.txt to extract timestamp, pid, and CPU usage percentage.
    """
    records = []
    pattern = re.compile(
        r"(?P<timestamp>\d{2}:\d{2}:\d{2}).*?pid=(?P<pid>\d+).*?cpu=(?P<cpu_pct>[0-9.]+)%"
    )
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    records.append(m.groupdict())
    except FileNotFoundError:
        return pd.DataFrame()
    return pd.DataFrame(records)


def render_scanners(glob_files: list[str], tmpdir: str, indicators_dir: str = "indicators"):
    st.title("🔎 Threat Indicators Scanner")

    # Sidebar filters
    st.sidebar.header("Filters")
    severity_options = ["Low", "Medium", "High", "Extreme"]
    selected_sev = st.sidebar.multiselect("Severity", severity_options, default=severity_options)
    show_repeats = st.sidebar.checkbox("Show only repeated matches", value=False)

    # 1) Load indicator definitions
    indicator_files = glob.glob(os.path.join(indicators_dir, "*_indicators.json"))
    indicators = []
    for jf in sorted(indicator_files):
        try:
            indicators.extend(load_indicators(jf))
        except Exception as e:
            st.sidebar.error(f"Failed loading {jf}: {e}")
    if not indicators:
        st.error("No indicators defined.")
        return

    # 2) Scan .txt logs
    txt_logs = [p for p in glob_files if p.lower().endswith('.txt')]
    if not txt_logs:
        st.info("No text logs to scan.")
        return
    dfs = [scan_path(p, indicators) for p in txt_logs]
    df_hits = pd.concat([d for d in dfs if not d.empty], ignore_index=True) if dfs else pd.DataFrame()

    if df_hits.empty:
        st.info("No indicators triggered.")
        return

    # 3) Filter Unusual Protocol Traffic false positives
    mask_up = df_hits['indicator'] == 'Unusual Protocol Traffic'
    df_hits = df_hits[~(mask_up & ~df_hits['file'].str.lower().str.contains('netstats.txt'))]
    if df_hits.empty:
        st.info("No relevant indicators after filtering false positives.")
        return

    # 4) Count occurrences and build basic summaries
    counts = df_hits['indicator'].value_counts().to_dict()
    # Executive Summary
    st.header("📋 Executive Summary")
    summary_lines = []
    for ind in indicators:
        name = ind['name']
        c = counts.get(name, 0)
        if c > 1:
            desc = ind.get('layman_description') or ind.get('description','')
            summary_lines.append(f"- **{name}** (x{c}): {desc}")
    if summary_lines:
        st.markdown("The following issues were detected multiple times (higher risk):")
        st.markdown("\n".join(summary_lines))
    else:
        st.markdown("No repeated matches detected; single hits are low-confidence.")
    st.markdown("---")

    # 5) Correlated alerts
    correlated = []
    for combo in COMBINED_INDICATORS:
        if all(counts.get(n,0) > 1 for n in combo['names']):
            correlated.append(combo['message'])
    if correlated:
        st.subheader("⚡ Correlated Alerts")
        for msg in correlated:
            st.error(msg)
        st.markdown("---")

    # 6) Definition table and metrics
    defs = []
    for ind in indicators:
        name = ind['name']
        c = counts.get(name,0)
        defs.append({
            'Name': name,
            'Occurrences': c,
            'Severity': ind.get('severity',''),
            'Score': ind.get('score',''),
            'Repeated': c > 1
        })
    df_defs = pd.DataFrame(defs)
    df_defs = df_defs[df_defs['Severity'].isin(selected_sev)]
    if show_repeats:
        df_defs = df_defs[df_defs['Repeated']]

    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Indicators", len(df_defs))
    col2.metric("Repeated Matches", int(df_defs['Repeated'].sum()))
    col3.metric("Severities", ", ".join(df_defs[df_defs['Repeated']]['Severity'].unique()) or "None")
    col4.metric("Total Findings", len(df_hits))
    st.markdown("---")

    # 7) Charts
    # Pie: repeated vs single
    pie = df_defs['Repeated'].value_counts().reset_index()
    pie.columns = ['Repeated','Count']
    pie_chart = alt.Chart(pie).mark_arc(innerRadius=50).encode(
        theta=alt.Theta('Count:Q'),
        color=alt.Color('Repeated:N', scale=alt.Scale(domain=[True,False], range=["#d62728","#1f77b4"])),
        tooltip=['Repeated','Count']
    ).properties(width=300, height=300)
    st.subheader("Repeated vs Single Matches")
    st.altair_chart(pie_chart, use_container_width=True)

    # Bar: severity counts
    st.subheader("Findings by Severity")
    bar = df_hits['severity'].value_counts().reset_index()
    bar.columns = ['Severity','Count']
    bar_chart = alt.Chart(bar).mark_bar().encode(
        x=alt.X('Severity:N', sort=severity_options),
        y='Count:Q',
        color=alt.Color('Severity:N', scale=alt.Scale(domain=severity_options,
                                                     range=["#2ca02c","#ff7f0e","#d62728","#9467bd"])),
        tooltip=['Severity','Count']
    ).properties(width=400, height=300)
    st.altair_chart(bar_chart, use_container_width=True)
    st.markdown("---")

    # 8) Enrichment from sysdiagnose
    launchd_log = os.path.join(tmpdir, "system_logs", "launchd_output.log")
    net_file = os.path.join(tmpdir, "netstats.txt")
