import streamlit as st
import pandas as pd
import altair as alt
import os
import re
import pandas as pd
from datetime import datetime


def parse_net_events(pre_path: str, post_path: str, ifconfig_path: str, arp_path: str) -> pd.DataFrame:
    """
    Fallback parser: reads the BEGIN timestamp from each sysdiagnose marker file,
    and emits one event per file, with interface='all' and event name = file key.
    """
    records = []
    for key, path in [
        ('netstat_PRE',  pre_path),
        ('netstat_POST', post_path),
        ('ifconfig',     ifconfig_path),
        ('arp',          arp_path),
    ]:
        text = open(path, 'r').read()
        m = re.search(r'BEGIN:\s*([\d:\.]+)', text)
        if m:
            # Use the device’s dump date (file mtime) + marker time for a full timestamp
            dump_date = datetime.fromtimestamp(os.path.getmtime(path)).date()
            hh_mm_ss = m.group(1).split('.')[0]          # drop milliseconds
            ctime = pd.to_datetime(f"{dump_date} {hh_mm_ss}")
            records.append({
                'ctime':    ctime,
                'interface':'all',
                'event':    key
            })
    return pd.DataFrame(records)


def parse_vm_stat(path: str) -> pd.DataFrame:
    """
    Reads vm_stat.txt and returns a DataFrame with:
      • ctime (snapshot timestamp; you may need to supply this externally)
      • active
      • wired
    """
    # vm_stat has no timestamps per snapshot by default; if you ran it periodically, 
    # prefix each block with a timestamp line in the log. 
    # Otherwise, you’ll have to extract based on your capture tool’s time.
    lines = open(path).read().splitlines()
    # Skip the header, read the first numeric line
    header_idx = next(i for i,l in enumerate(lines) if re.match(r'\s*free\s+active', l))
    data_line = lines[header_idx+1].strip()
    nums = list(map(int, re.findall(r'\d+', data_line)))
    # vm_stat reports values in pages of 16384 bytes by default
    page_size = 16384
    active = nums[1] * page_size
    wired  = nums[5] * page_size

    # You’ll need the snapshot time—if you have no timestamp in the file,
    # you can use file-modified time as an approximation:
    ctime = datetime.fromtimestamp(os.path.getmtime(path))

    return pd.DataFrame([{'ctime': ctime, 'active': active, 'wired': wired}])

def parse_spindump(path: str) -> pd.DataFrame:
    """
    Reads spindump output and returns a DataFrame with:
      • ctime      – report end time
      • duration   – seconds sampled
      • total_cpu_time – CPU seconds spent (from header)
    """
    text = open(path).read()
    # Extract end time
    m = re.search(r'End time:\s+([\d\-]+ [\d:\.]+) \+0530', text)
    end_ts = pd.to_datetime(m.group(1)) if m else None

    # Extract Duration: 2.00s
    d = re.search(r'Duration:\s+([\d\.]+)s', text)
    duration = float(d.group(1)) if d else None

    # Extract Total CPU Time:   2.212s
    c = re.search(r'Total CPU Time:\s+([\d\.]+)s', text)
    total_cpu = float(c.group(1)) if c else None

    return pd.DataFrame([{
        'ctime': end_ts,
        'duration': duration,
        'total_cpu_time': total_cpu
    }])


def render_dashboard(df: pd.DataFrame) -> None:
    """
    Render a multi-tab forensic dashboard with:
      • Overview (file counts & sizes)
      • Timeline (exact file-creation ticks)
      • Crash Analysis
      • Resource Usage Heatmaps
      • Network Events
      • File-System Activity
      • Anomaly Alerts
    """
    
    df = df.copy()

    # Ensure timestamp and size columns
    if 'ctime' not in df.columns:
        st.error("DataFrame missing required 'ctime' column.")
        return
    df['ctime'] = pd.to_datetime(df['ctime'], errors='coerce')
    if df['ctime'].isna().all():
        st.error("Column 'ctime' could not be parsed as datetime.")
        return

    if 'size_bytes' in df.columns:
        df['size_bytes'] = pd.to_numeric(df['size_bytes'], errors='coerce').fillna(0)
    
        df['date'] = df['ctime'].dt.date

    # Derive memory_peak from vm stats if not explicitly provided
    if 'memory_peak' not in df.columns and {'active','wired'}.issubset(df.columns):
        df['memory_peak'] = pd.to_numeric(df['active'], errors='coerce') + pd.to_numeric(df['wired'], errors='coerce')
    # Derive cpu_pct from spindump if not explicitly provided
    if 'cpu_pct' not in df.columns and {'total_cpu_time','duration'}.issubset(df.columns):
        df['cpu_pct'] = pd.to_numeric(df['total_cpu_time'], errors='coerce') / pd.to_numeric(df['duration'], errors='coerce') * 100


    tabs = st.tabs([
        "📊 Overview",
        "⏱ Timeline",
        "💥 Crashes",
        "📈 Resources",
        "🌐 Network",
        "📁 FS Activity",
        "⚠️ Anomalies"
    ])

    # 1. Overview
    with tabs[0]:
        st.subheader("Overview: File Distribution & Storage Usage")
        if 'category' not in df.columns:
            st.error("Missing 'category' column for Overview charts.")
        else:
            counts = df.groupby('category').size().reset_index(name='count')
            chart1 = alt.Chart(counts).mark_bar().encode(
                x=alt.X('category:N', sort='-y', title='Category'),
                y=alt.Y('count:Q', title='File Count'),
                tooltip=['category', 'count']
            ).properties(height=300)
            st.altair_chart(chart1, use_container_width=True)

        if 'size_bytes' in df.columns and 'category' in df.columns:
            sizes = df.groupby('category')['size_bytes'].sum().reset_index()
            chart2 = alt.Chart(sizes).mark_bar().encode(
                x=alt.X('category:N', sort='-y', title='Category'),
                y=alt.Y('size_bytes:Q', title='Total Size (bytes)'),
                tooltip=['category', 'size_bytes']
            ).properties(height=300)
            st.altair_chart(chart2, use_container_width=True)
        elif 'size_bytes' not in df.columns:
            st.info("Optional column 'size_bytes' missing; skipping storage usage chart.")

    # 2. Timeline
    with tabs[1]:
        st.subheader("Timeline: Exact File-Creation Events")
        required = {'category', 'ctime'}
        if not required.issubset(df.columns):
            missing = required - set(df.columns)
            st.error(f"Missing columns for Timeline: {', '.join(missing)}")
        else:
            df['relpath'] = df.get('relpath', df.get('filename', '<unknown>')).astype(str)
            chart = (
                alt.Chart(df)
                   .mark_tick(thickness=2, size=20)
                   .encode(
                       x=alt.X(
                           'ctime:T',
                           title='Timestamp',
                           axis=alt.Axis(
                               format='%Y-%m-%d %H:%M',
                               tickCount='hour',
                               labelAngle=-45,
                               labelOverlap='greedy'
                           )
                       ),
                       y=alt.Y('category:N', title=None, sort=list(df['category'].unique())),
                       color=alt.Color('category:N', legend=None),
                       tooltip=[
                           alt.Tooltip('relpath:N', title='File'),
                           alt.Tooltip('ctime:T', title='Created'),
                           alt.Tooltip('category:N', title='Category'),
                           alt.Tooltip('size_bytes:Q', title='Size (bytes)', format=',')                   
                       ]
                   )
                   .properties(height=300)
                   .interactive()
            )
            st.altair_chart(chart, use_container_width=True)

        # 3. Crash Analysis
    with tabs[2]:
        st.subheader("Crash Analysis")
        if 'category' not in df.columns or 'ctime' not in df.columns:
            st.error("Missing 'category' or 'ctime' for Crash Analysis.")
        else:
            crashes = df[df['category'].str.contains('crash', case=False, na=False)]
            if crashes.empty:
                st.info("No crash reports found.")
            else:
                crashes['ctime'] = pd.to_datetime(crashes['ctime'])
                # Frequency
                freq = (
                    crashes
                      .groupby(pd.Grouper(key='ctime', freq='H'))
                      .size()
                      .reset_index(name='count')
                )
                ch_freq = (
                    alt.Chart(freq)
                       .mark_line(point=True)
                       .encode(
                           x=alt.X(
                               'ctime:T',
                               title='Time (Hourly)',
                               axis=alt.Axis(
                                   format='%Y-%m-%d %H:%M',
                                   tickCount='day',
                                   labelAngle=-45
                               )
                           ),
                           y=alt.Y('count:Q', title='Crash Count'),
                           tooltip=[
                               alt.Tooltip('ctime:T', title='Hour'),
                               alt.Tooltip('count:Q', title='Crash Count')
                           ]
                       )
                       .properties(height=250)
                )
                st.altair_chart(ch_freq, use_container_width=True)

                # Top processes
                if 'process_name' in crashes.columns:
                    top = (
                        crashes['process_name']
                          .value_counts()
                          .head(10)
                          .reset_index()
                          .rename(columns={'index':'process_name','process_name':'crashes'})
                    )
                    ch_top = (
                        alt.Chart(top)
                           .mark_bar()
                           .encode(
                               x=alt.X('crashes:Q', title='Number of Crashes'),
                               y=alt.Y('process_name:N', sort='-x', title='Process'),
                               tooltip=[
                                   alt.Tooltip('process_name:N', title='Process'),
                                   alt.Tooltip('crashes:Q', title='Crash Count')
                               ]
                           )
                           .properties(height=300)
                    )
                    st.altair_chart(ch_top, use_container_width=True)
                else:
                    st.info("Column 'process_name' missing; skipping top-crash generators.")


    # 4. Resource Usage Heatmaps
    with tabs[3]:
        st.subheader("Resource Usage")
        # Memory
        if 'memory_peak' in df.columns:
            mem = df.copy()
            mem['hour'] = mem['ctime'].dt.hour
            heat = mem.groupby(['date','hour'])['memory_peak'].max().reset_index()
            ch_mem = alt.Chart(heat).mark_rect().encode(
                x='hour:O', y='date:O',
                color=alt.Color('memory_peak:Q', scale=alt.Scale(scheme='reds')),
                tooltip=['date','hour','memory_peak']
            ).properties(height=300)
            st.altair_chart(ch_mem, use_container_width=True)
        else:
            st.info("Column 'memory_peak' missing; skipping memory heatmap.")
        # CPU
        if 'cpu_pct' in df.columns:
            cpu = df.copy()
            cpu['hour'] = cpu['ctime'].dt.hour
            dens = alt.Chart(cpu).transform_density(
                'cpu_pct', as_=['cpu_pct','density'], extent=[0,100]
            ).mark_area().encode(
                x='cpu_pct:Q', y='density:Q'
            ).properties(height=250)
            st.altair_chart(dens, use_container_width=True)
        else:
            st.info("Column 'cpu_pct' missing; skipping CPU density plot.")

    # 5. Network Events
    with tabs[4]:
        st.subheader("Network Events")
        if 'interface' in df.columns and 'event' in df.columns:
            net = df[df['category'].str.contains('net', case=False, na=False)]
            ch_net = alt.Chart(net).mark_point(filled=True, size=100).encode(
                x='ctime:T', y=alt.Y('interface:N', title='Interface'),
                color='event:N', tooltip=['ctime:T','interface','event']
            ).properties(height=300).interactive()
            st.altair_chart(ch_net, use_container_width=True)
        else:
            st.info("Columns 'interface' or 'event' missing; skipping network events.")

    # 6. File-System Activity
    with tabs[5]:
        st.subheader("File-System Activity")
        if 'relpath' in df.columns:
            df['directory'] = df['relpath'].apply(lambda p: p.rsplit('/', 1)[0] if '/' in p else '<root>')
            agg = df.groupby('directory').size().reset_index(name='count')
            ch_fs = alt.Chart(agg).mark_rect().encode(
                x=alt.X('sum(count):Q', stack='normalize', title=None),
                y=alt.Y('sum(count):Q', stack='normalize', title=None),
                color=alt.Color('directory:N', title='Directory'),
                tooltip=['directory','count']
            ).properties(height=300)
            st.altair_chart(ch_fs, use_container_width=True)
        else:
            st.info("Column 'relpath' missing; skipping FS activity treemap.")

    # 7. Anomaly Alerts
    with tabs[6]:
        st.subheader("Anomaly Alerts")
        if 'size_bytes' in df.columns:
            mu, sigma = df['size_bytes'].mean(), df['size_bytes'].std()
            outliers = df[df['size_bytes'] > mu + 3*sigma]
            st.write(f"Found {len(outliers)} files > μ+3σ by size:")
            st.dataframe(outliers[['relpath','category','size_bytes','ctime']].sort_values('size_bytes', ascending=False))
        else:
            st.info("Column 'size_bytes' missing; skipping anomaly detection.")
