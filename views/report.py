# views/report.py

import streamlit as st
import pandas as pd
import json
import os
from pathlib import Path
import folium
from streamlit_folium import st_folium

from ai_summary import get_summary, summarize_indicators
from indicator_engine import scan_path, load_indicators

def render_report():
    # ─── Paths ───────────────────────────────────────────────────────────────────
    SCRIPT_DIR   = Path(__file__).resolve().parent
    PROJECT_ROOT = SCRIPT_DIR.parent
    CASES_ROOT   = PROJECT_ROOT / "sysdiagnose" / "cases"
    REPORT_DIR   = PROJECT_ROOT / "reports"
    REPORT_DIR.mkdir(exist_ok=True)

    # ─── Pick latest case ────────────────────────────────────────────────────────
    case_dirs = [d for d in os.listdir(CASES_ROOT) if (CASES_ROOT / d).is_dir()]
    if not case_dirs:
        st.error("No sysdiagnose cases found.")
        return
    latest_case = max(case_dirs, key=lambda d: (CASES_ROOT / d).stat().st_mtime)
    parsed_data = CASES_ROOT / latest_case / "parsed_data"

    # ─── Load DataFrames ──────────────────────────────────────────────────────────
    def load_jsonl(fp): return [json.loads(l) for l in open(fp, 'r')]
    def load_json(fp):  return json.load(open(fp, 'r'))

    try:
        accessibility = pd.DataFrame(load_jsonl(parsed_data/"accessibility_tcc.jsonl"))
        activation    = pd.DataFrame(load_jsonl(parsed_data/"mobileactivation.jsonl"))
        backup        = pd.DataFrame(load_jsonl(parsed_data/"mobilebackup.jsonl"))
        wifinetworks  = pd.DataFrame(load_json(parsed_data/"wifinetworks.json"))
        crashlogs     = pd.DataFrame(load_jsonl(parsed_data/"crashlogs.jsonl"))
        lockdownd     = pd.DataFrame(load_jsonl(parsed_data/"lockdownd.jsonl"))
        wifiscan      = pd.DataFrame(load_jsonl(parsed_data/"wifiscan.jsonl"))
    except FileNotFoundError as e:
        st.error(f"Missing file: {e}")
        return

    dfs = [
        (accessibility, "Accessibility Permissions",
         "Records of which services/apps requested device permissions and whether they were granted."),
        (activation,    "Mobile Activation",
         "Timestamps of device activation events (e.g. unlocks, wakeups)."),
        (backup,        "Mobile Backups",
         "Metadata about device backups, including file sizes."),
        (crashlogs,     "Crash Logs",
         "Parsed crash reports, categorized by crash reason."),
        (lockdownd,     "Lockdown Pairings",
         "Bluetooth lockdown pairings between device and peripherals."),
        (wifinetworks,  "Wi-Fi Networks",
         "Known Wi-Fi networks saved on device, including auto-join settings."),
        (wifiscan,      "Wi-Fi Scans",
         "Geo-located Wi-Fi scan results showing networks seen nearby."),
    ]

    # ─── Persist ALL tables (hidden) ─────────────────────────────────────────────
    xlsx_path = REPORT_DIR / f"{latest_case}_tables.xlsx"
    with pd.ExcelWriter(xlsx_path, engine="xlsxwriter") as writer:
        for df, name, _ in dfs:
            df.to_excel(writer, sheet_name=name[:31], index=False)
            (REPORT_DIR / f"{name}.csv").write_text(df.to_csv(index=False))

    # ─── Report Tab ──────────────────────────────────────────────────────────────
    tab = st.tabs(["Report"])[0]
    with tab:
        # API key input once
        api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        if not api_key:
            api_key = st.text_input(
                "OpenRouter API Key", type="password",
                placeholder="Paste API key here to enable AI summaries"
            )
        if not api_key:
            st.warning("No API key — AI summaries will be skipped.")

        # ─── Section Loop ───────────────────────────────────────────────────────
        for df, name, desc in dfs:
            st.header(name)
            st.markdown(f"**What is this section about?**  {desc}")
            st.markdown("**Important Findings**")
            st.write(f"- Total entries: **{len(df)}**")

            suspicious_notes = []
            if name == "Crash Logs" and 'category' in df.columns:
                top = df['category'].value_counts()
                if not top.empty:
                    suspicious_notes.append(f"- Top crash category “{top.index[0]}” with **{top.iloc[0]}** entries.")
            if name == "Accessibility Permissions" and 'allowed' in df.columns:
                denied = df['allowed'].eq('DENIED').sum()
                if denied:
                    suspicious_notes.append(f"- **{denied}** permission denials found.")
            if name == "Wi-Fi Networks" and 'auto_join' in df.columns:
                aj = df['auto_join'].eq(True).sum()
                suspicious_notes.append(f"- **{aj}** networks set to auto-join.")

            st.markdown("**Anything Suspicious?**")
            st.write(suspicious_notes or "- None flagged.")

            # ─ Chart per section ────────────────────────────────────────────────
            st.subheader("Chart")
            if name == "Accessibility Permissions" and {'service','allowed'}.issubset(df.columns):
                df['status'] = df['allowed'].map(lambda v: 'Granted' if v=='ALLOWED' else 'Denied')
                st.bar_chart(df.groupby(['service','status']).size().unstack(fill_value=0))
            elif name == "Mobile Activation" and 'timestamp' in df.columns:
                df['ts'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
                by_day = df.dropna(subset=['ts']).groupby(df['ts'].dt.date).size()
                st.line_chart(by_day)
            elif name == "Mobile Backups" and 'size' in df.columns:
                st.bar_chart(df['size'].value_counts(bins=20))
            elif name == "Crash Logs" and 'category' in df.columns:
                st.bar_chart(df['category'].value_counts().head(10))
            elif name == "Wi-Fi Scans" and {'lat','lon'}.issubset(df.columns):
                m = folium.Map(location=[0,0], zoom_start=2)
                for _, r in df.iterrows():
                    folium.CircleMarker([r.lat, r.lon], radius=3).add_to(m)
                st_folium(m, width=700, height=400)

            # Wi-Fi Networks: Auto-join locations map
            if name == "Wi-Fi Networks" and 'auto_join' in df.columns:
                st.subheader("Auto-Join Locations Map")
                auto_ssids = df.loc[df['auto_join'], 'ssid'].unique()
                scans = wifiscan[wifiscan['ssid'].isin(auto_ssids)]
                if not scans.empty and {'lat','lon'}.issubset(scans.columns):
                    m2 = folium.Map(location=[0,0], zoom_start=2)
                    for _, r in scans.iterrows():
                        folium.Marker([r.lat, r.lon], popup=r.ssid).add_to(m2)
                    st_folium(m2, width=700, height=400)
                else:
                    st.info("No auto-join scan locations.")

            # ─ AI-Generated Summary ───────────────────────────────────────────────
            st.subheader("AI-Generated Summary")
            if api_key:
                csv_path = REPORT_DIR / f"{name}.csv"
                try:
                    st.write(get_summary(str(csv_path)))
                except Exception as e:
                    st.error(f"Failed to summarize {name}: {e}")
            else:
                st.info("Skipped (no API key).")

        # ─── Triggered Indicators ────────────────────────────────────────────────
        st.header("Triggered Indicators")

        # -- NEW: load all indicator files from the indicators directory
        indicators = []
        ind_dir = PROJECT_ROOT / "indicators"
        if ind_dir.is_dir():
            for f in ind_dir.iterdir():
                if f.is_file():
                    try:
                        indicators.extend(load_indicators(str(f)))
                    except Exception as e:
                        st.warning(f"Failed loading indicators from {f.name}: {e}")
        else:
            # fallback if it's a single file
            indicators = load_indicators(str(ind_dir))

        hits = scan_path(str(CASES_ROOT/latest_case), indicators)
        if hits.empty:
            st.info("No indicators triggered.")
        else:
            st.subheader("AI-Generated Indicators Summary")
            if api_key:
                try:
                    st.write(summarize_indicators(hits))
                except Exception as e:
                    st.error(f"Indicators summary failed: {e}")
            else:
                st.info("Skipped (no API key).")
