import streamlit as st
import pandas as pd
import re
import io

# --- Indicator Definitions ---
indicators = [
    {
        "File": "wifi_status.txt",
        "Indicator": "Static MAC Address",
        "Description": [
            "MAC address does not follow randomized format",
            "Might allow persistent device tracking"
        ],
        "Logic": "MAC does not start with randomized prefixes (02, 06, 0A, 0E)",
        "Search Term": lambda line: "MAC Address" in line and not re.search(r"^..", line.split(":" )[-1].strip()).group(0).lower() in ["02", "06", "0a", "0e"],
        "Threat Score": 8.0
    },
    {
        "File": "wifi_status.txt",
        "Indicator": "Covert Upload (High Tx on Low RSSI)",
        "Description": [
            "Transmission rate > 100 Mbps despite weak signal",
            "May indicate stealthy data exfiltration"
        ],
        "Logic": "Tx Rate > 100 and RSSI < -75",
        "Search Term": lambda line: "Tx Rate" in line and float(re.search(r"[\d.]+", line).group()) > 100,
        "Threat Score": 4.5
    },
    {
        "File": "wifi_scan_cache.txt",
        "Indicator": "Multiple Hidden SSIDs",
        "Description": [
            "Hidden SSIDs present in scan cache",
            "Often used by spyware for stealthy beacons"
        ],
        "Logic": "Hidden SSID count >= 2",
        "Search Term": lambda line: "hidden=" in line and int(re.search(r"hidden=(\d+)", line).group(1)) >= 2 if re.search(r"hidden=(\d+)", line) else False,
        "Threat Score": 5.0
    },
    {
        "File": "wifi_scan_cache.txt",
        "Indicator": "Open or Enterprise SSIDs",
        "Description": [
            "Scan contains open or WPA2-enterprise networks",
            "May indicate MITM risk or corporate surveillance"
        ],
        "Logic": "Presence of open or enterprise networks",
        "Search Term": lambda line: "security=open" in line or "wpa2-enterprise" in line,
        "Threat Score": 4.0
    },
    {
        "File": "wifi_scan.txt",
        "Indicator": "Open or Enterprise SSIDs",
        "Description": [
            "Scan contains open or WPA2-enterprise networks",
            "May indicate MITM risk or corporate surveillance"
        ],
        "Logic": "Presence of open or enterprise networks",
        "Search Term": lambda line: "security=open" in line or "wpa2-enterprise" in line,
        "Threat Score": 4.0
    },
    {
        "File": "wifi_datapath-POST.txt",
        "Indicator": "Packet Logging Enabled",
        "Description": [
            "Flags like print_peers, print_packets, etc. are enabled",
            "May indicate peer surveillance or packet capture"
        ],
        "Logic": "Debug flags include 'print_peers' or similar",
        "Search Term": lambda line: any(flag in line for flag in ["print_peers", "print_packets", "print_all_peers_verbose"]),
        "Threat Score": 4.5
    },
    {
        "File": "wifi_datapath-PRE.txt",
        "Indicator": "MAC Randomization Disabled",
        "Description": [
            "bgscan-private-mac seen in core capture",
            "Indicates persistent identity or tracking risk"
        ],
        "Logic": "Line contains 'bgscan-private-mac'",
        "Search Term": lambda line: "bgscan-private-mac" in line,
        "Threat Score": 5.0
    },
    {
        "File": "wifi_datapath-POST.txt",
        "Indicator": "AWDL0 Peer Interface Logging",
        "Description": [
            "Interface awdl0 is active with logging enabled",
            "Could signal AirDrop/BLE data transfer"
        ],
        "Logic": "Logging flags active on awdl0",
        "Search Term": lambda line: "INTERFACE: awdl0" in line,
        "Threat Score": 4.5
    },
    {
        "File": "network_status.txt",
        "Indicator": "Local Gateway DNS",
        "Description": [
            "DNS is set to local gateway or link-local address",
            "Could be used for DNS hijacking or tunneling"
        ],
        "Logic": "DNS uses 172.20.x.x or fe80::",
        "Search Term": lambda line: "DNS" in line and ("172.20." in line or "fe80::" in line),
        "Threat Score": 3.0
    }
]

# --- Helper ---
def match_context(content, match, lines_before=2, lines_after=2):
    output = []
    lines = content.splitlines()
    for i, line in enumerate(lines):
        try:
            if isinstance(match, str) and match in line:
                output.append("\n".join(lines[max(i-lines_before,0):i+lines_after+1]))
            elif callable(match):
                if match(line):
                    output.append("\n".join(lines[max(i-lines_before,0):i+lines_after+1]))
        except:
            continue
    return output

def find_matching_file(uploaded_map, target_name):
    for name in uploaded_map:
        if target_name.replace(".txt", "") in name:
            return uploaded_map[name]
    return None

# --- UI ---
st.set_page_config(layout="wide")
st.title("📡 Wi-Fi & Core Capture Forensic Analyzer")
uploaded_files = st.file_uploader("📁 Upload Wi-Fi and Core Capture logs", type=["txt"], accept_multiple_files=True)

if uploaded_files:
    st.markdown("---")
    st.subheader("🧠 Indicator Cards with Log Context")
    results = []

    uploaded_map = {f.name: f.read().decode("utf-8", errors="ignore") for f in uploaded_files}

    for ind in indicators:
        content = find_matching_file(uploaded_map, ind["File"])
        if not content:
            continue

        matches = match_context(content, ind["Search Term"])
        triggered = bool(matches)

        with st.expander(f"📍 {ind['Indicator']} ({ind['File']})"):
            for desc in ind["Description"]:
                st.markdown(f"- {desc}")
            st.markdown(f"**Logic:** `{ind['Logic']}`")
            st.markdown(f"**Triggered:** `{triggered}`")
            st.markdown(f"**Threat Score:** `{ind['Threat Score'] if triggered else 0}`")

            if triggered:
                st.markdown("**Findings:**")
                for block in matches:
                    st.code(block, language="text")

        results.append({
            "File": ind["File"],
            "Indicator": ind["Indicator"],
            "Condition Met": triggered,
            "Threat Score": ind["Threat Score"] if triggered else 0
        })

    # --- Summary Table ---
    df = pd.DataFrame(results)
    st.subheader("📊 Summary Table")
    st.dataframe(df)

    # --- Export Options ---
    csv = df.to_csv(index=False).encode("utf-8")
    excel_io = io.BytesIO()
    with pd.ExcelWriter(excel_io, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Indicators")

    st.download_button("⬇ Download CSV", data=csv, file_name="wifi_core_summary.csv", mime="text/csv")
    st.download_button("⬇ Download Excel", data=excel_io.getvalue(), file_name="wifi_core_summary.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
else:
    st.info("Please upload Wi-Fi and Core Capture log files (e.g., wifi_status.txt, datapath logs, scan logs).")
