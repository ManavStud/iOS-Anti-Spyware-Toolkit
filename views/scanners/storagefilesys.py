import streamlit as st
import pandas as pd
import re
from io import BytesIO

# ----------------------------
# 🎯 Indicator Definitions
# ----------------------------
INDICATORS = []

def add_indicator(name, severity, description, triggered, details, highlights=None):
    INDICATORS.append({
        "Indicator": name,
        "Severity": severity,
        "Description": description,
        "Triggered": "Yes" if triggered else "No",
        "Details": details,
        "Highlights": highlights or []
    })

# ----------------------------
# 📁 UI: File Upload
# ----------------------------
st.set_page_config(layout="wide")
st.title("📀 Forensic Storage & APFS Analyzer")
mount_file = st.file_uploader("📂 Upload mount.txt", type="txt")
apfs_file = st.file_uploader("📂 Upload apfs_stats.txt", type="txt")

if mount_file and apfs_file:
    mount_txt = mount_file.read().decode('utf-8', errors='ignore')
    apfs_txt = apfs_file.read().decode('utf-8', errors='ignore')

    # ----------------------------
    # 🧩 MOUNT ANALYSIS
    # ----------------------------
    mount_lines = mount_txt.strip().splitlines()
    mount_info = []
    for line in mount_lines:
        if " (apfs" in line:
            m = re.match(r"([^ ]+) on ([^ ]+) \(([^)]+)\)", line)
            if m:
                device, mountpt, flags = m.groups()
                flaglist = [f.strip() for f in flags.split(',')]
                mount_info.append({'device': device, 'mountpoint': mountpt, 'flags': flaglist, 'raw': line})

    # --- Noatime Flag
    noatime_vols = [m['mountpoint'] for m in mount_info if 'noatime' in m['flags']]
    noatime_lines = [m['raw'] for m in mount_info if 'noatime' in m['flags']]
    add_indicator(
        "Noatime Flag Used", "Medium",
        "The 'noatime' flag prevents file access times from being updated. Malware may use it to avoid detection based on timestamps.",
        triggered=bool(noatime_vols),
        details=", ".join(noatime_vols) or "None",
        highlights=noatime_lines
    )

    # --- Protected Volumes
    protected_vols = [m['mountpoint'] for m in mount_info if 'protect' in m['flags']]
    protect_lines = [m['raw'] for m in mount_info if 'protect' in m['flags']]
    add_indicator(
        "Protected Volume", "Medium",
        "Volumes flagged as 'protected' often include system integrity protection. Malware can abuse this for persistence.",
        triggered=bool(protected_vols),
        details=", ".join(protected_vols) or "None",
        highlights=protect_lines
    )

    # --- Journaling Disabled
    journaling_issues = [m['mountpoint'] for m in mount_info if 'journaled' not in m['flags']]
    journaling_lines = [m['raw'] for m in mount_info if 'journaled' not in m['flags']]
    add_indicator(
        "Journaling Disabled", "High",
        "Journaling improves recoverability. Volumes without it may be tampered with or vulnerable to corruption.",
        triggered=bool(journaling_issues),
        details=", ".join(journaling_issues) or "None",
        highlights=journaling_lines
    )

    # ----------------------------
    # 🧩 APFS STATS ANALYSIS
    # ----------------------------

    # Read/Write Ratio
    total_idx = apfs_txt.find("Totals for all")
    read_bytes = write_bytes = None
    rw_block = ""
    if total_idx != -1:
        lines = apfs_txt[total_idx:].splitlines()
        for l in lines:
            if "read requests" in l and "transfered" in l:
                match = re.search(r"transfered\s+(\d+)\s+bytes", l)
                if match:
                    read_bytes = int(match.group(1))
                    rw_block += l + "\n"
            if "write requests" in l and "transfered" in l:
                match = re.search(r"transfered\s+(\d+)\s+bytes", l)
                if match:
                    write_bytes = int(match.group(1))
                    rw_block += l + "\n"

    rw_detail = "Insufficient data"
    unusual_ratio = False
    if read_bytes and write_bytes and write_bytes != 0:
        ratio = read_bytes / write_bytes
        unusual_ratio = ratio > 3 or ratio < 0.33
        rw_detail = f"Read: {read_bytes}, Write: {write_bytes}, Ratio: {ratio:.2f}"

    add_indicator(
        "Unusual Read/Write Ratio", "High",
        "An imbalanced read/write ratio can signal forensic scans or malware exfiltration.",
        triggered=unusual_ratio,
        details=rw_detail,
        highlights=[rw_block] if unusual_ratio else []
    )

    # Low Free APFS Blocks
    free_percent = None
    match = re.search(r"Available now:\s+\d+ MiB.*?(\d+\.\d+)%", apfs_txt)
    if match:
        free_percent = float(match.group(1))
    low_space = free_percent is not None and free_percent < 10.0
    detail = f"{free_percent:.2f}% free" if free_percent else "Not found"

    add_indicator(
        "Low Free APFS Blocks", "Medium",
        "Low available blocks may indicate an attempt to exhaust disk space for denial of service or logging disruption.",
        triggered=low_space,
        details=detail
    )

    # Metadata Errors
    re_match = re.search(r"Metadata: Number of read errors =\s*(\d+)", apfs_txt)
    we_match = re.search(r"Metadata: Number of write errors =\s*(\d+)", apfs_txt)
    rerr, werr = int(re_match.group(1)) if re_match else 0, int(we_match.group(1)) if we_match else 0
    metadata_err = rerr + werr > 0
    add_indicator(
        "APFS Metadata Errors", "High",
        "Metadata I/O failures suggest possible disk corruption, hardware issues, or interference with filesystem integrity.",
        triggered=metadata_err,
        details=f"Read errors: {rerr}, Write errors: {werr}"
    )

    # AuthAPFS Digest Mismatches
    auth_match = re.search(r"AuthAPFS: Number of times digest did not match =\s*(\d+)", apfs_txt)
    auth_mismatch = int(auth_match.group(1)) if auth_match else 0
    add_indicator(
        "AuthAPFS Digest Mismatches", "High",
        "Digest mismatches indicate that authenticated APFS blocks were tampered with or corrupted.",
        triggered=auth_mismatch > 0,
        details=f"{auth_mismatch} mismatches"
    )

    # Decompression Errors
    decmp_match = re.search(r"Decmpfs errors =\s*(\d+)", apfs_txt)
    decmp_errs = int(decmp_match.group(1)) if decmp_match else 0
    add_indicator(
        "APFS Decompression Errors", "Medium",
        "Decompression failures may point to malicious compression tricks or corrupted system files.",
        triggered=decmp_errs > 0,
        details=f"{decmp_errs} errors"
    )

    # ----------------------------
    # 📊 Summary + Download
    # ----------------------------
    df = pd.DataFrame(INDICATORS)
    st.subheader("📋 Summary Table")
    st.dataframe(df[["Indicator", "Severity", "Triggered", "Details"]], use_container_width=True)

    # CSV + Excel
    csv = df.to_csv(index=False).encode("utf-8")
    excel_io = BytesIO()
    with pd.ExcelWriter(excel_io, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Indicators")

    st.download_button("⬇ Download CSV", data=csv, file_name="forensic_indicators.csv", mime="text/csv")
    st.download_button("⬇ Download Excel", data=excel_io.getvalue(), file_name="forensic_indicators.xlsx",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    # ----------------------------
    # 🔍 Indicator Cards w/ Context
    # ----------------------------
    st.subheader("🔎 Indicator Details")
    for ind in INDICATORS:
        with st.expander(f"🧩 {ind['Indicator']} ({ind['Severity']}) - Triggered: {ind['Triggered']}"):
            st.markdown(f"**Description:** {ind['Description']}")
            st.markdown(f"**Details:** {ind['Details']}")
            if ind["Highlights"]:
                st.markdown("**Log Highlights:**")
                for h in ind["Highlights"]:
                    # Bold important lines inside the log block
                    highlighted = re.sub(r'(?i)(noatime|protect|journaled|digest did not match|errors|read requests|write requests)',
                                         r'**\1**', h)
                    st.code(highlighted, language="text")
else:
    st.info("📂 Please upload both `mount.txt` and `apfs_stats.txt` files to begin analysis.")
