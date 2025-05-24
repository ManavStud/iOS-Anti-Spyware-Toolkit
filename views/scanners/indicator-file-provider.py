import streamlit as st
import pandas as pd
import io

# --- Indicator Definitions ---
indicators = [
    {
        "File": "fileproviderctl_stderr.txt",
        "Indicator": "Running as root",
        "Description": [
            "Log contains 'running as root'",
            "Elevated privilege use may allow spyware to bypass protections"
        ],
        "Logic": "Look for 'running as root' in the file.",
        "Search Term": "running as root",
        "Threat Score": 8
    },
    {
        "File": "fileproviderctl_task_failures.txt",
        "Indicator": "SIGINT or interrupted check",
        "Description": [
            "Scan terminated unexpectedly",
            "May indicate malware interfering with diagnostics"
        ],
        "Logic": "Look for 'SIGINT' or 'signal 2'",
        "Search Term": ["SIGINT", "signal 2"],
        "Threat Score": 7
    },
    {
        "File": "brctl_errors.txt",
        "Indicator": "Container registration errors",
        "Description": [
            "Repeated container sync issues",
            "Could signal tampering or rogue sync behavior"
        ],
        "Logic": "Look for 'failed to register' or 'conflict'",
        "Search Term": ["failed to register", "conflict"],
        "Threat Score": 6
    },
    {
        "File": "brctl-dump.txt",
        "Indicator": "Rogue or unverified containers",
        "Description": [
            "Non-Apple iCloud containers detected",
            "Possible malicious sync paths"
        ],
        "Logic": "Look for 'com.' but not 'com.apple.'",
        "Search Term": lambda line: "com." in line and "apple" not in line,
        "Threat Score": 9
    }
]

# --- UI Setup ---
st.set_page_config(layout="wide")
st.title("🔍 iCloud & FileProvider Threat Detection")
uploaded_files = st.file_uploader("📁 Upload Sysdiagnose log files", type=["txt", "log"], accept_multiple_files=True)

def match_and_extract_lines(content, match, lines_before=5, lines_after=5):
    output = []
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if isinstance(match, str) and match in line:
            start = max(i - lines_before, 0)
            end = min(i + lines_after + 1, len(lines))
            output.append("\n".join(lines[start:end]))
        elif isinstance(match, list) and any(m in line for m in match):
            start = max(i - lines_before, 0)
            end = min(i + lines_after + 1, len(lines))
            output.append("\n".join(lines[start:end]))
        elif callable(match) and match(line):
            start = max(i - lines_before, 0)
            end = min(i + lines_after + 1, len(lines))
            output.append("\n".join(lines[start:end]))
    return output

if uploaded_files:
    st.markdown("---")
    st.subheader("📦 Indicator Cards with Log Context")
    results = []

    for ind in indicators:
        matched_file = next((f for f in uploaded_files if f.name == ind["File"]), None)
        if matched_file:
            content = matched_file.read().decode("utf-8", errors="ignore")
            matched_file.seek(0)
            context_blocks = match_and_extract_lines(content, ind["Search Term"])

            triggered = bool(context_blocks)
            threat_score = ind["Threat Score"] if triggered else 0

            # --- UI for Card ---
            with st.expander(f"🧩 {ind['Indicator']} ({ind['File']})"):
                for line in ind["Description"]:
                    st.markdown(f"- {line}")
                st.markdown(f"**Logic:** `{ind['Logic']}`")
                st.markdown(f"**Triggered:** `{triggered}`")
                st.markdown(f"**Threat Score:** `{threat_score}`")

                if triggered:
                    st.markdown("**Findings:**")
                    for idx, block in enumerate(context_blocks):
                        st.code(block, language="text")

            results.append({
                "File": ind["File"],
                "Indicator": ind["Indicator"],
                "Condition Met": triggered,
                "Threat Score": threat_score
            })

    # --- Tabular View ---
    df = pd.DataFrame(results)
    st.subheader("📊 Summary Table")
    st.dataframe(df)

    # --- Downloads ---
    csv = df.to_csv(index=False).encode("utf-8")
    excel_io = io.BytesIO()
    with pd.ExcelWriter(excel_io, engine="xlsxwriter") as writer:
        df.to_excel(writer, sheet_name="Indicators", index=False)

    st.download_button("⬇ Download CSV", data=csv, file_name="threat_summary.csv", mime="text/csv")
    st.download_button("⬇ Download Excel", data=excel_io.getvalue(), file_name="threat_summary.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
