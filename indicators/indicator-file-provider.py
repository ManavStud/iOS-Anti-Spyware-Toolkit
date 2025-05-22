import streamlit as st
import pandas as pd
import io
import re

# --------------------- INDICATORS ---------------------
indicators = [
    {
        "Name": "Running as root",
        "File": "fileproviderctl_stderr.txt",
        "Condition": "Log contains 'running as root'",
        "Search Term": "running as root",
        "Severity": "High",
        "Threat Score": 8,
        "Description": "The tool was executed with elevated privileges. Running as root may allow spyware to silently modify system behavior, bypassing security protections.",
        "Logic": "Look for 'running as root' in the log."
    },
    {
        "Name": "SIGINT Interrupt",
        "File": "fileproviderctl_task_failures.txt",
        "Condition": "Check terminated via SIGINT or signal 2",
        "Search Term": ["SIGINT", "signal 2"],
        "Severity": "High",
        "Threat Score": 7,
        "Description": "The diagnostic process was interrupted, possibly by malware avoiding detection. Normal diagnostic tools should complete without interruption.",
        "Logic": "Detect signals indicating abnormal termination."
    },
    {
        "Name": "Container Registration Errors",
        "File": "brctl_errors.txt",
        "Condition": "Repeated container registration errors",
        "Search Term": ["failed to register", "conflict"],
        "Severity": "Medium",
        "Threat Score": 6,
        "Description": "Indicates failed attempts to register iCloud containers. May suggest unauthorized container manipulation or syncing disruptions.",
        "Logic": "Search for sync failure patterns."
    },
    {
        "Name": "Rogue Containers",
        "File": "brctl-dump.txt",
        "Condition": "Container IDs not in com.apple.*",
        "Search Term": lambda line: "com." in line and "com.apple." not in line,
        "Severity": "Critical",
        "Threat Score": 9,
        "Description": "Container names not signed by Apple may indicate rogue syncing processes or spyware exfiltrating data via iCloud.",
        "Logic": "Find iCloud containers not signed by Apple."
    }
]

# --------------------- FUNCTIONS ---------------------
def extract_context(content, match_check, lines_before=5, lines_after=5):
    lines = content.splitlines()
    findings = []
    for i, line in enumerate(lines):
        match = False
        if isinstance(match_check, str):
            match = match_check in line
        elif isinstance(match_check, list):
            match = any(term in line for term in match_check)
        elif callable(match_check):
            match = match_check(line)

        if match:
            start, end = max(0, i - lines_before), min(len(lines), i + lines_after + 1)
            context_block = lines[start:end]
            findings.append(context_block)
    return findings

def highlight_terms(text_block, terms):
    if isinstance(terms, str):
        terms = [terms]
    for term in terms:
        text_block = re.sub(f'({re.escape(term)})', r'<span style="background-color: #fff68f"><b>\1</b></span>', text_block, flags=re.IGNORECASE)
    return text_block

def get_severity_color(severity):
    return {
        "Low": "#b0e57c",
        "Medium": "#ffdb58",
        "High": "#ff8c42",
        "Critical": "#ff5e5e"
    }.get(severity, "#d3d3d3")

# --------------------- STREAMLIT UI ---------------------
st.set_page_config(layout="wide")
st.title("📁 File Provider & iCloud Threat Intelligence Tool")
uploaded_files = st.file_uploader("Upload Logs", type=["txt", "log"], accept_multiple_files=True)

if uploaded_files:
    uploaded_dict = {f.name: f for f in uploaded_files}
    summary = []

    for ind in indicators:
        file = uploaded_dict.get(ind["File"])
        st.markdown(f"---\n### 📄 File: `{ind['File']}`")

        if file:
            content = file.read().decode("utf-8", errors="ignore")
            matches = extract_context(content, ind["Search Term"])
            triggered = bool(matches)

            score = ind["Threat Score"] if triggered else 0
            summary.append({
                "Indicator": ind["Name"],
                "File": ind["File"],
                "Condition": ind["Condition"],
                "Triggered": triggered,
                "Threat Score": score,
                "Severity": ind["Severity"]
            })

            st.markdown(f"**🧠 Indicator:** {ind['Name']}")
            st.markdown(f"**📝 Condition:** {ind['Condition']}")
            st.markdown(f"**🧾 Description:** {ind['Description']}")
            st.markdown(f"**🔬 Logic:** *{ind['Logic']}*")
            st.markdown(f"**🔥 Severity:** `{ind['Severity']}`", unsafe_allow_html=True)
            st.markdown(f"**📊 Threat Score:** `{score}`")
            st.markdown(f"**✅ Triggered:** {'Yes' if triggered else 'No'}")

            if triggered:
                st.markdown("#### 🔍 Matched Context:")
                for context_lines in matches:
                    context = "\n".join(context_lines)
                    highlighted = highlight_terms(context, ind["Search Term"])
                    st.markdown(f"<pre>{highlighted}</pre>", unsafe_allow_html=True)
            else:
                st.success("✅ No matches found.")
        else:
            st.warning(f"⚠️ `{ind['File']}` not uploaded.")
            summary.append({
                "Indicator": ind["Name"],
                "File": ind["File"],
                "Condition": ind["Condition"],
                "Triggered": False,
                "Threat Score": 0,
                "Severity": ind["Severity"]
            })

    # -------------------- Summary Table --------------------
    st.markdown("---\n## 📋 Summary Table")
    df = pd.DataFrame(summary)
    st.dataframe(df)

    csv = df.to_csv(index=False).encode("utf-8")
    excel_io = io.BytesIO()
    with pd.ExcelWriter(excel_io, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Threat Summary")
    st.download_button("⬇️ Download CSV", csv, "threat_summary.csv", "text/csv")
    st.download_button("⬇️ Download Excel", excel_io.getvalue(), "threat_summary.xlsx",
                       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
