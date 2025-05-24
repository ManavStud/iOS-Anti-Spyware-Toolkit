import streamlit as st
import pandas as pd
import re
import io

st.set_page_config(page_title="Network Threat Indicators", layout="wide")
st.title("📡 Network Threat Indicator Scanner")

# Define Network Indicators
indicators = [
    {
        "File": "netstat-POST.txt",
        "Condition": "Unusual Outbound Connections (non-private IPs)",
        "Description": "Outbound connection to public IP",
        "Reasoning": "Device may be communicating with remote attacker/C2 servers",
        "Logic": "Detect public IPs not in RFC1918 ranges",
        "Threat Score": 8,
        "Check": lambda line: bool(re.search(r'\b(?!(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])))(\d{1,3}\.){3}\d{1,3}\b', line)),
    },
    {
        "File": "ifconfig.txt",
        "Condition": "Interface in Promiscuous Mode",
        "Description": "Interface is set to PROMISC",
        "Reasoning": "Could indicate sniffing activity on the device",
        "Logic": "Search for PROMISC in interface config",
        "Threat Score": 9,
        "Check": lambda line: "PROMISC" in line,
    },
    {
        "File": "arp.txt",
        "Condition": "Unknown MAC Address in ARP cache",
        "Description": "ARP entry with non-local vendor prefix",
        "Reasoning": "Might indicate rogue device nearby",
        "Logic": "Non-Apple MACs with unknown vendor prefixes",
        "Threat Score": 7,
        "Check": lambda line: re.search(r'(([0-9a-f]{2}[:-]){5}[0-9a-f]{2})', line, re.IGNORECASE) and "incomplete" not in line,
    }
]

# Upload files
uploaded_files = st.file_uploader("Upload network-related logs", type=["txt"], accept_multiple_files=True)

# Results container
results = []

if uploaded_files:
    for ind in indicators:
        matched_file = next((f for f in uploaded_files if f.name == ind["File"]), None)
        if matched_file:
            content = matched_file.read().decode("utf-8", errors="ignore")
            lines = content.splitlines()

            matched_lines = []
            for i, line in enumerate(lines):
                if ind["Check"](line):
                    start = max(0, i - 5)
                    end = min(len(lines), i + 6)
                    context = lines[start:end]
                    matched_lines.append("\n".join(context))

            if matched_lines:
                results.append({
                    "File": ind["File"],
                    "Condition": ind["Condition"],
                    "Description": ind["Description"],
                    "Reasoning": ind["Reasoning"],
                    "Logic": ind["Logic"],
                    "Threat Score": ind["Threat Score"],
                    "Matches Found": len(matched_lines),
                    "Context": matched_lines
                })
            else:
                results.append({
                    "File": ind["File"],
                    "Condition": ind["Condition"],
                    "Description": ind["Description"],
                    "Reasoning": ind["Reasoning"],
                    "Logic": ind["Logic"],
                    "Threat Score": 0,
                    "Matches Found": 0,
                    "Context": ["No matches found for this indicator."]
                })

    # Display results
    for res in results:
        with st.expander(f"🔍 File: {res['File']}"):
            st.markdown(f"**Condition:** {res['Condition']}")
            st.markdown(f"**Description:** {res['Description']}")
            st.markdown(f"**Reasoning:** {res['Reasoning']}")
            st.markdown(f"**Logic:** {res['Logic']}")
            st.markdown(f"**Threat Score:** {res['Threat Score']}")

            st.divider()
            if res["Matches Found"] > 0:
                for i, context in enumerate(res["Context"], 1):
                    st.code(context, language="text")
            else:
                st.success("✅ No matches found for this indicator.")

    # Generate DataFrame for CSV/Excel download
    df = pd.DataFrame([{
        "File": r["File"],
        "Condition": r["Condition"],
        "Description": r["Description"],
        "Reasoning": r["Reasoning"],
        "Logic": r["Logic"],
        "Threat Score": r["Threat Score"],
        "Matches Found": r["Matches Found"]
    } for r in results])

    st.subheader("📊 Threat Indicator Summary Table")
    st.dataframe(df, use_container_width=True)

    csv = df.to_csv(index=False).encode("utf-8")
    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine="xlsxwriter") as writer:
        df.to_excel(writer, sheet_name="Network Threats", index=False)
        writer.close()

    st.download_button("⬇ Download CSV", data=csv, file_name="network_threats.csv", mime="text/csv")
    st.download_button("⬇ Download Excel", data=excel_buffer.getvalue(), file_name="network_threats.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
