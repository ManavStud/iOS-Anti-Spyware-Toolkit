import streamlit as st

# Sample Indicators
indicators = [
    {
        "File": "IOUSB.txt",
        "Condition": "Non-Apple Vendor IDs (≠ 0x05AC)",
        "Match Keyword": "0x",
        "Exclude Keyword": "0x05AC"
    },
    {
        "File": "IOUSB.txt",
        "Condition": "MassStorage or Serial Class Detected",
        "Match Keyword": "MassStorage",
        "Exclude Keyword": ""
    },
    {
        "File": "IOService.txt",
        "Condition": "AppleUSBSerial or IOUserClient Present",
        "Match Keyword": "AppleUSBSerial",
        "Exclude Keyword": ""
    },
    {
        "File": "IOPort.txt",
        "Condition": "Legacy Port Dock30PinBuiltIn",
        "Match Keyword": "Dock30PinBuiltIn",
        "Exclude Keyword": ""
    }
]

st.title("🔍 Hardware & IOKit Indicator Context Viewer")

uploaded_files = st.file_uploader("Upload relevant files", type=["txt"], accept_multiple_files=True)

if uploaded_files:
    file_dict = {file.name: file.read().decode("utf-8", errors="ignore").splitlines() for file in uploaded_files}

    for ind in indicators:
        file_name = ind["File"]
        match_kw = ind["Match Keyword"]
        exclude_kw = ind["Exclude Keyword"]

        if file_name in file_dict:
            lines = file_dict[file_name]
            matches = []

            for idx, line in enumerate(lines):
                if match_kw in line and (not exclude_kw or exclude_kw not in line):
                    context = lines[max(0, idx - 5): min(len(lines), idx + 6)]
                    matches.append({
                        "Index": idx,
                        "Match Line": line.strip(),
                        "Context": context
                    })

            # Display results
            if matches:
                for m in matches:
                    with st.expander(f"📁 {ind['Condition']} — Triggered in {file_name}"):
                        st.markdown(f"**Matching Line (Line {m['Index']}):** `{m['Match Line']}`")
                        st.code("\n".join(m["Context"]), language="text")
            else:
                with st.expander(f"✅ {ind['Condition']} — No match found in {file_name}"):
                    st.info("No suspicious entries detected based on this indicator.")
        else:
            st.warning(f"⚠️ File `{file_name}` not uploaded.")
