import streamlit as st
import pandas as pd
import io

st.set_page_config(page_title="Preferences & Personalization Threats", layout="wide")
st.title("🎛️ Preferences & Personalization Threat Scanner")

# Define threat indicators
indicators = [
    {
        "File": "Accessibility_Preferences.txt",
        "Condition": "Assistive access or accessibility features are enabled globally",
        "Description": (
            "Assistive access allows system control through accessibility APIs. "
            "If this is enabled unexpectedly, it may indicate a backdoor for remote control or malware automation. "
            "Attackers often exploit these APIs for keylogging or UI interaction without user consent."
        ),
        "Logic": "Look for 'Assistive' or 'UniversalAccess' keywords",
        "Cause": "May be triggered by malicious software requiring accessibility permissions to automate UI actions.",
        "Threat Score": 6,
        "Check": lambda line: "Assistive" in line or "UniversalAccess" in line
    },
    {
        "File": "com.apple.camera_CurrentUser.txt",
        "Condition": "Camera usage flag altered or privacy flag missing",
        "Description": (
            "PrivacyCamera keys control app access to the webcam. If these are tampered with, "
            "it may enable silent camera usage. Malicious apps may bypass privacy prompts or spoof permissions."
        ),
        "Logic": "Look for camera flags like 'PrivacyCamera' or missing entries",
        "Cause": "Potential malware modifying entitlements or altering system preferences for webcam.",
        "Threat Score": 8,
        "Check": lambda line: "PrivacyCamera" in line or "CameraUsageDescription" not in line
    },
    {
        "File": "com.apple.coreaudio_CurrentUser.txt",
        "Condition": "Voice processing is off or input device altered",
        "Description": (
            "Voice processing helps with audio quality and echo cancellation. If turned off or if the input device "
            "is unknown, it could indicate microphone hijacking or silent audio routing to spyware tools."
        ),
        "Logic": "Look for 'voiceProcessing = 0' or 'inputDevice' issues",
        "Cause": "May occur due to tampering by audio redirection malware or apps bypassing audio restrictions.",
        "Threat Score": 7,
        "Check": lambda line: "voiceProcessing = 0" in line or ("inputDevice" in line and "Built-in" not in line)
    },
    {
        "File": "subscribedAssets_CurrentUser.txt",
        "Condition": "No voice assets subscribed or asset mismatch",
        "Description": (
            "This file lists downloaded language or speech assets. Anomalies or absence of these may point to "
            "disabled features, system corruption, or failed updates that affect voice-based personalization."
        ),
        "Logic": "Check for empty asset list or unexpected locales",
        "Cause": "Often occurs after failed speech model updates or unauthorized removal.",
        "Threat Score": 6,
        "Check": lambda line: "VoiceAssets" in line and ("[]" in line or "locale" not in line)
    },
    {
        "File": "com.apple.MobileAsset_Global.txt",
        "Condition": "Assistant model not verified or validation failed",
        "Description": (
            "This file tracks model assets (e.g., Siri). Missing or invalid verification indicates possible tampering "
            "with assistant models. Could point to compromised models used to inject commands or responses."
        ),
        "Logic": "Check for 'verified: false' or missing validation",
        "Cause": "Possible mobile asset corruption, system rollback, or deliberate override of verification.",
        "Threat Score": 9,
        "Check": lambda line: "verified: false" in line or "validation" not in line
    }
]

def get_severity(score):
    if score >= 7:
        return "🔴 High"
    elif score >= 4:
        return "🟠 Medium"
    else:
        return "🟢 Low"

uploaded_files = st.file_uploader("📤 Upload Preference/Personalization Logs", type=["txt"], accept_multiple_files=True)

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
                    highlighted = "\n".join([
                        f"<mark>{l}</mark>" if l == line else l
                        for l in context
                    ])
                    matched_lines.append(highlighted)

            triggered = bool(matched_lines)
            results.append({
                "File": ind["File"],
                "Condition": ind["Condition"],
                "Description": ind["Description"],
                "Logic": ind["Logic"],
                "Cause": ind["Cause"],
                "Threat Score": ind["Threat Score"] if triggered else 0,
                "Severity": get_severity(ind["Threat Score"]) if triggered else "🟢 Low",
                "Matches Found": len(matched_lines),
                "Triggered": "Yes" if triggered else "No",
                "Context": matched_lines if triggered else ["<i>No matches found for this indicator.</i>"]
            })

    for res in results:
        with st.expander(f"📁 {res['File']}"):
            st.markdown(f"*📝 Condition:* {res['Condition']}")
            st.markdown(f"*📚 Description:* {res['Description']}")
            st.markdown(f"*🔎 Logic:* {res['Logic']}")
            st.markdown(f"*💥 Cause:* {res['Cause']}")
            st.markdown(f"*🔥 Threat Score:* ⁠ {res['Threat Score']} ⁠")
            st.markdown(f"*⚠️ Severity:* {res['Severity']}")
            st.markdown(f"*🚨 Triggered:* {res['Triggered']}")
            st.markdown("### 📂 Context Matches")
            for ctx in res["Context"]:
                st.markdown(f"<pre>{ctx}</pre>", unsafe_allow_html=True)

    st.subheader("📊 Threat Summary Table")
    df = pd.DataFrame([{
        "File": r["File"],
        "Condition": r["Condition"],
        "Threat Score": r["Threat Score"],
        "Severity": r["Severity"],
        "Matches Found": r["Matches Found"],
        "Triggered": r["Triggered"],
        "Cause": r["Cause"]
    } for r in results])

    st.dataframe(df, use_container_width=True)

    csv = df.to_csv(index=False).encode("utf-8")
    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Threats")
        writer.close()

    st.download_button("⬇️ Download CSV", data=csv, file_name="preferences_threats.csv", mime="text/csv")
    st.download_button("⬇️ Download Excel", data=excel_buffer.getvalue(), file_name="preferences_threats.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")