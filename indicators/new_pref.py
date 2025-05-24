import streamlit as st
import pandas as pd
import io

st.set_page_config(page_title="Preferences & Personalization Threats", layout="wide")
st.title("🎛️ Preferences & Personalization Threat Scanner")

# Define threat indicators with exact descriptions
indicators = [
    {
        "Title": "Assistive Access Enabled",
        "File": "Accessibility_Preferences.txt",
        "Condition": "Accessibility features are enabled",
        "Description": (
            "File: Accessibility_Preferences.txt\n"
            "Block: com.apple.Accessibility\n\n"
            "AccessibilityEnabled = 1;\n"
            "Accessibility services are globally enabled—used by VoiceOver, Switch Control, etc. "
            "Can indicate scripted UI interaction if user has no disability.\n\n"
            "ApplicationAccessibilityEnabled = 1;\n"
            "Enables app-specific accessibility. Allows apps to expose UI hierarchy—necessary for screen readers, "
            "but also enables programmatic UI observation.\n\n"
            "EnhancedBackgroundContrastEnabled = 0;\n"
            "No high-contrast visuals requested.\n\n"
            "QuickSpeak = 0;\n"
            "Quick text-to-speech is off.\n\n"
            "ReduceMotionEnabled = 0;\n"
            "Full UI animations enabled—no motion sensitivity.\n\n"
            "SpeakThisEnabled = 1;\n"
            "'Speak Selection' is on—used for hands-free or cognitive assistance.\n\n"
            "ZoomTouchEnabled = 0;\n"
            "No zoom gestures—suggests no visual impairment tools in use.\n\n"
            "Block: com.apple.Accessibility.TouchAccommodations\n"
            "All Touch Accommodation settings = 0\n"
            "No tap-delay or hold gestures enabled—implies standard screen interaction.\n\n"
            "Summary:\n"
            "Only 'Speak This' is active. Indicates limited accessibility usage—no evidence of misuse alone, "
            "but could raise flags if paired with automation logs."
        ),
        "Logic": "Look for 'Assistive' or 'UniversalAccess' keywords",
        "Cause": "May be triggered by malicious software requiring accessibility permissions to automate UI actions.",
        "Threat Score": 6,
        "Check": lambda line: "Assistive" in line or "UniversalAccess" in line
    },
    {
        "Title": "Camera Privacy Tampering",
        "File": "com.apple.camera_CurrentUser.txt",
        "Condition": "Camera usage flag altered or privacy flag missing",
        "Description": (
            "File: com.apple.camera_CurrentUser.txt\n\n"
            "Capture Behavior:\n"
            "Default to rear camera (0) and photo mode (0).\n"
            "Front camera mirroring = 1 — typical for selfies.\n\n"
            "Image Enhancements:\n"
            "HDR (1), Night mode (1), Modern HDR = on — user prioritizes quality in varied lighting.\n"
            "Portrait mode with max blur and effect type 16 — indicates use of advanced photo features.\n\n"
            "Feature Upgrades & Migrations:\n"
            "Live Photo, HDR upgrades performed — user actively adopts new camera features.\n\n"
            "Live Photos & Timers:\n"
            "Live Photos preserved; no timer — manual capture preferred.\n\n"
            "Grid & Composition Tools:\n"
            "Grid and horizon overlays enabled — suggests intentional framing, possibly by a photography enthusiast.\n\n"
            "Media Object Configuration:\n"
            "Handles many pro formats (Canon, Nikon, etc.) — suggests pro-level editing tools or imports.\n\n"
            "Metadata:\n"
            "Last config update: March 2025 — confirms recent activity.\n\n"
            "Summary:\n"
            "Advanced, deliberate camera use. Helpful for determining habits, timing, and potential for sensitive media capture."
        ),
        "Logic": "Look for camera flags like 'PrivacyCamera' or missing entries",
        "Cause": "Potential malware modifying entitlements or altering system preferences for webcam.",
        "Threat Score": 8,
        "Check": lambda line: "PrivacyCamera" in line or "CameraUsageDescription" not in line
    },
    {
        "Title": "Microphone Input Tampering",
        "File": "com.apple.coreaudio_CurrentUser.txt",
        "Condition": "Voice processing is off or input device altered",
        "Description": (
            "File: com.apple.coreaudio_CurrentUser.txt\n\n"
            "Common Entry Patterns:\n"
            "AUVoiceIOBypassVoiceProcessing = 0; — mic input goes through Apple's audio filters.\n"
            "AUVoiceIOSupportedChatFlavors entries define VoIP/audio modes used.\n\n"
            "App-Level Activity:\n"
            "Audio interaction seen with Discord, WhatsApp, Google Meet, Zoom, Teams, OpenAI Chat — active or initialized microphone use.\n\n"
            "Accessory Logging:\n"
            "Logs Apple accessory with timestamp (June 2022) — tracks physical mic use.\n\n"
            "Summary:\n"
            "No evidence of audio interception. Helps confirm which apps accessed mic and when—valuable with other forensic data."
        ),
        "Logic": "Look for 'voiceProcessing = 0' or 'inputDevice' issues",
        "Cause": "May occur due to tampering by audio redirection malware or apps bypassing audio restrictions.",
        "Threat Score": 7,
        "Check": lambda line: "voiceProcessing = 0" in line or ("inputDevice" in line and "Built-in" not in line)
    },
    {
        "Title": "Voice Assets Missing",
        "File": "subscribedAssets_CurrentUser.txt",
        "Condition": "No voice assets subscribed or asset mismatch",
        "Description": (
            "File: subscribedAssets_CurrentUser.txt\n\n"
            "Key Observations:\n"
            "Voice resources used by Siri, telephony, and accessibility services:\n"
            "nora (en-US), riya (en-IN), catherine (accessibility voice).\n\n"
            "Suggests multilingual use, possibly for regional Siri or accessibility settings.\n\n"
            "Summary:\n"
            "No threat indicators. Useful for understanding voice assistant preferences and potential geolocation."
        ),
        "Logic": "Check for empty asset list or unexpected locales",
        "Cause": "Often occurs after failed speech model updates or unauthorized removal.",
        "Threat Score": 6,
        "Check": lambda line: "VoiceAssets" in line and ("[]" in line or "locale" not in line)
    },
    {
        "Title": "Assistant Model Integrity Failed",
        "File": "com.apple.MobileAsset_Global.txt",
        "Condition": "Assistant model not verified or validation failed",
        "Description": (
            "File: com.apple.MobileAsset_Global.txt\n\n"
            "Important Entries:\n"
            "Unique ID identifies this device's asset profile.\n"
            "URL override points to experimental Siri components — implies:\n"
            "- Beta/dev program enrollment\n"
            "- Use of trial Siri features\n\n"
            "Summary:\n"
            "No signs of misuse, but suggests advanced or test device. Might be used for Siri feature evaluation."
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
                    highlighted = "\n".join([f"<mark>{l}</mark>" if l == line else l for l in context])
                    matched_lines.append(highlighted)

            triggered = bool(matched_lines)
            results.append({
                "Title": ind["Title"],
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
        with st.expander(f"🔍 {res['Title']}"):
            st.markdown(f"**📁 File:** `{res['File']}`")
            st.markdown(f"**📝 Condition:** {res['Condition']}")
            st.markdown(f"**📚 Description:**\n{res['Description']}", unsafe_allow_html=True)
            st.markdown(f"**🔎 Logic:** {res['Logic']}")
            st.markdown(f"**💥 Cause:** {res['Cause']}")
            st.markdown(f"**🔥 Threat Score:** `{res['Threat Score']}`")
            st.markdown(f"**⚠️ Severity:** {res['Severity']}")
            st.markdown(f"**🚨 Triggered:** {res['Triggered']}")
            st.markdown("### 📂 Context Matches")
            for ctx in res["Context"]:
                st.markdown(f"<pre>{ctx}</pre>", unsafe_allow_html=True)

    st.subheader("📊 Threat Summary Table")
    df = pd.DataFrame([{
        "File": r["File"],
        "Condition": r["Condition"],
        "Cause": r["Cause"],
        "Triggered": r["Triggered"],
        "Threat Score": r["Threat Score"],
        "Severity": r["Severity"]
    } for r in results])

    st.dataframe(df, use_container_width=True)

    csv = df.to_csv(index=False).encode("utf-8")
    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Threats")

    st.download_button("⬇️ Download CSV", data=csv, file_name="preferences_threats.csv", mime="text/csv")
    st.download_button("⬇️ Download Excel", data=excel_buffer.getvalue(), file_name="preferences_threats.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")