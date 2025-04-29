import streamlit as st
import pandas as pd
import json
import networkx as nx
import matplotlib.pyplot as plt
import folium
from streamlit_folium import st_folium
import os
from pathlib import Path    

# ─── DYNAMIC PROJECT-ROOT RESOLUTION ────────────────────────────────────────────
# Get the folder where this script lives:
# ─── 1. Locate this script’s directory ─────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).resolve().parent    # e.g. <project>/views

# ─── 2. Go up one level to project root ────────────────────────────────────────
PROJECT_ROOT = SCRIPT_DIR.parent                   # <project>

# ─── 3. Point at your cases folder under project ──────────────────────────────
CASES_ROOT   = PROJECT_ROOT / "sysdiagnose" / "cases"

if not CASES_ROOT.exists():
    st.error(f"Cannot find sysdiagnose cases folder at:\n`{CASES_ROOT}`")
    st.stop()


def render_dashboard():
    # Auto-detect latest case
    case_dirs = [d for d in os.listdir(CASES_ROOT) if (CASES_ROOT / d).is_dir()]
    if not case_dirs:
        st.error("No case subfolders found under sysdiagnose/cases")
        return

    latest_case = max(case_dirs, key=lambda d: (CASES_ROOT / d).stat().st_mtime)
    parsed_data_dir = CASES_ROOT / latest_case / "parsed_data"

    # Load JSON/JSONL … just replace your old os.path.join(…, hardcode) with parsed_data_dir / filename
    def load_jsonl(fp): 
        return [json.loads(l) for l in open(fp, 'r')]


    def load_json(fp):
        with open(fp, 'r') as f:
            return json.load(f)

    # --- Load your data frames ---
    try:
        accessibility = pd.DataFrame(load_jsonl(
            os.path.join(parsed_data_dir, "accessibility_tcc.jsonl")))
        activation    = pd.DataFrame(load_jsonl(
            os.path.join(parsed_data_dir, "mobileactivation.jsonl")))
        backup        = pd.DataFrame(load_jsonl(
            os.path.join(parsed_data_dir, "mobilebackup.jsonl")))
        wifinetworks  = pd.DataFrame(load_json(
            os.path.join(parsed_data_dir, "wifinetworks.json")))
        crashlogs     = pd.DataFrame(load_jsonl(
            os.path.join(parsed_data_dir, "crashlogs.jsonl")))
        lockdownd     = pd.DataFrame(load_jsonl(
            os.path.join(parsed_data_dir, "lockdownd.jsonl")))
        wifiscan      = pd.DataFrame(load_jsonl(
            os.path.join(parsed_data_dir, "wifiscan.jsonl")))
    except FileNotFoundError as e:
        st.error(f"Missing file: {e}")
        return
    tabs = st.tabs([
        "Summary",
        "Accessibility Permissions",
        "Mobile Activation",
        "Mobile Backups",
        "Wi-Fi Scans",
        "Crash Logs",
        "Lockdown Pairings",
        "Applications Evidence Map",  # <-- Add this new tab name here!
        "Security Health Overview",
        "Process Snapshot Overview",
        "Wifi Autojoin Locations Map"
    ])

    # --- Summary Tab ---
    with tabs[0]:
        st.header("🔍 Quick Summary")
        st.info("This section summarizes the key forensic metrics extracted from the device, such as app permissions, Wi-Fi networks, crashes, and pairings.")
        col1, col2, col3 = st.columns(3)
        col1.metric("Apps with Camera Access", accessibility[accessibility['service'] == 'kTCCServiceCamera'].shape[0])
        col2.metric("Wi-Fi Networks Known", wifinetworks.shape[0])
        col3.metric("Total Crashes", crashlogs.shape[0])
        st.metric("Device Pairings Found", lockdownd.shape[0])

    with tabs[1]:
        st.header("🛡️ Accessibility Permissions Overview")
        st.info("Displays all apps that have requested sensitive permissions (e.g., Camera, Microphone, Contacts) and highlights potential anomalies.")
        st.dataframe(accessibility)

        # 📋 1. Analyze permission grants
        st.subheader("🔍 Permission Grant vs Deny by Service Type")

        if 'service' in accessibility.columns and 'allowed' in accessibility.columns:
            # Map ALLOWED / not ALLOWED
            accessibility['auth_status'] = accessibility['allowed'].apply(lambda x: 'Granted' if x == 'ALLOWED' else 'Denied')

            grant_counts = accessibility.groupby(['service', 'auth_status']).size().unstack(fill_value=0)
            st.bar_chart(grant_counts)

        # 🎥 2. Sensitive services: Camera / Microphone
        st.subheader("🎥 Apps with Camera or Microphone Access")
        sensitive_services = ['kTCCServiceCamera', 'kTCCServiceMicrophone']

        sensitive_access = accessibility[(accessibility['service'].isin(sensitive_services)) & (accessibility['auth_status'] == 'Granted')]

        st.dataframe(sensitive_access[['client', 'service', 'last modified']])

        st.download_button(
            "Download Sensitive Apps List",
            sensitive_access.to_csv(index=False),
            file_name="sensitive_apps_permissions.csv"
        )
        # 🚨 3. Detect Potential Permission Anomalies
        st.subheader("🚨 Potential Permission Anomalies Detected")

        # Common expected safe apps (example list, can expand)
        safe_apps = [
            'com.apple.MobileSMS',  # iMessage
            'com.apple.facetime',   # FaceTime
            'net.whatsapp.WhatsApp', # WhatsApp
            'com.instagram.iphone'  # Instagram
        ]

        # Sensitive permissions we care about
        sensitive_services = ['kTCCServiceCamera', 'kTCCServiceMicrophone', 'kTCCServiceContacts', 'kTCCServiceLocation']

        # Apps that are not in the safe list but have critical permissions
        potential_anomalies = accessibility[
            (accessibility['service'].isin(sensitive_services)) &
            (accessibility['auth_status'] == 'Granted') &
            (~accessibility['client'].isin(safe_apps))
        ]

        st.dataframe(potential_anomalies[['client', 'service', 'last modified']])

        st.download_button(
            "Download Potential Anomalies CSV",
            potential_anomalies.to_csv(index=False),
            file_name="potential_permission_anomalies.csv"
        )



    # --- Mobile Activation Tab ---
    with tabs[2]:
        st.header("📶 Mobile Activation Events Overview")

        # ℹ️ Info tooltip explaining what this tab shows
        st.info("Activation events represent SIM insertions, device activations, or server communication related to enabling the device. Useful for forensic timelines and SIM change detection.")

        # Display raw activation data
        st.dataframe(activation)

        st.download_button(
            "Download Activation Events CSV",
            activation.to_csv(index=False),
            file_name="mobile_activation_events.csv"
        )

        # 📈 1. Activation Events Timeline (Safe Fallback)
        st.subheader("📈 Activation Event Timeline")

        if 'timestamp' in activation.columns:
            activation['timestamp'] = pd.to_datetime(activation['timestamp'], unit='s', errors='coerce')
            activation_sorted = activation.dropna(subset=['timestamp']).sort_values('timestamp')

            # Count events per day
            events_by_day = activation_sorted.groupby(activation_sorted['timestamp'].dt.date).size()

            # Rename for plotting
            events_by_day_df = events_by_day.reset_index()
            events_by_day_df.columns = ['Date', 'Activation Events']

            st.line_chart(events_by_day_df.set_index('Date'))
        else:
            st.info("No 'timestamp' field found for timeline plotting.")


        # 🚨 2. Detect Activation Failures


    # --- Mobile Backups Tab ---
    with tabs[3]:
        st.header("💾 Mobile Backup Information")
        st.info(	"Lists all mobile backup operations, which may indicate data syncs, restorations, or critical user behavior.")
        st.dataframe(backup)
        st.download_button("Download CSV", backup.to_csv(index=False), file_name="mobile_backup.csv")

    

    # --- Wi-Fi Scans Tab ---
    # --- Wi-Fi Scans Tab ---
    with tabs[4]:
        st.header("📶 Wi-Fi Scan Events")
        st.info("Shows detected Wi-Fi scan events. Helps in understanding surrounding networks and potential user locations over time.")
        
        # Display raw Wi-Fi scan data
        st.dataframe(wifiscan)
        st.download_button(
            "Download CSV",
            wifiscan.to_csv(index=False),
            file_name="wifi_scans.csv"
        )

        # 📊 1. Top Wi-Fi SSIDs seen
        if 'ssid' in wifiscan.columns:
            st.subheader("🏆 Top Wi-Fi Networks Seen")
            top_ssids = wifiscan['ssid'].value_counts().head(10)
            st.bar_chart(top_ssids)

        # 📈 2. Wi-Fi Session Timeline
        if 'timestamp' in wifiscan.columns:
            st.subheader("⏱️ Wi-Fi Scanning Sessions Over Time")
            wifiscan['timestamp'] = pd.to_datetime(wifiscan['timestamp'], errors='coerce')
            wifiscan = wifiscan.dropna(subset=['timestamp'])
            wifiscan_sorted = wifiscan.sort_values('timestamp')

            #st.line_chart(wifiscan_sorted.set_index('timestamp').resample('30T').count()['ssid'])  # 30-minute session bins

        # 🛡️ 3. Security Type Pie Chart
        if 'security_type' in wifiscan.columns:
            st.subheader("🔒 Security Type Distribution")
            sec_type_counts = wifiscan['security_type'].value_counts()
            st.dataframe(sec_type_counts)
            st.plotly_chart(sec_type_counts.plot.pie(autopct='%1.1f%%', ylabel='').figure)

        # 🚩 4. Hidden Wi-Fi Networks
        st.subheader("👻 Hidden Networks Detected")
        hidden_ssids = wifiscan[(wifiscan['ssid'].isnull()) | (wifiscan['ssid'].str.strip() == '')]
        # Dynamically select columns that exist
        columns_to_show = ['timestamp']
        if 'security_type' in hidden_ssids.columns:
            columns_to_show.append('security_type')

        st.dataframe(hidden_ssids[columns_to_show])

        # 📅 5. First and Last Wi-Fi seen
        st.subheader("📅 First and Last Wi-Fi Scanned")

        if 'timestamp' in wifiscan.columns and 'ssid' in wifiscan.columns:
            # Parse timestamp assuming epoch seconds
            wifiscan['timestamp'] = pd.to_datetime(wifiscan['timestamp'], unit='s', errors='coerce')
            
            # Drop rows where timestamp is invalid or nonsensical (before year 2000)
            wifiscan_valid = wifiscan.dropna(subset=['timestamp', 'ssid'])
            wifiscan_valid = wifiscan_valid[wifiscan_valid['timestamp'] > pd.to_datetime('2000-01-01')].sort_values('timestamp')

            if not wifiscan_valid.empty:
                first_seen = wifiscan_valid.iloc[0]
                last_seen = wifiscan_valid.iloc[-1]
                st.write(f"**First Wi-Fi Seen:** {first_seen['ssid']} at {first_seen['timestamp']}")
                st.write(f"**Last Wi-Fi Seen:** {last_seen['ssid']} at {last_seen['timestamp']}")
            else:
                st.info("No valid Wi-Fi scans after 2000 found to display.")
        else:
            st.warning("Wi-Fi scan data missing required fields.")




    # --- Crash Logs Tab ---
    with tabs[5]:
        st.header("💥 Application Crash Logs")
        st.info("Provides all recorded app and system crash logs. Useful for analyzing app instability or malicious crash attempts.")

        # Show raw crash logs
        st.dataframe(crashlogs)
        st.download_button(
            "Download Crash Logs CSV",
            crashlogs.to_csv(index=False),
            file_name="crashlogs.csv"
        )

        # 📊 1. Top Crashing Apps
        st.subheader("🏆 Top Crashing Apps")
        if 'app_name' in crashlogs.columns:
            top_crashes = crashlogs['app_name'].value_counts().head(10)
            st.bar_chart(top_crashes)
        else:
            st.info("No 'app_name' field found in crashlogs.")

        # 📈 2. Crash Timeline
        st.subheader("⏱️ Crash Events Over Time")

        if 'timestamp' in crashlogs.columns:
            crashlogs['timestamp'] = pd.to_datetime(crashlogs['timestamp'], unit='s', errors='coerce')
            crashlogs_sorted = crashlogs.dropna(subset=['timestamp']).sort_values('timestamp')

            crashlogs_sorted = crashlogs_sorted[crashlogs_sorted['timestamp'] > pd.to_datetime('2000-01-01')]

            # Show sample timestamps to debug
            st.write(crashlogs_sorted[['timestamp', 'app_name']])

            # Proper grouping
            crashes_by_day = crashlogs_sorted.groupby(crashlogs_sorted['timestamp'].dt.date).count()['app_name']

            st.line_chart(crashes_by_day)
        else:
            st.info("No 'timestamp' field found to plot timeline.")



        # 📋 3. Top Crashed Apps Table
        st.subheader("📋 Top Crashed Apps List")
        if 'app_name' in crashlogs.columns:
            top_crashed_apps_df = crashlogs['app_name'].value_counts().reset_index()
            top_crashed_apps_df.columns = ['App Name', 'Crash Count']
            st.dataframe(top_crashed_apps_df)
        else:
            st.info("No 'app_name' data available for top app listing.")


    # --- Lockdown Pairings Tab ---
    with tabs[6]:
        st.header("🔒 Device Lockdown Pairings")
        st.info("Lists all computers or devices that have been trusted by this iPhone/iPad (lockdown pairings).")
        st.dataframe(lockdownd)
        st.download_button("Download CSV", lockdownd.to_csv(index=False), file_name="lockdownd_pairings.csv")

    st.success("Dashboard Loaded Successfully!")

    # --- Applications Evidence Map Tab ---
    with tabs[7]:
        st.header("📚 Applications Evidence Map")
        st.info("Lists apps and services found on the device, including libraries used and iCloud synchronization status. Helps in profiling user activity.")

        apps_json = parsed_data_dir / "apps.json"
        with open(apps_json, "r") as f:
            apps_data = json.load(f)

        # Prepare a flattened DataFrame
        records = []
        for app, details in apps_data.items():
            found_in = ", ".join(details.get("found", []))
            libraries = ", ".join(details.get("libraries", [])) if "libraries" in details else "-"
            has_icloud = "✅" if "libraries" in details else "❌"
            records.append({
                "App/Service Name": app,
                "Found In": found_in,
                "Libraries (if any)": libraries,
                "iCloud Synced?": has_icloud
            })

        apps_df = pd.DataFrame(records)

        # Search bar
        search_query = st.text_input("🔍 Search App or Service Name")

        if search_query:
            filtered_df = apps_df[apps_df["App/Service Name"].str.contains(search_query, case=False, na=False)]
        else:
            filtered_df = apps_df

        # Color coding function
        def highlight_icloud(row):
            color = "background-color: #000000" if row["iCloud Synced?"] == "✅" else "background-color: #000000"
            return [color] * len(row)

        st.dataframe(filtered_df.style.apply(highlight_icloud, axis=1))

        st.download_button(
            "Download Applications Evidence Map as CSV",
            apps_df.to_csv(index=False),
            file_name="applications_evidence_map.csv"
        )

    # --- Security Health Overview Tab ---
    with tabs[8]:
        st.header("🔒 Security Health Overview")
        st.info("Highlights security-relevant events such as secure boot validation, keychain issues, trust failures, and pending device wipes.")

        # ℹ️ Info tooltip explaining what this tab shows
        st.info("This section provides an overview of the device's security state, including encryption status, keychain health, secure boot validations, trust evaluation results, and any pending wipe flags. It helps determine if the device was secure or compromised.")

        # Load the security_sysdiagnose.jsonl
        security_jl = parsed_data_dir / "security_sysdiagnose.jsonl"
        security_events = []
        with open(security_jl, "r") as f:
            for line in f:
                security_events.append(json.loads(line))
        security_df = pd.DataFrame(security_events)

        # Display raw security events
        st.dataframe(security_df)

        st.download_button(
            "Download Security Events CSV",
            security_df.to_csv(index=False),
            file_name="security_events.csv"
        )

        # 📋 1. Trust Evaluation Failures
        st.subheader("🚨 Trust Evaluation Hard Failures")
        trust_failures = security_df[(security_df['section'] == 'client_trust') & (security_df['result'] == 'EventHardFailure')]

        if not trust_failures.empty:
            st.dataframe(trust_failures[['datetime', 'result', 'event', 'attributes']])
            st.download_button(
                "Download Trust Failures CSV",
                trust_failures.to_csv(index=False),
                file_name="trust_failures.csv"
            )
        else:
            st.success("No trust evaluation hard failures detected.")

        # 📋 2. Keychain or Keybag Events
        st.subheader("🔑 Keychain / Keybag Events")
        keychain_events = security_df[security_df['section'].str.contains('keybag|keychain', case=False, na=False)]

        if not keychain_events.empty:
            st.dataframe(keychain_events[['datetime', 'section', 'event', 'result']])
        else:
            st.success("No keybag or keychain related issues detected.")

        # 📋 3. Secure Boot Status
        st.subheader("🛡️ Secure Boot Validation Events")
        secure_boot_events = security_df[security_df['section'].str.contains('secure_boot|boot_policy', case=False, na=False)]

        if not secure_boot_events.empty:
            st.dataframe(secure_boot_events[['datetime', 'section', 'event', 'result']])
        else:
            st.success("No secure boot validation issues detected.")

        # 📋 4. Pending Wipe Detection
        st.subheader("🧹 Pending Device Wipe Detection")
        wipe_pending = security_df[(security_df['section'].str.contains('device_policy', case=False, na=False)) & (security_df['result'].str.contains('pending', case=False, na=False))]

        if not wipe_pending.empty:
            st.warning("🚨 Device wipe was pending at some point!")
            st.dataframe(wipe_pending[['datetime', 'section', 'result']])
        else:
            st.success("No device wipe pending detected.")

        # --- Process Snapshot Overview Tab ---
    with tabs[9]:
        st.header("🧩 Process Snapshot Overview")
        st.info(	"Shows all active processes at the time sysdiagnose was captured. Helps in detecting suspicious or unexpected activity.")

        # ℹ️ Info tooltip explaining what this tab shows
        st.info("This section displays all running processes on the device at the time the sysdiagnose was collected. Useful to detect which apps or system services were active, identify user activity, and flag suspicious processes.")

        # Load the ps_matrix.txt
        
        ps_txt = parsed_data_dir / "ps_matrix.txt"
        ps_df = pd.read_csv(ps_txt, delimiter="|", engine="python")

        # Display full process list
        st.dataframe(ps_df)

        st.download_button(
            "Download Process List CSV",
            ps_df.to_csv(index=False),
            file_name="process_list.csv"
        )


            # --- Wi-Fi Auto-Join Locations Map Tab ---
        with tabs[10]:
            st.header("🌍 Wi-Fi Auto-Join Locations Map")
            st.info(	"Visualizes locations where the device auto-joined known Wi-Fi networks, allowing for passive location reconstruction.")

            # ℹ️ Info tooltip explaining what this tab shows
            st.info("This map shows physical locations where the device automatically joined Wi-Fi networks. These locations are passively collected during auto-join events, even without active GPS tracking, and can be used to reconstruct user movement.")



            # Parse WiFi_com.apple.wifi.plist.json
        
            wifi_auto_locations = []
            wifi_plist = parsed_data_dir / "plists" / "WiFi_com.apple.wifi.plist.json"
            try:
                with open(wifi_plist, "r") as f:
                    wifi_plist_map = json.load(f)

                # Check if location metric exists
                location_metric = wifi_plist_map.get("UserAutoJoinLocationMetric", {})

                latitude = location_metric.get("kCLLocationCodingKeyRawCoordinateLatitude")
                longitude = location_metric.get("kCLLocationCodingKeyRawCoordinateLongitude")


                if latitude and longitude:
                    wifi_auto_locations.append((latitude, longitude))
            except Exception as e:
                st.warning(f"Could not load Wi-Fi Auto-Join location data: {e}")

            if wifi_auto_locations:
                wifi_map = folium.Map(location=[wifi_auto_locations[0][0], wifi_auto_locations[0][1]], zoom_start=15)

                for lat, lon in wifi_auto_locations:
                    folium.Marker(
                        [lat, lon],
                        popup="Wi-Fi Auto-Join Location",
                        tooltip="Auto-Joined Wi-Fi Spot",
                        icon=folium.Icon(color="blue", icon="wifi", prefix="fa")
                    ).add_to(wifi_map)

                st_data = st_folium(wifi_map, width=800)
            else:
                st.info("No Wi-Fi auto-join location data available to map.")




