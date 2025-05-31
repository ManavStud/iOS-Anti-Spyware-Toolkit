#!/usr/bin/env python3
"""
Automatically detect connected iOS devices and extract their sysdiagnose log bundles.
Relies on libimobiledevice tools: idevice_id and idevicecrashreport.
"""

import subprocess
import time
import os
import sys
from datetime import datetime

# How often (in seconds) to poll for device changes
POLL_INTERVAL = 5

def get_connected_udids():
    """Return a list of UDIDs for currently connected iOS devices."""
    proc = subprocess.run(
        ["idevice_id", "-l"],
        capture_output=True, text=True
    )
    if proc.returncode != 0:
        print(f"[ERROR] idevice_id failed: {proc.stderr.strip()}", file=sys.stderr)
        return []
    # Filter out any empty lines
    return [udid for udid in proc.stdout.splitlines() if udid.strip()]

def download_and_extract(udid, base_dir):
    """
    Use idevicecrashreport to download crash logs (incl. sysdiagnose)
    and unpack any .tar.gz archives found.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_dir, f"{udid}_{timestamp}")
    os.makedirs(out_dir, exist_ok=True)

    print(f"[INFO] Downloading logs for {udid} into {out_dir}")
    cmd = ["idevicecrashreport", "-k", "-u", udid, out_dir]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"[ERROR] idevicecrashreport failed for {udid}: {proc.stderr.strip()}", file=sys.stderr)
        return

    # Look for any sysdiagnose archives and unpack them
    for fname in os.listdir(out_dir):
        if fname.lower().endswith(".tar.gz"):
            tar_path = os.path.join(out_dir, fname)
            extract_dir = os.path.join(out_dir, os.path.splitext(os.path.splitext(fname)[0])[0])
            os.makedirs(extract_dir, exist_ok=True)
            print(f"[INFO] Extracting {fname} → {extract_dir}")
            subprocess.run(["tar", "-xzf", tar_path, "-C", extract_dir], check=False)

    print(f"[SUCCESS] Completed logs for {udid}")

def main():
    print("[*] Monitoring for iOS devices. Press Ctrl+C to exit.")
    seen = set()
    # Base folder where all logs will be stored
    base_dir = os.path.expanduser("~/iPhone_sysdiagnose")
    os.makedirs(base_dir, exist_ok=True)

    try:
        while True:
            current = set(get_connected_udids())
            # New devices
            for udid in current - seen:
                print(f"[+] Device connected: {udid}")
                download_and_extract(udid, base_dir)
            # Removed devices
            for udid in seen - current:
                print(f"[-] Device disconnected: {udid}")
            seen = current
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\n[!] Exiting.")

if __name__ == "__main__":
    main()
