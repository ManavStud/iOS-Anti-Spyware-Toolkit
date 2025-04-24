import re
import json
from pathlib import Path

# Overrides file for user-driven retagging
OVERRIDES_FILE = "category_overrides.json"

# Regex-based category patterns (case-insensitive)
CATEGORY_PATTERNS = {
    "Overview": [r"(?i)README\.txt$", r"(?i)sysdiagnose\.log$"] ,
    "Crash Reports": [r"(?i)\.ips$", r"(?i)\.crash$", r"CrashReporter/"],
    "Performance & Processes": [r"(?i)spindump", r"microstackshots", r"tailspin-info", r"jetsam_priority"],
    "Storage & File System": [r"(?i)mount\.txt$", r"apfs_stats", r"disks"],
    "File Provider & ICloud": [r"fileproviderctl", r"brctl-dump", r"brctl-container-list", r"defaults-com\.apple\.iclouddrive", r"brctl_errors"],
    "Network": [r"(?i)ifconfig", r"netstat", r"arp", r"ping", r"tcpdump"],
    "Wi‑Fi & CoreCapture": [r"wifi_status", r"network_status", r"wifi_datapath", r"wifi_scan", r"WiFiStat"],
    "Hardware & IOKit": [r"IOService", r"IOPort", r"IOUSB", r"IOReg\.xml$"],
    "Preferences & Personalization": [r"Preferences/", r"Personalization/"],
    "Security & Privacy": [r"security-sysdiagnose", r"smcDiagnose", r"transparency\.log", r"kbdebug"],
    "Services & Daemons": [r"logs/", r"MCState/", r"pmudiagnose", r"MobileBackup/", r"AppSupport/"],
    "Media & Calls": [r"AVConference/", r"downloads\.\d+\.sqlitedb$"],
    "OTA & Updates": [r"OTAUpdateLogs/"]
}

# Parent-folder based quick classification
PARENT_FOLDERS = {
    "Network": ["network", "wifi", "netstat"],
    "Crash Reports": ["crashreporter", "reports"],
    "Performance & Processes": ["spindump", "microstackshots"],
    # add more folder names as needed
}

# Extension fallback mapping
EXTENSION_FALLBACK = {
    ".ips": "Crash Reports",
    ".crash": "Crash Reports",
    ".csv": "Data Tables",
    ".tsv": "Data Tables",
    ".log": "Logs",
    ".txt": "Text Files",
    ".json": "JSON Files",
    ".plist": "PLIST Files"
}


def load_overrides() -> dict:
    """
    Load user-driven category overrides from JSON file.
    """
    try:
        with open(OVERRIDES_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def save_overrides(overrides: dict) -> None:
    """
    Save user-driven category overrides to JSON file.
    """
    with open(OVERRIDES_FILE, 'w') as f:
        json.dump(overrides, f, indent=2)


def categorize(path: str, raw_text: str | None = None) -> str:
    """
    Determine category for a given file path.
    Order:
      1. User override
      2. Regex patterns
      3. Parent-folder context
      4. Content-based hints
      5. Extension fallback
      6. Uncategorized
    """
    overrides = load_overrides()
    key = str(Path(path))
    if key in overrides:
        return overrides[key]

    # Regex matching
    for cat, patterns in CATEGORY_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, key):
                return cat

    # Parent-folder context
    parent = Path(path).parent.name.lower()
    for cat, folders in PARENT_FOLDERS.items():
        if parent in folders:
            return cat

    # Content-based hints
    if raw_text:
        txt = raw_text.lower()
        if 'panic' in txt or 'exception' in txt:
            return 'Crash Reports'
        if 'trace' in txt and 'cpu' in txt:
            return 'Performance & Processes'

    # Extension fallback
    ext = Path(path).suffix.lower()
    if ext in EXTENSION_FALLBACK:
        return EXTENSION_FALLBACK[ext]

    # Default
    return 'Uncategorized'
