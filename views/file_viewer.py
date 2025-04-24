import streamlit as st
import pandas as pd
import plistlib
import json
import os
from pathlib import Path


def _read_text(path: str) -> str | None:
    """
    Safely read a text file, returning its contents or None on failure.
    """
    try:
        with open(path, 'r', errors='ignore') as f:
            return f.read()
    except Exception:
        return None


def _show_json(path: str) -> None:
    """
    Display JSON and a flattened table if possible.
    """
    try:
        with open(path, 'r', errors='ignore') as f:
            data = json.load(f)
    except Exception:
        st.write("Failed to parse JSON.")
        return

    st.subheader("JSON")
    st.json(data)

    flat = None
    if isinstance(data, list) and data and all(isinstance(i, dict) for i in data):
        flat = pd.json_normalize(data)
    elif isinstance(data, dict):
        flat = pd.json_normalize(data)

    if flat is not None and not flat.empty:
        st.subheader("Flattened Data")
        st.dataframe(flat)


def _show_plist(path: str) -> None:
    """
    Display PLIST contents and a flattened table if it's a dict.
    """
    try:
        with open(path, 'rb') as f:
            data = plistlib.load(f)
    except Exception:
        st.write("Failed to parse PLIST.")
        return

    st.subheader("PLIST")
    st.json(data)

    if isinstance(data, dict):
        flat = pd.json_normalize(data)
        if not flat.empty:
            st.subheader("Flattened Data")
            st.dataframe(flat)


def render_file(sel: str) -> None:
    """
    Render a two-column view for the selected file with enhanced .ips formatting:
      - Left: raw text with search
      - Right: structured view for CSV, JSON, PLIST, and enhanced IPS
    """
    left, right = st.columns(2)

    # Left pane: raw text + in-file search
    with left:
        raw = _read_text(sel)
        if raw:
            st.subheader("Raw Data")
            query = st.text_input(
                "Search raw data", key=f"search_{Path(sel).name}"
            )
            lines = raw.splitlines()
            if query:
                lines = [l for l in lines if query.lower() in l.lower()]
                if not lines:
                    lines = ["No matches found."]
            st.text_area(
                "Raw Data Content",
                "\n".join(lines),
                height=300,
                label_visibility="hidden"
            )
        else:
            st.write("Binary or non-text file.")

    # Right pane: structured view by extension
    with right:
        ext = os.path.splitext(sel)[1].lower()
        if ext == '.csv':
            try:
                df = pd.read_csv(sel)
                st.subheader("CSV Table")
                st.dataframe(df)
            except Exception:
                st.write("Failed to load CSV.")
        elif ext == '.json':
            _show_json(sel)
        elif ext == '.plist':
            _show_plist(sel)
        elif ext == '.ips':
            # Enhanced IPS formatting: split header and stack traces
            st.subheader("Crash Report (.ips)")
            report = raw or _read_text(sel)
            if report:
                sections = report.split('\n\n', 1)
                header = sections[0].splitlines()
                body = sections[1].splitlines() if len(sections) > 1 else []

                with st.expander("Report Header", expanded=True):
                    st.code("\n".join(header), language='text')
                if body:
                    with st.expander("Stack & Details", expanded=False):
                        st.code("\n".join(body), language='text')
            else:
                st.write("Empty crash report file.")
        else:
            st.write("No structured view available.")
