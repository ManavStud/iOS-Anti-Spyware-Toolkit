import streamlit as st
from pathlib import Path


def render_sidebar(glob_files, categories, root_dir, session_state):
    """
    Renders a sidebar with a global search bar and expandable category sections.
    """
    # Global search input
    search_query = st.sidebar.text_input("Search files", placeholder="Type to filter file names...")

    # Initialize grouped buckets, including All and Uncategorized
    grouped: dict[str, list[tuple[str, str]]] = {cat: [] for cat in categories}
    grouped["All"] = []
    grouped["Uncategorized"] = []

    # Populate groups
    for f in glob_files:
        rel = Path(f).relative_to(root_dir)
        label = str(rel)
        # Apply global search filter
        if search_query and search_query.lower() not in label.lower():
            continue

        # Always include in All
        grouped["All"].append((f, label))

        # Try to assign to a specific category
        placed = False
        for cat, patterns in categories.items():
            if any(pat in label for pat in patterns):
                grouped[cat].append((f, label))
                placed = True
                break
        if not placed:
            grouped["Uncategorized"].append((f, label))

    # Render the sidebar expanders
    for cat, items in grouped.items():
        if not items:
            continue
        with st.sidebar.expander(cat, expanded=(cat == "All")):
            for fpath, label in items:
                key = f"btn_{cat}_{label}"
                if st.button(label, key=key):
                    session_state.selected = fpath
