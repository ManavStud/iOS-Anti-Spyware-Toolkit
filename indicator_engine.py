import json
import re
import pandas as pd
import streamlit as st
import os 


def load_indicators(config_path: str) -> list[dict]:
    """
    Load indicator definitions from a JSON file.
    Each indicator should be a dict with keys:
      - name (str)
      - description (str)
      - pattern (str): regex to match
      - neg_pattern (str, optional): regex to exclude
      - context (int, optional): lines of context before/after
      - severity (str, optional)
      - score (int or float, optional)
    """
    with open(config_path, 'r') as f:
        indicators = json.load(f)
    return indicators


def scan_file_lines(
    lines: list[str],
    pattern: str,
    neg_pattern: str | None = None,
    context: int = 2
) -> list[dict]:
    """
    Scan lines for a regex pattern, optionally excluding neg_pattern.
    Returns list of dicts with keys: lineno, line, context.
    """
    regex = re.compile(pattern)
    neg_regex = re.compile(neg_pattern) if neg_pattern else None
    hits = []
    for idx, line in enumerate(lines):
        if regex.search(line) and (not neg_regex or not neg_regex.search(line)):
            start = max(0, idx - context)
            end = min(len(lines), idx + context + 1)
            snippet = ''.join(lines[start:end])
            hits.append({
                'lineno': idx + 1,
                'line': line.rstrip(),
                'context': snippet.rstrip()
            })
    return hits


def scan_path(path: str, indicators: list[dict]) -> pd.DataFrame:
    """
    For a given text file, run through all indicators and
    return every line that matches any of their regex_patterns.
    """
    matches = []
    basename = os.path.basename(path)

    try:
        with open(path, 'r', errors='ignore') as f:
            for lineno, raw in enumerate(f, start=1):
                line = raw.rstrip()
                for ind in indicators:
                    # 1) Filename filter
                    if not any(re.search(fp, basename, re.IGNORECASE)
                               for fp in ind.get('file_patterns', [])):
                        continue

                    # 2) Regex scan
                    for rpat in ind.get('regex_patterns', []):
                        if re.search(rpat, line, re.IGNORECASE):
                            matches.append({
                                'id':        ind.get('id'),
                                'indicator': ind.get('name'),
                                'file':      path,
                                'line_no':   lineno,
                                'line':      line,
                                'severity':  ind.get('severity', '')
                            })
                            break  # don’t double-count one line per indicator
    except Exception:
        # you can log here if you like
        pass

    return pd.DataFrame(matches)


def render_results(df: pd.DataFrame) -> None:
    """
    Render scan results in Streamlit:
      - An expander per indicator
      - A summary table and CSV download
    """
    if df.empty:
        st.info("No findings.")
        return

    # Summary table
    summary = (
        df.groupby(['indicator','severity','triggered','score'])
          .size()
          .reset_index(name='count')
          .sort_values(['score','severity'], ascending=False)
    )
    st.subheader('Indicator Summary')
    st.dataframe(summary, use_container_width=True)

    # Detailed expanders
    for name, group in df.groupby('indicator'):
        with st.expander(f"{name} ({len(group)} hits)"):
            st.markdown(group[['file','lineno','line','context']]
                        .to_markdown(index=False))
    
    # Download all results
    csv_data = df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label='Download All Findings as CSV',
        data=csv_data,
        file_name='indicator_findings.csv',
        mime='text/csv'
    )
