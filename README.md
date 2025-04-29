# iOS-Anti_Spyware-Toolkit
A Streamlit-based dashboard for exploring, categorizing, and visualizing Apple sysdiagnose archives. It extracts the archive, scans and categorizes all relevant files, and provides:

- **Explorer**: Sidebar navigation by category (with global search and user overrides).
- **File Viewer**: Two-column raw/structured view for text, CSV, JSON, PLIST, and enhanced crash-report (.ips) formatting.
- **Timeline**: Interactive stacked bar chart of file creation dates by category.
- **Charts**: Overview of file counts and storage usage per category.
- **AI Summaries** (optional): Call out to an LLM via OpenRouter for concise file summaries.

---

## 🚀 Features

- **Automatic Extraction** of `.tar.gz` sysdiagnose bundles.
- **Smart Categorization** using:
  - Regex patterns
  - Parent-folder context
  - Content-based hints (e.g. crash keywords)
  - Extension fallbacks
  - User-driven overrides
- **Global File Search** in sidebar and in-file text search.
- **Enhanced Crash Report View**: Split header vs. stack trace in collapsible sections.
- **Integrated Metrics**: VM, CPU, and network event parsers merged into timeline data.
- **Interactive Altair Charts** for timeline and dashboard metrics.

---

## 🛠 Installation

1. **Clone this repository**
   ```bash
   git clone https://github.com/your-org/sysdiagnose-analysis.git
   cd sysdiagnose-analysis
   ```

2. **(Required) Clone the Apple sysdiagnose data repo**
   ```bash
   # Inside the toolkit root, create a "sysdiagnose" subfolder:
   git clone https://github.com/EC-DIGIT-CSIRC/sysdiagnose.git sysdiagnose
   ```

3. **Create a virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **(Optional) Configure upload size**
   In `.streamlit/config.toml`:
   ```toml
   [server]
   maxUploadSize = 500  # MB
   ```
   Or launch with CLI flag:
   ```bash
   streamlit run main.py --server.maxUploadSize=500
   ```

---

## 🚦 Usage

### 🔄 Pre-run Parsing & Analysis
Before launching the Streamlit dashboard, ensure your sysdiagnose data is parsed and analyzed:

```bash
cd sysdiagnose
# Activate your venv
source venv/bin/activate
# Initialize the archive (creates case folder)
sysdiag init path/to/your/sysdiagnose.tar.gz
# Parse all data
sysdiag -c 1 parse all
# Run all analysers
sysdiag -c 1 analyse all
```

Run the Streamlit app (ensure the `sysdiagnose` folder is present next to `main.py`):

Run the Streamlit app (ensure the `sysdiagnose` folder is present next to `main.py`):

```bash
streamlit run main.py
```

1. **Upload** your `sysdiagnose.tar.gz` archive via the sidebar or point to the cloned cases under `sysdiagnose/cases`.
2. **Browse** files in the Explorer (use search or expand categories).
3. **View** file contents or structured data in the File Viewer.
4. **Inspect** creation trends in the Timeline tab.
5. **Analyze** category distributions in the Charts tab.
6. **Generate** AI summaries by entering your OpenRouter API key.

---

## ⚙️ Configuration & Customization

- **Category Patterns**: Edit `constants.py` → `CATEGORY_PATTERNS`, `PARENT_FOLDERS`, and `EXTENSION_FALLBACK`.
- **Overrides**: Add manual mappings in `category_overrides.json` (created on first override).
- **Extensions**: Modify supported extensions in `metadata.py` if adding new file types.

---

## 📁 Project Structure

```
├── main.py               # Launches the Streamlit app
├── extraction.py         # sysdiagnose archive extractor
├── metadata.py           # File scanner & categorizer
├── constants.py          # Categorization rules & overrides
├── ai_summary.py         # OpenRouter LLM summary helper
├── requirements.txt      # Python dependencies
├── .streamlit/           # Streamlit config (e.g. upload size)
└── views/                # UI modules
    ├── sidebar.py        # File navigation pane
    ├── file_viewer.py    # Two-column content viewer
    ├── timeline.py       # Altair timeline chart
    ├── charts.py         # Altair dashboard charts
    └── dashboard.py      # Additional parsed-data dashboard views
```

---

## 🤝 Contributing

1. Fork the repo & create a branch.
2. Make your changes & commit.
3. Submit a pull request with a clear description.

