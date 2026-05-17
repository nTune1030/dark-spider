# 🕷️ Dark Web Info Seek Spider

A multithreaded, recursive spider for monitoring dark web `.onion` sites with keyword and regex matching, JavaScript-rendered page support, and SQLite-backed persistence.

> **⚠️ Disclaimer**: This tool is for educational and research purposes only. The authors are not responsible for how you use this tool. Always obey local laws regarding dark web usage.

---

**New here?** → Read [START_HERE.md](START_HERE.md) for a 5-minute quick-start guide.

---

## How It Works

```
  Seed URLs ──► Fetch via Tor ──► Keyword Match ──► Save to DB
      ▲              │                │
      │              ▼                ▼
      │        JS Shell?         Extract Links
      │         │  Yes               │
      │         ▼                    ▼
      │    Playwright render    Add as new seeds ──┘
      │         │
      └─────────┘  (recursive crawl)
```

1. **Seed URLs** are loaded from the database (populated via `url_populator.py`)
2. Each URL is **fetched through Tor** using isolated SOCKS5 streams
3. If the page is a **JS shell** (empty body, React/Vue/Next.js markers), Playwright re-renders it
4. The spider **matches keywords** (string or regex) and extracts ~100-char context snippets
5. New `.onion` links found on the page are **added as new seeds** for recursive crawling
6. Results are **persisted to SQLite** with deduplication and reported via HTML

---

## Features

- **Recursive Crawling** — Autonomously discovers and follows new V3 `.onion` links
- **Multithreaded Architecture** — Scans multiple sites simultaneously with a configurable worker pool
- **JS-Rendered Page Support** — Smart fallback to headless Chromium (via Playwright + Tor) for JavaScript-heavy sites (React, Vue, Next.js)
- **Advanced Search** — Supports both exact keyword matching and regex patterns with obfuscation awareness
- **Context Extraction** — Captures a ~100-character text snippet surrounding each match for easy verification
- **Stream Isolation** — Each request uses random SOCKS5 credentials for Tor stream isolation, preventing circuit correlation
- **Resilient** — Handles Tor connection instability, retries on SQLITE_BUSY with exponential backoff, and ignores dead links
- **Anti-Bot Evasion** — Auto-rotates Tor circuits on 403 Forbidden responses
- **Match Deduplication** — `UNIQUE INDEX` on `(url, keyword)` prevents inflated counts across scan cycles
- **Reporting** — Generates clean, detailed HTML reports with keyword hit rates and context snippets
- **Live Monitoring** — Watch crawl rates, DB statistics, and recent matches in real-time

---

## 📋 Prerequisites

| Requirement | Details |
|-------------|---------|
| **Python 3.8+** | Required for the runtime |
| **Tor** | Must be installed and running |
| | **Standalone Tor**: Port 9050 (SOCKS) + 9051 (Control) |
| | **Tor Browser**: Port 9150 (SOCKS) + 9151 (Control) — set `TOR_PROXY_PORT=9150` and `TOR_CONTROL_PORT=9151` in `core/config.py` |
| **Chromium** | Installed via `playwright install chromium` for JS rendering fallback |

> **Windows users**: The easiest way is to launch Tor Browser, then edit `core/config.py` to set `TOR_PROXY_PORT=9150` and `TOR_CONTROL_PORT=9151`.

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/nTune1030/dark-spider.git
cd darkweb_info_seek

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.\.venv\Scripts\activate    # Windows PowerShell

# 3. Install the package (editable mode with dev dependencies)
pip install -e ".[dev]"

# 4. Install Playwright browser binaries
playwright install chromium

# 5. Copy the config template and customise
cp config_template.py core/config.py
# Edit core/config.py with your local Tor settings

# 6. Ensure Tor is running
#    Linux/macOS:  tor --ControlPort 9051
#    Windows:      Launch Tor Browser (uses ports 9150/9151 by default)
#                  Then set TOR_PROXY_PORT=9150 and TOR_CONTROL_PORT=9151 in core/config.py
```

<details>
<summary><strong>Alternative: Install without pyproject.toml</strong></summary>

```bash
pip install -r requirements.txt
playwright install chromium
cp config_template.py core/config.py
```

</details>

---

## 📂 Project Structure

```
darkweb_info_seek/
├── auto_spider.py          # Automated runner (recommended entry point)
├── spider.py               # Main scanner: DarkWebMonitor + PersistentDarkWebMonitor
├── config_template.py      # Template for core/config.py (copy & customise)
├── dark_urls.txt           # Seed URLs for initial crawling
├── core/
│   ├── config.py           # Local configuration (git-ignored — created from template)
│   ├── db_manager.py       # SQLite persistence with retry logic and deduplication
│   ├── tor_manager.py      # Tor service management & identity rotation
│   └── link_validator.py   # .onion URL syntax & reachability validation
├── scripts/
│   ├── keyword_manager.py  # Add / list / delete / import search keywords
│   ├── url_populator.py    # Fetch seed URLs from directory sites
│   ├── report_generator.py # Generate HTML findings report
│   ├── live_monitor.py     # Real-time crawl rate & match dashboard
│   ├── maintenance.py      # Prune dead seeds / reset failures
│   ├── analyze_keywords.py # Keyword hit-rate analysis
│   ├── migrate_keywords.py # One-time keyword migration script
│   ├── inspect_leak.py     # DB inspection utility
│   └── snapshot.py         # One-shot DB statistics snapshot
└── tests/
    ├── test_matching.py    # Keyword matching & JS detection tests
    └── test_db_manager.py  # Database CRUD tests
```

---

## 🛠️ Usage Guide

### 1. Populate Seed URLs

Fetch a fresh list of directory sites to crawl:

```bash
python scripts/url_populator.py
```

### 2. Manage Keywords

Tell the spider what to look for — simple strings or regex patterns:

```bash
# Add a string keyword (case-insensitive match)
python scripts/keyword_manager.py --add "data breach"

# Add a regex pattern (e.g., find email addresses)
python scripts/keyword_manager.py --add "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" --regex

# List all tracked keywords
python scripts/keyword_manager.py --list

# Delete a keyword
python scripts/keyword_manager.py --delete "data breach"

# Import keywords from a file (one per line)
python scripts/keyword_manager.py --import-file keywords.txt
```

### 3. Run the Spider

**Automated Cycle** (recommended) — handles Tor identity rotation automatically:

```bash
python auto_spider.py
```

Press **Ctrl+C** for graceful shutdown — in-flight requests finish, progress is saved to the database.

### 4. Live Monitoring

While the spider is running, monitor progress in a separate terminal:

```bash
python scripts/live_monitor.py
```

Displays real-time crawl rates (seeds/min), database statistics, and recent matches. Updates every 30 seconds. Press **Ctrl+C** to stop.

### 5. View Results

Generate an HTML report with keyword hit rates and context snippets:

```bash
python scripts/report_generator.py
```

Open `dark_web_report.html` in your browser.

For a quick terminal summary:

```bash
python scripts/analyze_keywords.py
```

### 6. Maintenance

Keep your database healthy:

```bash
# Remove seeds inactive for > 14 days
python scripts/maintenance.py --cull-dead 14

# Reset all inactive seeds (give them a second chance)
python scripts/maintenance.py --reset-failures
```

---

## ⚙️ Configuration

Copy the template and edit your local settings:

```bash
cp config_template.py core/config.py
```

| Setting | Default | Description |
|---------|---------|-------------|
| `MAX_WORKERS` | 10 | Concurrent spider threads |
| `MAX_FAILURES` | 3 | Failures before a seed is marked inactive |
| `PLAYWRIGHT_ENABLED` | `True` | Toggle JS rendering fallback |
| `JS_FALLBACK_BODY_THRESHOLD` | 512 | Body text length (bytes) to trigger Playwright re-render |
| `TOR_PROXY` | `socks5h://127.0.0.1:9050` | SOCKS proxy URL |
| `TOR_PROXY_HOST` | `127.0.0.1` | Tor proxy host |
| `TOR_PROXY_PORT` | `9050` | Tor SOCKS port (Tor Browser: `9150`) |
| `TOR_CONTROL_PORT` | `9051` | Tor control port (Tor Browser: `9151`) |
| `SEED_SOURCES` | 3 directories | Known directory mirrors for seeding |
| `ONION_V3_REGEX` | `r"(?:https?://)?([a-z2-7]{56}\.onion)"` | Regex for V3 onion address extraction |

---

## 🔒 Security

- **Stream Isolation**: Every request uses random SOCKS5 credentials so Tor assigns a separate circuit per stream
- **SQL Injection Prevention**: All database queries use parameterized statements
- **XSS Prevention**: All user-sourced values in reports are escaped with `html.escape()`
- **Match Deduplication**: `UNIQUE INDEX` on `(url, keyword)` prevents duplicate rows
- **Config Privacy**: `core/config.py` is git-ignored — local settings never leave your machine
- **No Personal Data**: The codebase contains no personal information (emails, phone numbers, etc.)

---

## 🧪 Running Tests

```bash
pytest
```

Tests cover keyword matching logic, JS detection heuristics, context extraction, and database CRUD operations.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on code style, pull requests, and security practices.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
