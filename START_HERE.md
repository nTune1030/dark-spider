# 🚀 START HERE — Quick-Start Guide

Get from zero to your first dark web scan in under 5 minutes.

---

## Step 0 — Prerequisites

| What | Why |
|------|-----|
| **Python 3.8+** | Runtime |
| **Tor** | Must be running — standalone Tor uses ports 9050/9051; Tor Browser uses 9150/9151 |
| **pip + venv** | Package management |

> **Install Tor**: <https://www.torproject.org/download/>
>
> **Windows shortcut**: Just launch Tor Browser, then edit `core/config.py` and set `TOR_PROXY_PORT=9150` and `TOR_CONTROL_PORT=9151`.

---

## Step 1 — Clone & Install

```bash
git clone https://github.com/nTune1030/darkweb_info_seek.git
cd darkweb_info_seek

# Create virtual environment
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.\.venv\Scripts\activate     # Windows

# Install dependencies
pip install -e ".[dev]"

# Install Playwright browser (for JS-rendered page support)
playwright install chromium

# Create your local config
cp config_template.py core/config.py
```

> **That's it for setup.** Edit `core/config.py` if your Tor ports differ from the defaults.

---

## Step 2 — Add Keywords

Tell the spider what to search for. You can use plain strings or regex patterns:

```bash
# String keyword (case-insensitive match)
python scripts/keyword_manager.py --add "data breach"

# Regex pattern (e.g., email addresses)
python scripts/keyword_manager.py --add "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" --regex

# Verify your keywords
python scripts/keyword_manager.py --list
```

---

## Step 3 — Populate Seed URLs

Fetch starting URLs from known dark web directories:

```bash
python scripts/url_populator.py
```

This contacts the directory sites listed in `SEED_SOURCES` (in your config) and scrapes `.onion` addresses into the database.

> **Tip**: You can also manually add seeds via the database or by editing `dark_urls.txt`.

---

## Step 4 — Run the Spider

```bash
python auto_spider.py
```

This will:
1. Verify Tor is running
2. Rotate to a fresh Tor identity
3. Scan all active seeds in parallel (10 workers by default)
4. Match your keywords and extract context snippets
5. Discover new `.onion` links and add them to the database
6. Save all results to the SQLite database

Press **Ctrl+C** for a graceful shutdown — in-flight requests finish and progress is saved.

---

## Step 5 — View Results

### HTML Report

```bash
python scripts/report_generator.py
```

Open `dark_web_report.html` in your browser to see keyword hit rates and context snippets.

### Live Monitor

While the spider is running, open a second terminal:

```bash
python scripts/live_monitor.py
```

Shows real-time crawl rates, database stats, and recent matches — updated every 30 seconds.

### Quick Stats

```bash
python scripts/analyze_keywords.py
```

Prints a one-shot summary: keyword hit rates, seed coverage, zero-hit keywords, and top matching URLs.

---

## Step 6 — Maintenance

Over time, dead seeds accumulate. Clean them up:

```bash
# Remove seeds that have been inactive for 14+ days
python scripts/maintenance.py --cull-dead 14

# Or give all inactive seeds a second chance
python scripts/maintenance.py --reset-failures
```

---

## What's Next?

| Task | Command |
|------|---------|
| Add more keywords | `python scripts/keyword_manager.py --add "new keyword"` |
| Add more seed sources | Edit `SEED_SOURCES` in `core/config.py` |
| Tune concurrency | Change `MAX_WORKERS` in `core/config.py` |
| Disable JS fallback | Set `PLAYWRIGHT_ENABLED = False` in `core/config.py` |
| Run tests | `pytest` |
| Read full docs | [README.md](README.md) |
| Contribute | [CONTRIBUTING.md](CONTRIBUTING.md) |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Tor service is not available` | Start Tor: `tor --ControlPort 9051` (standalone) or launch Tor Browser and set `TOR_CONTROL_PORT=9151` in `core/config.py` |
| `playwright not installed` | Run `playwright install chromium` |
| `No active seeds in database` | Run `python scripts/url_populator.py` first |
| `No search keywords found` | Run `python scripts/keyword_manager.py --add "something"` |
| Connection timeouts | Normal on Tor — the spider retries automatically |
| 403 Forbidden responses | The spider auto-rotates to a new Tor circuit on 403s |

---

## ⚠️ Important Reminder

This tool is for **educational and research purposes only**. Always obey local laws regarding dark web usage. Never commit personal information (emails, phone numbers, API keys) to source control.