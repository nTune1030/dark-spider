"""
Shared configuration constants for the Dark Web Spider project.

This is the TEMPLATE — copy it to create your local config:
    cp config_template.py core/config.py

Then edit core/config.py to match your local Tor setup and preferences.
Note: core/config.py is git-ignored so your settings stay private.
"""

import os
import random
import string

# Resolve all paths relative to the project root (one level above core/)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# ── Tor ──────────────────────────────────────────────────────────────────────
TOR_PROXY      = "socks5h://127.0.0.1:9050"
TOR_PROXY_HOST = "127.0.0.1"
TOR_PROXY_PORT = 9050

# ── Paths ────────────────────────────────────────────────────────────────────
DB_PATH       = os.path.join(PROJECT_ROOT, "dark_spider.db")
QUARANTINE_DIR = os.path.join(PROJECT_ROOT, "quarantine")

# ── Crawler Tuning ───────────────────────────────────────────────────────────
MAX_WORKERS = 10          # Concurrent spider threads
MAX_FAILURES = 3           # Failures before a seed is marked inactive

# ── Playwright JS-rendering fallback ─────────────────────────────────────────
# Set to False to disable entirely (e.g. when Tor is slow or binaries aren't installed)
PLAYWRIGHT_ENABLED = True
# Minimum visible body text length (bytes) before a page is considered a JS shell
JS_FALLBACK_BODY_THRESHOLD = 512

# ── Known Directory Mirrors for Seeding ──────────────────────────────────────
SEED_SOURCES = [
    "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/",  # The Hidden Wiki
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/",       # Ahmia Index
    "http://danschat356lctri3zavzh6fbxg2a7lo6z3etgkctzzpspewu7zdsaqd.onion/"        # Daniel's List
]

# ── Regex for finding V3 onion addresses in text ─────────────────────────────
ONION_V3_REGEX = r"(?:https?://)?([a-z2-7]{56}\.onion)"

# ── User-Agent Rotation ─────────────────────────────────────────────────────
# Identifying as a standard browser helps avoid some basic blocks.
# We rotate these to avoid fingerprinting.
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67'
]

# Default headers for backward compatibility
HEADERS = {
    'User-Agent': USER_AGENTS[0]
}

# ── Helper Functions ─────────────────────────────────────────────────────────

def get_random_header():
    """Returns a header dict with a random User-Agent."""
    return {
        'User-Agent': random.choice(USER_AGENTS)
    }

def get_isolated_tor_proxy():
    """Returns a Tor SOCKS5 proxy URL with random credentials for stream isolation."""
    rand_auth = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"socks5h://{rand_auth}:{rand_auth}@{TOR_PROXY_HOST}:{TOR_PROXY_PORT}"

def get_isolated_pw_proxy():
    """Returns a Tor proxy dictionary for Playwright with random credentials."""
    rand_auth = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return {
        'server': f"socks5://{TOR_PROXY_HOST}:{TOR_PROXY_PORT}",
        'username': rand_auth,
        'password': rand_auth
    }
