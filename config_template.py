"""
Shared configuration constants for the Dark Web Spider project.
"""

TOR_PROXY = "socks5h://127.0.0.1:9050"
DB_PATH = "dark_spider.db"
QUARANTINE_DIR = "quarantine"

# Identifying as a standard browser helps avoid some basic blocks
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0'
}
