"""
GOAL:
Object-oriented spider that takes a set of known .onion 
search engines or paste sites and looks for specific keywords.
Creates a file with the results.
"""

import requests
from requests.exceptions import RequestException
from typing import List, Optional, Dict
import time
import logging
import sqlite3
import os
import sys
from stem import Signal
from stem.control import Controller
import config
from tor_manager import start_tor_service

# Ensure we can import the validator from the same directory
try:
    from link_validator import OnionValidator
except ImportError:
    logging.error("Could not import OnionValidator. Ensure link_validator.py is in the same directory.")
    OnionValidator = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler() # Output to console
    ]
)

def rotate_tor_identity(control_port=9051, password=None):
    """
    Signals Tor to switch to a new circuit (new IP).
    """
    try:
        with Controller.from_port(port=control_port) as controller:
            if password:
                controller.authenticate(password=password)
            else:
                controller.authenticate()  # Cookie authentication
            controller.signal(Signal.NEWNYM)
            logging.info("[*] Tor identity rotated. New circuit established.")
            time.sleep(controller.get_newnym_wait()) # Wait for the new circuit
    except Exception as e:
        logging.warning(f"[!] Failed to rotate Tor identity: {e}")

class DarkWebMonitor:
    """
    Monitors dark web onion sites for specific keywords.
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = {
            'http': config.TOR_PROXY,
            'https': config.TOR_PROXY
        }
        self.session.headers.update(config.HEADERS)
        self.validator = OnionValidator(proxy_url=config.TOR_PROXY) if OnionValidator else None
        
        # Ensure quarantine directory exists
        self.quarantine_dir = config.QUARANTINE_DIR
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    def fetch_page(self, url: str) -> Optional[str]:
        """
        Attempts to fetch a .onion page. Handles file downloads for .zip/.sql.
        """
        try:
            logging.info(f"[*] Attempting to fetch: {url}")
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                # Check for interesting files
                content_type = response.headers.get('Content-Type', '')
                if 'application/zip' in content_type or 'application/sql' in content_type or url.endswith(('.zip', '.sql')):
                    filename = os.path.join(self.quarantine_dir, os.path.basename(url) or "download.file")
                    with open(filename, 'wb') as f:
                        f.write(response.content)
                    logging.info(f"[+] Downloaded extraction to {filename}")
                    return None # return None so we don't parse binary as text
                
                return response.text
            else:
                logging.warning(f"[!] Failed with status: {response.status_code}")
                return None
                
        except RequestException as e:
            logging.error(f"[!] Connection error (common on Tor): {e}")
            return None

    def scan_for_keywords(self, urls: List[str], keywords: List[str]) -> Dict[str, List[str]]:
        results = {}
        
        # Simple validation for the base class
        valid_urls = urls
        if self.validator:
            logging.info("Validating URLs before scanning...")
            valid_urls = self.validator.filter_batch(urls)
        
        for url in valid_urls:
            html_content = self.fetch_page(url)
            
            if html_content:
                found = [k for k in keywords if k.lower() in html_content.lower()]
                if found:
                    logging.info(f"[!!!] MATCH FOUND on {url}: {found}")
                    results[url] = found
            
            time.sleep(2)
            
        return results

class PersistentDarkWebMonitor(DarkWebMonitor):
    def __init__(self, db_path=config.DB_PATH, **kwargs):
        super().__init__(**kwargs)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize tables for links and findings."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT,
                    keyword TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS seed_list (
                    url TEXT PRIMARY KEY,
                    last_checked DATETIME,
                    failure_count INTEGER DEFAULT 0,
                    is_active BOOLEAN
                )
            """)

    def save_match(self, url: str, keywords: List[str]):
        """Log findings to the database."""
        data = [(url, k) for k in keywords]
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany("INSERT INTO matches (url, keyword) VALUES (?, ?)", data)

    def update_seed_status(self, url: str, success: bool):
        """Updates failure count or resets it on success."""
        with sqlite3.connect(self.db_path) as conn:
            if success:
                conn.execute("UPDATE seed_list SET failure_count = 0, last_checked = CURRENT_TIMESTAMP, is_active = 1 WHERE url = ?", (url,))
            else:
                conn.execute("UPDATE seed_list SET failure_count = failure_count + 1, last_checked = CURRENT_TIMESTAMP WHERE url = ?", (url,))
                # 3-Strikes Rule
                conn.execute("DELETE FROM seed_list WHERE failure_count >= 3")

    def add_seeds(self, urls: List[str]):
        """Adds new seeds to the database."""
        with sqlite3.connect(self.db_path) as conn:
            for url in urls:
                conn.execute("INSERT OR IGNORE INTO seed_list (url, is_active) VALUES (?, 1)", (url,))

    def run_automated_scan(self, keywords: List[str]):
        """Main loop: fetches seeds from DB, scans, updates status."""
        
        # 1. Fetch seeds from DB
        with sqlite3.connect(self.db_path) as conn:
            seeds = [row[0] for row in conn.execute("SELECT url FROM seed_list WHERE is_active = 1")]

        if not seeds:
            logging.info("No active seeds in database.")
            return

        logging.info(f"Starting scan on {len(seeds)} seeds...")
        
        # 2. Key difference: We iterate manually to update DB status per URL
        for url in seeds:
            # Rotate identity occasionally (e.g. every 10 sites or on errors - keeping it simple here)
            # rotate_tor_identity() 
            
            html_content = self.fetch_page(url)
            
            if html_content:
                # Success
                self.update_seed_status(url, True)
                found = [k for k in keywords if k.lower() in html_content.lower()]
                if found:
                    logging.info(f"[!!!] MATCH FOUND on {url}: {found}")
                    self.save_match(url, found)
            else:
                # Failure (connection error or 404 handled in fetch_page return None)
                self.update_seed_status(url, False)
            
            time.sleep(2)

        logging.info("Scan complete.")

if __name__ == "__main__":
    if not start_tor_service():
        sys.exit(1)
        
    # Example Usage
    target_onions = [
        "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=myemail@example.com",
        "http://invalid-link-for-test.onion"
    ]
    
    search_keywords = ["myemail@example.com", "My Name", "Password"]

    monitor = PersistentDarkWebMonitor()
    logging.info("Initializing Persistent Monitor...")
    
    # Pre-populate DB for the example
    monitor.add_seeds(target_onions)
    
    # Run the scan
    monitor.run_automated_scan(search_keywords)