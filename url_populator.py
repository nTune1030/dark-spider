import requests
import sqlite3
import re
import logging
from bs4 import BeautifulSoup
from typing import Set
import config
import sys
from tor_manager import start_tor_service

# Known 2025 Directory Mirrors for Seeding
# Note: These links are subject to change.
SEED_SOURCES = [
    "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/", # The Hidden Wiki
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/",      # Ahmia Index
    "http://danschat356lctri3zavzh6fbxg2a7lo6z3etgkctzzpspewu7zdsaqd.onion/"       # Daniel's List
]

class SeedPopulator:
    def __init__(self, db_path: str = config.DB_PATH):
        self.db_path = db_path
        self.proxies = {
            'http': config.TOR_PROXY, 
            'https': config.TOR_PROXY
        }
        self.headers = config.HEADERS
        self.onion_regex = re.compile(r"[a-z2-7]{56}\.onion")

    def fetch_seeds_from_url(self, source_url: str) -> Set[str]:
        """Scrapes a directory page for all unique V3 onion addresses."""
        found_onions = set()
        try:
            logging.info(f"[*] Seeding from: {source_url}")
            response = requests.get(
                source_url, 
                proxies=self.proxies, 
                headers=self.headers, 
                timeout=30
            )
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                # Find all links and text that look like V3 onion addresses
                links = [a.get('href') for a in soup.find_all('a', href=True)]
                for link in links:
                    match = self.onion_regex.search(link)
                    if match:
                        found_onions.add(f"http://{match.group(0)}")
            else:
                logging.warning(f"[!] Failed to fetch {source_url}: Status {response.status_code}")
                
            return found_onions
        except Exception as e:
            logging.error(f"[!] Failed to fetch seeds from {source_url}: {e}")
            return set()

    def update_database(self, onions: Set[str]):
        """Inserts new onions into the existing seed_list table."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Ensure table exists (defensive programming)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS seed_list (
                        url TEXT PRIMARY KEY,
                        last_checked DATETIME,
                        failure_count INTEGER DEFAULT 0,
                        is_active BOOLEAN
                    )
                """)
                
                new_count = 0
                for onion in onions:
                    # INSERT OR IGNORE avoids duplicates in your PRIMARY KEY url column
                    cursor.execute(
                        "INSERT OR IGNORE INTO seed_list (url, is_active, failure_count) VALUES (?, 1, 0)", 
                        (onion,)
                    )
                    if cursor.rowcount > 0:
                        new_count += 1
                logging.info(f"[+] Successfully added {new_count} new unique seeds to the database.")
        except sqlite3.Error as e:
            logging.error(f"[!] Database error: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    
    if not start_tor_service():
        sys.exit(1)

    populator = SeedPopulator()
    
    all_discovered = set()
    for source in SEED_SOURCES:
        discovered = populator.fetch_seeds_from_url(source)
        all_discovered.update(discovered)
    
    if all_discovered:
        populator.update_database(all_discovered)
    else:
        logging.info("[-] No seeds found. Ensure Tor is running and sources are reachable.")
