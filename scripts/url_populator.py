"""Fetches seed .onion URLs from known directory sites and stores them in the database.

Scrapes the directory pages listed in ``config.SEED_SOURCES`` for V3 onion
addresses and inserts them as new seeds via DatabaseManager.

Usage::

    python scripts/url_populator.py
"""

import requests
import re
import logging
from bs4 import BeautifulSoup
from typing import Set
import sys
import os

# Add parent directory to path to import core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core import config
from core.tor_manager import start_tor_service
from core.db_manager import DatabaseManager

class SeedPopulator:
    def __init__(self, db_path: str = config.DB_PATH):
        self.db = DatabaseManager(db_path)
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
            logging.info("[*] Seeding from: %s", source_url)
            response = requests.get(
                source_url, 
                proxies=self.proxies, 
                headers=self.headers, 
                timeout=30
            )
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                # Find all links and text that look like V3 onion addresses
                links = [str(a['href']) for a in soup.find_all('a', href=True)]
                for link in links:
                    match = self.onion_regex.search(link)
                    if match:
                        found_onions.add(f"http://{match.group(0)}")
            else:
                logging.warning("[!] Failed to fetch %s: Status %s", source_url, response.status_code)
                
            return found_onions
        except Exception as e:
            logging.error("[!] Failed to fetch seeds from %s: %s", source_url, e)
            return set()

    def update_database(self, onions: Set[str]):
        """Inserts new onions into the existing seed_list table."""
        new_count = self.db.add_seeds(list(onions))
        logging.info("[+] Successfully added %d new unique seeds to the database.", new_count)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    
    # Check if we should dry run or just checking syntax
    if "--dry" in sys.argv:
        print("Dry run initialized.")
    
    if not start_tor_service():
        sys.exit(1)

    populator = SeedPopulator()
    
    all_discovered = set()
    for source in config.SEED_SOURCES:
        discovered = populator.fetch_seeds_from_url(source)
        all_discovered.update(discovered)
    
    if all_discovered:
        populator.update_database(all_discovered)
    else:
        logging.info("[-] No seeds found. Ensure Tor is running and sources are reachable.")
