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

# Ensure we can import the validator from the same directory
try:
    from link_validator import OnionValidator
except ImportError:
    # If running directly or in a different context, this might fail without path setup.
    # For now, we assume same directory availability.
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

class DarkWebMonitor:
    """
    Monitors dark web onion sites for specific keywords.
    
    Attributes:
        session (requests.Session): Request session with Tor proxy configuration.
    """
    
    def __init__(self, tor_proxy: str = "socks5h://127.0.0.1:9050"):
        """
        Initialize the DarkWebMonitor.
        
        Args:
            tor_proxy (str): The Tor SOCKS5 proxy URL.
        """
        # Use a Session for connection pooling and cookie persistence
        self.session = requests.Session()
        self.session.proxies = {
            'http': tor_proxy,
            'https': tor_proxy
        }
        # Identifying as a standard browser helps avoid some basic blocks
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0'
        })
        self.validator = OnionValidator(proxy_url=tor_proxy) if OnionValidator else None

    def fetch_page(self, url: str) -> Optional[str]:
        """
        Attempts to fetch a .onion page with high tolerance for failure.
        Onions are slow; we need generous timeouts.
        
        Args:
            url (str): The URL to fetch.
            
        Returns:
            Optional[str]: The HTML content if successful, None otherwise.
        """
        try:
            logging.info(f"[*] Attempting to fetch: {url}")
            # 30 second timeout is standard for Tor latency
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                return response.text
            else:
                logging.warning(f"[!] Failed with status: {response.status_code}")
                return None
                
        except RequestException as e:
            logging.error(f"[!] Connection error (common on Tor): {e}")
            return None

    def scan_for_keywords(self, urls: List[str], keywords: List[str]) -> Dict[str, List[str]]:
        """
        Iterates through a list of onion URLs and checks for keywords.
        First validates the URLs to avoid wasting time on dead links.
        
        Args:
            urls (List[str]): List of .onion URLs to scan.
            keywords (List[str]): List of keywords to search for.
            
        Returns:
            Dict[str, List[str]]: Dictionary mapping URLs to list of found keywords.
        """
        results = {}
        
        # Step 1: Validate Links (if validator is available)
        valid_urls = urls
        if self.validator:
            logging.info("Validating URLs before scanning...")
            valid_urls = self.validator.filter_batch(urls)
            logging.info(f"Validation complete. {len(valid_urls)}/{len(urls)} sites are active.")
        
        # Step 2: Scan Active Links
        for url in valid_urls:
            html_content = self.fetch_page(url)
            
            if html_content:
                found = [k for k in keywords if k.lower() in html_content.lower()]
                if found:
                    logging.info(f"[!!!] MATCH FOUND on {url}: {found}")
                    results[url] = found
            
            # Respect the network: delay between requests to avoid circuit overload
            time.sleep(2) 
            
        return results

if __name__ == "__main__":
    # Example: A list of known paste sites or search engine queries
    # Note: These must be valid .onion addresses
    target_onions = [
        "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=myemail@example.com", # Example: Ahmia Search Query
        "http://invalid-link-for-test.onion"
    ]
    
    # Define keywords to search for
    search_keywords = ["myemail@example.com", "My Name", "Password"]

    monitor = DarkWebMonitor()
    logging.info("Starting Dark Web Monitor...")
    matches = monitor.scan_for_keywords(target_onions, search_keywords)
    
    if matches:
        logging.info("\nSummary of Findings:")
        for url, items in matches.items():
            logging.info(f" - {url}: {items}")
    else:
        logging.info("No matches found.")