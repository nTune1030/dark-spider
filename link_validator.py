import requests
import re
import logging
from dataclasses import dataclass
from typing import List

# Configure logging for 24/7 server operation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("onion_validator.log"),
        logging.StreamHandler()
    ]
)

@dataclass
class OnionSite:
    """
    A data class to hold site information cleanly.
    
    Attributes:
        url (str): The .onion URL.
        is_active (bool): Whether the site is currently reachable.
        response_time (float): Time taken to receive a response in seconds.
        status_code (int): HTTP status code returned by the site.
        title (str): Title of the page if available.
    """
    url: str
    is_active: bool = False
    response_time: float = 0.0
    status_code: int = 0
    title: str = "N/A"

class OnionValidator:
    """
    Validates Tor .onion addresses by checking syntax and reachability.
    
    This class handles the connection via a local Tor proxy and inspects
    responses to determine if a site is active, seized, or dead.
    """
    
    def __init__(self, proxy_url: str = "socks5h://127.0.0.1:9050"):
        """
        Initialize the OnionValidator with a Tor proxy.
        
        Args:
            proxy_url (str): The SOCKS5 proxy URL for Tor. Defaults to "socks5h://127.0.0.1:9050".
        """
        self.session = requests.Session()
        self.session.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        # Masquerade as a standard Tor Browser to avoid basic filtering
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0'
        })
        
        # Compile regex for Tor v3 addresses (56 chars + .onion)
        # We ignore v2 addresses as they are deprecated and insecure.
        self.onion_pattern = re.compile(r"^[a-z2-7]{56}\.onion$")

    def _is_valid_syntax(self, url: str) -> bool:
        """
        Checks if the URL string looks like a valid V3 onion address.
        
        Args:
            url (str): The URL to check.
            
        Returns:
            bool: True if the syntax matches a V3 onion address, False otherwise.
        """
        # Strip protocol and path to check the domain
        try:
            domain = url.split("://")[-1].split("/")[0]
            return bool(self.onion_pattern.match(domain))
        except IndexError:
            return False

    def _check_for_seizure(self, html_content: str) -> bool:
        """
        Heuristic check: Returns True if site appears seized by law enforcement.
        Seized sites return 200 OK but display a banner.
        
        Args:
            html_content (str): The raw HTML content of the page.
            
        Returns:
            bool: True if keywords indicating seizure are found.
        """
        seizure_keywords = [
            "this hidden site has been seized",
            "federal bureau of investigation",
            "operation onymous",
            "law enforcement"
        ]
        return any(keyword in html_content.lower() for keyword in seizure_keywords)

    def validate_url(self, url: str) -> OnionSite:
        """
        The core logic: Probes the URL and returns a structured OnionSite object.
        
        Args:
            url (str): The .onion URL to validate.
            
        Returns:
            OnionSite: An object containing verification results.
        """
        site_data = OnionSite(url=url)

        if not self._is_valid_syntax(url):
            logging.warning(f"Invalid syntax: {url}")
            return site_data

        try:
            logging.info(f"Probing: {url}")
            
            # TOR LATENCY WARNING:
            # We allow a 45-second timeout. Dark web servers are slow.
            # If it takes longer than 45s, it's effectively dead for scraping.
            response = self.session.get(url, timeout=45)
            
            site_data.status_code = response.status_code
            site_data.response_time = response.elapsed.total_seconds()

            if response.status_code == 200:
                if self._check_for_seizure(response.text):
                    logging.warning(f"Site Seized: {url}")
                    site_data.title = "[SEIZED]"
                else:
                    site_data.is_active = True
                    # Simple extraction of page title for context
                    if "<title>" in response.text:
                        try:
                            site_data.title = response.text.split("<title>")[1].split("</title>")[0]
                        except IndexError:
                            site_data.title = "No Title"
                    logging.info(f"Success: {url} ({site_data.response_time:.2f}s)")
            else:
                logging.warning(f"Dead Link ({response.status_code}): {url}")

        except requests.exceptions.Timeout:
            logging.error(f"Timeout: {url}")
        except requests.exceptions.ConnectionError:
            logging.error(f"Connection Failed: {url}")
        except Exception as e:
            logging.error(f"Error checking {url}: {e}")

        return site_data

    def filter_batch(self, url_list: List[str]) -> List[str]:
        """
        Takes a raw list of URLs and returns only the active ones.
        
        Args:
            url_list (List[str]): List of URLs to check.
            
        Returns:
            List[str]: simple list of active URL strings.
        """
        active_onions = []
        for url in url_list:
            result = self.validate_url(url)
            if result.is_active:
                active_onions.append(result.url)
        return active_onions

# --- Usage Example ---
if __name__ == "__main__":
    # In a real scenario, you would load this list from a database or file
    raw_links = [
        "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", # Valid (DuckDuckGo)
        "http://invalid-address.onion",                                           # Invalid Syntax
        "http://v2deprecatedonionaddress.onion",                                  # Invalid (Short v2)
    ]

    validator = OnionValidator()
    print("Starting validation batch...")
    clean_list = validator.filter_batch(raw_links)
    
    print("\n--- Validated Clean List ---")
    for link in clean_list:
        print(link)