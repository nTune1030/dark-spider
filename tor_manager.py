import subprocess
import time
import logging
import shutil
from stem.control import Controller
from stem import SocketError
import config

def start_tor_service():
    """
    Checks if Tor is running. If not, attempts to start it.
    Returns:
        bool: True if Tor is running (or started successfully), False otherwise.
    """
    # Use config values if available, else defaults
    control_port = 9051 # Default for standard Tor, Browser usually 9151
    
    # Try to parse port from config.TOR_PROXY (e.g., "socks5h://127.0.0.1:9050")
    # But usually ControlPort is 9051. Let's assume 9051 for the service.
    
    try:
        # Check if we can already connect to the ControlPort
        with Controller.from_port(port=control_port) as controller:
            logging.info("[*] Tor is already running and accessible via ControlPort.")
            return True
    except SocketError:
        logging.info("[!] Tor not detected on ControlPort 9051. Attempting to start service...")
        
        tor_path = shutil.which("tor")
        if not tor_path:
            # Fallback for Windows if 'tor' is not in PATH but maybe in a standard location?
            # For now, just fail gracefully
            logging.error("[!] 'tor' executable not found in PATH. Please install Tor or add it to system PATH.")
            return False
        
        try:
            # Start Tor as a background process
            # Note: Ensure your torrc has 'ControlPort 9051' and 'CookieAuthentication 1'
            subprocess.Popen([tor_path, "--ControlPort", str(control_port)], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.STDOUT)
            
            # Give it time to initialize
            for i in range(10):
                time.sleep(2)
                try:
                    with Controller.from_port(port=control_port) as controller:
                        logging.info("[+] Tor service started successfully.")
                        return True
                except SocketError:
                    logging.info(f"...Waiting for Tor to bootstrap ({i+1}/10)")
            
            logging.error("[!] Timed out waiting for Tor to start.")
            return False
        except Exception as e:
            logging.error(f"[!] Failed to start Tor: {e}")
            return False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    if start_tor_service():
        logging.info("[*] System ready.")
    else:
        logging.error("[!] Critical: Tor service unavailable.")
