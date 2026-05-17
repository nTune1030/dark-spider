import subprocess
import time
import logging
import shutil
from typing import Optional
from stem.control import Controller
from stem import Signal, SocketError
import threading
from core import config

# Suppress annoying stem SocketClosed warnings on Windows
logging.getLogger('stem').setLevel(logging.CRITICAL)

_rotate_lock = threading.Lock()
_last_rotated = 0.0
_COOLDOWN_SECONDS = 15.0

def start_tor_service() -> bool:
    """Check if Tor is running on the control port; start it if not.

    Attempts to connect to the Tor control port (9051).  If the connection
    fails, looks for the ``tor`` executable in PATH and launches it as a
    background process, then waits up to 60 seconds for bootstrapping.

    Returns:
        True if Tor is running (or was started successfully), False otherwise.
    """
    control_port = 9051  # Standard Tor control port (Tor Browser uses 9151)
    
    try:
        # Check if we can already connect to the ControlPort
        with Controller.from_port(port=str(control_port)) as controller:  # type: ignore[arg-type]
            controller.authenticate()
            logging.info("[*] Tor is already running and accessible via ControlPort.")
            return True
    except (SocketError, Exception):
        # Proceed to start
        pass

    logging.info("[!] Tor not detected on ControlPort 9051. Attempting to start service...")
    
    tor_path = shutil.which("tor")
    if not tor_path:
        logging.error("[!] 'tor' executable not found in PATH. Please install Tor or add it to system PATH.")
        return False
    
    try:
        # Start Tor as a background process
        subprocess.Popen([tor_path, "--ControlPort", str(control_port)], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.STDOUT)
        
        # Give it time to initialize and bootstrap
        controller = None
        for i in range(30): # Wait up to 60 seconds
            time.sleep(2)
            try:
                controller = Controller.from_port(port=str(control_port))  # type: ignore[arg-type]
                controller.authenticate()
                
                # Check bootstrap status
                bootstrap_status = controller.get_info("status/bootstrap-phase")
                if "TAG=done" in bootstrap_status:
                    logging.info("[+] Tor service started and bootstrapped successfully.")
                    controller.close()
                    return True
                else:
                    summary = bootstrap_status.split(' SUMMARY=')[1] if 'SUMMARY=' in bootstrap_status else 'in progress'
                    logging.info("...Tor bootstrapping: %s (%d/30)", summary, i + 1)
                    controller.close()
            except Exception:
                pass # Still initializing
        
        logging.error("[!] Timed out waiting for Tor to bootstrap.")
        if controller: controller.close()
        return False
    except Exception as e:
        logging.error("[!] Failed to start Tor: %s", e)
        return False

def rotate_identity() -> bool:
    """Signal Tor to switch to a new identity (NEWNYM) for a fresh exit node.

    Rate-limited to one rotation per 15 seconds (Tor's internal rate limit).
    Thread-safe — uses a lock to serialise concurrent rotation requests.

    Returns:
        True if the NEWNYM signal was sent (or cooldown was active),
        False if the signal could not be delivered.
    """
    global _last_rotated
    
    with _rotate_lock:
        now = time.time()
        if now - _last_rotated < _COOLDOWN_SECONDS:
            logging.debug("[-] Identity rotation requested, but on cooldown.")
            return True # Pretend it succeeded since we recently rotated
            
        try:
            with Controller.from_port(port=str(9051)) as controller:  # type: ignore[arg-type]
                controller.authenticate()
                controller.signal('NEWNYM') # Use string instead of Signal.NEWNYM to avoid IDE false-positive errors
                logging.info("[*] Signal NEWNYM sent. Tor is switching identity...")
            
            _last_rotated = time.time()
            time.sleep(5) # Give it a moment to build a new circuit
            return True
        except Exception as e:
            logging.error("[!] Failed to rotate identity: %s", e)
            return False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    if start_tor_service():
        logging.info("[*] System ready.")
    else:
        logging.error("[!] Critical: Tor service unavailable.")
