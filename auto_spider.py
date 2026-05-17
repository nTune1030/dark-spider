r"""
Automated runner for the Dark Web Spider.

Handles the full scan lifecycle:
  1. Verifies the Tor service is running (must be started manually first)
  2. Rotates to a fresh Tor identity for a clean exit node
  3. Runs one complete monitoring cycle via PersistentDarkWebMonitor

Usage::
    python auto_spider.py

Or after ``pip install -e .``::
    darkweb-spider
"""

import logging
import sys

from spider import PersistentDarkWebMonitor
from core.tor_manager import start_tor_service, rotate_identity
from core import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

def run_monitor_cycle():
    """
    Executes a single monitoring cycle:
    1. Rotates Tor identity for a fresh circuit.
    2. Initializes the monitor.
    3. Runs the automated scan (keywords are pulled from the database).
    """

    try:
        logging.info("--- Starting Automated Cycle ---")
        
        # Rotate identity at the start of every cycle to ensure a fresh exit node
        rotate_identity()
        
        # Initialize with your local Tor settings from config
        monitor = PersistentDarkWebMonitor()
        
        # Run the scan (keywords are loaded from the DB by the monitor)
        monitor.run_automated_scan()
        
    except Exception as e:
        logging.error("Cycle failed: %s", e)

def main():
    """Entry point for the darkweb-spider console script."""
    # Ensure Tor is running before we start
    if not start_tor_service():
        logging.critical("Tor service is not available. Exiting.")
        sys.exit(1)

    try:
        run_monitor_cycle()
    except KeyboardInterrupt:
        logging.info("\n[*] Exiting.")
        sys.exit(0)


if __name__ == "__main__":
    main()

