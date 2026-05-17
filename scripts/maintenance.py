"""Database maintenance tool for pruning dead seeds and resetting failure counts.

Usage::

    # Remove seeds inactive for > 14 days
    python scripts/maintenance.py --cull-dead 14

    # Reset all inactive seeds to give them another chance
    python scripts/maintenance.py --reset-failures
"""

import sqlite3
import argparse
import logging
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to import core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core import config

def prune_dead_seeds(days=14):
    """Hard delete seeds that have been inactive for more than `days`."""
    cutoff = datetime.now() - timedelta(days=days)
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM seed_list WHERE is_active = 0 AND last_checked < ?", 
                (cutoff,)
            )
            count = cursor.rowcount
            if count > 0:
                logging.info("[+] Pruned %d stale seeds (inactive > %d days).", count, days)
            else:
                logging.info("[-] No stale seeds found older than %d days.", days)
    except sqlite3.Error as e:
        logging.error("[!] Database error: %s", e)

def reset_failures():
    """Resets inactive seeds to give them a second chance."""
    try:
        with sqlite3.connect(config.DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE seed_list SET is_active = 1, failure_count = 0 WHERE is_active = 0"
            )
            count = cursor.rowcount
            if count > 0:
                logging.info("[+] Revived %d inactive seeds.", count)
            else:
                logging.info("[-] No inactive seeds to revive.")
    except sqlite3.Error as e:
        logging.error("[!] Database error: %s", e)

def main():
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    parser = argparse.ArgumentParser(description="Maintenance tool for Dark Web Spider DB.")
    group = parser.add_mutually_exclusive_group(required=True)
    
    group.add_argument("--cull-dead", type=int, nargs='?', const=14, metavar="DAYS",
                       help="Hard delete seeds inactive for > DAYS (default: 14)")
    group.add_argument("--reset-failures", action="store_true",
                       help="Reset all inactive seeds to active status (try again)")

    args = parser.parse_args()

    if args.cull_dead is not None:
        prune_dead_seeds(args.cull_dead)
    elif args.reset_failures:
        reset_failures()

if __name__ == "__main__":
    main()
