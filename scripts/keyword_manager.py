"""CLI tool for managing search keywords in the Dark Web Spider database.

Supports adding string keywords, regex patterns, listing tracked keywords,
deleting keywords, and bulk-importing from a text file.

Usage examples::

    python scripts/keyword_manager.py --add "data breach"
    python scripts/keyword_manager.py --add "[a-z]+@[a-z]+\\.[a-z]+" --regex
    python scripts/keyword_manager.py --list
    python scripts/keyword_manager.py --delete "data breach"
    python scripts/keyword_manager.py --import-file keywords.txt
"""

import argparse
import sys
import logging
import os

# Add parent directory to path to import core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.db_manager import DatabaseManager
from core import config

def main():
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    parser = argparse.ArgumentParser(description="Manage search keywords for the Dark Web Spider.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--add", help="Add a new keyword to the database")
    parser.add_argument("--regex", action="store_true", help="Treat the added keyword as a ReGex pattern")
    group.add_argument("--list", action="store_true", help="List all tracked keywords")
    group.add_argument("--delete", help="Remove a keyword from the database")
    group.add_argument("--import-file", help="Import keywords from a text file (one per line)")

    args = parser.parse_args()
    db = DatabaseManager(config.DB_PATH)

    if args.add:
        k_type = 'REGEX' if args.regex else 'STRING'
        if db.add_keyword(args.add, k_type):
            logging.info("[+] Added (%s): %s", k_type, args.add)
        else:
            logging.error("[!] Failed to add keyword: %s", args.add)

    elif args.delete:
        if db.remove_keyword(args.delete):
            logging.info("[-] Removed keyword: %s", args.delete)
        else:
            logging.error("[!] Failed to remove keyword: %s", args.delete)

    elif args.list:
        keywords = db.get_keywords()
        if keywords:
            logging.info("--- Tracked Keywords (%d) ---", len(keywords))
            for kw, k_type in keywords:
                logging.info("- [%s] %s", k_type, kw)
        else:
            logging.info("[-] No keywords found in database.")

    elif args.import_file:
        try:
            with open(args.import_file, 'r') as f:
                lines = [line.strip() for line in f if line.strip()]
            
            count = 0
            for kw in lines:
                if db.add_keyword(kw):
                    count += 1
            logging.info("[+] Imported %d keywords from %s", count, args.import_file)
        except Exception as e:
            logging.error("[!] Failed to read file: %s", e)

if __name__ == "__main__":
    main()
