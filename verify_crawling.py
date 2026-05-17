"""Ad-hoc verification script for keyword matching logic.

Tests that string and regex keywords are correctly matched against mock HTML
content using the same logic as ``PersistentDarkWebMonitor.process_url()``.

Run manually::

    python verify_crawling.py

For proper automated tests, see the ``tests/`` directory (``pytest``).
"""

import logging
import re
import os

from spider import PersistentDarkWebMonitor
from core.db_manager import DatabaseManager

# Mock DB for testing (don't write to real one if possible, or cleanup after)
TEST_DB = "test_regex.db"


def test_regex():
    logging.basicConfig(level=logging.INFO)

    # Setup
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except OSError:
            pass

    # Initialize with regex support
    db = DatabaseManager(TEST_DB)
    db.add_keyword("secret", "STRING")
    db.add_keyword(r"[a-z]+@[a-z]+\.com", "REGEX")  # Simple email regex

    monitor = PersistentDarkWebMonitor(db_path=TEST_DB)

    # Mock HTML content
    mock_html = """
    <html>
        <body>
            <p>This is a secret message.</p>
            <p>Contact us at testuser@example.com for more info.</p>
        </body>
    </html>
    """

    logging.info("Testing Regex Matching Logic...")
    keywords = db.get_keywords()  # [('secret', 'STRING'), ('...regex...', 'REGEX')]

    found_matches = []
    for kw, k_type in keywords:
        if k_type == 'REGEX':
            if re.search(kw, mock_html):
                found_matches.append("REGEX:%s" % kw)
        else:
            if kw.lower() in mock_html.lower():
                found_matches.append(kw)

    expected = {"secret", r"REGEX:[a-z]+@[a-z]+\.com"}
    found_set = set(found_matches)

    if expected.issubset(found_set):
        logging.info("[PASS] Successfully matched both String and Regex. Found: %s", found_set)
    else:
        logging.error("[FAIL] Expected %s but got %s", expected, found_set)

    # Cleanup
    try:
        del db  # Ensure DB object is collected and connection closed
        del monitor
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)
    except Exception as e:
        logging.warning("Cleanup failed (non-critical): %s", e)


if __name__ == "__main__":
    test_regex()
