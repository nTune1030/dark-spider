"""One-time migration script for keyword database updates.

Performs three operations:
  1. Deletes orphaned LEAK test data from the matches table.
  2. Replaces the narrow phone regex with a broader, obfuscation-aware pattern.
  3. Adds obfuscation-aware REGEX variants for email addresses.

Run once::

    python scripts/migrate_keywords.py

IMPORTANT: Personal keywords (emails, phone numbers, etc.) should be managed
via ``keyword_manager.py`` or a local config file — never committed to
source control.  Edit the ``OBFUSCATED`` list below with your own keywords
before running.
"""
import sqlite3
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core import config

con = sqlite3.connect(config.DB_PATH)
cur = con.cursor()

# 1. Purge orphaned LEAK test data
cur.execute("DELETE FROM matches WHERE keyword = 'LEAK'")
purged = cur.rowcount
print('[+] Purged %d LEAK test records from matches.' % purged)

# 2. Replace narrow phone regex with a broader one
#    *** EDIT THESE VALUES with your own keywords before running. ***
OLD_PHONE = r'555[-]?123[-]?4567'
NEW_PHONE  = r'\(?\b555\)?[\s.\-]?123[\s.\-]?4567\b'
cur.execute("DELETE FROM search_keywords WHERE keyword = ?", (OLD_PHONE,))
cur.execute(
    "INSERT OR IGNORE INTO search_keywords (keyword, type) VALUES (?, 'REGEX')",
    (NEW_PHONE,)
)
print('[+] Phone regex updated.')
print('    Old: %s' % OLD_PHONE)
print('    New: %s' % NEW_PHONE)

# 3. Add obfuscation-aware email REGEX variants
#    *** EDIT THIS LIST with your own keywords before running. ***
#    Do NOT commit personal information to source control.
OBFUSCATED = [
    # Example: (r'user\s*[\[\(]?@[\]\)]?\s*protonmail', 'REGEX'),
    # Example: (r'anotheruser\s*[\[\(]?@[\]\)]?\s*gmail',     'REGEX'),
]
for kw, ktype in OBFUSCATED:
    cur.execute(
        "INSERT OR IGNORE INTO search_keywords (keyword, type) VALUES (?, ?)",
        (kw, ktype)
    )
    print('[+] Added obfuscation-aware variant: %s' % kw)

con.commit()

# Report final keyword list
print()
print('--- Final keyword list ---')
for row in con.execute("SELECT type, keyword FROM search_keywords ORDER BY added_at"):
    print('  [%s] %s' % (row[0], row[1]))

con.close()
