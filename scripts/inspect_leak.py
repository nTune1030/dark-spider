"""Debug utility — inspects the database for LEAK test data and prints schema/match info.

Usage::

    python scripts/inspect_leak.py
"""

import sqlite3
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core import config

con = sqlite3.connect(config.DB_PATH)

print('LEAK in search_keywords?')
r = con.execute("SELECT * FROM search_keywords WHERE keyword='LEAK'").fetchall()
print(r)
r2 = con.execute("SELECT * FROM search_keywords WHERE keyword LIKE '%leak%'").fetchall()
print('Any leak-like keywords:', r2)

print()
print('Matches table schema:')
r = con.execute('PRAGMA table_info(matches)').fetchall()
for row in r:
    print(row)

print()
print('Sample raw match rows:')
rows = con.execute('SELECT * FROM matches LIMIT 5').fetchall()
for row in rows:
    print(row)

print()
print('All distinct keyword values in matches:')
rows = con.execute('SELECT DISTINCT keyword FROM matches').fetchall()
for row in rows:
    print(' ', row)

con.close()
