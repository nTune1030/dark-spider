"""One-shot database statistics snapshot — prints seed counts, crawl rates, and failure distribution.

Reads from the database in read-only mode (safe to run while the spider is active).

Usage::

    python scripts/snapshot.py
"""

import sqlite3
import time
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core import config

con = sqlite3.connect('file:%s?mode=ro' % config.DB_PATH, uri=True)

total   = con.execute('SELECT COUNT(*) FROM seed_list').fetchone()[0]
checked = con.execute('SELECT COUNT(*) FROM seed_list WHERE last_checked IS NOT NULL').fetchone()[0]
active  = con.execute('SELECT COUNT(*) FROM seed_list WHERE is_active=1').fetchone()[0]
dead    = con.execute('SELECT COUNT(*) FROM seed_list WHERE is_active=0').fetchone()[0]
matches = con.execute('SELECT COUNT(*) FROM matches').fetchone()[0]

recent_60s = con.execute(
    "SELECT COUNT(*) FROM seed_list WHERE last_checked >= datetime('now', '-60 seconds')"
).fetchone()[0]

recent_5m = con.execute(
    "SELECT COUNT(*) FROM seed_list WHERE last_checked >= datetime('now', '-300 seconds')"
).fetchone()[0]

oldest = con.execute('SELECT MIN(last_checked) FROM seed_list WHERE last_checked IS NOT NULL').fetchone()[0]
newest = con.execute('SELECT MAX(last_checked) FROM seed_list WHERE last_checked IS NOT NULL').fetchone()[0]

fail_dist = con.execute(
    'SELECT failure_count, COUNT(*) FROM seed_list GROUP BY failure_count ORDER BY failure_count'
).fetchall()

print('=== LIVE SNAPSHOT  %s ===' % time.strftime('%H:%M:%S'))
print()
print('  Seeds total   : %d' % total)
print('  Active        : %d' % active)
print('  Dead          : %d' % dead)
print('  Ever checked  : %d  (%.1f%%)' % (checked, checked / total * 100))
print('  Never checked : %d' % (total - checked))
print()
print('  Checked in last 60s : %d seeds  (~%d/min)' % (recent_60s, recent_60s))
print('  Checked in last 5m  : %d seeds  (~%d/min)' % (recent_5m, recent_5m // 5))
print()
print('  First check : %s' % oldest)
print('  Last check  : %s' % newest)
print()
print('  Matches found : %d' % matches)
print()
print('  Failure count distribution:')
for fc, cnt in fail_dist:
    bar = '#' * min(cnt // 200, 40)
    print('    failures=%d  count=%6d  %s' % (fc, cnt, bar))

con.close()
