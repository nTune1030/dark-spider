"""Live dashboard that polls the database every 30 seconds and prints crawl statistics.

Displays seed counts, crawl rates (seeds/min), match counts, and the 5 most
recent keyword hits.  Run alongside the spider in a separate terminal.

Usage::

    python scripts/live_monitor.py

Press Ctrl+C to stop.
"""
import sqlite3
import time
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core import config

POLL_INTERVAL = 30  # seconds

def snapshot():
    try:
        con = sqlite3.connect(f'file:{config.DB_PATH}?mode=ro', uri=True)


        total   = con.execute('SELECT COUNT(*) FROM seed_list').fetchone()[0]
        checked = con.execute('SELECT COUNT(*) FROM seed_list WHERE last_checked IS NOT NULL').fetchone()[0]
        active  = con.execute('SELECT COUNT(*) FROM seed_list WHERE is_active=1').fetchone()[0]
        dead    = con.execute('SELECT COUNT(*) FROM seed_list WHERE is_active=0').fetchone()[0]
        matches = con.execute('SELECT COUNT(*) FROM matches').fetchone()[0]

        # Seeds checked in the last 60s (proxy for current crawl rate)
        recent  = con.execute(
            "SELECT COUNT(*) FROM seed_list WHERE last_checked >= datetime('now', '-60 seconds')"
        ).fetchone()[0]

        # Recent matches
        new_matches = con.execute(
            "SELECT keyword, url FROM matches ORDER BY timestamp DESC LIMIT 5"
        ).fetchall()

        con.close()
        return total, checked, active, dead, matches, recent, new_matches
    except Exception as e:
        print("[!] Database read error: %s" % e)
        return None, None, None, None, None, None, []

def main():
    print('Live Spider Monitor  (Ctrl+C to stop)')
    print('=' * 72)
    prev_checked = None
    prev_matches = None

    while True:
        total, checked, active, dead, matches, recent_rate, new_matches = snapshot()

        if total is None:
            print('[!] Could not read database')
        else:
            pct     = checked / total * 100 if total else 0
            delta_c = ('  (+%d/min)' % (recent_rate)) if recent_rate else ''
            delta_m = ('  [+%d NEW]' % (matches - prev_matches)) if prev_matches is not None and matches > prev_matches else ''

            print('\n[%s]' % time.strftime('%H:%M:%S'))
            print('  Seeds   total=%-8d checked=%-8d (%.1f%%)%s  active=%-8d dead=%d' % (
                total, checked, pct, delta_c, active, dead))
            print('  Matches total=%-8d%s' % (matches, delta_m))

            if new_matches:
                print('  --- Recent hits ---')
                for kw, url in new_matches:
                    print('    [%s]  %s' % (kw, url))

            prev_checked = checked
            prev_matches = matches

        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nMonitor stopped.')
