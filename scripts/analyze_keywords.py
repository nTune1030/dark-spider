"""One-shot keyword analysis — prints match rates, zero-hit keywords, and top matching URLs.

Reads directly from the SQLite database and prints a formatted summary to
the terminal.  Useful for a quick health check without generating a full
HTML report.

Usage::

    python scripts/analyze_keywords.py
"""

import sqlite3
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core import config


def main():
    con = sqlite3.connect(config.DB_PATH)
    con.row_factory = sqlite3.Row

    # Keywords
    kws = con.execute('SELECT keyword, type, added_at FROM search_keywords ORDER BY added_at').fetchall()
    print('=== KEYWORDS (%d total) ===' % len(kws))
    for r in kws:
        print('  [%s] %s  (added: %s)' % (r['type'], r['keyword'], r['added_at']))

    # Match stats
    print()
    print('=== MATCH STATS ===')
    total = con.execute('SELECT COUNT(*) FROM matches').fetchone()[0]
    print('  Total match records: %d' % total)

    kw_counts = con.execute('SELECT keyword, COUNT(*) as hits FROM matches GROUP BY keyword ORDER BY hits DESC').fetchall()
    for r in kw_counts:
        print('  %-45s %d hits' % (r['keyword'], r['hits']))

    # Seed stats
    print()
    print('=== SEED STATS ===')
    seed_total   = con.execute('SELECT COUNT(*) FROM seed_list').fetchone()[0]
    seed_active  = con.execute('SELECT COUNT(*) FROM seed_list WHERE is_active=1').fetchone()[0]
    seed_dead    = con.execute('SELECT COUNT(*) FROM seed_list WHERE is_active=0').fetchone()[0]
    seed_checked = con.execute('SELECT COUNT(*) FROM seed_list WHERE last_checked IS NOT NULL').fetchone()[0]
    print('  Total seeds:   %d' % seed_total)
    print('  Active:        %d' % seed_active)
    print('  Dead (soft):   %d' % seed_dead)
    print('  Ever checked:  %d' % seed_checked)
    unchecked = seed_total - seed_checked
    print('  Never checked: %d' % unchecked)

    # How many seeds have at least one match?
    matched_seeds = con.execute('SELECT COUNT(DISTINCT url) FROM matches').fetchone()[0]
    print()
    print('=== COVERAGE ===')
    print('  Seeds that produced at least 1 match: %d' % matched_seeds)
    if seed_checked > 0:
        print('  Match rate (of checked seeds): %.1f%%' % (matched_seeds / seed_checked * 100))

    # Keywords with ZERO hits
    print()
    print('=== ZERO-HIT KEYWORDS ===')
    kw_set = set(r['keyword'] for r in kws)
    hit_kws = set(r['keyword'] for r in kw_counts if r['hits'] > 0)
    # Also check REGEX: prefix in matches
    hit_kws_all = set()
    for r in con.execute('SELECT DISTINCT keyword FROM matches').fetchall():
        hit_kws_all.add(r['keyword'])
    zero_hit = []
    for r in kws:
        plain = r['keyword']
        regex_key = 'REGEX:' + plain
        if plain not in hit_kws_all and regex_key not in hit_kws_all:
            zero_hit.append((r['type'], plain))
    if zero_hit:
        for t, k in zero_hit:
            print('  [%s] %s' % (t, k))
    else:
        print('  (all keywords produced at least one hit)')

    # Top URLs
    print()
    print('=== TOP MATCHING URLs (up to 10) ===')
    top_urls = con.execute('SELECT url, COUNT(*) as hits FROM matches GROUP BY url ORDER BY hits DESC LIMIT 10').fetchall()
    for r in top_urls:
        print('  %4d hits  %s' % (r['hits'], r['url']))

    # Recent matches
    print()
    print('=== RECENT MATCHES (last 10) ===')
    recent = con.execute('SELECT url, keyword, timestamp FROM matches ORDER BY timestamp DESC LIMIT 10').fetchall()
    for r in recent:
        print('  %s  [%s]  %s' % (r['timestamp'], r['keyword'], r['url']))

    # Duplicate/noisy keywords (hits > threshold relative to total)
    print()
    print('=== POTENTIALLY NOISY KEYWORDS (>50%% of all matches) ===')
    for r in kw_counts:
        if total > 0 and (r['hits'] / total) > 0.5:
            print('  %-45s %.1f%% of all hits' % (r['keyword'], r['hits']/total*100))

    con.close()


if __name__ == "__main__":
    main()
