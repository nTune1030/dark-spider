"""Generates an HTML report of spider findings with keyword hit rates and context snippets.

Reads matches and statistics from the SQLite database and writes a styled
HTML report to ``dark_web_report.html`` in the project root.

All user-sourced values (URLs, keywords, context) are escaped with
``html.escape()`` to prevent XSS.

Usage::

    python scripts/report_generator.py
"""

import logging
import os
import sys
import sqlite3
import html
from datetime import datetime, timezone

# Add parent directory to path to import core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.db_manager import DatabaseManager
from core import config

DATA_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dark Web Spider Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #121212;
            color: #e0e0e0;
            margin: 0;
            padding: 20px 32px;
        }}
        h1 {{
            color: #bb86fc;
            text-align: center;
            margin-bottom: 4px;
        }}
        .generated {{
            text-align: center;
            font-size: 0.85em;
            color: #666;
            margin-bottom: 28px;
        }}

        /* ── Summary cards ── */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .card {{
            background: #1e1e1e;
            border: 1px solid #2c2c2c;
            border-radius: 8px;
            padding: 16px 20px;
        }}
        .card .label {{
            font-size: 0.78em;
            color: #888;
            text-transform: uppercase;
            letter-spacing: .06em;
        }}
        .card .value {{
            font-size: 1.8em;
            font-weight: 700;
            color: #03dac6;
            margin-top: 4px;
        }}

        /* ── Keyword hit-rate table ── */
        h2 {{
            color: #bb86fc;
            margin: 28px 0 10px;
            font-size: 1.05em;
            text-transform: uppercase;
            letter-spacing: .08em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 32px;
            background-color: #1e1e1e;
            box-shadow: 0 4px 8px rgba(0,0,0,0.5);
            border-radius: 6px;
            overflow: hidden;
        }}
        th, td {{
            padding: 11px 14px;
            text-align: left;
            border-bottom: 1px solid #2a2a2a;
            font-size: 0.9em;
        }}
        th {{
            background-color: #2c2c2c;
            color: #03dac6;
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: .06em;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background-color: #252525; }}
        a {{
            color: #bb86fc;
            text-decoration: none;
        }}
        a:hover {{ text-decoration: underline; }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.78em;
            font-weight: 600;
        }}
        .badge-regex  {{ background: #2d1f4a; color: #bb86fc; }}
        .badge-string {{ background: #1a2d2d; color: #03dac6; }}
        .badge-zero   {{ background: #2d2d1a; color: #f0c040; }}
        .context-snippet {{
            font-family: 'Courier New', monospace;
            font-size: 0.82em;
            color: #aaa;
            background: #181818;
            padding: 4px 8px;
            border-radius: 4px;
            max-width: 500px;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .footer {{
            margin-top: 32px;
            text-align: center;
            font-size: 0.85em;
            color: #555;
        }}
    </style>
</head>
<body>

    <h1>🕷️ Dark Web Spider Findings</h1>
    <p class="generated">Generated: {generated_at}</p>

    <!-- ── Scan Summary ── -->
    <div class="summary-grid">
        <div class="card">
            <div class="label">Seeds Checked</div>
            <div class="value">{seeds_checked}</div>
        </div>
        <div class="card">
            <div class="label">Active Seeds</div>
            <div class="value">{seeds_active}</div>
        </div>
        <div class="card">
            <div class="label">Dead Seeds</div>
            <div class="value">{seeds_dead}</div>
        </div>
        <div class="card">
            <div class="label">Total Matches</div>
            <div class="value">{total_matches}</div>
        </div>
        <div class="card">
            <div class="label">Keywords Active</div>
            <div class="value">{keyword_count}</div>
        </div>
    </div>

    <!-- ── Keyword Hit Rates ── -->
    <h2>Keyword Performance</h2>
    <table>
        <thead>
            <tr>
                <th>Type</th>
                <th>Keyword</th>
                <th>Hits</th>
                <th>Hit Rate (of checked seeds)</th>
            </tr>
        </thead>
        <tbody>
            {keyword_rows}
        </tbody>
    </table>

    <!-- ── Match Detail ── -->
    <h2>Match Details</h2>
    {matches_section}

    <div class="footer">
        Dark Web Spider &mdash; Report generated {generated_at}
    </div>

</body>
</html>
"""

def _badge(ktype):
    cls = 'badge-regex' if ktype == 'REGEX' else 'badge-string'
    return f'<span class="badge {cls}">{ktype}</span>'

def generate_report():
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    db = DatabaseManager(config.DB_PATH)

    # --- Stats ---
    con = sqlite3.connect(config.DB_PATH)
    seeds_checked = con.execute("SELECT COUNT(*) FROM seed_list WHERE last_checked IS NOT NULL").fetchone()[0]
    seeds_active  = con.execute("SELECT COUNT(*) FROM seed_list WHERE is_active = 1").fetchone()[0]
    seeds_dead    = con.execute("SELECT COUNT(*) FROM seed_list WHERE is_active = 0").fetchone()[0]
    con.close()

    matches     = db.get_all_matches()
    hit_rates   = db.get_keyword_hit_rates()

    # --- Keyword rows ---
    kw_rows = []
    for kw, ktype, hits, rate in hit_rates:
        badge = _badge(ktype)
        hit_class = 'badge-zero' if hits == 0 else ''
        kw_rows.append(f"""
            <tr>
                <td>{badge}</td>
                <td><code>{html.escape(kw)}</code></td>
                <td><span class="badge {hit_class}">{hits}</span></td>
                <td>{rate}%</td>
            </tr>""")

    # --- Match detail rows ---
    if matches:
        rows = []
        for match in matches:
            # (id, url, keyword, context, timestamp)
            _, url, keyword, context, timestamp = match
            safe_url = html.escape(url)
            context_html = (
                f'<div class="context-snippet">&hellip;{html.escape(context)}&hellip;</div>'
                if context else '<span style="color:#555">—</span>'
            )
            rows.append(f"""
            <tr>
                <td>{html.escape(str(timestamp))}</td>
                <td>{html.escape(keyword)}</td>
                <td><a href="{safe_url}" target="_blank">{safe_url}</a></td>
                <td>{context_html}</td>
            </tr>""")

        matches_section = f"""
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Keyword</th>
                    <th>Onion URL</th>
                    <th>Context Snippet</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>"""
    else:
        matches_section = '<p style="color:#888;">No matches recorded yet. Run the spider to populate results.</p>'

    html_content = DATA_TEMPLATE.format(
        generated_at   = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        seeds_checked  = f'{seeds_checked:,}',
        seeds_active   = f'{seeds_active:,}',
        seeds_dead     = f'{seeds_dead:,}',
        total_matches  = len(matches),
        keyword_count  = len(hit_rates),
        keyword_rows   = ''.join(kw_rows),
        matches_section= matches_section,
    )

    report_path = os.path.join(config.PROJECT_ROOT, "dark_web_report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    logging.info("[+] Report generated: %s", report_path)
    logging.info("    %d matches | %s seeds checked | %d keywords tracked",
                len(matches), f'{seeds_checked:,}', len(hit_rates))

if __name__ == "__main__":
    generate_report()
