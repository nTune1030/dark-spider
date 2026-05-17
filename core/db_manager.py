import sqlite3
import logging
import time
import functools
from typing import List, Tuple
from core import config

# ── Retry decorator for SQLITE_BUSY / SQLITE_LOCKED ──────────────────────────
# Under high concurrency (10+ workers), WAL mode can still produce brief
# contention.  This decorator retries with exponential backoff instead of
# failing immediately.

_MAX_RETRIES = 5
_BASE_DELAY  = 0.1  # 100 ms

def _retry_on_busy(fn):
    """Decorator that retries a method on sqlite3.OperationalError (busy/locked)."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        delay = _BASE_DELAY
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                return fn(*args, **kwargs)
            except sqlite3.OperationalError as e:
                if "busy" in str(e).lower() or "locked" in str(e).lower():
                    if attempt == _MAX_RETRIES:
                        logging.error("[DB] Giving up after %d retries: %s", _MAX_RETRIES, e)
                        raise
                    logging.debug("[DB] Retrying (%d/%d) after busy/locked: %s", attempt, _MAX_RETRIES, e)
                    time.sleep(delay)
                    delay *= 2  # exponential backoff
                else:
                    raise  # not a contention error — re-raise immediately
        return fn(*args, **kwargs)  # final attempt (shouldn't reach here)
    return wrapper

class DatabaseManager:
    """SQLite persistence layer for seeds, keywords, and match results.

    All public methods are wrapped with ``@_retry_on_busy`` which retries
    on ``sqlite3.OperationalError`` (SQLITE_BUSY / SQLITE_LOCKED) with
    exponential backoff, making the class safe for concurrent access from
    the spider's ThreadPoolExecutor workers.

    Schema:
      - ``seed_list`` — crawled URLs with failure tracking and active status
      - ``search_keywords`` — keyword/regex patterns to match
      - ``matches`` — findings with context snippets and timestamps
      - ``idx_match_dedup`` — UNIQUE index on (url, keyword) for deduplication
    """
    def __init__(self, db_path: str = config.DB_PATH):
        self.db_path = db_path
        self._init_db()

    @_retry_on_busy
    def _init_db(self):
        """Initialize tables for links and findings."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT,
                    keyword TEXT,
                    context TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS seed_list (
                    url TEXT PRIMARY KEY,
                    last_checked DATETIME,
                    failure_count INTEGER DEFAULT 0,
                    is_active BOOLEAN
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS search_keywords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    keyword TEXT UNIQUE,
                    type TEXT DEFAULT 'STRING',
                    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Deduplication index: prevent duplicate match rows across scan cycles
            try:
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_match_dedup ON matches (url, keyword)"
                )
            except sqlite3.OperationalError:
                pass  # Index already exists
            
            # Simple migration checks: add columns if they don't exist yet
            # (handles databases created before these schema updates)
            for migration in [
                "ALTER TABLE search_keywords ADD COLUMN type TEXT DEFAULT 'STRING'",
                "ALTER TABLE matches ADD COLUMN context TEXT",
            ]:
                try:
                    conn.execute(migration)
                except sqlite3.OperationalError:
                    pass  # Column already exists

    @_retry_on_busy
    def add_seeds(self, urls: List[str]) -> int:
        """Adds new seeds to the database. Returns count of new seeds added."""
        new_count = 0
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for url in urls:
                cursor.execute(
                    "INSERT OR IGNORE INTO seed_list (url, is_active, failure_count) VALUES (?, 1, 0)",
                    (url,)
                )
                if cursor.rowcount > 0:
                    new_count += 1
        return new_count
        
    @_retry_on_busy
    def add_keyword(self, keyword: str, keyword_type: str = 'STRING') -> bool:
        """Adds a search keyword to the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO search_keywords (keyword, type) VALUES (?, ?)",
                (keyword, keyword_type)
            )
        return True

    @_retry_on_busy
    def get_keywords(self) -> List[Tuple[str, str]]:
        """Returns a list of all search keywords as (keyword, type)."""
        with sqlite3.connect(self.db_path) as conn:
            return [(row[0], row[1]) for row in conn.execute("SELECT keyword, type FROM search_keywords")]

    @_retry_on_busy
    def remove_keyword(self, keyword: str) -> bool:
        """Removes a keyword from the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM search_keywords WHERE keyword = ?", (keyword,))
        return True

    @_retry_on_busy
    def get_active_seeds(self) -> List[str]:
        """Returns a list of active URLs to scan."""
        with sqlite3.connect(self.db_path) as conn:
            seeds = [row[0] for row in conn.execute("SELECT url FROM seed_list WHERE is_active = 1 ORDER BY last_checked ASC")]
        return seeds

    @_retry_on_busy
    def update_seed_status(self, url: str, success: bool):
        """Updates failure count or resets it on success."""
        with sqlite3.connect(self.db_path) as conn:
            if success:
                conn.execute("UPDATE seed_list SET failure_count = 0, last_checked = CURRENT_TIMESTAMP, is_active = 1 WHERE url = ?", (url,))
            else:
                conn.execute("UPDATE seed_list SET failure_count = failure_count + 1, last_checked = CURRENT_TIMESTAMP WHERE url = ?", (url,))
                # 3-Strikes Rule (Soft Delete)
                conn.execute("UPDATE seed_list SET is_active = 0 WHERE failure_count >= ? AND url = ?", (config.MAX_FAILURES, url))

    @_retry_on_busy
    def save_match(self, url: str, keyword_contexts: dict):
        """Log findings to the database.
        
        Uses INSERT OR IGNORE so duplicate (url, keyword) pairs across scan
        cycles are silently skipped instead of inflating match counts.
        
        Args:
            url: The page URL where matches were found.
            keyword_contexts: Dict mapping each matched keyword to a short
                              context snippet extracted from around the match.
        """
        data = [(url, kw, ctx) for kw, ctx in keyword_contexts.items()]
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO matches (url, keyword, context) VALUES (?, ?, ?)",
                data
            )

    @_retry_on_busy
    def get_all_matches(self) -> List[Tuple]:
        """Returns all matches from the database, ordered by newest first.
        
        Returns tuples of (id, url, keyword, context, timestamp).
        """
        with sqlite3.connect(self.db_path) as conn:
            return list(conn.execute(
                "SELECT id, url, keyword, context, timestamp FROM matches ORDER BY timestamp DESC"
            ))

    @_retry_on_busy
    def get_keyword_hit_rates(self) -> List[Tuple]:
        """Returns per-keyword hit counts alongside total seeds checked.
        
        Returns list of (keyword, type, hits, hit_rate_pct) tuples.
        """
        with sqlite3.connect(self.db_path) as conn:
            seeds_checked = conn.execute(
                "SELECT COUNT(*) FROM seed_list WHERE last_checked IS NOT NULL"
            ).fetchone()[0] or 1  # avoid div-by-zero

            rows = conn.execute("""
                SELECT sk.keyword, sk.type, COUNT(m.id) AS hits
                FROM search_keywords sk
                LEFT JOIN matches m ON m.keyword = sk.keyword
                                   OR m.keyword = 'REGEX:' || sk.keyword
                GROUP BY sk.keyword, sk.type
                ORDER BY hits DESC
            """).fetchall()

            return [
                (kw, ktype, hits, round(hits / seeds_checked * 100, 3))
                for kw, ktype, hits in rows
            ]
