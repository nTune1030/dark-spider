"""Unit tests for DatabaseManager using an in-memory SQLite database."""

import os
import pytest  # type: ignore
from core.db_manager import DatabaseManager


@pytest.fixture
def db(tmp_path):
    """Create a fresh DatabaseManager with a temporary database file."""
    db_path = str(tmp_path / "test.db")
    manager = DatabaseManager(db_path)
    yield manager
    # Cleanup
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


class TestDatabaseManager:
    """Tests for DatabaseManager CRUD operations."""

    def test_init_creates_tables(self, db):
        """DatabaseManager.__init__ should create all required tables."""
        # If we got here without error, tables were created
        keywords = db.get_keywords()
        assert keywords == []

    def test_add_and_get_keywords(self, db):
        db.add_keyword("secret", "STRING")
        db.add_keyword(r"[a-z]+@[a-z]+\.[a-z]+", "REGEX")
        keywords = db.get_keywords()
        assert len(keywords) == 2
        types = {kw: kt for kw, kt in keywords}
        assert "secret" in types
        assert types["secret"] == "STRING"

    def test_add_duplicate_keyword_ignored(self, db):
        db.add_keyword("secret", "STRING")
        db.add_keyword("secret", "STRING")  # duplicate
        keywords = db.get_keywords()
        assert len(keywords) == 1

    def test_remove_keyword(self, db):
        db.add_keyword("secret", "STRING")
        assert db.remove_keyword("secret") is True
        keywords = db.get_keywords()
        assert len(keywords) == 0

    def test_add_seeds(self, db):
        urls = ["http://abc56charsonionaddress1234567890abcdef1234567890abcdef12.onion",
                "http://xyz56charsonionaddress1234567890abcdef1234567890abcdef12.onion"]
        count = db.add_seeds(urls)
        assert count == 2

    def test_add_duplicate_seeds_ignored(self, db):
        url = "http://abc56charsonionaddress1234567890abcdef1234567890abcdef12.onion"
        db.add_seeds([url])
        count = db.add_seeds([url])  # duplicate
        assert count == 0

    def test_get_active_seeds(self, db):
        url = "http://abc56charsonionaddress1234567890abcdef1234567890abcdef12.onion"
        db.add_seeds([url])
        seeds = db.get_active_seeds()
        assert url in seeds

    def test_update_seed_status_success(self, db):
        url = "http://abc56charsonionaddress1234567890abcdef1234567890abcdef12.onion"
        db.add_seeds([url])
        db.update_seed_status(url, success=True)
        seeds = db.get_active_seeds()
        assert url in seeds

    def test_update_seed_status_failure_deactivates(self, db):
        url = "http://abc56charsonionaddress1234567890abcdef1234567890abcdef12.onion"
        db.add_seeds([url])
        # MAX_FAILURES defaults to 3
        db.update_seed_status(url, success=False)
        db.update_seed_status(url, success=False)
        db.update_seed_status(url, success=False)
        seeds = db.get_active_seeds()
        assert url not in seeds

    def test_save_match(self, db):
        url = "http://abc56charsonionaddress1234567890abcdef1234567890abcdef12.onion"
        db.save_match(url, {"secret": "this is a secret message"})
        matches = db.get_all_matches()
        assert len(matches) == 1
        assert matches[0][1] == url  # url column
        assert matches[0][2] == "secret"  # keyword column

    def test_save_match_deduplication(self, db):
        url = "http://abc56charsonionaddress1234567890abcdef1234567890abcdef12.onion"
        db.save_match(url, {"secret": "context 1"})
        db.save_match(url, {"secret": "context 2"})  # same url+keyword — should be ignored
        matches = db.get_all_matches()
        assert len(matches) == 1

    def test_get_keyword_hit_rates(self, db):
        db.add_keyword("secret", "STRING")
        url = "http://abc56charsonionaddress1234567890abcdef1234567890abcdef12.onion"
        db.add_seeds([url])
        db.update_seed_status(url, success=True)
        db.save_match(url, {"secret": "found a secret"})
        rates = db.get_keyword_hit_rates()
        assert len(rates) == 1
        kw, ktype, hits, rate = rates[0]
        assert kw == "secret"
        assert hits == 1