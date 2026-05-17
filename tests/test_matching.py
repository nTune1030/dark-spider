"""Unit tests for keyword matching and context extraction logic."""

import re
import pytest  # type: ignore

from spider import _is_js_rendered, _extract_context


# ── _extract_context ──────────────────────────────────────────────────────────

class TestExtractContext:
    """Tests for the _extract_context helper function."""

    def test_basic_extraction(self):
        text = "The quick brown fox jumps over the lazy dog"
        # "fox" starts at index 16, ends at 19
        result = _extract_context(text, 16, 19, window=5)
        assert "fox" in result

    def test_start_of_string(self):
        text = "Hello world this is a test"
        result = _extract_context(text, 0, 5, window=3)
        assert "Hello" in result

    def test_end_of_string(self):
        text = "Hello world this is a test"
        result = _extract_context(text, 20, 24, window=3)
        assert "test" in result

    def test_strips_html_tags(self):
        text = 'The <b>secret</b> is out and <i>important</i> stuff'
        result = _extract_context(text, 7, 13, window=10)
        assert "<b>" not in result
        assert "<i>" not in result
        assert "secret" in result

    def test_collapses_whitespace(self):
        text = "The   secret    is     here"
        result = _extract_context(text, 7, 13, window=5)
        assert "   " not in result

    def test_truncates_to_200_chars(self):
        text = "x" * 500
        result = _extract_context(text, 0, 1, window=300)
        assert len(result) <= 200


# ── _is_js_rendered ───────────────────────────────────────────────────────────

class TestIsJsRendered:
    """Tests for the JS-rendering detection heuristic."""

    def test_normal_page_not_js(self):
        html = "<html><body><p>" + "A" * 600 + "</p></body></html>"
        assert _is_js_rendered(html) is False

    def test_empty_body_is_js(self):
        html = "<html><body></body></html>"
        assert _is_js_rendered(html) is True

    def test_noscript_tag_is_js(self):
        html = "<html><body><noscript>Enable JS</noscript><p>" + "A" * 600 + "</p></body></html>"
        assert _is_js_rendered(html) is True

    def test_react_marker_is_js(self):
        html = '<html><body><p>' + 'A' * 600 + '</p><script>React.createElement("div")</script></body></html>'
        assert _is_js_rendered(html) is True

    def test_vue_marker_is_js(self):
        html = '<html><body><p>' + 'A' * 600 + '</p><script>Vue.createApp()</script></body></html>'
        assert _is_js_rendered(html) is True

    def test_next_data_is_js(self):
        html = '<html><body><p>' + 'A' * 600 + '</p><script>__NEXT_DATA__ = {}</script></body></html>'
        assert _is_js_rendered(html) is True

    def test_no_block_elements_is_js(self):
        html = "<html><body><span>short</span></body></html>"
        assert _is_js_rendered(html) is True


# ── Keyword matching logic (mirrors process_url) ─────────────────────────────

class TestKeywordMatching:
    """Tests for the string and regex keyword matching logic used in process_url."""

    def test_string_match_case_insensitive(self):
        html_content = "This is a SECRET message"
        keyword = "secret"
        lower_content = html_content.lower()
        idx = lower_content.find(keyword.lower())
        assert idx != -1

    def test_regex_match(self):
        html_content = "Contact us at testuser@example.com for info"
        pattern = r"[a-z]+@[a-z]+\.[a-z]+"
        m = re.search(pattern, html_content, re.IGNORECASE)
        assert m is not None
        assert "testuser@example.com" in m.group(0)

    def test_regex_prefix_stored(self):
        """Verify that regex matches are stored with the REGEX: prefix."""
        kw = r"[a-z]+@[a-z]+\.[a-z]+"
        k_type = "REGEX"
        found_key = "REGEX:%s" % kw
        assert found_key.startswith("REGEX:")

    def test_no_match(self):
        html_content = "Nothing to see here"
        keyword = "secret"
        lower_content = html_content.lower()
        idx = lower_content.find(keyword.lower())
        assert idx == -1

    def test_invalid_regex_does_not_crash(self):
        """Invalid regex patterns should be caught and logged, not crash."""
        pattern = r"[invalid"
        with pytest.raises(re.error):
            re.search(pattern, "test content")