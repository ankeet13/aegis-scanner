"""
AEGIS Scanner — Tests for Response Analyzer
Tests the core detection engine that compares baseline vs attack responses.
Covers error pattern matching, status change detection, length differentials,
timing analysis, similarity checks, and BAC vulnerability detection.

Usage:
    pytest tests/test_response_analyzer.py -v
"""

import pytest
from unittest.mock import MagicMock
from backend.utils.response_analyzer import ResponseAnalyzer


# ---------------------------------------------------------------------------
# Helper — create a mock Response object
# ---------------------------------------------------------------------------
def make_response(status_code=200, body="", elapsed_ms=100.0, headers=None):
    """Create a mock Response object matching http_client.Response interface."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.body = body
    resp.body_length = len(body) if body else 0
    resp.elapsed_ms = elapsed_ms
    resp.headers = headers or {}
    resp.error = None
    return resp


class TestCheckErrorPatterns:
    """Tests for error-based SQL injection detection."""

    def test_detects_mysql_error(self):
        resp = make_response(body="You have an error in your SQL syntax near 'test'")
        matches = ResponseAnalyzer.check_error_patterns(resp)
        assert len(matches) > 0
        assert any("sql syntax" in m for m in matches)

    def test_detects_sqlite_error(self):
        resp = make_response(body="sqlite3.OperationalError: unrecognized token")
        matches = ResponseAnalyzer.check_error_patterns(resp)
        assert len(matches) > 0

    def test_detects_postgresql_error(self):
        resp = make_response(body="ERROR: unterminated quoted string at position 42")
        matches = ResponseAnalyzer.check_error_patterns(resp)
        assert len(matches) > 0

    def test_detects_oracle_error(self):
        resp = make_response(body="ORA-01756: quoted string not properly terminated")
        matches = ResponseAnalyzer.check_error_patterns(resp)
        assert len(matches) > 0

    def test_detects_mssql_error(self):
        resp = make_response(body="Microsoft SQL Native Client Error '80040e14'")
        matches = ResponseAnalyzer.check_error_patterns(resp)
        assert len(matches) > 0

    def test_no_match_on_clean_response(self):
        resp = make_response(body="<html><body>Welcome to our website</body></html>")
        matches = ResponseAnalyzer.check_error_patterns(resp)
        assert len(matches) == 0

    def test_no_match_on_empty_body(self):
        resp = make_response(body="")
        matches = ResponseAnalyzer.check_error_patterns(resp)
        assert len(matches) == 0

    def test_case_insensitive_matching(self):
        resp = make_response(body="YOU HAVE AN ERROR IN YOUR SQL SYNTAX")
        matches = ResponseAnalyzer.check_error_patterns(resp)
        assert len(matches) > 0

    def test_custom_patterns(self):
        resp = make_response(body="custom database error occurred")
        custom_patterns = [r"custom database error"]
        matches = ResponseAnalyzer.check_error_patterns(resp, patterns=custom_patterns)
        assert len(matches) == 1


class TestCheckStatusChange:
    """Tests for HTTP status code change detection."""

    def test_detects_server_error(self):
        baseline = make_response(status_code=200)
        attack = make_response(status_code=500)
        result = ResponseAnalyzer.check_status_change(baseline, attack)
        assert result is not None
        assert result["type"] == "server_error"
        assert result["baseline_status"] == 200
        assert result["attack_status"] == 500

    def test_detects_auth_bypass(self):
        baseline = make_response(status_code=403)
        attack = make_response(status_code=200)
        result = ResponseAnalyzer.check_status_change(baseline, attack)
        assert result is not None
        assert result["type"] == "auth_bypass"

    def test_detects_redirect(self):
        baseline = make_response(status_code=200)
        attack = make_response(status_code=302)
        result = ResponseAnalyzer.check_status_change(baseline, attack)
        assert result is not None
        assert result["type"] == "redirect"

    def test_no_change_returns_none(self):
        baseline = make_response(status_code=200)
        attack = make_response(status_code=200)
        result = ResponseAnalyzer.check_status_change(baseline, attack)
        assert result is None

    def test_401_to_200_is_auth_bypass(self):
        baseline = make_response(status_code=401)
        attack = make_response(status_code=200)
        result = ResponseAnalyzer.check_status_change(baseline, attack)
        assert result["type"] == "auth_bypass"


class TestCheckLengthDifferential:
    """Tests for response body length comparison."""

    def test_significant_length_decrease(self):
        baseline = make_response(body="A" * 1000)
        attack = make_response(body="A" * 100)
        result = ResponseAnalyzer.check_length_differential(baseline, attack)
        assert result["significant"] is True
        assert result["ratio"] < 0.6

    def test_significant_length_increase(self):
        baseline = make_response(body="A" * 100)
        attack = make_response(body="A" * 1000)
        result = ResponseAnalyzer.check_length_differential(baseline, attack)
        assert result["significant"] is True

    def test_similar_lengths_not_significant(self):
        baseline = make_response(body="A" * 1000)
        attack = make_response(body="A" * 950)
        result = ResponseAnalyzer.check_length_differential(baseline, attack)
        assert result["significant"] is False

    def test_identical_lengths(self):
        baseline = make_response(body="A" * 500)
        attack = make_response(body="B" * 500)
        result = ResponseAnalyzer.check_length_differential(baseline, attack)
        assert result["significant"] is False
        assert result["ratio"] == 1.0

    def test_empty_baseline(self):
        baseline = make_response(body="")
        attack = make_response(body="A" * 100)
        result = ResponseAnalyzer.check_length_differential(baseline, attack)
        assert result["significant"] is False


class TestCheckTimeDifferential:
    """Tests for time-based blind injection detection."""

    def test_significant_delay_is_suspicious(self):
        baseline = make_response(elapsed_ms=100.0)
        attack = make_response(elapsed_ms=5500.0)
        result = ResponseAnalyzer.check_time_differential(baseline, attack)
        assert result["suspicious"] is True
        assert result["differential_seconds"] > 4.5

    def test_normal_timing_not_suspicious(self):
        baseline = make_response(elapsed_ms=100.0)
        attack = make_response(elapsed_ms=200.0)
        result = ResponseAnalyzer.check_time_differential(baseline, attack)
        assert result["suspicious"] is False

    def test_faster_response_not_suspicious(self):
        baseline = make_response(elapsed_ms=500.0)
        attack = make_response(elapsed_ms=100.0)
        result = ResponseAnalyzer.check_time_differential(baseline, attack)
        assert result["suspicious"] is False

    def test_exact_threshold_boundary(self):
        # 4.5s threshold — attack is exactly 4600ms slower
        baseline = make_response(elapsed_ms=100.0)
        attack = make_response(elapsed_ms=4700.0)
        result = ResponseAnalyzer.check_time_differential(baseline, attack)
        assert result["suspicious"] is True


class TestCheckSimilarity:
    """Tests for content similarity comparison (BAC scanner)."""

    def test_identical_responses(self):
        resp_a = make_response(body="<html>Identical content</html>")
        resp_b = make_response(body="<html>Identical content</html>")
        ratio = ResponseAnalyzer.check_similarity(resp_a, resp_b)
        assert ratio == 1.0

    def test_completely_different_responses(self):
        resp_a = make_response(body="AAAAAAAAAA" * 100)
        resp_b = make_response(body="ZZZZZZZZZZ" * 100)
        ratio = ResponseAnalyzer.check_similarity(resp_a, resp_b)
        assert ratio < 0.3

    def test_partially_similar_responses(self):
        resp_a = make_response(body="<html><body>Welcome admin</body></html>")
        resp_b = make_response(body="<html><body>Welcome guest</body></html>")
        ratio = ResponseAnalyzer.check_similarity(resp_a, resp_b)
        assert 0.5 < ratio < 1.0

    def test_both_empty(self):
        resp_a = make_response(body="")
        resp_b = make_response(body="")
        ratio = ResponseAnalyzer.check_similarity(resp_a, resp_b)
        assert ratio == 1.0

    def test_one_empty(self):
        resp_a = make_response(body="Some content")
        resp_b = make_response(body="")
        ratio = ResponseAnalyzer.check_similarity(resp_a, resp_b)
        assert ratio == 0.0


class TestCheckBACVulnerability:
    """Tests for broken access control detection logic."""

    def test_blocked_with_401(self):
        auth = make_response(status_code=200, body="<html>Admin panel</html>")
        unauth = make_response(status_code=401, body="Unauthorized")
        result = ResponseAnalyzer.check_bac_vulnerability(auth, unauth)
        assert result["vulnerable"] is False
        assert result["reason"] == "properly_blocked"

    def test_blocked_with_403(self):
        auth = make_response(status_code=200, body="<html>Admin panel</html>")
        unauth = make_response(status_code=403, body="Forbidden")
        result = ResponseAnalyzer.check_bac_vulnerability(auth, unauth)
        assert result["vulnerable"] is False
        assert result["reason"] == "properly_blocked"

    def test_redirected_to_login(self):
        auth = make_response(status_code=200, body="Dashboard")
        unauth = make_response(status_code=302, body="")
        result = ResponseAnalyzer.check_bac_vulnerability(auth, unauth)
        assert result["vulnerable"] is False
        assert result["reason"] == "redirected_to_login"

    def test_vulnerable_same_content(self):
        content = "<html><body>Sensitive admin data here</body></html>"
        auth = make_response(status_code=200, body=content)
        unauth = make_response(status_code=200, body=content)
        result = ResponseAnalyzer.check_bac_vulnerability(auth, unauth)
        assert result["vulnerable"] is True
        assert result["similarity"] > 0.85

    def test_different_content_not_vulnerable(self):
        auth = make_response(
            status_code=200,
            body="<html>Admin panel with sensitive data and user lists</html>"
        )
        unauth = make_response(
            status_code=200,
            body="<html>Public homepage with marketing content only</html>"
        )
        result = ResponseAnalyzer.check_bac_vulnerability(auth, unauth)
        # Similarity will be low since content is very different
        assert result["reason"] == "different_content"


class TestCheckContentContains:
    """Tests for keyword detection in responses."""

    def test_finds_keywords(self):
        resp = make_response(body="Welcome to the dashboard! Click logout to exit.")
        keywords = ["dashboard", "logout", "welcome"]
        found = ResponseAnalyzer.check_content_contains(resp, keywords)
        assert "dashboard" in found
        assert "logout" in found
        assert "welcome" in found

    def test_no_keywords_found(self):
        resp = make_response(body="Invalid username or password")
        keywords = ["dashboard", "welcome", "logout"]
        found = ResponseAnalyzer.check_content_contains(resp, keywords)
        assert len(found) == 0

    def test_case_insensitive(self):
        resp = make_response(body="WELCOME TO THE DASHBOARD")
        keywords = ["welcome", "dashboard"]
        found = ResponseAnalyzer.check_content_contains(resp, keywords)
        assert len(found) == 2

    def test_empty_body(self):
        resp = make_response(body="")
        keywords = ["test"]
        found = ResponseAnalyzer.check_content_contains(resp, keywords)
        assert len(found) == 0


class TestCheckHeaders:
    """Tests for header inspection methods."""

    def test_header_exists(self):
        resp = make_response(headers={"Content-Security-Policy": "default-src 'self'"})
        assert ResponseAnalyzer.check_header_exists(resp, "Content-Security-Policy") is True

    def test_header_not_exists(self):
        resp = make_response(headers={"Server": "nginx"})
        assert ResponseAnalyzer.check_header_exists(resp, "Content-Security-Policy") is False

    def test_header_case_insensitive(self):
        resp = make_response(headers={"content-security-policy": "default-src 'self'"})
        assert ResponseAnalyzer.check_header_exists(resp, "Content-Security-Policy") is True

    def test_get_header_value(self):
        resp = make_response(headers={"Server": "nginx/1.18.0"})
        value = ResponseAnalyzer.get_header_value(resp, "Server")
        assert value == "nginx/1.18.0"

    def test_get_missing_header_value(self):
        resp = make_response(headers={})
        value = ResponseAnalyzer.get_header_value(resp, "Server")
        assert value is None