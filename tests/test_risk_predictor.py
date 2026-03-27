# Author: Aayush — ML Pipeline Tests

"""
AEGIS Scanner — Tests for ML Pipeline
Tests feature extraction, risk prediction, and the rule-based fallback.

Usage:
    pytest tests/test_risk_predictor.py -v
"""

import pytest
from backend.ml.feature_extractor import (
    extract_features,
    features_to_vector,
    features_to_dataframe_row,
    summarise_features,
    FEATURE_COLUMNS,
)
from backend.ml.risk_predictor import RiskPredictor


# ---------------------------------------------------------------------------
# Sample findings for testing
# ---------------------------------------------------------------------------
EMPTY_FINDINGS = []

SAFE_FINDINGS = [
    {
        "vuln_type": "Security Misconfiguration (Missing Header)",
        "severity": "Low",
        "url": "http://example.com",
        "parameter": "Referrer-Policy",
        "evidence": "Missing header",
        "confidence": "Confirmed",
        "details": {},
    },
]

MEDIUM_FINDINGS = [
    {
        "vuln_type": "Security Misconfiguration (Missing Header)",
        "severity": "High",
        "url": "http://example.com",
        "parameter": "Content-Security-Policy",
        "evidence": "Missing CSP",
        "confidence": "Confirmed",
        "details": {},
    },
    {
        "vuln_type": "Security Misconfiguration (Missing Header)",
        "severity": "Medium",
        "url": "http://example.com",
        "parameter": "X-Frame-Options",
        "evidence": "Missing header",
        "confidence": "Confirmed",
        "details": {},
    },
    {
        "vuln_type": "Authentication Failure (Missing Rate Limiting)",
        "severity": "Medium",
        "url": "http://example.com/login",
        "parameter": "username, password",
        "evidence": "No rate limiting",
        "confidence": "Confirmed",
        "details": {},
    },
    {
        "vuln_type": "Security Misconfiguration (Information Disclosure)",
        "severity": "Low",
        "url": "http://example.com",
        "parameter": "Server",
        "evidence": "Server: nginx/1.18",
        "confidence": "Confirmed",
        "details": {},
    },
]

CRITICAL_FINDINGS = [
    {
        "vuln_type": "SQL Injection (Error-Based)",
        "severity": "Critical",
        "url": "http://example.com/search",
        "parameter": "q",
        "payload": "' OR 1=1--",
        "evidence": "MySQL error detected",
        "confidence": "Confirmed",
        "details": {},
    },
    {
        "vuln_type": "SQL Injection (Boolean-Blind)",
        "severity": "High",
        "url": "http://example.com/search",
        "parameter": "q",
        "payload": "AND 1=1|||AND 1=2",
        "evidence": "TRUE/FALSE differential",
        "confidence": "Confirmed",
        "details": {},
    },
    {
        "vuln_type": "SQL Injection (Time-Based Blind)",
        "severity": "Critical",
        "url": "http://example.com/api/search",
        "parameter": "q",
        "payload": "'; WAITFOR DELAY '0:0:5'--",
        "evidence": "Response delayed 5.2s",
        "confidence": "Confirmed",
        "details": {},
    },
    {
        "vuln_type": "Broken Access Control (Unauthenticated Access)",
        "severity": "Critical",
        "url": "http://example.com/api/users",
        "parameter": "N/A",
        "evidence": "Unauth access returned same content",
        "confidence": "Confirmed",
        "details": {},
    },
    {
        "vuln_type": "Broken Access Control (IDOR)",
        "severity": "High",
        "url": "http://example.com/api/users/1",
        "parameter": "user_id",
        "payload": "2",
        "evidence": "Different user data returned",
        "confidence": "Tentative",
        "details": {},
    },
    {
        "vuln_type": "Authentication Failure (Weak Credentials)",
        "severity": "Critical",
        "url": "http://example.com/login",
        "parameter": "username, password",
        "payload": "admin:admin",
        "evidence": "Login succeeded",
        "confidence": "Confirmed",
        "details": {},
    },
    {
        "vuln_type": "Authentication Failure (Missing Rate Limiting)",
        "severity": "Medium",
        "url": "http://example.com/login",
        "parameter": "username, password",
        "evidence": "10 attempts without lockout",
        "confidence": "Confirmed",
        "details": {},
    },
    {
        "vuln_type": "Security Misconfiguration (Missing Header)",
        "severity": "High",
        "url": "http://example.com",
        "parameter": "Content-Security-Policy",
        "evidence": "Missing CSP",
        "confidence": "Confirmed",
        "details": {},
    },
    {
        "vuln_type": "Security Misconfiguration (Exposed Sensitive File)",
        "severity": "Critical",
        "url": "http://example.com/.env",
        "parameter": "/.env",
        "evidence": "DB_PASSWORD exposed",
        "confidence": "Confirmed",
        "details": {"path": "/.env"},
    },
    {
        "vuln_type": "Security Misconfiguration (Exposed Sensitive File)",
        "severity": "High",
        "url": "http://example.com/.git/HEAD",
        "parameter": "/.git/HEAD",
        "evidence": "Git metadata exposed",
        "confidence": "Confirmed",
        "details": {"path": "/.git/HEAD"},
    },
    {
        "vuln_type": "Security Misconfiguration (Information Disclosure)",
        "severity": "Low",
        "url": "http://example.com",
        "parameter": "Server",
        "evidence": "Server: Werkzeug/3.0.1",
        "confidence": "Confirmed",
        "details": {},
    },
    {
        "vuln_type": "Security Misconfiguration (Verbose Error Page)",
        "severity": "Medium",
        "url": "http://example.com/nonexistent",
        "parameter": "N/A",
        "evidence": "Python stack trace detected",
        "confidence": "Confirmed",
        "details": {},
    },
]


# ---------------------------------------------------------------------------
# Feature Extraction Tests
# ---------------------------------------------------------------------------
class TestFeatureExtraction:
    """Tests for converting findings to feature vectors."""

    def test_empty_findings(self):
        features = extract_features(EMPTY_FINDINGS)
        assert features["total_findings"] == 0
        assert features["weighted_risk_score"] == 0
        assert features["has_confirmed_sqli"] == 0
        assert features["num_critical"] == 0

    def test_safe_findings_features(self):
        features = extract_features(SAFE_FINDINGS)
        assert features["total_findings"] == 1
        assert features["num_misconfig_findings"] == 1
        assert features["num_low"] == 1
        assert features["missing_headers_count"] == 1
        assert features["has_confirmed_sqli"] == 0

    def test_critical_findings_features(self):
        features = extract_features(CRITICAL_FINDINGS)
        assert features["num_sqli_findings"] == 3
        assert features["num_bac_findings"] == 2
        assert features["num_auth_findings"] == 2
        assert features["num_misconfig_findings"] >= 4
        assert features["has_confirmed_sqli"] == 1
        assert features["has_blind_sqli"] == 1
        assert features["has_time_based_sqli"] == 1
        assert features["has_unauth_access"] == 1
        assert features["has_idor"] == 1
        assert features["has_weak_credentials"] == 1
        assert features["has_missing_rate_limit"] == 1
        assert features["has_exposed_env"] == 1
        assert features["has_exposed_git"] == 1
        assert features["has_info_disclosure"] == 1
        assert features["has_verbose_errors"] == 1
        assert features["num_critical"] >= 4
        assert features["total_findings"] > 10
        assert features["weighted_risk_score"] > 50

    def test_severity_counts(self):
        features = extract_features(CRITICAL_FINDINGS)
        total_severity = (
            features["num_critical"]
            + features["num_high"]
            + features["num_medium"]
            + features["num_low"]
        )
        assert total_severity == len(CRITICAL_FINDINGS)

    def test_weighted_score_calculation(self):
        features = extract_features(CRITICAL_FINDINGS)
        expected = (
            features["num_critical"] * 10
            + features["num_high"] * 7
            + features["num_medium"] * 4
            + features["num_low"] * 2
        )
        assert features["weighted_risk_score"] == expected

    def test_feature_vector_length(self):
        features = extract_features(CRITICAL_FINDINGS)
        vector = features_to_vector(features)
        assert len(vector) == len(FEATURE_COLUMNS)

    def test_feature_vector_order(self):
        features = extract_features(SAFE_FINDINGS)
        vector = features_to_vector(features)
        # First element should be num_sqli_findings (0 for safe)
        assert vector[0] == 0
        # total_findings is second to last
        assert vector[-2] == features["total_findings"]
        # weighted_risk_score is last
        assert vector[-1] == features["weighted_risk_score"]

    def test_dataframe_row_shape(self):
        features = extract_features(MEDIUM_FINDINGS)
        df = features_to_dataframe_row(features)
        assert df.shape == (1, len(FEATURE_COLUMNS))
        assert list(df.columns) == FEATURE_COLUMNS

    def test_feature_summary(self):
        features = extract_features(CRITICAL_FINDINGS)
        summary = summarise_features(features)
        assert "total_findings" in summary
        assert "findings_by_category" in summary
        assert "findings_by_severity" in summary
        assert "key_flags" in summary
        assert summary["key_flags"]["confirmed_sqli"] is True
        assert summary["key_flags"]["weak_credentials"] is True


# ---------------------------------------------------------------------------
# Risk Predictor Tests
# ---------------------------------------------------------------------------
class TestRiskPredictor:
    """Tests for the risk prediction pipeline."""

    @pytest.fixture
    def predictor(self):
        """Create a RiskPredictor (uses rule-based fallback if model not trained)."""
        return RiskPredictor()

    def test_predict_returns_required_keys(self, predictor):
        result = predictor.predict(MEDIUM_FINDINGS)
        assert "risk_level" in result
        assert "confidence" in result
        assert "probabilities" in result
        assert "features_summary" in result
        assert "features_raw" in result

    def test_predict_empty_findings_is_safe(self, predictor):
        result = predictor.predict(EMPTY_FINDINGS)
        assert result["risk_level"] == "Safe"
        assert result["confidence"] > 0.5

    def test_predict_critical_findings_is_high_or_critical(self, predictor):
        result = predictor.predict(CRITICAL_FINDINGS)
        assert result["risk_level"] in ("High", "Critical")
        assert result["confidence"] > 0.5

    def test_predict_safe_findings_is_safe_or_low(self, predictor):
        result = predictor.predict(SAFE_FINDINGS)
        assert result["risk_level"] in ("Safe", "Low")

    def test_probabilities_sum_to_one(self, predictor):
        result = predictor.predict(MEDIUM_FINDINGS)
        total = sum(result["probabilities"].values())
        assert abs(total - 1.0) < 0.05  # Allow small floating point variance

    def test_probabilities_contain_all_levels(self, predictor):
        result = predictor.predict(MEDIUM_FINDINGS)
        expected_levels = {"Safe", "Low", "Medium", "High", "Critical"}
        assert set(result["probabilities"].keys()) == expected_levels

    def test_confidence_is_between_0_and_1(self, predictor):
        result = predictor.predict(CRITICAL_FINDINGS)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_features_raw_matches_extraction(self, predictor):
        result = predictor.predict(CRITICAL_FINDINGS)
        features = extract_features(CRITICAL_FINDINGS)
        assert result["features_raw"]["total_findings"] == features["total_findings"]
        assert result["features_raw"]["num_sqli_findings"] == features["num_sqli_findings"]

    def test_model_info(self, predictor):
        info = predictor.get_model_info()
        assert "model_loaded" in info
        assert "risk_levels" in info
        assert len(info["risk_levels"]) == 5


# ---------------------------------------------------------------------------
# Rule-Based Fallback Tests
# ---------------------------------------------------------------------------
class TestRuleBasedFallback:
    """Tests for the rule-based prediction when no ML model is available."""

    @pytest.fixture
    def fallback_predictor(self):
        """Create a predictor with a deliberately wrong model path to force fallback."""
        return RiskPredictor(
            model_path="/nonexistent/model.pkl",
            encoder_path="/nonexistent/encoder.pkl",
        )

    def test_fallback_activates(self, fallback_predictor):
        assert fallback_predictor.is_loaded() is False

    def test_fallback_empty_is_safe(self, fallback_predictor):
        result = fallback_predictor.predict(EMPTY_FINDINGS)
        assert result["risk_level"] == "Safe"
        assert "note" in result  # Fallback adds a note

    def test_fallback_critical_findings(self, fallback_predictor):
        result = fallback_predictor.predict(CRITICAL_FINDINGS)
        assert result["risk_level"] in ("High", "Critical")

    def test_fallback_has_probabilities(self, fallback_predictor):
        result = fallback_predictor.predict(MEDIUM_FINDINGS)
        assert "probabilities" in result
        assert len(result["probabilities"]) == 5

    def test_fallback_confidence_reasonable(self, fallback_predictor):
        result = fallback_predictor.predict(SAFE_FINDINGS)
        assert 0.5 <= result["confidence"] <= 1.0