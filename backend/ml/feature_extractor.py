"""
AEGIS Scanner — Feature Extractor
Converts raw scan findings from all four scanners into a numeric feature
vector that the trained Random Forest model can consume.

This is the bridge between the scanners and the ML model:
    Scanner findings (list of Finding dicts)
        → Feature Extractor
            → 23-element numeric vector
                → Random Forest
                    → Risk Level prediction

The feature columns MUST match exactly what synthetic_data.py produces,
otherwise the model will receive misaligned input.
"""

import logging
from backend.config import SEVERITY_WEIGHTS

logger = logging.getLogger(__name__)

# Feature column order — must match synthetic_data.FEATURE_COLUMNS exactly
FEATURE_COLUMNS = [
    "num_sqli_findings",
    "num_bac_findings",
    "num_auth_findings",
    "num_misconfig_findings",
    "num_critical",
    "num_high",
    "num_medium",
    "num_low",
    "has_confirmed_sqli",
    "has_blind_sqli",
    "has_time_based_sqli",
    "has_unauth_access",
    "has_idor",
    "has_weak_credentials",
    "has_missing_rate_limit",
    "missing_headers_count",
    "exposed_files_count",
    "has_info_disclosure",
    "has_verbose_errors",
    "has_exposed_env",
    "has_exposed_git",
    "total_findings",
    "weighted_risk_score",
]


def extract_features(findings):
    """
    Convert a list of Finding dicts into a feature vector.

    Args:
        findings: list of dicts, each with keys like:
            vuln_type, severity, confidence, url, parameter, details, etc.
            (These come from Finding.to_dict() across all four scanners)

    Returns:
        dict mapping feature name → numeric value
    """
    features = {col: 0 for col in FEATURE_COLUMNS}

    for finding in findings:
        vuln_type = finding.get("vuln_type", "").lower()
        severity = finding.get("severity", "Info")
        details = finding.get("details", {})

        # ----- Category counts -----
        if "sql injection" in vuln_type:
            features["num_sqli_findings"] += 1
        elif "broken access control" in vuln_type or "bac" in vuln_type:
            features["num_bac_findings"] += 1
        elif "authentication" in vuln_type:
            features["num_auth_findings"] += 1
        elif "misconfiguration" in vuln_type or "misconfig" in vuln_type:
            features["num_misconfig_findings"] += 1

        # ----- Severity counts -----
        severity_key = f"num_{severity.lower()}"
        if severity_key in features:
            features[severity_key] += 1

        # ----- Boolean flags: SQLi subtypes -----
        if "error-based" in vuln_type and "sql injection" in vuln_type:
            features["has_confirmed_sqli"] = 1
        if "boolean-blind" in vuln_type and "sql injection" in vuln_type:
            features["has_blind_sqli"] = 1
        if "time-based" in vuln_type and "sql injection" in vuln_type:
            features["has_time_based_sqli"] = 1

        # ----- Boolean flags: BAC subtypes -----
        if "unauthenticated access" in vuln_type:
            features["has_unauth_access"] = 1
        if "idor" in vuln_type:
            features["has_idor"] = 1

        # ----- Boolean flags: Auth subtypes -----
        if "weak credentials" in vuln_type:
            features["has_weak_credentials"] = 1
        if "rate limiting" in vuln_type or "missing rate" in vuln_type:
            features["has_missing_rate_limit"] = 1

        # ----- Boolean flags: Misconfig subtypes -----
        if "missing header" in vuln_type:
            features["missing_headers_count"] += 1
            # Undo the +1 from num_misconfig above for header count
            # (missing_headers_count tracks headers separately)

        if "exposed sensitive file" in vuln_type or "exposed file" in vuln_type:
            features["exposed_files_count"] += 1

            # Check for specific high-value exposed files
            path = details.get("path", "")
            if ".env" in path:
                features["has_exposed_env"] = 1
            if ".git" in path:
                features["has_exposed_git"] = 1

        if "information disclosure" in vuln_type:
            features["has_info_disclosure"] = 1

        if "verbose error" in vuln_type:
            features["has_verbose_errors"] = 1

    # ----- Derived features -----
    features["total_findings"] = (
        features["num_sqli_findings"]
        + features["num_bac_findings"]
        + features["num_auth_findings"]
        + features["num_misconfig_findings"]
    )

    features["weighted_risk_score"] = (
        features["num_critical"] * SEVERITY_WEIGHTS.get("Critical", 10)
        + features["num_high"] * SEVERITY_WEIGHTS.get("High", 7)
        + features["num_medium"] * SEVERITY_WEIGHTS.get("Medium", 4)
        + features["num_low"] * SEVERITY_WEIGHTS.get("Low", 2)
    )

    logger.info(
        f"Extracted features: {features['total_findings']} findings, "
        f"weighted_score={features['weighted_risk_score']}, "
        f"sqli={features['num_sqli_findings']}, "
        f"bac={features['num_bac_findings']}, "
        f"auth={features['num_auth_findings']}, "
        f"misconfig={features['num_misconfig_findings']}"
    )

    return features


def features_to_vector(features):
    """
    Convert a features dict to an ordered list (vector) matching
    FEATURE_COLUMNS order. This is what gets fed to the model.

    Args:
        features: dict from extract_features()

    Returns:
        list of numeric values in FEATURE_COLUMNS order
    """
    return [features.get(col, 0) for col in FEATURE_COLUMNS]


def features_to_dataframe_row(features):
    """
    Convert features dict to a single-row pandas DataFrame,
    suitable for model.predict().

    Args:
        features: dict from extract_features()

    Returns:
        pandas DataFrame with one row and FEATURE_COLUMNS as columns
    """
    import pandas as pd
    return pd.DataFrame([features_to_vector(features)], columns=FEATURE_COLUMNS)


def summarise_features(features):
    """
    Return a human-readable summary of the extracted features.
    Used in reports and API responses.

    Args:
        features: dict from extract_features()

    Returns:
        dict with high-level summary
    """
    return {
        "total_findings": features["total_findings"],
        "findings_by_category": {
            "SQL Injection": features["num_sqli_findings"],
            "Broken Access Control": features["num_bac_findings"],
            "Authentication Failures": features["num_auth_findings"],
            "Security Misconfiguration": features["num_misconfig_findings"],
        },
        "findings_by_severity": {
            "Critical": features["num_critical"],
            "High": features["num_high"],
            "Medium": features["num_medium"],
            "Low": features["num_low"],
        },
        "key_flags": {
            "confirmed_sqli": bool(features["has_confirmed_sqli"]),
            "blind_sqli": bool(features["has_blind_sqli"]),
            "time_based_sqli": bool(features["has_time_based_sqli"]),
            "unauthenticated_access": bool(features["has_unauth_access"]),
            "idor": bool(features["has_idor"]),
            "weak_credentials": bool(features["has_weak_credentials"]),
            "missing_rate_limiting": bool(features["has_missing_rate_limit"]),
            "exposed_env_file": bool(features["has_exposed_env"]),
            "exposed_git_repo": bool(features["has_exposed_git"]),
            "info_disclosure": bool(features["has_info_disclosure"]),
            "verbose_errors": bool(features["has_verbose_errors"]),
        },
        "missing_security_headers": features["missing_headers_count"],
        "exposed_files": features["exposed_files_count"],
        "weighted_risk_score": features["weighted_risk_score"],
    }