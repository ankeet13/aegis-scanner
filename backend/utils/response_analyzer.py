"""
AEGIS Scanner — Response Analyzer
Compares baseline and attack responses to detect anomalies.
This is the core detection engine — equivalent to Burp Suite's
differential analysis logic.

Detection methods:
1. Status code change (200 → 500 = error-based SQLi)
2. Body length differential (significant change = blind detection)
3. Response time differential (slow response = time-based blind)
4. Content pattern matching (regex for DB errors, info disclosure)
5. Similarity ratio (for BAC — comparing auth vs unauth responses)
"""

import re
from difflib import SequenceMatcher
from backend.config import (
    SQLI_ERROR_PATTERNS,
    SQLI_TIME_THRESHOLD,
    SQLI_BLIND_LENGTH_RATIO,
    BAC_SIMILARITY_THRESHOLD,
)


class ResponseAnalyzer:
    """Compares two Response objects and identifies anomalies."""

    @staticmethod
    def check_error_patterns(response, patterns=None):
        """
        Check if the response body contains known error patterns.
        Used primarily for error-based SQL injection detection.

        Returns:
            list of matched pattern strings, empty if none found
        """
        if not response.body:
            return []

        patterns = patterns or SQLI_ERROR_PATTERNS
        body_lower = response.body.lower()
        matches = []

        for pattern in patterns:
            if re.search(pattern, body_lower, re.IGNORECASE):
                matches.append(pattern)

        return matches

    @staticmethod
    def check_status_change(baseline, attack):
        """
        Detect if the attack caused a status code change.

        Interesting transitions:
        - 200 → 500 (error-based injection)
        - 200 → 302 (auth bypass / redirect)
        - 401/403 → 200 (access control bypass)

        Returns:
            dict with change details, or None if no change
        """
        if baseline.status_code != attack.status_code:
            return {
                "baseline_status": baseline.status_code,
                "attack_status": attack.status_code,
                "type": _classify_status_change(
                    baseline.status_code, attack.status_code
                ),
            }
        return None

    @staticmethod
    def check_length_differential(baseline, attack):
        """
        Compare response body lengths between baseline and attack.
        Significant differences indicate the payload affected server behavior.

        Returns:
            dict with length comparison data
        """
        if baseline.body_length == 0:
            return {"differential": 0, "ratio": 0, "significant": False}

        differential = abs(attack.body_length - baseline.body_length)
        ratio = attack.body_length / baseline.body_length if baseline.body_length > 0 else 0

        significant = ratio < SQLI_BLIND_LENGTH_RATIO or ratio > (1 / SQLI_BLIND_LENGTH_RATIO)

        return {
            "baseline_length": baseline.body_length,
            "attack_length": attack.body_length,
            "differential": differential,
            "ratio": round(ratio, 3),
            "significant": significant,
        }

    @staticmethod
    def check_time_differential(baseline, attack):
        """
        Compare response times. If the attack response is significantly
        slower than baseline, it may indicate time-based blind injection.

        Returns:
            dict with timing data
        """
        time_diff = (attack.elapsed_ms - baseline.elapsed_ms) / 1000  # seconds
        suspicious = time_diff > SQLI_TIME_THRESHOLD

        return {
            "baseline_ms": round(baseline.elapsed_ms, 2),
            "attack_ms": round(attack.elapsed_ms, 2),
            "differential_seconds": round(time_diff, 2),
            "suspicious": suspicious,
        }

    @staticmethod
    def check_similarity(response_a, response_b):
        """
        Calculate similarity ratio between two response bodies.
        Used by BAC scanner to check if authenticated and unauthenticated
        responses return the same content.

        Returns:
            float between 0 (completely different) and 1 (identical)
        """
        if not response_a.body and not response_b.body:
            return 1.0
        if not response_a.body or not response_b.body:
            return 0.0

        # Use SequenceMatcher for efficient similarity comparison
        # Limit comparison to first 10000 chars for performance
        a = response_a.body[:10000]
        b = response_b.body[:10000]

        return SequenceMatcher(None, a, b).ratio()

    @staticmethod
    def check_bac_vulnerability(auth_response, unauth_response):
        """
        Determine if an endpoint has broken access control by comparing
        authenticated vs unauthenticated responses.

        Logic:
        - If unauth gets 200 and content is similar to auth → BAC confirmed
        - If unauth gets 200 but content is different → might be a public page
        - If unauth gets 401/403 → properly protected

        Returns:
            dict with BAC analysis
        """
        # If unauthenticated request got blocked, endpoint is protected
        if unauth_response.status_code in (401, 403):
            return {"vulnerable": False, "reason": "properly_blocked"}

        # If unauthenticated request got redirected (likely to login)
        if unauth_response.status_code in (301, 302, 307, 308):
            return {"vulnerable": False, "reason": "redirected_to_login"}

        # If both return 200, check content similarity
        if unauth_response.status_code == 200:
            similarity = ResponseAnalyzer.check_similarity(
                auth_response, unauth_response
            )

            if similarity > BAC_SIMILARITY_THRESHOLD:
                return {
                    "vulnerable": True,
                    "reason": "same_content_without_auth",
                    "similarity": round(similarity, 3),
                    "auth_length": auth_response.body_length,
                    "unauth_length": unauth_response.body_length,
                }
            else:
                return {
                    "vulnerable": False,
                    "reason": "different_content",
                    "similarity": round(similarity, 3),
                }

        return {"vulnerable": False, "reason": f"status_{unauth_response.status_code}"}

    @staticmethod
    def check_content_contains(response, keywords):
        """
        Check if response body contains any of the given keywords.
        Used for auth success/failure detection.

        Returns:
            list of found keywords
        """
        if not response.body:
            return []

        body_lower = response.body.lower()
        return [kw for kw in keywords if kw.lower() in body_lower]

    @staticmethod
    def check_header_exists(response, header_name):
        """Check if a specific header exists in the response."""
        return header_name.lower() in {k.lower(): v for k, v in response.headers.items()}

    @staticmethod
    def get_header_value(response, header_name):
        """Get the value of a specific response header (case-insensitive)."""
        for key, value in response.headers.items():
            if key.lower() == header_name.lower():
                return value
        return None


def _classify_status_change(baseline_status, attack_status):
    """Classify what type of status change occurred."""
    if baseline_status == 200 and attack_status >= 500:
        return "server_error"
    elif baseline_status in (401, 403) and attack_status == 200:
        return "auth_bypass"
    elif baseline_status == 200 and attack_status in (301, 302):
        return "redirect"
    elif attack_status == 200 and baseline_status != 200:
        return "unexpected_success"
    else:
        return "other"