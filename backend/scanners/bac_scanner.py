# Author : Sudip Ojha
"""
AEGIS Scanner — Broken Access Control Scanner
Detects broken access control vulnerabilities using two techniques:
1. Unauthenticated Access — replays authenticated requests without cookies
   and checks if the same content is returned (mirrors Burp's Autorize extension)
2. IDOR (Insecure Direct Object Reference) — manipulates ID parameters
   to access resources belonging to other users

Concept (mirrors Burp Suite's Autorize workflow):
- Capture a request made by an authenticated user
- Replay it with NO session cookie
- Compare the response: if content/status is the same, access control is broken
- Additionally test parameterised endpoints by changing ID values
"""

import re
import logging
from backend.config import (
    BAC_SIMILARITY_THRESHOLD,
    BAC_SENSITIVE_PATTERNS,
)
from backend.utils.http_client import HTTPClient
from backend.utils.response_analyzer import ResponseAnalyzer
from backend.scanners.sqli_scanner import Finding

logger = logging.getLogger(__name__)


class BACScanner:
    """
    Scans discovered endpoints for Broken Access Control vulnerabilities.

    Usage:
        scanner = BACScanner(http_client=authenticated_client)
        findings = scanner.scan(endpoints)

    The HTTP client should be configured with a valid auth cookie so we can
    compare authenticated vs unauthenticated responses.
    """

    def __init__(self, http_client=None):
        self.client = http_client or HTTPClient()
        self.analyzer = ResponseAnalyzer()
        self.findings = []

    def scan(self, endpoints, progress_callback=None):
        """
        Run BAC checks against all discovered endpoints.

        Args:
            endpoints: list of Endpoint objects from Crawler
            progress_callback: optional callable(phase, current, total)

        Returns:
            list of Finding objects
        """
        self.findings = []

        if not endpoints:
            logger.info("No endpoints to scan for BAC.")
            return self.findings

        total = len(endpoints)
        logger.info(f"BAC Scanner: testing {total} endpoints")

        for idx, endpoint in enumerate(endpoints):
            if progress_callback:
                progress_callback("bac", idx + 1, total)

            # Test 1: Unauthenticated access
            self._test_unauth_access(endpoint)

            # Test 2: IDOR on parameterised endpoints
            if endpoint.param_names:
                self._test_idor(endpoint)

        logger.info(
            f"BAC Scanner complete: {len(self.findings)} finding(s) discovered"
        )
        return self.findings

    # ------------------------------------------------------------------
    # Test 1: Unauthenticated Access
    # ------------------------------------------------------------------
    def _test_unauth_access(self, endpoint):
        """
        Replay the request without authentication and compare responses.

        Detection logic:
        1. Send the original request WITH auth cookies → authenticated response
        2. Send the SAME request WITHOUT auth cookies → unauthenticated response
        3. Compare using ResponseAnalyzer.check_bac_vulnerability()
        4. If unauth gets 200 with similar content → BAC confirmed
        5. If unauth gets 401/403 → properly protected (no finding)

        Only flag endpoints that match sensitive patterns (admin, api, etc.)
        or all endpoints if they are API routes.
        """
        url = endpoint.url

        # Prioritise endpoints that SHOULD be protected
        is_sensitive = self._is_sensitive_endpoint(url)
        is_api = "/api/" in url or "/api" == url.rstrip("/").split("/")[-1]

        # Still test non-sensitive endpoints, but with lower severity
        priority = "high" if (is_sensitive or is_api) else "low"

        # Step 1: Send authenticated request (baseline)
        auth_response = self.client.send_baseline(
            url=endpoint.url,
            method=endpoint.method,
            params=endpoint.params,
            data=endpoint.data,
        )
        if auth_response.error:
            logger.warning(f"  Auth request failed for {url}: {auth_response.error}")
            return

        # Skip endpoints that already return 401/403 when authenticated
        # (likely the user doesn't have access either)
        if auth_response.status_code in (401, 403):
            return

        # Step 2: Send unauthenticated request (no cookies)
        unauth_response = self.client.send_without_auth(
            url=endpoint.url,
            method=endpoint.method,
            params=endpoint.params,
            data=endpoint.data,
        )
        if unauth_response.error:
            return

        # Step 3: Compare using the BAC analysis method
        bac_result = self.analyzer.check_bac_vulnerability(
            auth_response, unauth_response
        )

        if bac_result["vulnerable"]:
            severity = "Critical" if priority == "high" else "High"
            confidence = "Confirmed" if bac_result["similarity"] > 0.95 else "Firm"

            finding = Finding(
                vuln_type="Broken Access Control (Unauthenticated Access)",
                severity=severity,
                url=endpoint.url,
                method=endpoint.method,
                parameter="N/A (endpoint-level)",
                payload="Request replayed without authentication cookies",
                evidence=(
                    f"Unauthenticated request returned HTTP "
                    f"{unauth_response.status_code} with "
                    f"{bac_result['similarity'] * 100:.1f}% content similarity "
                    f"to authenticated response"
                ),
                confidence=confidence,
                details={
                    "auth_status": auth_response.status_code,
                    "unauth_status": unauth_response.status_code,
                    "similarity": bac_result["similarity"],
                    "auth_body_length": auth_response.body_length,
                    "unauth_body_length": unauth_response.body_length,
                    "is_api": is_api,
                    "is_sensitive": is_sensitive,
                },
            )
            self.findings.append(finding)
            logger.info(
                f"    [!] BAC CONFIRMED: {endpoint.method} {url} "
                f"(similarity={bac_result['similarity']:.2f})"
            )

    # ------------------------------------------------------------------
    # Test 2: IDOR (Insecure Direct Object Reference)
    # ------------------------------------------------------------------
    def _test_idor(self, endpoint):
        """
        Manipulate ID-like parameters to test for IDOR.

        Detection logic:
        1. Identify parameters that look like object IDs (numeric, uuid-like)
        2. Send the original request → baseline response
        3. Change the ID parameter to a different value
        4. If the response returns 200 with valid content → possible IDOR
        5. Compare response structure to ensure we got a real different object

        Note: True IDOR testing requires two different authenticated sessions
        (user A trying to access user B's data). Since we may only have one
        session, we test by incrementing/decrementing numeric IDs and checking
        if the server returns different valid records.
        """
        id_params = self._find_id_params(endpoint)
        if not id_params:
            return

        # Send baseline request with original IDs
        baseline = self.client.send_baseline(
            url=endpoint.url,
            method=endpoint.method,
            params=endpoint.params,
            data=endpoint.data,
        )
        if baseline.error or baseline.status_code >= 400:
            return

        for param_name, original_value in id_params.items():
            # Generate alternative ID values to test
            alt_values = self._generate_alt_ids(original_value)

            for alt_value in alt_values:
                # Inject the alternative ID
                attack = self.client.send_attack(
                    url=endpoint.url,
                    method=endpoint.method,
                    params=endpoint.params,
                    data=endpoint.data,
                    injection_param=param_name,
                    payload=str(alt_value),
                )
                if attack.error:
                    continue

                # If we get 200 with different content, possible IDOR
                if attack.status_code == 200 and attack.body_length > 0:
                    similarity = self.analyzer.check_similarity(baseline, attack)

                    # Response should be structurally similar (same page type)
                    # but with different data (different object)
                    if 0.3 < similarity < 0.95:
                        finding = Finding(
                            vuln_type="Broken Access Control (IDOR)",
                            severity="High",
                            url=endpoint.url,
                            method=endpoint.method,
                            parameter=param_name,
                            payload=str(alt_value),
                            evidence=(
                                f"Changed {param_name} from '{original_value}' "
                                f"to '{alt_value}' — server returned HTTP 200 "
                                f"with different content "
                                f"(similarity={similarity:.2f}). "
                                f"Possible access to another user's resource."
                            ),
                            confidence="Tentative",
                            details={
                                "original_value": str(original_value),
                                "tested_value": str(alt_value),
                                "baseline_status": baseline.status_code,
                                "attack_status": attack.status_code,
                                "similarity": round(similarity, 3),
                                "baseline_length": baseline.body_length,
                                "attack_length": attack.body_length,
                            },
                        )
                        self.findings.append(finding)
                        logger.info(
                            f"    [?] Possible IDOR: {param_name}="
                            f"{original_value} → {alt_value} "
                            f"(similarity={similarity:.2f})"
                        )
                        # One finding per param is enough
                        break

                    # If we get 200 with nearly identical content, the param
                    # might not actually filter data (not IDOR)

                # If we get 403/404 for the alt ID, access control is working
                elif attack.status_code in (403, 404):
                    logger.debug(
                        f"    IDOR check: {param_name}={alt_value} "
                        f"returned {attack.status_code} — properly protected"
                    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _is_sensitive_endpoint(self, url):
        """Check if the URL matches patterns that should be access-controlled."""
        for pattern in BAC_SENSITIVE_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def _find_id_params(self, endpoint):
        """
        Identify parameters that look like object identifiers.
        Returns dict of {param_name: original_value} for ID-like params.
        """
        id_params = {}
        all_params = {}
        all_params.update(endpoint.params)
        all_params.update(endpoint.data)

        for name, value in all_params.items():
            value_str = str(value)

            # Numeric IDs (e.g., id=42, user_id=7, item=123)
            if re.match(r"^\d+$", value_str):
                id_params[name] = value_str
                continue

            # UUID-like patterns
            if re.match(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                value_str,
                re.IGNORECASE,
            ):
                id_params[name] = value_str
                continue

            # Parameter name suggests it's an ID
            id_name_patterns = [
                r"id$", r"_id$", r"^id_", r"^uid", r"^user",
                r"^item", r"^order", r"^account", r"^record",
                r"^doc", r"^file", r"^ref",
            ]
            for pattern in id_name_patterns:
                if re.search(pattern, name, re.IGNORECASE):
                    id_params[name] = value_str
                    break

        return id_params

    def _generate_alt_ids(self, original_value):
        """
        Generate alternative ID values to test IDOR.
        For numeric IDs: try adjacent values and common test values.
        For UUIDs: we can't easily guess, so skip.
        """
        alt_values = []
        value_str = str(original_value)

        if re.match(r"^\d+$", value_str):
            num = int(value_str)
            # Try adjacent IDs
            if num > 1:
                alt_values.append(num - 1)
            alt_values.append(num + 1)
            # Try common test IDs
            if num != 1:
                alt_values.append(1)
            if num != 0:
                alt_values.append(0)
            # Deduplicate and remove original
            alt_values = [v for v in alt_values if v != num]

        return alt_values[:3]  # Limit to 3 attempts per param

    def get_stats(self):
        """Return scan statistics."""
        stats = {
            "total_findings": len(self.findings),
            "by_type": {},
            "by_severity": {},
        }

        for f in self.findings:
            stats["by_type"][f.vuln_type] = stats["by_type"].get(f.vuln_type, 0) + 1
            stats["by_severity"][f.severity] = (
                stats["by_severity"].get(f.severity, 0) + 1
            )

        return stats