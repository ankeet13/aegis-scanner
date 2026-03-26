"""
AEGIS Scanner — Authentication Failures Scanner
Detects authentication weaknesses across four checks:
1. Weak Credentials  — tests common username:password pairs against login forms
2. Rate Limiting     — checks if the app locks out or throttles after many failures
3. CSRF Protection   — verifies login forms include anti-CSRF tokens
4. Session Security  — inspects session cookies for Secure/HttpOnly/SameSite flags

Concept (mirrors Burp Suite's Intruder + manual auth testing):
- Identify login forms (forms with a password field)
- Extract CSRF tokens from hidden fields and include them per request
- Submit common credential pairs and detect success vs failure by response analysis
- Track how many attempts succeed without lockout/throttle
- Inspect cookie attributes for session management weaknesses
"""

import re
import logging
from bs4 import BeautifulSoup
from backend.config import (
    AUTH_MAX_ATTEMPTS,
    AUTH_LOCKOUT_THRESHOLD,
    AUTH_SUCCESS_INDICATORS,
    AUTH_FAILURE_INDICATORS,
)
from backend.utils.http_client import HTTPClient
from backend.utils.response_analyzer import ResponseAnalyzer
from backend.utils.payload_manager import PayloadManager
from backend.scanners.sqli_scanner import Finding

logger = logging.getLogger(__name__)


class AuthScanner:
    """
    Scans login forms for authentication weaknesses.

    Usage:
        scanner = AuthScanner()
        findings = scanner.scan(endpoints)

    Where `endpoints` is a list of Endpoint objects from the Crawler.
    Only endpoints identified as login forms (with password fields) are tested.
    """

    def __init__(self, http_client=None):
        self.client = http_client or HTTPClient()
        self.analyzer = ResponseAnalyzer()
        self.findings = []

    def scan(self, endpoints, progress_callback=None):
        """
        Run all authentication checks against discovered login forms.

        Args:
            endpoints: list of Endpoint objects from Crawler
            progress_callback: optional callable(phase, current, total)

        Returns:
            list of Finding objects
        """
        self.findings = []

        # Filter to only login forms (endpoints with password fields)
        login_forms = self._find_login_forms(endpoints)

        if not login_forms:
            logger.info("Auth Scanner: no login forms found.")
            return self.findings

        total = len(login_forms)
        logger.info(f"Auth Scanner: testing {total} login form(s)")

        for idx, endpoint in enumerate(login_forms):
            if progress_callback:
                progress_callback("auth", idx + 1, total)

            logger.info(f"  Testing login form: {endpoint.method} {endpoint.url}")

            # Test 1: Weak credentials
            self._test_weak_credentials(endpoint)

            # Test 2: Rate limiting / account lockout
            self._test_rate_limiting(endpoint)

            # Test 3: CSRF token presence
            self._test_csrf_protection(endpoint)

        # Test 4: Session cookie security (runs against any response)
        self._test_session_security(endpoints)

        logger.info(
            f"Auth Scanner complete: {len(self.findings)} finding(s) discovered"
        )
        return self.findings

    # ------------------------------------------------------------------
    # Test 1: Weak Credentials
    # ------------------------------------------------------------------
    def _test_weak_credentials(self, endpoint):
        """
        Test common username:password pairs against a login form.

        Detection logic:
        1. Load credential pairs from common_creds.txt
        2. For each pair, build form submission data
        3. Extract fresh CSRF token if present (per request)
        4. Submit and analyse the response
        5. If response contains success indicators (dashboard, welcome, logout)
           AND does not contain failure indicators → weak creds confirmed

        Mirrors Burp Intruder's Sniper/Pitchfork attack on login forms.
        """
        cred_lines = PayloadManager.get_common_credentials()

        # Identify the username and password field names from form_fields
        username_field = self._find_field_by_type(endpoint, "text", "email", "username")
        password_field = self._find_field_by_type(endpoint, "password")

        if not username_field or not password_field:
            logger.warning(
                f"  Could not identify username/password fields in "
                f"{endpoint.url}: fields={endpoint.form_fields}"
            )
            return

        # Send a baseline failure request first to understand what failure looks like
        baseline_failure = self._submit_login(
            endpoint, username_field, password_field,
            "definitely_not_a_real_user_xyzzy", "not_a_real_password_12345"
        )
        if baseline_failure is None:
            return

        tested = 0
        for line in cred_lines:
            if tested >= AUTH_MAX_ATTEMPTS:
                break

            if ":" not in line:
                continue

            username, password = line.split(":", 1)

            response = self._submit_login(
                endpoint, username_field, password_field,
                username, password
            )
            if response is None:
                continue

            tested += 1

            # Detect success: response differs from baseline failure
            is_success = self._detect_login_success(
                baseline_failure, response
            )

            if is_success:
                finding = Finding(
                    vuln_type="Authentication Failure (Weak Credentials)",
                    severity="Critical",
                    url=endpoint.url,
                    method=endpoint.method,
                    parameter=f"{username_field}, {password_field}",
                    payload=f"{username}:{password}",
                    evidence=(
                        f"Login succeeded with weak credentials "
                        f"'{username}:{password}'. Response contained success "
                        f"indicators and differed from failed login baseline."
                    ),
                    confidence="Confirmed",
                    details={
                        "username_field": username_field,
                        "password_field": password_field,
                        "credentials": f"{username}:{password}",
                        "response_status": response.status_code,
                        "baseline_failure_status": baseline_failure.status_code,
                        "response_length": response.body_length,
                        "failure_length": baseline_failure.body_length,
                    },
                )
                self.findings.append(finding)
                logger.info(
                    f"    [!] WEAK CREDENTIALS CONFIRMED: "
                    f"{username}:{password} at {endpoint.url}"
                )
                # Don't stop — continue to find all weak creds, but cap at MAX

        if tested > 0:
            logger.info(f"  Tested {tested} credential pairs against {endpoint.url}")

    # ------------------------------------------------------------------
    # Test 2: Rate Limiting / Account Lockout
    # ------------------------------------------------------------------
    def _test_rate_limiting(self, endpoint):
        """
        Check if the application rate-limits or locks out after repeated
        failed login attempts.

        Detection logic:
        1. Submit AUTH_LOCKOUT_THRESHOLD failed login attempts rapidly
        2. If all attempts return the same failure response (no lockout,
           no CAPTCHA, no increasing delay) → missing rate limiting
        3. If response changes to indicate lockout/block → properly protected

        This mirrors what a tester does manually in Burp Intruder: run a
        cluster bomb with many attempts and observe whether the app fights back.
        """
        username_field = self._find_field_by_type(endpoint, "text", "email", "username")
        password_field = self._find_field_by_type(endpoint, "password")

        if not username_field or not password_field:
            return

        responses = []
        for i in range(AUTH_LOCKOUT_THRESHOLD):
            response = self._submit_login(
                endpoint, username_field, password_field,
                "admin", f"wrong_password_{i}"
            )
            if response is None:
                return
            responses.append(response)

        # Analyse: did the app ever fight back?
        lockout_detected = False
        captcha_detected = False

        for resp in responses:
            body_lower = (resp.body or "").lower()

            # Check for lockout indicators
            lockout_words = [
                "locked", "too many", "rate limit", "temporarily blocked",
                "try again later", "exceeded", "throttle", "banned",
                "account disabled", "wait",
            ]
            if any(word in body_lower for word in lockout_words):
                lockout_detected = True
                break

            # Check for CAPTCHA
            if "captcha" in body_lower or "recaptcha" in body_lower:
                captcha_detected = True
                break

            # Check for increasing status codes (429 Too Many Requests)
            if resp.status_code == 429:
                lockout_detected = True
                break

        if not lockout_detected and not captcha_detected:
            finding = Finding(
                vuln_type="Authentication Failure (Missing Rate Limiting)",
                severity="Medium",
                url=endpoint.url,
                method=endpoint.method,
                parameter=f"{username_field}, {password_field}",
                payload=f"{AUTH_LOCKOUT_THRESHOLD} rapid failed login attempts",
                evidence=(
                    f"Submitted {AUTH_LOCKOUT_THRESHOLD} failed login attempts "
                    f"with no lockout, rate limiting, or CAPTCHA detected. "
                    f"Application is vulnerable to brute-force attacks."
                ),
                confidence="Confirmed",
                details={
                    "attempts_made": AUTH_LOCKOUT_THRESHOLD,
                    "final_status": responses[-1].status_code if responses else None,
                    "lockout_detected": False,
                    "captcha_detected": False,
                },
            )
            self.findings.append(finding)
            logger.info(
                f"    [!] NO RATE LIMITING: {AUTH_LOCKOUT_THRESHOLD} failed "
                f"attempts accepted at {endpoint.url}"
            )

    # ------------------------------------------------------------------
    # Test 3: CSRF Token Protection
    # ------------------------------------------------------------------
    def _test_csrf_protection(self, endpoint):
        """
        Check if the login form includes a CSRF/anti-forgery token.

        Detection logic:
        1. Fetch the login page
        2. Parse the form for hidden input fields
        3. Look for common CSRF token names (csrf, token, _token, etc.)
        4. If no CSRF token found → CSRF protection missing

        Burp flags this in its passive scanner when it sees forms without
        anti-CSRF tokens.
        """
        # Fetch the page containing the form
        response = self.client.send_request(endpoint.url)
        if response.error or not response.body:
            return

        soup = BeautifulSoup(response.body, "html.parser")

        # Look for hidden inputs that look like CSRF tokens
        csrf_names = [
            "csrf", "csrftoken", "csrf_token", "_csrf", "_token",
            "token", "authenticity_token", "__requestverificationtoken",
            "antiforgery", "xsrf", "xsrf_token", "_xsrf",
        ]

        has_csrf = False
        for form in soup.find_all("form"):
            for inp in form.find_all("input", {"type": "hidden"}):
                name = (inp.get("name") or "").lower()
                if any(csrf_name in name for csrf_name in csrf_names):
                    has_csrf = True
                    break
            if has_csrf:
                break

        if not has_csrf:
            finding = Finding(
                vuln_type="Authentication Failure (Missing CSRF Protection)",
                severity="Medium",
                url=endpoint.url,
                method=endpoint.method,
                parameter="N/A (form-level)",
                payload="N/A",
                evidence=(
                    f"Login form at {endpoint.url} does not contain a CSRF "
                    f"token in any hidden input field. This makes the form "
                    f"vulnerable to Cross-Site Request Forgery attacks."
                ),
                confidence="Confirmed",
                details={
                    "checked_csrf_names": csrf_names,
                    "hidden_fields_found": [
                        inp.get("name")
                        for form in soup.find_all("form")
                        for inp in form.find_all("input", {"type": "hidden"})
                    ],
                },
            )
            self.findings.append(finding)
            logger.info(
                f"    [!] MISSING CSRF TOKEN on login form: {endpoint.url}"
            )

    # ------------------------------------------------------------------
    # Test 4: Session Cookie Security
    # ------------------------------------------------------------------
    def _test_session_security(self, endpoints):
        """
        Inspect session cookies for missing security flags.

        Checks:
        - HttpOnly flag (prevents JavaScript access to cookie)
        - Secure flag (cookie only sent over HTTPS)
        - SameSite attribute (CSRF mitigation)

        This mirrors Burp's passive scanner which flags insecure cookie
        attributes on every response.
        """
        # Pick any endpoint to get a response with cookies
        tested_urls = set()

        for endpoint in endpoints:
            # Only test each unique host+path once
            base_key = endpoint.url.split("?")[0]
            if base_key in tested_urls:
                continue
            tested_urls.add(base_key)

            response = self.client.send_request(endpoint.url)
            if response.error:
                continue

            # Check Set-Cookie headers
            set_cookie_header = None
            for key, value in response.headers.items():
                if key.lower() == "set-cookie":
                    set_cookie_header = value
                    break

            if not set_cookie_header:
                continue

            # Parse cookie attributes
            cookie_lower = set_cookie_header.lower()

            missing_flags = []
            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "samesite" not in cookie_lower:
                missing_flags.append("SameSite")

            if missing_flags:
                finding = Finding(
                    vuln_type="Authentication Failure (Insecure Session Cookie)",
                    severity="Low" if len(missing_flags) == 1 else "Medium",
                    url=endpoint.url,
                    method="GET",
                    parameter="Set-Cookie header",
                    payload="N/A",
                    evidence=(
                        f"Session cookie is missing security flag(s): "
                        f"{', '.join(missing_flags)}. "
                        f"This can lead to session hijacking via XSS "
                        f"({'' if 'HttpOnly' in missing_flags else 'not '}HttpOnly), "
                        f"interception over HTTP "
                        f"({'' if 'Secure' in missing_flags else 'not '}Secure), "
                        f"or CSRF "
                        f"({'' if 'SameSite' in missing_flags else 'not '}SameSite)."
                    ),
                    confidence="Confirmed",
                    details={
                        "missing_flags": missing_flags,
                        "raw_set_cookie": set_cookie_header[:200],
                    },
                )
                self.findings.append(finding)
                logger.info(
                    f"    [!] INSECURE SESSION COOKIE at {endpoint.url}: "
                    f"missing {', '.join(missing_flags)}"
                )
                # Only report once per application, not per endpoint
                break

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _find_login_forms(self, endpoints):
        """Identify login forms from the discovered endpoints."""
        login_forms = []
        for ep in endpoints:
            if not ep.is_form:
                continue
            has_password = any(
                ftype == "password"
                for ftype in ep.form_fields.values()
            )
            if has_password:
                login_forms.append(ep)
        return login_forms

    def _find_field_by_type(self, endpoint, *field_types):
        """
        Find the field name in the form that matches one of the given types.
        Falls back to matching common field names if type matching fails.
        """
        # First try: match by field type
        for name, ftype in endpoint.form_fields.items():
            if ftype in field_types:
                return name

        # Second try: match by common field name patterns
        name_patterns = {
            "text": ["username", "user", "login", "email", "uname", "name"],
            "email": ["email", "e-mail", "mail"],
            "username": ["username", "user", "login", "uname"],
            "password": ["password", "pass", "passwd", "pwd"],
        }

        for ftype in field_types:
            patterns = name_patterns.get(ftype, [])
            for name in endpoint.form_fields:
                if any(p in name.lower() for p in patterns):
                    return name

        return None

    def _submit_login(self, endpoint, username_field, password_field,
                      username, password):
        """
        Submit a login form with the given credentials.
        Handles CSRF token extraction automatically.

        Returns:
            Response object, or None if the request failed
        """
        # Build the form data
        form_data = dict(endpoint.data) if endpoint.data else {}
        form_data[username_field] = username
        form_data[password_field] = password

        # Try to extract a fresh CSRF token from the form page
        csrf_token = self._extract_csrf_token(endpoint.url)
        if csrf_token:
            token_name, token_value = csrf_token
            form_data[token_name] = token_value

        # Submit the form
        response = self.client.send_request(
            url=endpoint.url,
            method=endpoint.method,
            data=form_data if endpoint.method == "POST" else None,
            params=form_data if endpoint.method == "GET" else None,
            allow_redirects=True,
        )

        if response.error:
            logger.debug(
                f"  Login attempt failed: {username}:{password} → {response.error}"
            )
            return None

        return response

    def _extract_csrf_token(self, url):
        """
        Fetch the form page and extract the CSRF token.

        Returns:
            tuple (token_name, token_value) or None
        """
        response = self.client.send_request(url)
        if response.error or not response.body:
            return None

        soup = BeautifulSoup(response.body, "html.parser")

        csrf_names = [
            "csrf", "csrftoken", "csrf_token", "_csrf", "_token",
            "token", "authenticity_token", "__requestverificationtoken",
            "xsrf", "xsrf_token", "_xsrf",
        ]

        for form in soup.find_all("form"):
            for inp in form.find_all("input", {"type": "hidden"}):
                name = inp.get("name", "")
                value = inp.get("value", "")
                if any(csrf_name in name.lower() for csrf_name in csrf_names):
                    return (name, value)

        return None

    def _detect_login_success(self, baseline_failure, response):
        """
        Determine if a login attempt succeeded by comparing against
        the known failure baseline.

        Strategy (multiple signals):
        1. Status code: redirect (302) from login page often means success
        2. Body content: presence of success indicators (dashboard, welcome)
        3. Body content: absence of failure indicators (invalid, incorrect)
        4. Response length: significantly different from failure baseline
        5. Set-Cookie: new session cookie issued after login
        """
        body_lower = (response.body or "").lower()
        baseline_lower = (baseline_failure.body or "").lower()

        # Signal 1: Redirect (common after successful login)
        is_redirect = response.status_code in (301, 302, 303, 307, 308)

        # Signal 2: Success indicators present in response
        success_matches = [
            kw for kw in AUTH_SUCCESS_INDICATORS
            if kw.lower() in body_lower
        ]

        # Signal 3: Failure indicators ABSENT from response
        failure_matches = [
            kw for kw in AUTH_FAILURE_INDICATORS
            if kw.lower() in body_lower
        ]

        # Signal 4: Response body differs significantly from failure
        length_ratio = 0
        if baseline_failure.body_length > 0:
            length_ratio = response.body_length / baseline_failure.body_length
        body_different = length_ratio < 0.7 or length_ratio > 1.3

        # Signal 5: New session cookie set
        has_set_cookie = any(
            k.lower() == "set-cookie" for k in response.headers
        )

        # Decision: combine signals
        score = 0
        if is_redirect:
            score += 2
        if success_matches:
            score += 2
        if not failure_matches:
            score += 1
        if body_different:
            score += 1
        if has_set_cookie:
            score += 1

        # If failure indicators are present, it's almost certainly a failure
        if failure_matches and not is_redirect:
            return False

        # Need at least 3 signals to call it a success
        return score >= 3

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