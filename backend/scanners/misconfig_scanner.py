"""
AEGIS Scanner — Security Misconfiguration Scanner
Detects security misconfigurations across four checks:
1. Missing Security Headers  — checks responses for absent protective headers
2. Exposed Sensitive Files   — probes common paths for files that shouldn't be public
3. Information Disclosure    — flags response headers that leak server/framework info
4. Verbose Error Pages       — detects detailed error messages and stack traces

Concept (mirrors Burp Suite's passive scanner + active content discovery):
- Passive checks run against every response the crawler already collected
  (headers, cookies, error patterns) — zero extra requests needed
- Active checks probe a curated list of sensitive paths to discover exposed
  configuration files, backups, debug endpoints, and version control artifacts
"""

import re
import logging
from urllib.parse import urljoin, urlparse
from backend.config import (
    EXPECTED_SECURITY_HEADERS,
    INFO_DISCLOSURE_HEADERS,
)
from backend.utils.http_client import HTTPClient
from backend.utils.response_analyzer import ResponseAnalyzer
from backend.utils.payload_manager import PayloadManager
from backend.scanners.sqli_scanner import Finding

logger = logging.getLogger(__name__)


# Paths that are ALWAYS sensitive if accessible — higher severity
HIGH_SENSITIVITY_PATHS = {
    "/.env", "/.env.backup", "/.env.local", "/.env.production",
    "/.git/HEAD", "/.git/config",
    "/.htpasswd",
    "/wp-config.php", "/config.php", "/config.yml", "/config.json",
    "/database.yml", "/db.sqlite3",
    "/backup.sql", "/dump.sql",
    "/actuator/env",
    "/web.config",
}

# Patterns in response bodies that indicate sensitive file content
SENSITIVE_CONTENT_PATTERNS = [
    (r"DB_PASSWORD|DB_HOST|DB_USER|DATABASE_URL", "Database credentials exposed"),
    (r"SECRET_KEY|API_KEY|PRIVATE_KEY|AWS_SECRET", "Secret keys exposed"),
    (r"password\s*[:=]\s*\S+", "Password value found in file"),
    (r"\[core\]\s*\n\s*repositoryformatversion", "Git repository metadata exposed"),
    (r"<\?php", "PHP source code exposed"),
    (r"BEGIN RSA PRIVATE KEY", "Private key file exposed"),
    (r"BEGIN OPENSSH PRIVATE KEY", "SSH private key exposed"),
]

# Patterns that indicate verbose error / debug pages
VERBOSE_ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace"),
    (r"at .+\.java:\d+", "Java stack trace"),
    (r"at .+\.cs:\d+", "C# stack trace"),
    (r"Fatal error:.+on line \d+", "PHP fatal error with line number"),
    (r"SQLSTATE\[", "SQL driver error with state info"),
    (r"Stack Trace:", "Generic stack trace header"),
    (r"Exception in thread", "Java thread exception"),
    (r"Debug mode is on", "Debug mode explicitly enabled"),
    (r"Werkzeug Debugger", "Flask/Werkzeug interactive debugger"),
    (r"Django Debug Toolbar", "Django debug toolbar exposed"),
    (r"Laravel.*exception", "Laravel framework exception page"),
]


class MisconfigScanner:
    """
    Scans for security misconfiguration vulnerabilities.

    Usage:
        scanner = MisconfigScanner()
        findings = scanner.scan(endpoints, target_url)

    Combines passive analysis of existing responses with active probing
    of sensitive file paths.
    """

    def __init__(self, http_client=None):
        self.client = http_client or HTTPClient()
        self.analyzer = ResponseAnalyzer()
        self.findings = []

    def scan(self, endpoints, target_url=None, progress_callback=None):
        """
        Run all misconfiguration checks.

        Args:
            endpoints: list of Endpoint objects from Crawler
            target_url: the original target URL (used as base for path probing)
            progress_callback: optional callable(phase, current, total)

        Returns:
            list of Finding objects
        """
        self.findings = []

        # Determine base URL for active probing
        if target_url:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        elif endpoints:
            parsed = urlparse(endpoints[0].url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        else:
            logger.warning("Misconfig Scanner: no target URL or endpoints provided.")
            return self.findings

        logger.info(f"Misconfig Scanner: base URL = {base_url}")

        # ---- Passive Checks (analyse existing responses, no extra requests) ----

        # Test 1: Missing security headers
        self._test_missing_headers(endpoints, progress_callback)

        # Test 2: Information disclosure headers
        self._test_info_disclosure_headers(endpoints)

        # Test 3: Verbose error pages (check crawler responses)
        self._test_verbose_errors(endpoints)

        # ---- Active Checks (send new requests to discover exposed files) ----

        # Test 4: Probe sensitive file paths
        self._test_exposed_files(base_url, progress_callback)

        logger.info(
            f"Misconfig Scanner complete: {len(self.findings)} finding(s) discovered"
        )
        return self.findings

    # ------------------------------------------------------------------
    # Test 1: Missing Security Headers
    # ------------------------------------------------------------------
    def _test_missing_headers(self, endpoints, progress_callback=None):
        """
        Check responses for missing security headers.

        Detection logic:
        1. Load expected headers from security_headers.json
        2. Send a request to the target's root page (or first endpoint)
        3. Check which required headers are absent
        4. Each missing header is a separate finding

        This is a passive check — Burp flags missing headers on every
        response that flows through the proxy.
        """
        headers_config = PayloadManager.get_security_headers_config()
        required_headers = headers_config.get("required_headers", {})

        if not required_headers:
            logger.warning("  No required headers configured.")
            return

        # Get a response to check headers against — use the first endpoint
        if not endpoints:
            return

        response = self.client.send_request(endpoints[0].url)
        if response.error:
            return

        # Build a case-insensitive set of present headers
        present_headers = {k.lower(): v for k, v in response.headers.items()}

        for header_name, header_info in required_headers.items():
            if header_name.lower() not in present_headers:
                severity = header_info.get("severity", "Medium")
                description = header_info.get("description", "")
                remediation = header_info.get("remediation", "")

                finding = Finding(
                    vuln_type="Security Misconfiguration (Missing Header)",
                    severity=severity,
                    url=endpoints[0].url,
                    method="GET",
                    parameter=header_name,
                    payload="N/A",
                    evidence=(
                        f"Security header '{header_name}' is not present "
                        f"in the response. {description}."
                    ),
                    confidence="Confirmed",
                    details={
                        "missing_header": header_name,
                        "description": description,
                        "remediation": remediation,
                        "checked_url": endpoints[0].url,
                    },
                )
                self.findings.append(finding)
                logger.info(
                    f"    [!] MISSING HEADER: {header_name} ({severity})"
                )

    # ------------------------------------------------------------------
    # Test 2: Information Disclosure Headers
    # ------------------------------------------------------------------
    def _test_info_disclosure_headers(self, endpoints):
        """
        Check for response headers that leak server/framework information.

        Detection logic:
        1. Check for headers like Server, X-Powered-By, X-AspNet-Version
        2. If present with version info → flag as information disclosure
        3. Attackers use this info to find version-specific exploits

        Burp flags these in its passive scan as "Information disclosure"
        findings with Info/Low severity.
        """
        if not endpoints:
            return

        response = self.client.send_request(endpoints[0].url)
        if response.error:
            return

        headers_config = PayloadManager.get_security_headers_config()
        disclosure_config = headers_config.get("info_disclosure_headers", {})

        for header_name in INFO_DISCLOSURE_HEADERS:
            value = self.analyzer.get_header_value(response, header_name)
            if value:
                info = disclosure_config.get(header_name, {})
                description = info.get(
                    "description",
                    f"Header '{header_name}' reveals server information"
                )
                remediation = info.get(
                    "remediation",
                    f"Remove or obfuscate the {header_name} header"
                )

                finding = Finding(
                    vuln_type="Security Misconfiguration (Information Disclosure)",
                    severity="Low",
                    url=endpoints[0].url,
                    method="GET",
                    parameter=header_name,
                    payload="N/A",
                    evidence=(
                        f"Header '{header_name}: {value}' reveals "
                        f"server/framework information. {description}."
                    ),
                    confidence="Confirmed",
                    details={
                        "header": header_name,
                        "value": value,
                        "description": description,
                        "remediation": remediation,
                    },
                )
                self.findings.append(finding)
                logger.info(
                    f"    [!] INFO DISCLOSURE: {header_name}: {value}"
                )

    # ------------------------------------------------------------------
    # Test 3: Verbose Error Pages
    # ------------------------------------------------------------------
    def _test_verbose_errors(self, endpoints):
        """
        Check if the application returns detailed error information.

        Detection logic:
        1. Request a deliberately non-existent path to trigger a 404
        2. Request a path with invalid characters to trigger errors
        3. Check response bodies for stack traces, debug info, framework names
        4. Verbose errors help attackers identify the tech stack and find
           exploitable code paths

        Burp's passive scanner flags verbose error responses automatically.
        """
        if not endpoints:
            return

        # Derive base URL from first endpoint
        parsed = urlparse(endpoints[0].url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Trigger error pages with unusual requests
        error_triggers = [
            "/this_page_definitely_does_not_exist_aegis_test_404",
            "/%00",          # null byte
            "/'" ,           # single quote (may trigger SQL-related errors)
            "/;",            # semicolon
            "/<script>",     # angle brackets
        ]

        checked = False
        for path in error_triggers:
            url = urljoin(base_url, path)
            response = self.client.send_request(url)
            if response.error or not response.body:
                continue

            for pattern, description in VERBOSE_ERROR_PATTERNS:
                if re.search(pattern, response.body, re.IGNORECASE):
                    finding = Finding(
                        vuln_type="Security Misconfiguration (Verbose Error Page)",
                        severity="Medium",
                        url=url,
                        method="GET",
                        parameter="N/A (error handling)",
                        payload=path,
                        evidence=(
                            f"Verbose error page detected: {description}. "
                            f"The application exposes internal implementation "
                            f"details in error responses, which aids attacker "
                            f"reconnaissance."
                        ),
                        confidence="Confirmed",
                        details={
                            "trigger_path": path,
                            "matched_pattern": description,
                            "response_status": response.status_code,
                            "response_snippet": _safe_body_snippet(
                                response.body, pattern
                            ),
                        },
                    )
                    self.findings.append(finding)
                    logger.info(
                        f"    [!] VERBOSE ERROR: {description} at {url}"
                    )
                    checked = True
                    break  # One finding per trigger path

            if checked:
                break  # One verbose error finding is enough

    # ------------------------------------------------------------------
    # Test 4: Exposed Sensitive Files / Paths
    # ------------------------------------------------------------------
    def _test_exposed_files(self, base_url, progress_callback=None):
        """
        Probe common sensitive file paths and check if they are accessible.

        Detection logic:
        1. Load sensitive paths from sensitive_paths.txt
        2. For each path, send a GET request
        3. If response is 200 and body is non-trivial → exposed file
        4. Check body content against sensitive patterns for severity boost
        5. Paths like /.env or /.git/HEAD with real content are Critical

        This mirrors Burp's active content discovery / forced browsing.
        """
        paths = PayloadManager.get_sensitive_paths()

        total = len(paths)
        logger.info(f"  Probing {total} sensitive paths against {base_url}")

        for idx, path in enumerate(paths):
            if progress_callback:
                progress_callback("misconfig_files", idx + 1, total)

            url = urljoin(base_url, path)
            response = self.client.send_request(url)

            if response.error:
                continue

            # Skip non-200 responses (404, 403 = properly hidden)
            if response.status_code != 200:
                continue

            # Skip empty or trivially small responses (likely custom 404 pages)
            if response.body_length < 20:
                continue

            # Check if this is a generic "not found" page masquerading as 200
            if self._is_soft_404(response):
                continue

            # Determine severity based on path sensitivity
            is_high_sensitivity = path in HIGH_SENSITIVITY_PATHS
            base_severity = "High" if is_high_sensitivity else "Medium"

            # Check for sensitive content patterns in the response body
            content_matches = []
            for pattern, desc in SENSITIVE_CONTENT_PATTERNS:
                if re.search(pattern, response.body, re.IGNORECASE):
                    content_matches.append(desc)

            # Upgrade severity if sensitive content found
            if content_matches:
                severity = "Critical"
                evidence_extra = (
                    f" Sensitive content detected: {'; '.join(content_matches)}."
                )
            else:
                severity = base_severity
                evidence_extra = ""

            finding = Finding(
                vuln_type="Security Misconfiguration (Exposed Sensitive File)",
                severity=severity,
                url=url,
                method="GET",
                parameter=path,
                payload=f"GET {path}",
                evidence=(
                    f"Sensitive file/path '{path}' is publicly accessible "
                    f"(HTTP {response.status_code}, {response.body_length} bytes). "
                    f"This file may contain configuration data, credentials, "
                    f"or internal application details.{evidence_extra}"
                ),
                confidence="Confirmed",
                details={
                    "path": path,
                    "status_code": response.status_code,
                    "body_length": response.body_length,
                    "content_matches": content_matches,
                    "is_high_sensitivity": is_high_sensitivity,
                    "response_snippet": response.body[:300] if response.body else "",
                },
            )
            self.findings.append(finding)
            logger.info(
                f"    [!] EXPOSED FILE: {path} "
                f"({response.status_code}, {response.body_length}B) "
                f"→ {severity}"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _is_soft_404(self, response):
        """
        Detect soft 404 pages — pages that return HTTP 200 but actually
        show a "not found" message. Many apps do this instead of proper 404s.

        Returns True if the response looks like a soft 404.
        """
        if not response.body:
            return False

        body_lower = response.body.lower()

        soft_404_indicators = [
            "page not found",
            "404 not found",
            "not found",
            "page does not exist",
            "the page you requested",
            "page could not be found",
            "nothing here",
            "error 404",
            "file not found",
        ]

        # If the page is very short and contains a 404 indicator, it's a soft 404
        if response.body_length < 2000:
            matches = sum(
                1 for indicator in soft_404_indicators
                if indicator in body_lower
            )
            if matches >= 1:
                return True

        return False

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


# --------------------------------------------------------------------------
# Utility
# --------------------------------------------------------------------------
def _safe_body_snippet(body, pattern, context_chars=150):
    """Extract a snippet of the response body around a matched pattern."""
    if not body:
        return ""

    match = re.search(pattern, body, re.IGNORECASE)
    if not match:
        return body[:context_chars] + "..." if len(body) > context_chars else body

    start = max(0, match.start() - context_chars // 2)
    end = min(len(body), match.end() + context_chars // 2)
    snippet = body[start:end]

    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(body) else ""

    return f"{prefix}{snippet}{suffix}"