# Author: Shristi - SQL Injection Scanner Module

"""
AEGIS Scanner — SQL Injection Scanner
Detects SQL injection vulnerabilities using three detection techniques:
1. Error-Based  — injects payloads that trigger DB errors visible in the response
2. Boolean-Blind — sends TRUE/FALSE payload pairs and compares response differences
3. Time-Based Blind — injects SLEEP/WAITFOR payloads and measures response delay

Concept (mirrors Burp Suite's Active Scan → SQLi checks):
- For each endpoint with parameters (insertion points), send baseline request
- Inject each payload into each parameter one at a time
- Use ResponseAnalyzer to compare baseline vs attack response
- Classify and report any confirmed injection points
"""

import re
import logging
from backend.config import (
    SQLI_TIME_THRESHOLD,
    SQLI_BLIND_LENGTH_RATIO,
    SQLI_ERROR_PATTERNS,
)
from backend.utils.http_client import HTTPClient
from backend.utils.response_analyzer import ResponseAnalyzer
from backend.utils.payload_manager import PayloadManager

logger = logging.getLogger(__name__)


class Finding:
    """
    Represents a single confirmed or suspected vulnerability finding.
    This structure feeds into the report generator and ML feature extractor.
    """

    def __init__(self, vuln_type, severity, url, method, parameter,
                 payload, evidence, confidence, details=None):
        self.vuln_type = vuln_type       # e.g. "SQL Injection (Error-Based)"
        self.severity = severity         # Critical / High / Medium / Low / Info
        self.url = url
        self.method = method
        self.parameter = parameter       # the insertion point that was vulnerable
        self.payload = payload           # the payload that triggered it
        self.evidence = evidence         # matched error pattern, time diff, etc.
        self.confidence = confidence     # "Confirmed", "Tentative", "Firm"
        self.details = details or {}     # additional metadata

    def to_dict(self):
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "details": self.details,
        }

    def __repr__(self):
        return (
            f"Finding({self.severity} {self.vuln_type} "
            f"at {self.method} {self.url} param={self.parameter})"
        )


class SQLiScanner:
    """
    Scans discovered endpoints for SQL Injection vulnerabilities.

    Usage:
        scanner = SQLiScanner()
        findings = scanner.scan(endpoints)

    Where `endpoints` is a list of Endpoint objects from the Crawler.
    Only endpoints with parameters (insertion points) are tested.
    """

    def __init__(self, http_client=None):
        self.client = http_client or HTTPClient()
        self.analyzer = ResponseAnalyzer()
        self.findings = []

    def scan(self, endpoints, progress_callback=None):
        """
        Run all SQLi detection techniques against each parameterized endpoint.

        Args:
            endpoints: list of Endpoint objects from Crawler
            progress_callback: optional callable(phase, current, total) for UI updates

        Returns:
            list of Finding objects
        """
        self.findings = []

        # Filter to only endpoints with parameters (injection points)
        parameterized = [ep for ep in endpoints if ep.param_names]

        if not parameterized:
            logger.info("No parameterized endpoints to scan for SQLi.")
            return self.findings

        total = len(parameterized)
        logger.info(f"SQLi Scanner: testing {total} parameterized endpoints")

        for idx, endpoint in enumerate(parameterized):
            if progress_callback:
                progress_callback("sqli", idx + 1, total)

            logger.info(f"  Testing: {endpoint.method} {endpoint.url}")

            # Run all three detection techniques per endpoint
            self._test_error_based(endpoint)
            self._test_boolean_blind(endpoint)
            self._test_time_based(endpoint)

        logger.info(
            f"SQLi Scanner complete: {len(self.findings)} finding(s) discovered"
        )
        return self.findings

    # ------------------------------------------------------------------
    # Error-Based SQL Injection
    # ------------------------------------------------------------------
    def _test_error_based(self, endpoint):
        """
        Inject payloads that provoke database error messages.

        Detection logic:
        1. Send baseline request (original parameters)
        2. For each payload, inject into each parameter
        3. Check attack response body for DB error regex patterns
        4. If error pattern found → Confirmed SQLi (Critical)
        5. If status changed to 500 → Tentative SQLi (High)
        """
        payloads = PayloadManager.get_sqli_error_payloads()

        # Send baseline request
        baseline = self.client.send_baseline(
            url=endpoint.url,
            method=endpoint.method,
            params=endpoint.params,
            data=endpoint.data,
        )
        if baseline.error:
            logger.warning(f"  Baseline failed for {endpoint.url}: {baseline.error}")
            return

        for param in endpoint.param_names:
            for payload in payloads:
                attack = self.client.send_attack(
                    url=endpoint.url,
                    method=endpoint.method,
                    params=endpoint.params,
                    data=endpoint.data,
                    injection_param=param,
                    payload=payload,
                )
                if attack.error:
                    continue

                # Check 1: Look for DB error patterns in response body
                error_matches = self.analyzer.check_error_patterns(attack)
                if error_matches:
                    finding = Finding(
                        vuln_type="SQL Injection (Error-Based)",
                        severity="Critical",
                        url=endpoint.url,
                        method=endpoint.method,
                        parameter=param,
                        payload=payload,
                        evidence=f"DB error pattern matched: {error_matches[0]}",
                        confidence="Confirmed",
                        details={
                            "matched_patterns": error_matches,
                            "attack_status": attack.status_code,
                            "baseline_status": baseline.status_code,
                            "response_snippet": _safe_snippet(attack.body, error_matches[0]),
                        },
                    )
                    self.findings.append(finding)
                    logger.info(
                        f"    [!] Error-Based SQLi CONFIRMED: "
                        f"param={param} payload={payload}"
                    )
                    # Move to next param — one confirmed finding per param is enough
                    break

                # Check 2: Status code changed to 500 (server error)
                status_change = self.analyzer.check_status_change(baseline, attack)
                if status_change and status_change["type"] == "server_error":
                    finding = Finding(
                        vuln_type="SQL Injection (Error-Based)",
                        severity="High",
                        url=endpoint.url,
                        method=endpoint.method,
                        parameter=param,
                        payload=payload,
                        evidence=(
                            f"Status changed from {status_change['baseline_status']} "
                            f"to {status_change['attack_status']}"
                        ),
                        confidence="Tentative",
                        details={
                            "status_change": status_change,
                            "attack_body_length": attack.body_length,
                        },
                    )
                    self.findings.append(finding)
                    logger.info(
                        f"    [?] Possible Error-Based SQLi (status change): "
                        f"param={param}"
                    )
                    break

    # ------------------------------------------------------------------
    # Boolean-Blind SQL Injection
    # ------------------------------------------------------------------
    def _test_boolean_blind(self, endpoint):
        """
        Send TRUE/FALSE payload pairs and compare response differences.

        Detection logic:
        1. Send baseline request
        2. For each payload pair (TRUE|||FALSE):
           a. Inject TRUE payload → get response A
           b. Inject FALSE payload → get response B
        3. If response A ≈ baseline AND response B differs significantly → Confirmed
        4. "Significantly differs" = body length ratio exceeds threshold
        """
        raw_payloads = PayloadManager.get_sqli_blind_payloads()

        # Parse paired payloads (format: TRUE_PAYLOAD|||FALSE_PAYLOAD)
        payload_pairs = []
        for raw in raw_payloads:
            if "|||" in raw:
                true_p, false_p = raw.split("|||", 1)
                payload_pairs.append((true_p.strip(), false_p.strip()))

        if not payload_pairs:
            logger.warning("  No valid blind payload pairs found.")
            return

        # Send baseline
        baseline = self.client.send_baseline(
            url=endpoint.url,
            method=endpoint.method,
            params=endpoint.params,
            data=endpoint.data,
        )
        if baseline.error:
            return

        for param in endpoint.param_names:
            for true_payload, false_payload in payload_pairs:
                # Send TRUE condition
                true_response = self.client.send_attack(
                    url=endpoint.url,
                    method=endpoint.method,
                    params=endpoint.params,
                    data=endpoint.data,
                    injection_param=param,
                    payload=true_payload,
                )
                if true_response.error:
                    continue

                # Send FALSE condition
                false_response = self.client.send_attack(
                    url=endpoint.url,
                    method=endpoint.method,
                    params=endpoint.params,
                    data=endpoint.data,
                    injection_param=param,
                    payload=false_payload,
                )
                if false_response.error:
                    continue

                # Compare: TRUE response should be similar to baseline
                true_vs_baseline = self.analyzer.check_length_differential(
                    baseline, true_response
                )

                # Compare: FALSE response should differ from baseline
                false_vs_baseline = self.analyzer.check_length_differential(
                    baseline, false_response
                )

                # Detection: TRUE ≈ baseline AND FALSE ≠ baseline
                true_similar = not true_vs_baseline["significant"]
                false_different = false_vs_baseline["significant"]

                if true_similar and false_different:
                    finding = Finding(
                        vuln_type="SQL Injection (Boolean-Blind)",
                        severity="High",
                        url=endpoint.url,
                        method=endpoint.method,
                        parameter=param,
                        payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                        evidence=(
                            f"TRUE response matched baseline "
                            f"(ratio={true_vs_baseline['ratio']}), "
                            f"FALSE response diverged "
                            f"(ratio={false_vs_baseline['ratio']})"
                        ),
                        confidence="Confirmed",
                        details={
                            "baseline_length": baseline.body_length,
                            "true_length": true_response.body_length,
                            "false_length": false_response.body_length,
                            "true_ratio": true_vs_baseline["ratio"],
                            "false_ratio": false_vs_baseline["ratio"],
                            "true_status": true_response.status_code,
                            "false_status": false_response.status_code,
                        },
                    )
                    self.findings.append(finding)
                    logger.info(
                        f"    [!] Boolean-Blind SQLi CONFIRMED: param={param}"
                    )
                    break  # One finding per param

                # Secondary check: status code divergence between TRUE and FALSE
                if (
                    true_response.status_code == baseline.status_code
                    and false_response.status_code != baseline.status_code
                ):
                    finding = Finding(
                        vuln_type="SQL Injection (Boolean-Blind)",
                        severity="Medium",
                        url=endpoint.url,
                        method=endpoint.method,
                        parameter=param,
                        payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                        evidence=(
                            f"TRUE status={true_response.status_code} matched baseline, "
                            f"FALSE status={false_response.status_code} diverged"
                        ),
                        confidence="Tentative",
                        details={
                            "baseline_status": baseline.status_code,
                            "true_status": true_response.status_code,
                            "false_status": false_response.status_code,
                        },
                    )
                    self.findings.append(finding)
                    logger.info(
                        f"    [?] Possible Boolean-Blind SQLi "
                        f"(status divergence): param={param}"
                    )
                    break

    # ------------------------------------------------------------------
    # Time-Based Blind SQL Injection
    # ------------------------------------------------------------------
    def _test_time_based(self, endpoint):
        """
        Inject SLEEP / WAITFOR payloads and measure response time.

        Detection logic:
        1. Send baseline request — record response time
        2. For each time payload, inject into each parameter
        3. Compare attack response time vs baseline
        4. If attack is >SQLI_TIME_THRESHOLD seconds slower → Confirmed
        """
        payloads = PayloadManager.get_sqli_time_payloads()

        # Send baseline and record timing
        baseline = self.client.send_baseline(
            url=endpoint.url,
            method=endpoint.method,
            params=endpoint.params,
            data=endpoint.data,
        )
        if baseline.error:
            return

        for param in endpoint.param_names:
            for payload in payloads:
                # Use timed attack method (longer timeout to allow SLEEP)
                attack = self.client.send_timed_attack(
                    url=endpoint.url,
                    method=endpoint.method,
                    params=endpoint.params,
                    data=endpoint.data,
                    injection_param=param,
                    payload=payload,
                )
                if attack.error == "timeout":
                    # Timeout itself is a strong indicator of time-based SQLi
                    finding = Finding(
                        vuln_type="SQL Injection (Time-Based Blind)",
                        severity="High",
                        url=endpoint.url,
                        method=endpoint.method,
                        parameter=param,
                        payload=payload,
                        evidence="Request timed out (SLEEP/WAITFOR likely executed)",
                        confidence="Firm",
                        details={
                            "baseline_ms": round(baseline.elapsed_ms, 2),
                            "attack_result": "timeout",
                        },
                    )
                    self.findings.append(finding)
                    logger.info(
                        f"    [!] Time-Based SQLi (timeout): param={param}"
                    )
                    break

                if attack.error:
                    continue

                # Compare timing
                time_check = self.analyzer.check_time_differential(
                    baseline, attack
                )

                if time_check["suspicious"]:
                    # Verify with a second request to reduce false positives
                    verify = self.client.send_timed_attack(
                        url=endpoint.url,
                        method=endpoint.method,
                        params=endpoint.params,
                        data=endpoint.data,
                        injection_param=param,
                        payload=payload,
                    )
                    verify_check = self.analyzer.check_time_differential(
                        baseline, verify
                    )

                    if verify_check["suspicious"]:
                        # Both attempts showed delay → Confirmed
                        finding = Finding(
                            vuln_type="SQL Injection (Time-Based Blind)",
                            severity="Critical",
                            url=endpoint.url,
                            method=endpoint.method,
                            parameter=param,
                            payload=payload,
                            evidence=(
                                f"Response delayed by "
                                f"{time_check['differential_seconds']}s "
                                f"(verified: {verify_check['differential_seconds']}s), "
                                f"threshold={SQLI_TIME_THRESHOLD}s"
                            ),
                            confidence="Confirmed",
                            details={
                                "baseline_ms": time_check["baseline_ms"],
                                "attack_1_ms": time_check["attack_ms"],
                                "attack_2_ms": verify_check["attack_ms"],
                                "delay_1_seconds": time_check["differential_seconds"],
                                "delay_2_seconds": verify_check["differential_seconds"],
                                "threshold": SQLI_TIME_THRESHOLD,
                            },
                        )
                        self.findings.append(finding)
                        logger.info(
                            f"    [!] Time-Based SQLi CONFIRMED "
                            f"(verified): param={param}"
                        )
                        break
                    else:
                        # First attempt was slow, second was normal → Tentative
                        finding = Finding(
                            vuln_type="SQL Injection (Time-Based Blind)",
                            severity="Medium",
                            url=endpoint.url,
                            method=endpoint.method,
                            parameter=param,
                            payload=payload,
                            evidence=(
                                f"First request delayed by "
                                f"{time_check['differential_seconds']}s "
                                f"but verification was normal "
                                f"({verify_check['differential_seconds']}s)"
                            ),
                            confidence="Tentative",
                            details={
                                "baseline_ms": time_check["baseline_ms"],
                                "attack_1_ms": time_check["attack_ms"],
                                "attack_2_ms": verify_check["attack_ms"],
                            },
                        )
                        self.findings.append(finding)
                        logger.info(
                            f"    [?] Possible Time-Based SQLi "
                            f"(not verified): param={param}"
                        )
                        break

    # ------------------------------------------------------------------
    # Helper — get results summary
    # ------------------------------------------------------------------
    def get_stats(self):
        """Return scan statistics broken down by technique and severity."""
        stats = {
            "total_findings": len(self.findings),
            "by_type": {},
            "by_severity": {},
            "by_confidence": {},
        }

        for f in self.findings:
            stats["by_type"][f.vuln_type] = stats["by_type"].get(f.vuln_type, 0) + 1
            stats["by_severity"][f.severity] = (
                stats["by_severity"].get(f.severity, 0) + 1
            )
            stats["by_confidence"][f.confidence] = (
                stats["by_confidence"].get(f.confidence, 0) + 1
            )

        return stats


# --------------------------------------------------------------------------
# Utility
# --------------------------------------------------------------------------
def _safe_snippet(body, pattern, context_chars=120):
    """
    Extract a snippet of the response body around a matched error pattern.
    Used as evidence in findings — avoids dumping the full response.
    """
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