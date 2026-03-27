# Author: Aayush — OWASP Policy Engine
"""
AEGIS Scanner — Policy Engine
Maps scan findings and predicted risk levels to actionable OWASP
remediation recommendations. Each finding type gets specific, prioritised
guidance tied to the relevant OWASP Top 10 category.

Concept:
- Every finding has a vuln_type (e.g. "SQL Injection (Error-Based)")
- The policy engine maps vuln_type → OWASP category + remediation steps
- Recommendations are prioritised by severity and grouped by category
- The output feeds into both the JSON API response and the PDF report

Usage:
    from backend.utils.policy_engine import PolicyEngine

    engine = PolicyEngine()
    recommendations = engine.generate_recommendations(findings, risk_level)
"""

import logging

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# OWASP Top 10:2021 Mapping
# Maps vulnerability types to their OWASP category, description,
# and specific remediation steps.
# ------------------------------------------------------------------
OWASP_MAPPING = {
    # ---- A03:2021 — Injection ----
    "SQL Injection (Error-Based)": {
        "owasp_id": "A03:2021",
        "owasp_category": "Injection",
        "description": (
            "The application is vulnerable to error-based SQL injection. "
            "User input is concatenated directly into SQL queries, allowing "
            "attackers to extract database contents via error messages."
        ),
        "remediation": [
            "Use parameterised queries (prepared statements) for ALL database interactions.",
            "Use an ORM (SQLAlchemy, Django ORM, Hibernate) which parameterises by default.",
            "Apply input validation — whitelist expected characters and reject unexpected input.",
            "Implement least-privilege database accounts — the app should not use 'root' or 'sa'.",
            "Suppress detailed database error messages in production responses.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    },
    "SQL Injection (Boolean-Blind)": {
        "owasp_id": "A03:2021",
        "owasp_category": "Injection",
        "description": (
            "The application is vulnerable to boolean-blind SQL injection. "
            "While no error messages are returned, the application behaves "
            "differently for TRUE vs FALSE conditions, allowing data extraction."
        ),
        "remediation": [
            "Use parameterised queries (prepared statements) for ALL database interactions.",
            "Use an ORM which parameterises by default.",
            "Apply input validation — whitelist expected characters.",
            "Implement least-privilege database accounts.",
            "Ensure application responses are identical regardless of query truth value.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    },
    "SQL Injection (Time-Based Blind)": {
        "owasp_id": "A03:2021",
        "owasp_category": "Injection",
        "description": (
            "The application is vulnerable to time-based blind SQL injection. "
            "Injected SLEEP/WAITFOR commands cause measurable response delays, "
            "confirming that SQL commands are being executed."
        ),
        "remediation": [
            "Use parameterised queries (prepared statements) for ALL database interactions.",
            "Use an ORM which parameterises by default.",
            "Apply input validation — whitelist expected characters.",
            "Set strict database query timeouts to limit SLEEP-based extraction.",
            "Use a Web Application Firewall (WAF) with SQLi rule sets.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    },

    # ---- A01:2021 — Broken Access Control ----
    "Broken Access Control (Unauthenticated Access)": {
        "owasp_id": "A01:2021",
        "owasp_category": "Broken Access Control",
        "description": (
            "Sensitive endpoints are accessible without authentication. "
            "Unauthenticated requests return the same content as authenticated "
            "ones, indicating missing access control enforcement."
        ),
        "remediation": [
            "Implement server-side access control checks on EVERY endpoint.",
            "Deny access by default — require explicit grants for each resource.",
            "Use a centralised authorisation middleware rather than per-route checks.",
            "Enforce authentication at the API gateway or reverse proxy level.",
            "Log and alert on unauthenticated access attempts to sensitive endpoints.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        ],
    },
    "Broken Access Control (IDOR)": {
        "owasp_id": "A01:2021",
        "owasp_category": "Broken Access Control",
        "description": (
            "The application may be vulnerable to Insecure Direct Object "
            "References (IDOR). Changing ID parameters returns different "
            "records, suggesting users can access other users' data."
        ),
        "remediation": [
            "Validate that the authenticated user owns the requested resource.",
            "Use indirect references (UUIDs, tokens) instead of sequential integer IDs.",
            "Implement object-level authorisation checks in the data access layer.",
            "Never trust client-supplied IDs — always verify ownership server-side.",
            "Log access patterns to detect enumeration attempts.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        ],
    },

    # ---- A07:2021 — Identification and Authentication Failures ----
    "Authentication Failure (Weak Credentials)": {
        "owasp_id": "A07:2021",
        "owasp_category": "Identification and Authentication Failures",
        "description": (
            "The application accepts commonly known default credentials. "
            "Attackers can gain access using widely available credential lists."
        ),
        "remediation": [
            "Enforce strong password policies (minimum 12 characters, complexity requirements).",
            "Implement multi-factor authentication (MFA) for all accounts.",
            "Check new passwords against known breach databases (e.g., HaveIBeenPwned API).",
            "Force password change on first login for default accounts.",
            "Remove or disable all default/test accounts in production.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        ],
    },
    "Authentication Failure (Missing Rate Limiting)": {
        "owasp_id": "A07:2021",
        "owasp_category": "Identification and Authentication Failures",
        "description": (
            "The login endpoint does not enforce rate limiting or account "
            "lockout, allowing unlimited brute-force password attempts."
        ),
        "remediation": [
            "Implement progressive rate limiting (e.g., 5 attempts per minute per IP).",
            "Add account lockout after N consecutive failures (with unlock via email).",
            "Implement CAPTCHA after 3 failed attempts.",
            "Use exponential backoff for repeated failures.",
            "Monitor and alert on brute-force patterns in authentication logs.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        ],
    },
    "Authentication Failure (Missing CSRF Protection)": {
        "owasp_id": "A07:2021",
        "owasp_category": "Identification and Authentication Failures",
        "description": (
            "The login form does not include a CSRF token, making it "
            "vulnerable to Cross-Site Request Forgery attacks that can "
            "force users to submit login requests unknowingly."
        ),
        "remediation": [
            "Add a unique, unpredictable CSRF token to every state-changing form.",
            "Validate the CSRF token server-side on every POST/PUT/DELETE request.",
            "Use the SameSite cookie attribute as a defence-in-depth measure.",
            "Consider using the Synchronizer Token Pattern or Double Submit Cookie pattern.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "Authentication Failure (Insecure Session Cookie)": {
        "owasp_id": "A07:2021",
        "owasp_category": "Identification and Authentication Failures",
        "description": (
            "Session cookies are missing security flags, making them "
            "vulnerable to interception or theft via XSS."
        ),
        "remediation": [
            "Set HttpOnly flag on all session cookies to prevent JavaScript access.",
            "Set Secure flag to ensure cookies are only sent over HTTPS.",
            "Set SameSite=Lax or SameSite=Strict to prevent CSRF.",
            "Use short session timeouts and implement proper session invalidation.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
    },

    # ---- A05:2021 — Security Misconfiguration ----
    "Security Misconfiguration (Missing Header)": {
        "owasp_id": "A05:2021",
        "owasp_category": "Security Misconfiguration",
        "description": (
            "The application is missing recommended security response headers "
            "that protect against common web attacks."
        ),
        "remediation": [
            "Add all recommended security headers to HTTP responses.",
            "Configure headers at the web server or reverse proxy level for consistency.",
            "Use a security headers middleware in your framework.",
            "Test headers with securityheaders.com after deployment.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    },
    "Security Misconfiguration (Exposed Sensitive File)": {
        "owasp_id": "A05:2021",
        "owasp_category": "Security Misconfiguration",
        "description": (
            "Sensitive files (configuration, backups, version control metadata) "
            "are publicly accessible on the web server."
        ),
        "remediation": [
            "Block access to sensitive files and directories in web server configuration.",
            "Add rules to deny access to .env, .git, .htpasswd, backup files, etc.",
            "Move sensitive files outside the web root directory.",
            "Use .gitignore and deploy scripts that exclude sensitive files.",
            "Audit deployed files regularly — never deploy source control metadata.",
        ],
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    },
    "Security Misconfiguration (Information Disclosure)": {
        "owasp_id": "A05:2021",
        "owasp_category": "Security Misconfiguration",
        "description": (
            "Response headers reveal server software, framework, or version "
            "information that aids attacker reconnaissance."
        ),
        "remediation": [
            "Remove or obfuscate the Server header in web server configuration.",
            "Remove X-Powered-By header (e.g., app.disable('x-powered-by') in Express).",
            "Remove version-specific headers (X-AspNet-Version, etc.).",
            "Use a reverse proxy to strip information disclosure headers.",
        ],
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    },
    "Security Misconfiguration (Verbose Error Page)": {
        "owasp_id": "A05:2021",
        "owasp_category": "Security Misconfiguration",
        "description": (
            "The application returns detailed error messages including stack "
            "traces, file paths, or framework internals in production."
        ),
        "remediation": [
            "Disable debug mode in production (DEBUG=False in Django/Flask).",
            "Implement custom error pages that show user-friendly messages only.",
            "Log detailed errors server-side but never expose them to clients.",
            "Use a global exception handler that catches all unhandled errors.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    },
}


# ------------------------------------------------------------------
# Risk Level Guidance
# ------------------------------------------------------------------
RISK_LEVEL_GUIDANCE = {
    "Safe": {
        "summary": "No significant vulnerabilities detected.",
        "action": "Continue monitoring with regular scans.",
        "priority": "Routine",
    },
    "Low": {
        "summary": "Minor configuration issues detected.",
        "action": (
            "Address missing security headers and information disclosure "
            "findings during the next maintenance window."
        ),
        "priority": "Low — schedule for next sprint",
    },
    "Medium": {
        "summary": "Moderate security issues detected that should be addressed.",
        "action": (
            "Prioritise fixing authentication weaknesses and misconfigurations. "
            "Review exposed files and remove them from public access."
        ),
        "priority": "Medium — address within 2 weeks",
    },
    "High": {
        "summary": "Serious vulnerabilities detected that pose significant risk.",
        "action": (
            "Immediately address confirmed injection vulnerabilities and "
            "broken access control issues. Review all findings and create "
            "a remediation plan with your security team."
        ),
        "priority": "High — address within 48 hours",
    },
    "Critical": {
        "summary": "Critical vulnerabilities detected requiring immediate action.",
        "action": (
            "STOP — this application has confirmed critical vulnerabilities "
            "including SQL injection and/or broken access control combined "
            "with exposed credentials. Consider taking the application "
            "offline until critical issues are resolved."
        ),
        "priority": "Critical — immediate action required",
    },
}


class PolicyEngine:
    """
    Generates structured remediation recommendations from scan findings
    and the predicted risk level.
    """

    def generate_recommendations(self, findings, risk_level):
        """
        Generate prioritised OWASP remediation recommendations.

        Args:
            findings: list of Finding dicts from all scanners
            risk_level: predicted risk level string from RiskPredictor

        Returns:
            dict with:
                risk_guidance: overall guidance for the risk level
                recommendations: list of recommendation dicts, sorted by severity
                owasp_summary: count of findings per OWASP category
        """
        recommendations = []
        owasp_counts = {}

        for finding in findings:
            vuln_type = finding.get("vuln_type", "")
            severity = finding.get("severity", "Info")

            # Look up OWASP mapping
            mapping = OWASP_MAPPING.get(vuln_type)

            if mapping:
                owasp_id = mapping["owasp_id"]
                owasp_category = mapping["owasp_category"]

                rec = {
                    "finding_type": vuln_type,
                    "severity": severity,
                    "owasp_id": owasp_id,
                    "owasp_category": owasp_category,
                    "description": mapping["description"],
                    "remediation_steps": mapping["remediation"],
                    "references": mapping["references"],
                    "affected_endpoint": finding.get("url", ""),
                    "affected_parameter": finding.get("parameter", ""),
                }
                recommendations.append(rec)

                # Count per OWASP category
                key = f"{owasp_id} — {owasp_category}"
                owasp_counts[key] = owasp_counts.get(key, 0) + 1
            else:
                # Unknown finding type — provide generic recommendation
                rec = {
                    "finding_type": vuln_type,
                    "severity": severity,
                    "owasp_id": "N/A",
                    "owasp_category": "Other",
                    "description": finding.get("evidence", ""),
                    "remediation_steps": [
                        "Review the finding details and assess the risk.",
                        "Consult the OWASP Testing Guide for remediation guidance.",
                    ],
                    "references": [
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ],
                    "affected_endpoint": finding.get("url", ""),
                    "affected_parameter": finding.get("parameter", ""),
                }
                recommendations.append(rec)

        # Sort by severity (Critical first)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        recommendations.sort(
            key=lambda r: severity_order.get(r["severity"], 5)
        )

        # Deduplicate recommendations by type (keep the highest severity instance)
        seen_types = set()
        deduped = []
        for rec in recommendations:
            if rec["finding_type"] not in seen_types:
                deduped.append(rec)
                seen_types.add(rec["finding_type"])

        # Get risk level guidance
        risk_guidance = RISK_LEVEL_GUIDANCE.get(risk_level, {
            "summary": "Unknown risk level.",
            "action": "Review all findings manually.",
            "priority": "Unknown",
        })

        result = {
            "risk_guidance": risk_guidance,
            "recommendations": deduped,
            "owasp_summary": owasp_counts,
            "total_recommendations": len(deduped),
        }

        logger.info(
            f"Policy engine: {len(deduped)} recommendations "
            f"across {len(owasp_counts)} OWASP categories"
        )

        return result