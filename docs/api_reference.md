# AEGIS Scanner — API Reference

Base URL: `http://localhost:5000`

---

## POST /api/scan

Run a full vulnerability scan against a target web application.

### Request

```json
{
  "target_url": "http://localhost:8080",
  "auth_cookie": {"session": "abc123"},
  "max_depth": 3,
  "max_urls": 100,
  "generate_report": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| target_url | string | Yes | URL to scan (must start with http:// or https://) |
| auth_cookie | object | No | Cookie key-value pairs for authenticated scanning |
| max_depth | integer | No | Maximum crawl depth (default: 3) |
| max_urls | integer | No | Maximum URLs to visit (default: 100) |
| generate_report | boolean | No | Generate PDF report (default: true) |

### Response (200 OK)

```json
{
  "target_url": "http://localhost:8080",
  "scan_timestamp": "2026-03-18T14:30:00.000000",
  "scan_duration": 45.2,
  "crawl_stats": {
    "urls_visited": 12,
    "endpoints_discovered": 18,
    "forms_found": 2,
    "parameterized_endpoints": 6,
    "login_forms": 1,
    "api_endpoints": 8
  },
  "findings": [
    {
      "vuln_type": "SQL Injection (Error-Based)",
      "severity": "Critical",
      "url": "http://localhost:8080/search",
      "method": "GET",
      "parameter": "q",
      "payload": "' OR 1=1--",
      "evidence": "DB error pattern matched: you have an error in your sql syntax",
      "confidence": "Confirmed",
      "details": {
        "matched_patterns": ["you have an error in your sql syntax"],
        "attack_status": 500,
        "baseline_status": 200,
        "response_snippet": "...error in your SQL syntax near 'OR 1=1--'..."
      }
    }
  ],
  "risk_prediction": {
    "risk_level": "Critical",
    "confidence": 0.92,
    "probabilities": {
      "Safe": 0.01,
      "Low": 0.02,
      "Medium": 0.03,
      "High": 0.02,
      "Critical": 0.92
    },
    "features_summary": {
      "total_findings": 15,
      "findings_by_category": {
        "SQL Injection": 3,
        "Broken Access Control": 4,
        "Authentication Failures": 2,
        "Security Misconfiguration": 6
      },
      "findings_by_severity": {
        "Critical": 4,
        "High": 5,
        "Medium": 3,
        "Low": 3
      },
      "key_flags": {
        "confirmed_sqli": true,
        "blind_sqli": true,
        "weak_credentials": true,
        "exposed_env_file": true
      },
      "weighted_risk_score": 87
    }
  },
  "recommendations": {
    "risk_guidance": {
      "summary": "Critical vulnerabilities detected requiring immediate action.",
      "action": "Consider taking the application offline until critical issues are resolved.",
      "priority": "Critical — immediate action required"
    },
    "recommendations": [
      {
        "finding_type": "SQL Injection (Error-Based)",
        "severity": "Critical",
        "owasp_id": "A03:2021",
        "owasp_category": "Injection",
        "description": "User input is concatenated directly into SQL queries.",
        "remediation_steps": [
          "Use parameterised queries (prepared statements) for ALL database interactions.",
          "Use an ORM which parameterises by default.",
          "Apply input validation."
        ],
        "references": [
          "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
      }
    ],
    "owasp_summary": {
      "A03:2021 — Injection": 3,
      "A01:2021 — Broken Access Control": 4,
      "A05:2021 — Security Misconfiguration": 6,
      "A07:2021 — Identification and Authentication Failures": 2
    },
    "total_recommendations": 8
  },
  "model_info": {
    "model_loaded": true,
    "model_type": "RandomForestClassifier",
    "n_estimators": 200,
    "training_accuracy": 0.97,
    "cross_val_accuracy": 0.9585
  },
  "report_url": "/api/report/aegis_report_http_localhost_8080_20260318_143000",
  "scanner_stats": {
    "sqli": {"total_findings": 3, "by_type": {}, "by_severity": {}},
    "bac": {"total_findings": 4, "by_type": {}, "by_severity": {}},
    "auth": {"total_findings": 2, "by_type": {}, "by_severity": {}},
    "misconfig": {"total_findings": 6, "by_type": {}, "by_severity": {}}
  }
}
```

### Error Response (400/500)

```json
{
  "error": "target_url is required",
  "message": "Detailed error description"
}
```

---

## GET /api/report/:report_id

Download a previously generated PDF report.

### Response

- **200**: PDF file (application/pdf)
- **404**: `{"error": "Report not found"}`

---

## GET /api/model-info

Return information about the loaded ML model.

### Response (200 OK)

```json
{
  "model_loaded": true,
  "model_path": "backend/ml/model/risk_model.pkl",
  "risk_levels": ["Safe", "Low", "Medium", "High", "Critical"],
  "model_type": "RandomForestClassifier",
  "n_estimators": 200,
  "n_features": 23,
  "classes": ["Critical", "High", "Low", "Medium", "Safe"],
  "training_accuracy": 0.97,
  "cross_val_accuracy": 0.9585
}
```

---

## GET /api/health

Health check endpoint.

### Response (200 OK)

```json
{
  "status": "ok",
  "model_loaded": true,
  "timestamp": "2026-03-18T14:30:00.000000"
}
```

---

## Finding Object Schema

Every finding across all four scanners follows this schema:

| Field | Type | Description |
|-------|------|-------------|
| vuln_type | string | Vulnerability type identifier |
| severity | string | Critical, High, Medium, Low, or Info |
| url | string | Affected endpoint URL |
| method | string | HTTP method (GET, POST) |
| parameter | string | Vulnerable parameter name |
| payload | string | Attack payload that triggered the finding |
| evidence | string | Human-readable evidence description |
| confidence | string | Confirmed, Firm, or Tentative |
| details | object | Additional metadata (varies by scanner) |

## Vulnerability Types

| vuln_type | Scanner | OWASP |
|-----------|---------|-------|
| SQL Injection (Error-Based) | SQLi | A03:2021 |
| SQL Injection (Boolean-Blind) | SQLi | A03:2021 |
| SQL Injection (Time-Based Blind) | SQLi | A03:2021 |
| Broken Access Control (Unauthenticated Access) | BAC | A01:2021 |
| Broken Access Control (IDOR) | BAC | A01:2021 |
| Authentication Failure (Weak Credentials) | Auth | A07:2021 |
| Authentication Failure (Missing Rate Limiting) | Auth | A07:2021 |
| Authentication Failure (Missing CSRF Protection) | Auth | A07:2021 |
| Authentication Failure (Insecure Session Cookie) | Auth | A07:2021 |
| Security Misconfiguration (Missing Header) | Misconfig | A05:2021 |
| Security Misconfiguration (Exposed Sensitive File) | Misconfig | A05:2021 |
| Security Misconfiguration (Information Disclosure) | Misconfig | A05:2021 |
| Security Misconfiguration (Verbose Error Page) | Misconfig | A05:2021 |