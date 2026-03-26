# AEGIS Scanner

**AI-Based Automated Web Application Vulnerability Scanner**

NIT6150 Advanced Project — NMIT / Victoria University

---

## Overview

AEGIS Scanner is a DAST (Dynamic Application Security Testing) tool that scans web applications for vulnerabilities across four OWASP Top 10 categories:

- **A03:2021 — Injection** (SQL Injection: error-based, boolean-blind, time-based blind)
- **A01:2021 — Broken Access Control** (unauthenticated access, IDOR)
- **A07:2021 — Identification and Authentication Failures** (weak credentials, missing rate limiting, CSRF, session security)
- **A05:2021 — Security Misconfiguration** (missing headers, exposed files, info disclosure, verbose errors)

A trained **Random Forest classifier** predicts an overall risk level (Safe → Critical) from scan findings, and a **policy engine** maps each finding to actionable OWASP remediation guidance.

## Architecture

```
User enters URL
       │
       ▼
┌──────────────┐
│  Flask API   │  POST /api/scan
└──────┬───────┘
       │ ThreadPoolExecutor (4 workers)
       ▼
  ┌─────────┐
  │ Crawler │ → discovers endpoints, forms, API paths
  └────┬────┘
       │
  ┌────┴──────────────────────────────┐
  │  SQLi  │  BAC   │  Auth  │ Misconfig │  ← 4 scanners in parallel
  └────┬──────┬────────┬────────┬─────┘
       │      │        │        │
       ▼      ▼        ▼        ▼
  Combined findings → Feature Extractor → Random Forest → Risk Level
                                                │
                                          Policy Engine → Recommendations
                                                │
                                          PDF Report + JSON API Response
                                                │
                                          React Dashboard
```

## Quick Start

### Prerequisites

- Python 3.12+
- Node.js 18+

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Train the ML model (one time)

```bash
python -m backend.ml.train_model
```

### 3. Start the vulnerable test app

```bash
cd vulnerable_app
python setup_db.py
python app.py
```

Runs at `http://localhost:8080`

### 4. Start the scanner API

```bash
python -m backend.app
```

Runs at `http://localhost:5000`

### 5. Start the React frontend

```bash
cd frontend
npm install
npm start
```

Opens at `http://localhost:3000`

### 6. Scan

Enter `http://localhost:8080` in the dashboard and click **Scan Target**.

## API Reference

### POST /api/scan

```json
{
  "target_url": "http://localhost:8080",
  "auth_cookie": {"session": "abc123"},
  "generate_report": true
}
```

Returns structured JSON with findings, risk prediction, recommendations, and report download URL.

### GET /api/report/:id

Download a generated PDF report.

### GET /api/model-info

Returns ML model metadata (type, accuracy, feature importances).

### GET /api/health

Health check endpoint.

## Running Tests

```bash
pytest tests/ -v
```

## Project Structure

```
aegis-scanner/
├── backend/
│   ├── app.py                  # Flask API
│   ├── config.py               # Configuration constants
│   ├── scanners/
│   │   ├── crawler.py          # Endpoint discovery
│   │   ├── sqli_scanner.py     # SQL Injection scanner
│   │   ├── bac_scanner.py      # Broken Access Control scanner
│   │   ├── auth_scanner.py     # Authentication scanner
│   │   └── misconfig_scanner.py # Misconfiguration scanner
│   ├── ml/
│   │   ├── synthetic_data.py   # Training data generator
│   │   ├── feature_extractor.py # Findings → feature vector
│   │   ├── train_model.py      # Train Random Forest
│   │   └── risk_predictor.py   # Runtime predictions
│   ├── utils/
│   │   ├── http_client.py      # HTTP request engine
│   │   ├── response_analyzer.py # Response diff engine
│   │   ├── payload_manager.py  # Payload file loader
│   │   ├── policy_engine.py    # OWASP remediation mapping
│   │   └── report_generator.py # PDF report generation
│   └── payloads/               # Attack payload files
├── frontend/
│   └── src/App.jsx             # React dashboard
├── vulnerable_app/             # Deliberately insecure test target
├── tests/                      # Unit tests
└── docs/                       # Documentation
```

## Methodology

The scanner implements the same conceptual methodology as commercial DAST tools like Burp Suite Professional:

1. **Crawling** — BFS traversal to discover endpoints, forms, and API paths
2. **Insertion Point Analysis** — every parameter is treated as a potential injection point
3. **Baseline Comparison** — original request sent first, then payloads injected and responses compared
4. **Differential Analysis** — error patterns, status changes, length ratios, timing differences
5. **Parallel Scanning** — all four scanners run simultaneously via ThreadPoolExecutor

## Limitations

- Static crawler (requests + BeautifulSoup) — does not execute JavaScript or handle SPAs
- Focused payload sets — not as comprehensive as commercial tools with 15+ years of refinement
- Single-session BAC testing — true horizontal privilege escalation requires two authenticated sessions
- Synthetic ML training data — model accuracy depends on quality of generated samples

## License

Academic project — NIT6150, NMIT / Victoria University.