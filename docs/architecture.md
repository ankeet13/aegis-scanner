# AEGIS Scanner — Architecture Documentation

## 1. System Architecture

AEGIS Scanner follows a modular pipeline architecture with four distinct layers:

### 1.1 Presentation Layer (React Frontend)

The React dashboard provides a single-page application with three states: scan input, scanning progress, and results display. It communicates with the backend exclusively through the REST API. The frontend is stateless — all scan data lives on the backend.

Key components: URL input with auth cookie support, real-time progress simulation, severity summary cards, ML risk gauge (SVG donut), OWASP category bar chart (Recharts), severity distribution pie chart, expandable findings table with filtering, remediation recommendations accordion, and PDF download link.

### 1.2 API Layer (Flask)

The Flask REST API serves as the orchestration layer. It receives a target URL, coordinates the entire scan pipeline, and returns structured JSON. Four endpoints are exposed: POST /api/scan (main scan), GET /api/report/:id (PDF download), GET /api/model-info (ML metadata), and GET /api/health (health check).

The scan endpoint uses Python's ThreadPoolExecutor with 4 workers to run all scanners in parallel. Each scanner receives the same list of discovered endpoints and an HTTP client instance. Results are collected via futures and combined into a single findings list.

### 1.3 Scanner Layer

#### Crawler

The crawler performs breadth-first traversal starting from the target URL. It discovers endpoints by following anchor tags, extracting form actions with their input fields, and identifying API paths from inline JavaScript. Each discovered endpoint is represented as an Endpoint object containing the URL, HTTP method, query parameters, POST data, parameter names (insertion points), and form field metadata.

The crawler respects domain boundaries (only follows same-domain links), skips static resources (images, CSS, JS), normalises URLs to avoid re-crawling, and limits depth and total URLs via configuration.

#### SQL Injection Scanner

Implements three detection techniques mirroring Burp Suite's active scanner:

**Error-Based Detection:** For each parameterised endpoint, sends a baseline request to record normal behaviour, then injects payloads from sqli_error.txt into each parameter one at a time. The response body is checked against 20+ regex patterns covering MySQL, PostgreSQL, SQLite, MSSQL, and Oracle error strings. A match confirms the vulnerability. If no error pattern matches but the status code changed to 500, it records a tentative finding.

**Boolean-Blind Detection:** Uses paired payloads in TRUE|||FALSE format (e.g., "AND 1=1|||AND 1=2"). Injects the TRUE payload and compares its response to the baseline — they should be similar. Then injects the FALSE payload — its response should differ significantly. "Significantly" is defined by a body length ratio threshold (configurable, default 0.6). If TRUE matches baseline AND FALSE diverges, blind SQLi is confirmed.

**Time-Based Blind Detection:** Injects SLEEP/WAITFOR payloads and measures response time. If the attack response is more than 4.5 seconds slower than baseline, it sends a second verification request to reduce false positives. Both requests slow confirms the finding; only the first slow is tentative.

#### Broken Access Control Scanner

**Unauthenticated Access:** Mirrors Burp's Autorize extension. Sends each request with authentication cookies (baseline), then replays the exact same request without cookies. Uses SequenceMatcher to calculate content similarity between the two responses. If the unauthenticated response returns HTTP 200 with greater than 85% similarity, broken access control is confirmed. Endpoints matching sensitive patterns (/admin, /api/users, etc.) receive Critical severity; others receive High.

**IDOR Detection:** Identifies parameters that look like object IDs (numeric values, UUIDs, or names containing "id", "user", "item", etc.). Changes the ID to adjacent values (n-1, n+1, 0, 1) and checks if the server returns HTTP 200 with structurally similar but different content (similarity between 0.3 and 0.95). This range distinguishes between a real different object (IDOR) versus a public page that always returns the same content.

#### Authentication Scanner

**Weak Credentials:** Identifies login forms by finding forms with password-type input fields. Sends a known-bad login first to establish what failure looks like (baseline). Then tests credential pairs from common_creds.txt. Detects success using a multi-signal scoring system: HTTP redirect (score +2), success keywords in body like "dashboard" or "welcome" (score +2), absence of failure keywords like "invalid" or "incorrect" (score +1), response body length differs significantly from failure baseline (score +1), new Set-Cookie header issued (score +1). Score of 3 or higher indicates successful login. Automatically extracts and submits fresh CSRF tokens per request.

**Rate Limiting:** Submits a configurable number of rapid failed login attempts (default 10) and monitors for lockout indicators (keywords like "locked", "too many", "rate limit"), CAPTCHA presence, or HTTP 429 responses. If none detected, flags missing rate limiting.

**CSRF Protection:** Parses login form HTML for hidden input fields with common CSRF token names. Absence is flagged.

**Session Security:** Inspects Set-Cookie headers for missing HttpOnly, Secure, and SameSite flags.

#### Security Misconfiguration Scanner

**Passive Checks** (no extra requests): Analyses existing responses for missing security headers (loaded from security_headers.json with per-header severity and remediation guidance), information disclosure headers (Server, X-Powered-By), and verbose error patterns.

**Active Checks**: Probes 54 sensitive paths from sensitive_paths.txt. Includes a soft-404 detector to avoid false positives from applications that return HTTP 200 for non-existent pages. Checks response bodies for sensitive content patterns (database credentials, API keys, private keys, Git metadata). High-sensitivity paths like /.env and /.git/HEAD with actual sensitive content are upgraded to Critical severity.

### 1.4 ML Layer

**Synthetic Data Generation:** Generates 2,000 training samples (400 per risk level) encoding domain knowledge about how real-world vulnerabilities cluster. Safe applications have zero findings; Critical applications have confirmed SQLi combined with exposed credentials and heavy misconfiguration.

**Feature Extraction:** Converts raw Finding objects into a 23-element numeric feature vector. Features include counts per category, counts per severity, boolean flags for specific vulnerability subtypes, and derived metrics (total findings, weighted risk score).

**Model Training:** Random Forest classifier with 200 trees, max depth 15, balanced class weights. Trained with 80/20 stratified split. Evaluated via accuracy, per-class precision/recall/F1, confusion matrix, and 5-fold cross-validation. Feature importance ranking validates that the synthetic data produces sensible learning.

**Risk Prediction:** Loads the trained model at API startup. Extracts features from real scan findings, runs prediction, and returns the risk level with confidence (predicted class probability) and full probability distribution across all five levels. Includes a rule-based fallback for operation without a trained model.

## 2. Data Flow

```
Target URL
    → Crawler.crawl() → list[Endpoint]
    → SQLiScanner.scan(endpoints) → list[Finding]
    → BACScanner.scan(endpoints) → list[Finding]
    → AuthScanner.scan(endpoints) → list[Finding]
    → MisconfigScanner.scan(endpoints, target_url) → list[Finding]
    → All findings combined → list[dict] via Finding.to_dict()
    → extract_features(findings) → dict (23 features)
    → features_to_dataframe_row(features) → pandas DataFrame
    → model.predict(X) → risk_level + probabilities
    → PolicyEngine.generate_recommendations(findings, risk_level) → recommendations
    → ReportGenerator.generate(scan_results) → PDF file path
    → JSON response to React frontend
```

## 3. Key Design Decisions

**Insertion Point Model:** Adopted from Burp Suite. Every user-controllable parameter is an insertion point. Scanners iterate over every parameter on every endpoint, injecting payloads one at a time while keeping others at their original values. This systematic approach ensures complete coverage.

**Baseline Comparison:** Every scanner sends the original unmodified request first and records the response as a baseline. Attack responses are compared against this baseline — not against a static expected value. This handles dynamic content correctly.

**Parallel Scanning:** The four scanners are independent and can run simultaneously. ThreadPoolExecutor with 4 workers provides true parallelism. Each scanner failure is isolated — one crashing scanner doesn't affect the others.

**Synthetic Training Data:** Real-world training data would require scanning thousands of diverse applications. Synthetic generation encodes security domain knowledge directly, is reproducible, and can be regenerated with different distributions as needed.

**Rule-Based Fallback:** The risk predictor works without a trained model by using a hand-crafted decision tree. This ensures the scanner is functional from first deployment and allows the ML model to be validated against the rule-based baseline.