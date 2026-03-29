# Crawler & Broken Access Control Scanner

## Author: Sudip Ojha

## Crawler (crawler.py)

### Overview
The crawler discovers all endpoints, forms, and API paths on a target 
website using a three-phase approach. It supports both static HTML 
websites and JavaScript-rendered SPAs (Angular, React, Vue) through 
Playwright headless browser integration.

### Three-Phase Discovery

**Phase 1 — Common Path Probing**
Sends requests to ~60 well-known paths (/login, /admin, /api/users, 
/dashboard, /debug, /robots.txt). Any path returning HTTP 200 is 
added to the crawl queue. This discovers hidden pages not linked 
from the homepage.

**Phase 2 — Playwright Headless Browser**
Launches an invisible Chromium browser that:
- Renders JavaScript and waits for dynamic content
- Intercepts ALL network requests (discovers hidden API calls)
- Extracts links and forms from the rendered DOM
- Clicks buttons, nav links, and interactive elements
- Supports Angular routerLink, Vue @click, AngularJS ng-click

**Phase 3 — BFS Static HTML Crawl**
Breadth-first search across all discovered URLs. Extracts URLs from 
seven sources: anchor links, resource tags, form actions, JavaScript 
code, HTML comments, data attributes, and meta refresh tags.

### Key Design Decisions
- Graceful fallback: works without Playwright (static HTML only)
- Domain restriction: never crawls external websites
- Deduplication: visited set prevents re-crawling
- Depth limiting: MAX_CRAWL_DEPTH = 5
- URL limiting: MAX_URLS = 100
- Static file skipping: ignores .png, .css, .js, .pdf

### Output
List of Endpoint objects, each containing:
- URL, HTTP method, parameters (insertion points)
- Form field types (used by Auth scanner to find login forms)
- Whether it came from a form submission

### Comparison to Industry Tools
Mirrors Burp Suite's Chromium-based crawler introduced in v2.0. 
Same approach: real browser rendering + network interception.

---

## Broken Access Control Scanner (bac_scanner.py)

### Overview
Detects A01:2021 Broken Access Control using two techniques:
1. Unauthenticated Access Testing
2. IDOR (Insecure Direct Object Reference) Detection

### Test 1 — Unauthenticated Access
Mirrors Burp Suite's Autorize extension:
1. Send request WITH auth cookies → authenticated response
2. Send SAME request WITHOUT cookies → unauthenticated response
3. Compare using SequenceMatcher similarity algorithm
4. If similarity > 85% → BAC Confirmed (Critical/High)
5. If 401/403 returned → properly protected

The 85% threshold (not 100%) accounts for dynamic content like 
timestamps, CSRF tokens, and greeting text.

### Test 2 — IDOR Detection
1. Find parameters that look like IDs (numeric, UUID, name-based)
2. Change ID value to adjacent numbers (id=5 → id=4, 6, 1, 0)
3. Compare responses: similarity 0.3-0.95 = different data, same 
   page structure = IDOR confirmed

### Severity Classification
- Critical: endpoints matching /admin, /api/, /dashboard, /settings
- High: other endpoints accessible without authentication

### Dependencies
- config.py: BAC_SIMILARITY_THRESHOLD, BAC_SENSITIVE_PATTERNS
- http_client.py: send_baseline(), send_without_auth(), send_attack()
- response_analyzer.py: check_bac_vulnerability(), check_similarity()
- sqli_scanner.py: Finding class (shared data structure)

---

## Payload Manager (payload_manager.py)

### Overview
Centralised file loader with in-memory caching. All four scanners 
request payloads through this module instead of reading files directly.

### Features
- Class-level cache: each file read once, returned from memory after
- Supports .txt (one payload per line) and .json (structured data)
- Comment filtering: lines starting with # are skipped
- Empty line filtering: blank lines are ignored

### Payload Files Served
| Method | File | Used By |
|--------|------|---------|
| get_sqli_error_payloads() | sqli_error.txt | SQLi Scanner |
| get_sqli_blind_payloads() | sqli_blind.txt | SQLi Scanner |
| get_sqli_time_payloads() | sqli_time.txt | SQLi Scanner |
| get_common_credentials() | common_creds.txt | Auth Scanner |
| get_sensitive_paths() | sensitive_paths.txt | Misconfig Scanner |
| get_security_headers_config() | security_headers.json | Misconfig Scanner |