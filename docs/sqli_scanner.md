# SQL Injection Scanner & Core Infrastructure

## Author: Shristi Tuladhar

## Core Infrastructure

### config.py
Central configuration for all scanners. Contains:
- Thresholds: SQLI_TIME_THRESHOLD (4.5s), BAC_SIMILARITY_THRESHOLD (0.85)
- Error patterns for 5 databases (MySQL, PostgreSQL, SQLite, MSSQL, Oracle)
- Sensitive URL patterns for BAC severity classification
- Payload file paths mapping
- Crawler limits (MAX_CRAWL_DEPTH=5, MAX_URLS=100)

### http_client.py
HTTP engine shared by the crawler and all 4 scanners:
- send_request(): basic HTTP request with cookies
- send_baseline(): authenticated request for comparison
- send_attack(): replaces one parameter with payload
- send_without_auth(): creates clean session with no cookies
- send_timed_attack(): measures response time for time-based SQLi

### response_analyzer.py
Detection engine shared by all 4 scanners:
- check_error_patterns(): searches response for database error strings
- check_length_differential(): compares response sizes
- check_time_differential(): compares response times
- check_bac_vulnerability(): compares auth vs unauth responses
- check_similarity(): SequenceMatcher ratio between two responses

### Finding class (in sqli_scanner.py)
Universal data structure imported by all 4 scanners:
vuln_type, severity, url, method, parameter, payload, evidence, 
confidence, details

## SQL Injection Scanner (sqli_scanner.py)

### Three Detection Techniques

**Error-Based**: Inject payloads, check for database error patterns
**Boolean-Blind**: Send TRUE/FALSE pairs, compare response lengths
**Time-Based Blind**: Inject SLEEP(), measure response delay

### Scan Results (localhost:8080)
- 4 Error-Based: /login (username, password), /search (q), /api/search (q)
- 2 Boolean-Blind: /login (username, password)
- Total: 6 SQLi findings, all Confirmed