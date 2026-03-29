# Security Misconfiguration Scanner & Vulnerable Test App

## Author: Susam Tamang

## Misconfiguration Scanner (misconfig_scanner.py)
Detects A05:2021 Security Misconfiguration:

*Passive Checks (0 extra requests):*
- Missing security headers: CSP, X-Frame-Options, HSTS, 
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Information disclosure: Server, X-Powered-By headers
- Verbose error pages: stack traces, debug mode detection

*Active Checks (54 probes):*
- Sensitive file probing: /.env, /.git/HEAD, /config.json, 
  /debug, /robots.txt, /backup.sql
- Soft-404 detection: avoids false positives from apps that 
  return HTTP 200 for non-existent pages

## Vulnerable Test Application
Purpose-built Flask app with deliberate vulnerabilities:
- SQL Injection: string concatenation in queries (f-strings)
- No auth checks: /admin, /dashboard, /api/* unprotected
- Weak credentials: admin:admin, test:test, guest:guest, demo:demo
- Exposed files: /.env, /.git/config, /config.json, /debug
- Missing headers: no CSP, HSTS, X-Frame-Options
- Verbose errors: Flask debug mode with stack traces

100% detection rate: every vulnerability found by the scanners

## Test Database (setup_db.py)
Creates SQLite database with users, products, and orders tables.
Pre-loaded with test accounts for credential testing.

## React Frontend
Dashboard with URL input, severity cards, risk gauge, OWASP chart, 
severity distribution, filterable findings table, PDF download