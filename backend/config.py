# Author: Shristi — Configuration Module

"""
AEGIS Scanner — Configuration
Central constants, timeouts, thresholds, and paths used across all modules.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "true").lower() == "true"

# ---------------------------------------------------------------------------
# HTTP Client
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", 30))
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", 0.1))
USER_AGENT = os.getenv("USER_AGENT", "AEGIS-Scanner/1.0 (NIT6150 Academic Project)")
MAX_RETRIES = 2

# Default headers sent with every request
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/json,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------
MAX_CRAWL_DEPTH = int(os.getenv("MAX_CRAWL_DEPTH", 5))
MAX_URLS = int(os.getenv("MAX_URLS", 100))
IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
}

# ---------------------------------------------------------------------------
# SQL Injection Scanner
# ---------------------------------------------------------------------------
SQLI_TIME_THRESHOLD = 4.5          # seconds — if response takes longer, likely time-based SQLi
SQLI_BLIND_LENGTH_RATIO = 0.6      # if attack response length < 60% of baseline, boolean-blind flag
SQLI_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"mysql_fetch",
    r"mysql_num_rows",
    # PostgreSQL
    r"pg_query",
    r"pg_exec",
    r"valid PostgreSQL result",
    r"unterminated quoted string",
    # SQLite
    r"sqlite3\.OperationalError",
    r"SQLite\/JDBCDriver",
    r"sqlite\.SQLiteException",
    r"unrecognized token",
    # MSSQL
    r"microsoft sql native client error",
    r"mssql_query",
    r"\bOLE DB\b.*\bSQL Server\b",
    r"SQL Server.*Driver",
    # Oracle
    r"ORA-\d{5}",
    r"oracle error",
    r"quoted string not properly terminated",
    # Generic
    r"sql syntax.*error",
    r"syntax error.*sql",
    r"unexpected end of sql",
    r"division by zero",
]

# ---------------------------------------------------------------------------
# Broken Access Control Scanner
# ---------------------------------------------------------------------------
BAC_SIMILARITY_THRESHOLD = 0.85    # if unauth response is >85% similar to auth, likely BAC issue
BAC_SENSITIVE_PATTERNS = [
    r"/admin",
    r"/api/admin",
    r"/dashboard",
    r"/settings",
    r"/users",
    r"/api/users",
    r"/api/v\d+/",
    r"/profile",
    r"/account",
    r"/config",
    r"/internal",
    r"/management",
]

# ---------------------------------------------------------------------------
# Authentication Scanner
# ---------------------------------------------------------------------------
AUTH_MAX_ATTEMPTS = 20              # max credential pairs to test
AUTH_LOCKOUT_THRESHOLD = 10         # if >N attempts succeed without lockout, flag it
AUTH_SUCCESS_INDICATORS = [
    "dashboard",
    "welcome",
    "logout",
    "my account",
    "profile",
    "session",
]
AUTH_FAILURE_INDICATORS = [
    "invalid",
    "incorrect",
    "wrong password",
    "login failed",
    "authentication failed",
    "access denied",
    "bad credentials",
]

# ---------------------------------------------------------------------------
# Security Misconfiguration Scanner
# ---------------------------------------------------------------------------
EXPECTED_SECURITY_HEADERS = {
    "Content-Security-Policy": "Prevents XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking by controlling iframe embedding",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Controls browser feature access",
    "X-XSS-Protection": "Legacy XSS filter (backup for older browsers)",
}

INFO_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]

# ---------------------------------------------------------------------------
# ML Risk Predictor
# ---------------------------------------------------------------------------
MODEL_PATH = os.getenv("MODEL_PATH", "backend/ml/model/risk_model.pkl")
RISK_LEVELS = ["Safe", "Low", "Medium", "High", "Critical"]

# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "reports")

# ---------------------------------------------------------------------------
# Payload File Paths
# ---------------------------------------------------------------------------
PAYLOAD_DIR = os.path.join(os.path.dirname(__file__), "payloads")
PAYLOAD_FILES = {
    "sqli_error": os.path.join(PAYLOAD_DIR, "sqli_error.txt"),
    "sqli_blind": os.path.join(PAYLOAD_DIR, "sqli_blind.txt"),
    "sqli_time": os.path.join(PAYLOAD_DIR, "sqli_time.txt"),
    "common_creds": os.path.join(PAYLOAD_DIR, "common_creds.txt"),
    "sensitive_paths": os.path.join(PAYLOAD_DIR, "sensitive_paths.txt"),
    "security_headers": os.path.join(PAYLOAD_DIR, "security_headers.json"),
}

# ---------------------------------------------------------------------------
# Severity Weights (used by feature extractor)
# ---------------------------------------------------------------------------
SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 2,
    "Info": 1,
}