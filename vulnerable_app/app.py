"""
AEGIS Scanner — Deliberately Vulnerable Web Application
A purposefully insecure Flask app for testing and demonstrating
the AEGIS vulnerability scanner.

!! WARNING: This application is INTENTIONALLY VULNERABLE !!
!! DO NOT deploy this on any public-facing server          !!
!! Run ONLY on localhost for testing purposes              !!

Vulnerabilities included:
- SQL Injection (error-based, blind, time-based) in search and user lookup
- Broken Access Control (unauthenticated API access, IDOR)
- Authentication Failures (weak passwords, no rate limiting, no CSRF)
- Security Misconfiguration (missing headers, exposed files, verbose errors, info disclosure)
"""

import os
import sqlite3
import time
from functools import wraps
from flask import (
    Flask, request, jsonify, render_template, redirect,
    url_for, session, make_response,
)

app = Flask(__name__)
app.secret_key = "super_insecure_secret_key_12345"  # Intentionally weak

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnerable.db")


# ---------------------------------------------------------------------------
# Database helper — intentionally uses string formatting (NOT parameterised)
# ---------------------------------------------------------------------------
def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def query_db(query, args=(), one=False):
    """Execute a query and return results."""
    conn = get_db()
    cursor = conn.execute(query, args)
    results = cursor.fetchall()
    conn.close()
    if one:
        return results[0] if results else None
    return results


def execute_db(query, args=()):
    """Execute a write query."""
    conn = get_db()
    conn.execute(query, args)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# VULNERABILITY: No security headers middleware
# (Security Misconfiguration — missing headers, info disclosure)
# ---------------------------------------------------------------------------
@app.after_request
def add_insecure_headers(response):
    """Intentionally omit security headers and expose server info."""
    # VULNERABILITY: Server version disclosure
    response.headers["Server"] = "Werkzeug/3.0.1 Python/3.12.10"
    response.headers["X-Powered-By"] = "Flask/3.0.3"

    # VULNERABILITY: No security headers set
    # Missing: Content-Security-Policy, X-Frame-Options,
    #          X-Content-Type-Options, Strict-Transport-Security,
    #          Referrer-Policy, Permissions-Policy

    return response


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Home page with links to all features."""
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login page.

    VULNERABILITIES:
    - No CSRF token on the form
    - No rate limiting on login attempts
    - Weak credentials accepted (admin:admin, test:test, etc.)
    - Session cookie without HttpOnly/Secure/SameSite flags
    """
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABILITY: SQL Injection in login query
        # Using string formatting instead of parameterised query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        try:
            user = query_db(query, one=True)
        except Exception as e:
            # VULNERABILITY: Verbose error — exposes SQL error details
            error = f"Database error: {str(e)}"
            return render_template("login.html", error=error)

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            # VULNERABILITY: Session cookie without security flags
            response = make_response(redirect(url_for("dashboard")))
            response.set_cookie(
                "session_token",
                f"token_{user['id']}_{user['username']}",
                # Missing: httponly=True, secure=True, samesite='Lax'
            )
            return response

        error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    """Log out the current user."""
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    """
    Dashboard page — should require authentication.

    VULNERABILITY: No authentication check — accessible without login
    (Broken Access Control)
    """
    # VULNERABILITY: No auth check here
    username = session.get("username", "Guest")
    role = session.get("role", "unknown")
    return f"""
    <html>
    <body>
        <h1>Dashboard</h1>
        <p>Welcome, {username} (role: {role})</p>
        <p><a href="/admin">Admin Panel</a></p>
        <p><a href="/api/users">API: Users</a></p>
        <p><a href="/api/products">API: Products</a></p>
        <p><a href="/logout">Logout</a></p>
    </body>
    </html>
    """


@app.route("/admin")
def admin_panel():
    """
    Admin panel — should require admin role.

    VULNERABILITY: No role check — any user (or no user) can access
    (Broken Access Control)
    """
    # VULNERABILITY: No authentication or role check
    users = query_db("SELECT id, username, email, role, is_active FROM users")
    user_list = ""
    for u in users:
        user_list += (
            f"<tr><td>{u['id']}</td><td>{u['username']}</td>"
            f"<td>{u['email']}</td><td>{u['role']}</td></tr>"
        )

    return f"""
    <html>
    <body>
        <h1>Admin Panel</h1>
        <h2>All Users</h2>
        <table border="1">
            <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
            {user_list}
        </table>
        <p><a href="/dashboard">Back to Dashboard</a></p>
    </body>
    </html>
    """


# ---------------------------------------------------------------------------
# VULNERABILITY: SQL Injection endpoints
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    """
    Product search — vulnerable to SQL Injection.

    VULNERABILITY: User input directly concatenated into SQL query.
    Allows error-based, boolean-blind, and time-based blind SQLi.
    """
    q = request.args.get("q", "")

    # VULNERABILITY: String concatenation in SQL query
    query = f"SELECT id, name, price, description FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"

    try:
        results = query_db(query)
        items = ""
        for r in results:
            items += (
                f"<tr><td>{r['id']}</td><td>{r['name']}</td>"
                f"<td>${r['price']}</td><td>{r['description']}</td></tr>"
            )

        return f"""
        <html>
        <body>
            <h1>Product Search</h1>
            <form action="/search" method="GET">
                <input name="q" value="{q}" placeholder="Search products...">
                <button type="submit">Search</button>
            </form>
            <table border="1">
                <tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>
                {items}
            </table>
            <p>Found {len(results)} result(s)</p>
        </body>
        </html>
        """
    except Exception as e:
        # VULNERABILITY: Verbose SQL error returned to user
        return f"""
        <html>
        <body>
            <h1>Search Error</h1>
            <p style="color:red;">Database error: {str(e)}</p>
            <p>Query: {query}</p>
            <a href="/search">Try again</a>
        </body>
        </html>
        """, 500


# ---------------------------------------------------------------------------
# VULNERABILITY: API endpoints without authentication
# (Broken Access Control)
# ---------------------------------------------------------------------------
@app.route("/api/users")
def api_users():
    """
    API: List all users.

    VULNERABILITY: No authentication required — anyone can access.
    Also exposes password hashes (in this case, plaintext passwords).
    """
    users = query_db("SELECT id, username, email, role FROM users")
    return jsonify([dict(u) for u in users])


@app.route("/api/users/<int:user_id>")
def api_user_detail(user_id):
    """
    API: Get user details by ID.

    VULNERABILITY: No authentication + IDOR — can access any user's data
    by changing the ID parameter.
    """
    # VULNERABILITY: SQL Injection via user_id (though integer, the
    # pattern is demonstrated in the query string version below)
    user = query_db(
        f"SELECT id, username, email, role FROM users WHERE id = {user_id}",
        one=True,
    )
    if user:
        return jsonify(dict(user))
    return jsonify({"error": "User not found"}), 404


@app.route("/api/products")
def api_products():
    """
    API: List products.

    VULNERABILITY: No authentication — exposes internal_notes field
    which contains supplier costs and license keys.
    """
    products = query_db(
        "SELECT id, name, price, description, internal_notes FROM products"
    )
    return jsonify([dict(p) for p in products])


@app.route("/api/products/<int:product_id>")
def api_product_detail(product_id):
    """
    API: Get product by ID.

    VULNERABILITY: IDOR — changing product_id gives access to non-public
    products including internal tools and secret prototypes.
    """
    product = query_db(
        f"SELECT * FROM products WHERE id = {product_id}",
        one=True,
    )
    if product:
        return jsonify(dict(product))
    return jsonify({"error": "Product not found"}), 404


@app.route("/api/orders")
def api_orders():
    """
    API: List orders.

    VULNERABILITY: Returns ALL orders for ALL users without authentication.
    Should filter by the authenticated user's ID.
    """
    orders = query_db("""
        SELECT o.id, o.user_id, u.username, o.product_id, p.name as product_name,
               o.quantity, o.total, o.status, o.created_at
        FROM orders o
        JOIN users u ON o.user_id = u.id
        JOIN products p ON o.product_id = p.id
    """)
    return jsonify([dict(o) for o in orders])


@app.route("/api/orders/<int:order_id>")
def api_order_detail(order_id):
    """
    API: Get order by ID.

    VULNERABILITY: IDOR — can access any user's order by changing the ID.
    """
    order = query_db(
        f"SELECT * FROM orders WHERE id = {order_id}",
        one=True,
    )
    if order:
        return jsonify(dict(order))
    return jsonify({"error": "Order not found"}), 404


# ---------------------------------------------------------------------------
# VULNERABILITY: SQL Injection via API parameter
# ---------------------------------------------------------------------------
@app.route("/api/search")
def api_search():
    """
    API: Search products.

    VULNERABILITY: SQL Injection — q parameter is concatenated directly.
    """
    q = request.args.get("q", "")

    # VULNERABILITY: Direct string concatenation
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"

    try:
        results = query_db(query)
        return jsonify([dict(r) for r in results])
    except Exception as e:
        # VULNERABILITY: SQL error exposed in API response
        return jsonify({"error": str(e), "query": query}), 500


# ---------------------------------------------------------------------------
# VULNERABILITY: Exposed sensitive files
# (Security Misconfiguration)
# ---------------------------------------------------------------------------
@app.route("/.env")
def exposed_env():
    """VULNERABILITY: .env file accessible — exposes secrets."""
    return """
# Application Configuration
APP_SECRET=super_insecure_secret_key_12345
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=production_password_123
DB_NAME=vulnerable_app
API_KEY=sk-1234567890abcdef
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SMTP_PASSWORD=email_password_456
""", 200, {"Content-Type": "text/plain"}


@app.route("/.git/HEAD")
def exposed_git():
    """VULNERABILITY: Git metadata accessible — reveals branch info."""
    return "ref: refs/heads/main\n", 200, {"Content-Type": "text/plain"}


@app.route("/.git/config")
def exposed_git_config():
    """VULNERABILITY: Git config accessible — reveals repo URL."""
    return """[core]
\trepositoryformatversion = 0
\tfilemode = true
[remote "origin"]
\turl = https://github.com/example/vulnerable-app.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
""", 200, {"Content-Type": "text/plain"}


@app.route("/robots.txt")
def robots():
    """Robots.txt that reveals sensitive paths."""
    return """User-agent: *
Disallow: /admin
Disallow: /api/
Disallow: /.env
Disallow: /backup.sql
Disallow: /debug
""", 200, {"Content-Type": "text/plain"}


@app.route("/config.json")
def exposed_config():
    """VULNERABILITY: Application config exposed."""
    return jsonify({
        "database": {"host": "localhost", "user": "root", "password": "db_pass_123"},
        "api_keys": {"stripe": "sk_test_12345", "sendgrid": "SG.xxxxx"},
        "debug": True,
        "secret_key": "super_insecure_secret_key_12345",
    })


# ---------------------------------------------------------------------------
# VULNERABILITY: Debug / verbose error endpoint
# ---------------------------------------------------------------------------
@app.route("/debug")
def debug_page():
    """VULNERABILITY: Debug endpoint exposed in production."""
    return jsonify({
        "debug_mode": True,
        "python_version": "3.12.10",
        "flask_version": "3.0.3",
        "database": DB_PATH,
        "secret_key": app.secret_key,
        "environment_variables": {
            k: v for k, v in os.environ.items()
            if not k.startswith("_")
        },
    })


# ---------------------------------------------------------------------------
# Error handlers — intentionally verbose
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    """VULNERABILITY: Verbose 404 that reveals framework info."""
    return f"""
    <html>
    <body>
        <h1>404 — Page Not Found</h1>
        <p>The requested URL was not found on this server.</p>
        <p><small>Werkzeug Debugger — Flask/3.0.3 Python/3.12.10</small></p>
    </body>
    </html>
    """, 404


@app.errorhandler(500)
def server_error(e):
    """VULNERABILITY: Verbose 500 with stack trace."""
    import traceback
    tb = traceback.format_exc()
    return f"""
    <html>
    <body>
        <h1>500 — Internal Server Error</h1>
        <p>An unexpected error occurred.</p>
        <h2>Stack Trace:</h2>
        <pre>{tb}</pre>
        <p><small>Debug mode is on — Werkzeug Debugger</small></p>
    </body>
    </html>
    """, 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("Database not found. Run 'python setup_db.py' first.")
        exit(1)

    print("=" * 50)
    print("  VULNERABLE TEST APPLICATION")
    print("  !! FOR TESTING ONLY — DO NOT DEPLOY !!")
    print("=" * 50)
    print(f"\n  Running at: http://localhost:8080")
    print(f"  Database:   {DB_PATH}")
    print(f"\n  Test accounts:")
    print(f"    admin:admin")
    print(f"    test:test")
    print(f"    guest:guest")
    print(f"\n  Vulnerable endpoints:")
    print(f"    /search?q=test        (SQLi)")
    print(f"    /api/search?q=test    (SQLi)")
    print(f"    /api/users            (BAC)")
    print(f"    /api/orders           (BAC)")
    print(f"    /login                (Weak auth)")
    print(f"    /.env                 (Misconfig)")
    print(f"    /.git/HEAD            (Misconfig)")
    print()

    app.run(
        host="0.0.0.0",
        port=8080,
        debug=False,  # Don't use Flask's debug mode — we handle errors ourselves
    )