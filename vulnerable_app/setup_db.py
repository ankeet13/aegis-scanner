# Author: Susam — Database Setup Script

"""
AEGIS Scanner — Vulnerable App Database Setup
Creates a SQLite database with test data for the deliberately
vulnerable demo application.

Tables:
    users     — test accounts with plaintext passwords (intentionally insecure)
    products  — sample product data for IDOR testing
    orders    — sample order data tied to users

Usage:
    cd vulnerable_app
    python setup_db.py
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnerable.db")


def setup():
    """Create the database and populate with test data."""

    # Remove existing DB to start fresh
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ------------------------------------------------------------------
    # Users table — passwords stored in PLAINTEXT (intentionally insecure)
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1
        )
    """)

    users = [
        ("admin", "admin", "admin@example.com", "admin"),
        ("admin2", "password", "admin2@example.com", "admin"),
        ("user1", "user1pass", "user1@example.com", "user"),
        ("user2", "user2pass", "user2@example.com", "user"),
        ("test", "test", "test@example.com", "user"),
        ("guest", "guest", "guest@example.com", "guest"),
        ("demo", "demo", "demo@example.com", "user"),
    ]

    cursor.executemany(
        "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
        users,
    )

    # ------------------------------------------------------------------
    # Products table — for IDOR testing
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT,
            internal_notes TEXT,
            is_public INTEGER DEFAULT 1
        )
    """)

    products = [
        ("Widget A", 29.99, "A standard widget", "Supplier: Acme Corp, cost: $12.50", 1),
        ("Widget B", 49.99, "A premium widget", "Supplier: Globex, cost: $22.00", 1),
        ("Secret Prototype", 999.99, "Unreleased product", "DO NOT SHARE - Patent pending #12345", 0),
        ("Internal Tool", 0.00, "Admin-only tool", "License key: XXXX-YYYY-ZZZZ", 0),
    ]

    cursor.executemany(
        "INSERT INTO products (name, price, description, internal_notes, is_public) "
        "VALUES (?, ?, ?, ?, ?)",
        products,
    )

    # ------------------------------------------------------------------
    # Orders table — for IDOR testing (user-specific data)
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER DEFAULT 1,
            total REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    """)

    orders = [
        (1, 1, 2, 59.98, "shipped"),
        (1, 2, 1, 49.99, "delivered"),
        (3, 1, 1, 29.99, "pending"),
        (4, 2, 3, 149.97, "processing"),
        (3, 2, 1, 49.99, "shipped"),
    ]

    cursor.executemany(
        "INSERT INTO orders (user_id, product_id, quantity, total, status) "
        "VALUES (?, ?, ?, ?, ?)",
        orders,
    )

    conn.commit()
    conn.close()

    print(f"Database created at: {DB_PATH}")
    print(f"  Users: {len(users)}")
    print(f"  Products: {len(products)}")
    print(f"  Orders: {len(orders)}")
    print("\nTest accounts:")
    print("  admin:admin (admin role)")
    print("  test:test (user role)")
    print("  guest:guest (guest role)")


if __name__ == "__main__":
    setup()