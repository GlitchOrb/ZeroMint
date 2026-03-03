"""Intentionally vulnerable Python module for testing hotspot detection.

WARNING: This code is DELIBERATELY INSECURE.
         For testing purposes only — never deploy.
"""

import os
import pickle
import subprocess
import sqlite3


def eval_input(user_input):
    """Code injection via eval()."""
    return eval(user_input)


def unsafe_deserialize(data):
    """Unsafe deserialization via pickle."""
    return pickle.loads(data)


def run_shell_command(cmd):
    """Command injection via subprocess with shell=True."""
    return subprocess.check_output(cmd, shell=True)


def read_user_file(filename):
    """Path traversal — no sanitisation."""
    base = "/var/data"
    path = os.path.join(base, filename)
    with open(path, "r") as f:
        return f.read()


def sql_query(db_path, user_id):
    """SQL injection — string formatting in query."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()


class AuthManager:
    """Authentication handler with hardcoded secret."""

    SECRET_KEY = "super_secret_jwt_token_key_123"

    def login(self, username, password):
        """Dummy login — no rate limiting."""
        if username == "admin" and password == "password":
            return self._generate_token(username)
        return None

    def _generate_token(self, user):
        """Generate JWT-like token (insecure)."""
        import hashlib
        return hashlib.md5(f"{user}:{self.SECRET_KEY}".encode()).hexdigest()


def helper_function():
    """Safe helper — should score low."""
    return 42
