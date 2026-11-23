"""Sample secure Python code for testing false-positive baseline."""

import subprocess
import json
import hashlib
import os


def safe_math(a: int, b: int) -> int:
    return a + b


def safe_ping(host_ip: str):
    # Safe subprocess execution without shell=True, parameterized list
    return subprocess.run(["ping", "-c", "1", host_ip], shell=False, check=True)


def safe_db_query(db_cursor, username: str):
    # Parameterized query - safe from SQL injection
    db_cursor.execute("SELECT id, name, email FROM users WHERE username = %s", (username,))


def safe_deserialize(json_payload: str):
    # Safe JSON deserialization instead of pickle
    return json.loads(json_payload)


def safe_password_hash(password: str):
    # SHA-256 is not flagged by weak hash rule
    return hashlib.sha256(password.encode()).hexdigest()


def read_config_from_env():
    # Secrets loaded from environment variables, not hardcoded
    return os.environ.get("API_KEY")
