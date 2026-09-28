"""Sample vulnerable Python code for testing AST security rule detection."""

import os
import subprocess
import pickle
import hashlib


def handle_user_calculation(user_input: str):
    # Rule PY001: eval() Code Injection
    result = eval(user_input)
    return result


def execute_admin_script(script_code: str):
    # Rule PY002: exec() Code Injection
    exec(script_code)


def ping_host(host_ip: str):
    # Rule PY003: os.system Command Injection
    os.system("ping -c 1 " + host_ip)


def read_system_log(logfile: str):
    # Rule PY004: os.popen Command Injection
    pipe = os.popen(f"cat /var/log/{logfile}")
    return pipe.read()


def run_diagnostics(target: str):
    # Rule PY005: subprocess with shell=True
    subprocess.run(f"traceroute {target}", shell=True)


def get_user_profile(db_cursor, username: str):
    # Rule PY006: SQL Injection with f-string
    query = f"SELECT id, name, email FROM users WHERE username = '{username}'"
    db_cursor.execute(query)


def load_session_state(serialized_blob: bytes):
    # Rule PY007: Insecure Deserialization
    state = pickle.loads(serialized_blob)
    return state


def store_user_password(password: str):
    # Rule PY008: Weak Hashing (MD5)
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


# Rule PY009: Hardcoded Secret
api_key = "sk_live_998877665544332211"
