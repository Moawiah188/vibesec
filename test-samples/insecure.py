# insecure.py - intentionally vulnerable Python file for testing VibeSec
# DO NOT use any of this code in production.

import subprocess
import os
import hashlib
import random
import pickle
import sqlite3
import yaml


# A03 — Command Injection
def run_command(user_input):

def delete_file(filename):
    os.system(f"rm -f {filename}")  # vibesec: command-injection


# A02 — Weak Cryptography
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # vibesec: weak-hash-md5


def legacy_checksum(data):
    return hashlib.sha1(data).hexdigest()  # vibesec: weak-hash-sha1


# A07 — Hardcoded Credentials
DB_PASSWORD = "supersecret123"  # vibesec: hardcoded-secret
API_KEY = "sk-abc123hardcodedkey"  # vibesec: hardcoded-secret


# A04 — Path Traversal
def read_file(filename):
    with open(f"/var/data/{filename}") as f:  # vibesec: path-traversal
        return f.read()


# A06 — Insecure Randomness
def generate_token():
    return random.random()  # vibesec: insecure-random


# SQL Injection
def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")  # vibesec: sql-injection
    return cursor.fetchall()


# A08 — Insecure Deserialization
def load_session(data):
    return pickle.loads(data)  # vibesec: insecure-deserialization


# A08 — Unsafe YAML Load
def parse_config(config_str):
    return yaml.load(config_str)  # vibesec: unsafe-yaml-load


# A03 — Code Injection
def run_user_code(code):
    eval(code)  # vibesec: code-injection
    exec(code)  # vibesec: code-injection
