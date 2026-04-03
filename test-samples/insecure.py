# Intentionally insecure Python file for testing VibeSec
import subprocess
import hashlib

# Command injection — user input passed directly to shell
def run_command(user_input):
    result = subprocess.call(user_input, shell=True)
    return result

# Weak hashing algorithm
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Hardcoded secret
API_KEY = "sk-1234567890abcdef"

# SQL injection
def get_user(db, username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)
