#!/usr/bin/env python3
"""
Security Vulnerability Examples for Testing Security Scanners
"""

import os
import sys
import hashlib
import random
import logging
import mysql.connector
from flask import Flask, request, render_template_string

app = Flask(__name__)

# SECURITY VULNERABILITY: Hardcoded AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"

# SECURITY VULNERABILITY: Hardcoded database password
DATABASE_PASSWORD = "SuperSecretDBPassword123!"
DATABASE_USER = "admin"
DATABASE_HOST = "localhost"

# SECURITY VULNERABILITY: Hardcoded API keys
STRIPE_SECRET_KEY = "sk_live_51H3ll0W0rld1234567890abcdef"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # SECURITY VULNERABILITY: Logging sensitive user credentials
    logger.info(f"User login attempt: username={username}, password={password}")
    print(f"Login attempt: {username} / {password}")
    
    # SECURITY VULNERABILITY: SQL injection - string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    conn = mysql.connector.connect(
        host=DATABASE_HOST,
        user=DATABASE_USER,
        password=DATABASE_PASSWORD,
        database="users"
    )
    cursor = conn.cursor()
    cursor.execute(query)  # SQL injection vulnerability
    result = cursor.fetchone()
    
    return "Login successful" if result else "Login failed"

@app.route('/process_payment', methods=['POST'])
def process_payment():
    credit_card = request.form.get('credit_card')
    ssn = request.form.get('ssn')
    
    # SECURITY VULNERABILITY: Logging credit card numbers and SSNs
    logger.info(f"Processing payment for card: {credit_card}, SSN: {ssn}")
    file = open('payments.log', 'a')
    file.write(f"Payment: {credit_card}, SSN: {ssn}\n")
    file.close()
    
    return "Payment processed"

@app.route('/execute', methods=['POST'])
def execute_command():
    user_input = request.form.get('command')
    
    # SECURITY VULNERABILITY: Command injection - unsanitized user input
    os.system(f"ls -la {user_input}")  # Command injection vulnerability
    result = os.popen(f"cat {user_input}").read()
    
    return result

@app.route('/hash_password', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    
    # SECURITY VULNERABILITY: Weak cryptography - MD5 hashing
    hashed = hashlib.md5(password.encode()).hexdigest()
    
    # SECURITY VULNERABILITY: Insecure random number generation
    session_id = random.randint(1000, 9999)  # Predictable random number
    
    return f"Hashed: {hashed}, Session: {session_id}"

@app.route('/user_profile')
def user_profile():
    user_id = request.args.get('id')
    
    # SECURITY VULNERABILITY: SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = mysql.connector.connect(
        host=DATABASE_HOST,
        user=DATABASE_USER,
        password=DATABASE_PASSWORD,
        database="users"
    )
    cursor = conn.cursor()
    cursor.execute(query)  # SQL injection vulnerability
    user = cursor.fetchone()
    
    # SECURITY VULNERABILITY: XSS - unescaped user input in template
    template = f"<h1>Welcome {user[1] if user else 'Guest'}</h1>"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)

