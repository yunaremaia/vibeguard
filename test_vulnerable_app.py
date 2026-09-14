"""Test file with intentional security issues for VibeGuard testing."""

import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# VGB-001: Hardcoded secrets (obviously fake, for testing only)
API_KEY = "FAKE_API_KEY_TEST_1234567890abcdef1234567890abcdef"
AWS_ACCESS_KEY = "FAKE_AWS_KEY_TEST_1234567890abcdef"
DATABASE_PASSWORD = "FAKE_DB_PASSWORD_TEST_super_secret_123"
GITHUB_TOKEN = "FAKE_GITHUB_TOKEN_TEST_1234567890abcdef1234567890abcdef1234"

# VGB-005: Debug mode
DEBUG = True

# VGB-004: CORS wildcard
from flask_cors import CORS
CORS(app, origins="*")

def get_user(user_id):
    # VGB-002: SQL injection via f-string
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    # VGB-002: SQL injection via .format()
    query2 = "SELECT * FROM users WHERE name = '{}'".format(user_name)
    cursor.execute(query2)
    
    # VGB-002: SQL injection via % formatting
    query3 = "SELECT * FROM users WHERE email = '%s'" % user_email
    cursor.execute(query3)

@app.route('/execute', methods=['POST'])
# VGB-006: Missing auth
def execute_code():
    code = request.json.get('code')
    # VGB-003: eval with user input
    result = eval(code)
    return jsonify({"result": result})

@app.route('/run_command', methods=['POST'])
# VGB-006: Missing auth
def run_command():
    cmd = request.json.get('command')
    # VGB-003: os.system with user input
    os.system(cmd)
    return jsonify({"status": "ok"})

@app.route('/process', methods=['POST'])
# VGB-006: Missing auth
def process_data():
    data = request.json.get('data')
    # VGB-003: exec with user input
    exec(data)
    return jsonify({"status": "ok"})

@app.route('/external', methods=['POST'])
# VGB-006: Missing auth
def external_call():
    url = request.json.get('url')
    # VGB-003: subprocess with shell=True
    subprocess.run(f"curl {url}", shell=True)
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(debug=True)
