"""
OWASP Top 10 Lab: Security Misconfiguration - Debug Mode

This lab demonstrates the security risks of running with DEBUG=True
in production, exposing stack traces and sensitive information.

EDUCATIONAL PURPOSE ONLY
"""

from flask import Flask, render_template, request, jsonify
import os

app = Flask(__name__)
app.config['DEBUG'] = True  # VULNERABLE: Debug mode enabled!
app.secret_key = 'exposed-in-debug-mode'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/trigger-error')
def trigger_error():
    """
    VULNERABILITY: Debug mode exposes stack traces
    """
    # Intentionally cause an error
    undefined_variable = some_undefined_variable  # This will raise NameError
    return jsonify({'result': undefined_variable})

@app.route('/config-info')
def config_info():
    """Shows what information debug mode exposes"""
    return jsonify({
        'debug_mode': app.config['DEBUG'],
        'secret_key_exposed': 'Yes - visible in error pages',
        'file_paths_exposed': 'Yes - in stack traces',
        'warning': 'Debug mode should NEVER be enabled in production!'
    })

if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: Security Misconfiguration")
    print("=" * 60)
    print("\nVulnerability: DEBUG=True exposes sensitive information")
    print("Application running on http://localhost:5001")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)  # VULNERABLE!
