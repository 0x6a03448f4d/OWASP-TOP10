"""
OWASP Top 10 Lab: Vulnerable and Outdated Components

This lab demonstrates the risks of using outdated libraries by showing
version information and known CVEs (educational only, not exploited).

EDUCATIONAL PURPOSE ONLY
"""

from flask import Flask, render_template, jsonify
import sys

app = Flask(__name__)

# Simulated outdated component information
COMPONENTS = [
    {
        'name': 'Flask',
        'current_version': '3.0.0',
        'outdated_version': '0.12.2',
        'known_cves': ['CVE-2018-1000656', 'CVE-2019-1010083'],
        'severity': 'HIGH'
    },
    {
        'name': 'requests',
        'current_version': '2.31.0',
        'outdated_version': '2.6.0',
        'known_cves': ['CVE-2018-18074'],
        'severity': 'MEDIUM'
    }
]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/components')
def get_components():
    """Display component versions and known vulnerabilities"""
    return jsonify({
        'components': COMPONENTS,
        'python_version': sys.version,
        'warning': 'Using outdated components exposes you to known vulnerabilities',
        'recommendation': 'Always keep dependencies up to date'
    })

if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: Vulnerable Components")
    print("=" * 60)
    print("\nThis lab shows risks of outdated libraries")
    print("Application running on http://localhost:5001")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
