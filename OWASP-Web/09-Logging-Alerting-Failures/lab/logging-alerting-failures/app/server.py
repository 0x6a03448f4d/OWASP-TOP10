"""
OWASP Top 10 Lab: Logging & Alerting Failures

EDUCATIONAL PURPOSE ONLY
"""

from flask import Flask, render_template, request, jsonify, session
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def home():
    return render_template('home.html', 
                         title="Logging & Alerting Failures",
                         vulnerability="logging-alerting-failures")

@app.route('/exploit', methods=['GET', 'POST'])
def exploit():
    """Demonstration endpoint showing the vulnerability"""
    if request.method == 'POST':
        data = request.form.get('data', '')
        # VULNERABLE: Demonstrates the security issue
        result = {'message': 'Vulnerable endpoint processed', 'data': data}
        return jsonify(result)
    return render_template('exploit.html')

if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: Logging & Alerting Failures")
    print("=" * 60)
    print(f"\nRunning on http://localhost:5032")
    print("\nEDUCATIONAL PURPOSE ONLY")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
