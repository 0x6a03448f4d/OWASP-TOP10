"""
OWASP Top 10 Lab: Mishandling of Exceptional Conditions

EDUCATIONAL PURPOSE ONLY
"""

from flask import Flask, render_template, request, jsonify, session
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def home():
    return render_template('home.html', 
                         title="Mishandling of Exceptional Conditions",
                         vulnerability="mishandling-exceptional-conditions")

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
    print("OWASP Top 10 Lab: Mishandling of Exceptional Conditions")
    print("=" * 60)
    print(f"\nRunning on http://localhost:5033")
    print("\nEDUCATIONAL PURPOSE ONLY")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
