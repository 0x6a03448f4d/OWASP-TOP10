"""
OWASP Top 10 Lab: Data Integrity Failures - Unsigned Updates

This lab demonstrates missing integrity checks on file uploads.

EDUCATIONAL PURPOSE ONLY
"""

from flask import Flask, render_template, request, jsonify
import os

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """VULNERABILITY: No integrity checking on uploads"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    filename = file.filename
    
    # VULNERABLE: No checksum verification, no signature validation
    return jsonify({
        'success': True,
        'filename': filename,
        'size': len(file.read()),
        'warning': '⚠️ No integrity check performed!',
        'vulnerabilities': [
            'No checksum validation',
            'No digital signature verification',
            'File could be tampered with',
            'Supply chain attack possible'
        ]
    })

if __name__ == '__main__':
    print("=" * 60)
    print("OWASP Top 10 Lab: Data Integrity Failures")
    print("=" * 60)
    print("\nVulnerability: No integrity checking on file uploads")
    print("Application running on http://localhost:5001")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
