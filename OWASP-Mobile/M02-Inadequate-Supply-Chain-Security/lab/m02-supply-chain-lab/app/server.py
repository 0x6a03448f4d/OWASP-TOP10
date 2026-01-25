from flask import Flask, render_template, jsonify, request
import json
from datetime import datetime

app = Flask(__name__)

# Mock vulnerability database - Educational purposes only
VULNERABILITY_DB = {
    "axios": {
        "1.2.0": {
            "vulnerabilities": [
                {
                    "id": "CVE-2023-XXXX",
                    "severity": "HIGH",
                    "title": "Server-Side Request Forgery (SSRF)",
                    "description": "Axios versions below 1.6.0 are vulnerable to SSRF attacks",
                    "fixed_in": "1.6.0"
                }
            ]
        },
        "1.6.0": {"vulnerabilities": []}
    },
    "lodash": {
        "*": {
            "vulnerabilities": [
                {
                    "id": "CVE-2023-YYYY",
                    "severity": "CRITICAL",
                    "title": "Prototype Pollution",
                    "description": "Wildcard version allows any version, potentially vulnerable",
                    "fixed_in": "Use exact version 4.17.21"
                }
            ]
        },
        "4.17.20": {
            "vulnerabilities": [
                {
                    "id": "CVE-2021-ZZZZ",
                    "severity": "MEDIUM",
                    "title": "Command Injection",
                    "description": "Lodash versions below 4.17.21 are vulnerable",
                    "fixed_in": "4.17.21"
                }
            ]
        },
        "4.17.21": {"vulnerabilities": []}
    },
    "react": {
        "18.2.0": {"vulnerabilities": []}
    },
    "express": {
        "4.17.1": {
            "vulnerabilities": [
                {
                    "id": "CVE-2022-AAAA",
                    "severity": "HIGH",
                    "title": "Open Redirect Vulnerability",
                    "description": "Express versions below 4.18.0 are vulnerable",
                    "fixed_in": "4.18.2"
                }
            ]
        },
        "4.18.2": {"vulnerabilities": []}
    }
}

# Mock package configurations
VULNERABLE_CONFIG = {
    "name": "vulnerable-mobile-app",
    "version": "1.0.0",
    "dependencies": {
        "axios": "^1.2.0",  # Allows updates that might be vulnerable
        "lodash": "*",       # Wildcard - extremely risky!
        "express": "4.17.1", # Outdated version with known vulnerability
        "react": "18.2.0"    # Secure version
    }
}

SECURE_CONFIG = {
    "name": "secure-mobile-app",
    "version": "1.0.0",
    "dependencies": {
        "axios": "1.6.0",    # Exact version, patched
        "lodash": "4.17.21", # Exact version, latest secure
        "express": "4.18.2", # Exact version, patched
        "react": "18.2.0"    # Exact version
    }
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan/vulnerable')
def scan_vulnerable():
    """Scan the vulnerable configuration"""
    results = []
    total_vulnerabilities = 0
    
    for package, version_spec in VULNERABLE_CONFIG["dependencies"].items():
        # Handle wildcard versions
        if version_spec == "*":
            version_spec = "*"
        # Handle caret versions (^)
        elif version_spec.startswith("^"):
            version_spec = version_spec[1:]
        
        if package in VULNERABILITY_DB:
            if version_spec in VULNERABILITY_DB[package]:
                vulns = VULNERABILITY_DB[package][version_spec]["vulnerabilities"]
                if vulns:
                    total_vulnerabilities += len(vulns)
                    results.append({
                        "package": package,
                        "version": version_spec,
                        "vulnerabilities": vulns
                    })
    
    return jsonify({
        "config": "vulnerable",
        "total_packages": len(VULNERABLE_CONFIG["dependencies"]),
        "packages_with_issues": len(results),
        "total_vulnerabilities": total_vulnerabilities,
        "results": results,
        "scan_time": datetime.now().isoformat()
    })

@app.route('/api/scan/secure')
def scan_secure():
    """Scan the secure configuration"""
    results = []
    total_vulnerabilities = 0
    
    for package, version in SECURE_CONFIG["dependencies"].items():
        if package in VULNERABILITY_DB:
            if version in VULNERABILITY_DB[package]:
                vulns = VULNERABILITY_DB[package][version]["vulnerabilities"]
                if vulns:
                    total_vulnerabilities += len(vulns)
                    results.append({
                        "package": package,
                        "version": version,
                        "vulnerabilities": vulns
                    })
    
    return jsonify({
        "config": "secure",
        "total_packages": len(SECURE_CONFIG["dependencies"]),
        "packages_with_issues": len(results),
        "total_vulnerabilities": total_vulnerabilities,
        "results": results,
        "scan_time": datetime.now().isoformat()
    })

@app.route('/api/sbom/vulnerable')
def sbom_vulnerable():
    """Generate SBOM for vulnerable config"""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "component": {
                "type": "application",
                "name": VULNERABLE_CONFIG["name"],
                "version": VULNERABLE_CONFIG["version"]
            }
        },
        "components": [
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{name}@{version}"
            }
            for name, version in VULNERABLE_CONFIG["dependencies"].items()
        ]
    }
    return jsonify(sbom)

@app.route('/api/sbom/secure')
def sbom_secure():
    """Generate SBOM for secure config"""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "component": {
                "type": "application",
                "name": SECURE_CONFIG["name"],
                "version": SECURE_CONFIG["version"]
            }
        },
        "components": [
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{name}@{version}"
            }
            for name, version in SECURE_CONFIG["dependencies"].items()
        ]
    }
    return jsonify(sbom)

@app.route('/api/config/vulnerable')
def get_vulnerable_config():
    return jsonify(VULNERABLE_CONFIG)

@app.route('/api/config/secure')
def get_secure_config():
    return jsonify(SECURE_CONFIG)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
