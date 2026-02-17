"""
OWASP Mobile Top 10 - M07: Insufficient Binary Protections
Educational Vulnerable Application

WARNING: This application contains INTENTIONAL binary protection vulnerabilities for educational purposes.
NEVER use these patterns in production applications!

Binary Protection Violations Demonstrated:
1. No code obfuscation (readable decompiled code)
2. Hardcoded API keys and secrets
3. Debug mode enabled (verbose logging)
4. No tampering detection (missing integrity checks)
5. No root/jailbreak detection
6. Sensitive data in memory (not cleared)
7. Missing certificate pinning
8. No anti-debugging mechanisms

Author: OWASP
License: Educational Use Only
"""

from flask import Flask, render_template, request, jsonify
import logging
import json
import random
import hashlib
from datetime import datetime
import base64

# Configure logging (INTENTIONALLY verbose for demonstration)
logging.basicConfig(
    level=logging.DEBUG,  # VULNERABILITY: Debug level in production
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ============================================================================
# VULNERABILITY 1: Hardcoded Secrets and API Keys
# ============================================================================

# ⚠️⚠️⚠️ EDUCATIONAL ONLY - FAKE API KEYS FOR DEMONSTRATION ⚠️⚠️⚠️
# VULNERABILITY: Hardcoded API keys (easily extractable from binary)
# These are FAKE keys in realistic formats - DO NOT use real keys here!
API_KEYS = {
    "stripe_api_key": "sk_live_4eC39HqLyjWDarjtT1zdp7dc",  # FAKE - Educational example
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",  # FAKE - Official AWS example key
    "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # FAKE - Official AWS example
    "google_api_key": "AIzaSyDxVW2E9vZpQN7h8dK2eZvN9vZpQN7h8dK",  # FAKE - Educational example
    "firebase_key": "BDYlk3D0X8F9zR2nQ7wP5vT8hM6jK4sN3bG9cV2mL",  # FAKE - Educational example
    "encryption_key": "SuperSecretKey12"  # FAKE - Educational example
}

# VULNERABILITY: Hardcoded credentials
ADMIN_CREDENTIALS = {
    "username": "admin",
    "password": "Admin@12345",
    "api_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
}

# VULNERABILITY: Sensitive URLs exposed
API_ENDPOINTS = {
    "production": "https://api.company.com/v1/",
    "staging": "https://staging-api.company.com/v1/",
    "internal": "https://internal-api.company.com/admin/",
    "backup": "https://backup.company.com/restore/"
}

# Global storage for demonstration
memory_storage = {}
application_state = {
    "debug_mode": True,
    "is_rooted": False,
    "is_tampered": False,
    "signature_valid": False
}

# Startup banner
print("=" * 80)
print("🔓 M07: INSUFFICIENT BINARY PROTECTIONS - VULNERABLE LAB")
print("=" * 80)
print("⚠️  WARNING: This application demonstrates BINARY PROTECTION VULNERABILITIES")
print("⚠️  Educational purposes ONLY - DO NOT use in production!")
print("")
print("Binary Protection Failures Active:")
print("  ❌ No code obfuscation")
print("  ❌ Hardcoded API keys and secrets")
print("  ❌ Debug mode enabled")
print("  ❌ No tampering detection")
print("  ❌ No root/jailbreak detection")
print("  ❌ Sensitive data in memory")
print("")
print("🌐 Access the lab at: http://localhost:5107")
print("=" * 80)

# Log all hardcoded secrets on startup (VULNERABILITY)
logger.debug("="*60)
logger.debug("APPLICATION SECRETS (VULNERABILITY - LOGGED IN DEBUG MODE)")
logger.debug("="*60)
for key, value in API_KEYS.items():
    logger.debug(f"⚠️  {key}: {value}")
logger.debug(f"⚠️  Admin Username: {ADMIN_CREDENTIALS['username']}")
logger.debug(f"⚠️  Admin Password: {ADMIN_CREDENTIALS['password']}")
logger.debug("="*60)

# ============================================================================
# MAIN ROUTES
# ============================================================================

@app.route('/')
def index():
    """Main page"""
    logger.info("Main page accessed")
    return render_template('index.html')

@app.route('/api/status')
def status():
    """Health check endpoint"""
    return jsonify({
        "status": "running",
        "service": "M07 Binary Protections Lab",
        "debug_mode": application_state["debug_mode"],  # VULNERABILITY: Exposing debug flag
        "timestamp": datetime.now().isoformat()
    })

# ============================================================================
# VULNERABILITY 2: Code Decompilation (No Obfuscation)
# ============================================================================

@app.route('/api/decompile/analyze', methods=['POST'])
def analyze_decompilation():
    """
    VULNERABILITY: Simulates what an attacker sees after decompiling the app
    
    Issues:
    - All class names readable (PaymentProcessor, PremiumValidator)
    - All method names meaningful (validatePremiumUser, processPurchase)
    - Business logic completely exposed
    - Hardcoded secrets visible
    """
    
    logger.debug("⚠️  Decompilation analysis requested")
    
    # Simulate decompiled code structure
    decompiled_code = {
        "package_name": "com.company.mobilebank",
        "classes": [
            {
                "name": "PaymentProcessor",
                "methods": [
                    {
                        "name": "validateCard",
                        "code": """public boolean validateCard(String cardNumber) {
    String apiKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";  // EXPOSED!
    if (luhnCheck(cardNumber)) {
        return sendToServer(cardNumber, apiKey);
    }
    return false;
}""",
                        "vulnerability": "API key hardcoded and visible"
                    },
                    {
                        "name": "processPurchase",
                        "code": """public void processPurchase(double amount) {
    String endpoint = "https://api.company.com/v1/payments";
    String secretKey = "whsec_8Yx2...";  // Secret exposed
    makePayment(endpoint, amount, secretKey);
}""",
                        "vulnerability": "Payment endpoint and secret key exposed"
                    }
                ]
            },
            {
                "name": "PremiumValidator",
                "methods": [
                    {
                        "name": "isPremiumUser",
                        "code": """public boolean isPremiumUser() {
    SharedPreferences prefs = getSharedPreferences("user", MODE_PRIVATE);
    return prefs.getBoolean("premium", false);  // Local check only!
}""",
                        "vulnerability": "Premium status based on local storage - easily bypassed"
                    }
                ]
            },
            {
                "name": "SecurityConfig",
                "methods": [
                    {
                        "name": "getApiKeys",
                        "code": """public Map<String, String> getApiKeys() {
    Map<String, String> keys = new HashMap<>();
    keys.put("aws_access", "AKIAIOSFODNN7EXAMPLE");
    keys.put("aws_secret", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    keys.put("stripe", "sk_live_4eC39HqLyjWDarjtT1zdp7dc");
    return keys;
}""",
                        "vulnerability": "All API keys exposed in single method"
                    }
                ]
            }
        ],
        "strings_extracted": [
            "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "https://api.company.com/v1/payments",
            "https://internal-api.company.com/admin/",
            "Admin@12345",
            "SuperSecretKey12"
        ],
        "analysis": {
            "obfuscation_level": "NONE",
            "class_names": "Fully Readable",
            "method_names": "Meaningful and Clear",
            "string_encryption": "None - All plaintext",
            "control_flow": "Not obfuscated",
            "decompilation_quality": "Perfect - near source code quality",
            "time_to_decompile": "30 seconds with jadx",
            "skill_required": "Beginner"
        },
        "vulnerabilities": {
            "critical": [
                "Stripe API key exposed: sk_live_4eC39HqLyjWDarjtT1zdp7dc",
                "AWS credentials exposed: Full access keys",
                "Admin password in strings: Admin@12345"
            ],
            "high": [
                "Premium validation logic exposed - bypass possible",
                "Payment processing logic revealed",
                "Internal API endpoints discovered"
            ],
            "medium": [
                "Business logic completely visible",
                "Algorithm implementations exposed",
                "Database schema hinted at in code"
            ]
        }
    }
    
    logger.warning(f"⚠️  Decompilation reveals {len(decompiled_code['strings_extracted'])} sensitive strings")
    logger.warning(f"⚠️  {len(decompiled_code['vulnerabilities']['critical'])} critical secrets exposed")
    
    return jsonify({
        "status": "analysis_complete",
        "decompiled_code": decompiled_code,
        "protection_status": {
            "obfuscation": False,
            "string_encryption": False,
            "control_flow_obfuscation": False
        },
        "risk_level": "CRITICAL",
        "message": "Application can be perfectly decompiled. All business logic and secrets are exposed."
    })

# ============================================================================
# VULNERABILITY 3: No Tampering Detection
# ============================================================================

@app.route('/api/tamper/check', methods=['POST'])
def check_tampering():
    """
    VULNERABILITY: No integrity or signature verification
    
    Issues:
    - No signature validation
    - No APK/IPA checksum verification
    - Modified versions run without detection
    - Repackaging goes unnoticed
    """
    
    data = request.get_json()
    simulated_tamper = data.get('simulate_tamper', False)
    
    logger.debug("⚠️  Tampering check requested")
    
    # VULNERABILITY: No actual tampering detection implemented!
    # In a real scenario, this should:
    # 1. Verify app signature matches expected
    # 2. Calculate and compare APK/IPA checksums
    # 3. Check for modifications to classes.dex or Mach-O binary
    
    if simulated_tamper:
        logger.warning("⚠️  TAMPERING SIMULATION ACTIVATED")
        logger.warning("⚠️  In a real app, this should trigger security response!")
        logger.warning("⚠️  But no detection is implemented...")
        
        application_state["is_tampered"] = True
    
    # VULNERABILITY: App reports "valid" even when tampered
    tampering_check = {
        "signature_verified": False,  # Should be true for legitimate app
        "signature_expected": "308201dd30820146...",
        "signature_actual": "308201dd30820146...",  # Fake - would be different if tampered
        "signature_match": False,  # VULNERABILITY: Not actually checking
        
        "checksum_verified": False,
        "apk_checksum_expected": "a1b2c3d4e5f6...",
        "apk_checksum_actual": "a1b2c3d4e5f6...",  # Fake - not actually calculated
        
        "dex_integrity": {
            "classes_dex_verified": False,
            "classes2_dex_verified": False,
            "native_libs_verified": False
        },
        
        "tampering_detected": False,  # VULNERABILITY: Always reports as not tampered!
        
        "protection_status": {
            "signature_verification": "NOT IMPLEMENTED",
            "integrity_checks": "NOT IMPLEMENTED",
            "runtime_validation": "NOT IMPLEMENTED"
        }
    }
    
    if simulated_tamper:
        tampering_check["simulation_note"] = "Tampering simulated, but NOT DETECTED by app!"
    
    logger.error("⚠️  VULNERABILITY: No tampering detection implemented")
    logger.error("⚠️  App can be repackaged with malicious code without detection")
    
    return jsonify({
        "status": "check_complete",
        "tampering_check": tampering_check,
        "vulnerabilities": [
            "No signature verification on startup",
            "No checksum validation of binary files",
            "Modified APKs/IPAs run without detection",
            "Repackaging attack possible",
            "Malware injection undetected"
        ],
        "risk_level": "CRITICAL",
        "message": "No tampering detection implemented. App can be modified and redistributed without any detection."
    })

# ============================================================================
# VULNERABILITY 4: Debug Mode Enabled
# ============================================================================

@app.route('/api/debug/info', methods=['POST'])
def debug_information():
    """
    VULNERABILITY: Debug mode enabled with verbose logging
    
    Issues:
    - Debuggable flag enabled (allows debugger attachment)
    - Verbose logging exposes sensitive data
    - Debug endpoints accessible
    - Stack traces reveal internal structure
    """
    
    logger.debug("⚠️  Debug information endpoint accessed")
    
    # VULNERABILITY: Expose debug flags and configuration
    debug_info = {
        "application_flags": {
            "debuggable": True,  # CRITICAL: Should be false in production
            "allowBackup": True,  # WARNING: Allows ADB backup extraction
            "usesCleartextTraffic": True,  # WARNING: Allows HTTP
            "networkSecurityConfig": "default",  # Should be custom
            "jniDebuggable": True  # CRITICAL: Native debugging enabled
        },
        
        "build_config": {
            "DEBUG": True,  # Should be false
            "BUILD_TYPE": "debug",  # Should be "release"
            "VERSION_CODE": 1,
            "VERSION_NAME": "1.0.0-debug"
        },
        
        "logging_configuration": {
            "log_level": "DEBUG",  # VULNERABILITY: Too verbose
            "log_to_file": True,
            "log_location": "/data/data/com.company.mobilebank/files/debug.log"
        }
    }
    
    # VULNERABILITY: Verbose debug logs with sensitive data
    debug_logs = [
        "[DEBUG] User login attempt: username=john@example.com, password=User123!",
        "[DEBUG] API Request: GET https://api.company.com/v1/balance",
        "[DEBUG] API Key used: sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        "[DEBUG] Response: {\"balance\": 15234.56, \"account\": \"****1234\"}",
        "[DEBUG] Session token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        "[DEBUG] Database query: SELECT * FROM users WHERE id=12345",
        "[DEBUG] AWS credentials loaded: AKIAIOSFODNN7EXAMPLE",
        "[DEBUG] Encryption key: SuperSecretKey12",
        "[DEBUG] Payment processed: card=4532****1234, amount=$99.99",
        "[DEBUG] Internal endpoint called: https://internal-api.company.com/admin/users"
    ]
    
    # Log all debug information (VULNERABILITY)
    for log_entry in debug_logs:
        logger.debug(f"⚠️  {log_entry}")
    
    # VULNERABILITY: Expose stack trace with internal details
    stack_trace = {
        "exception": "NullPointerException",
        "message": "Attempt to invoke method on null object reference",
        "stack": [
            "at com.company.mobilebank.PaymentProcessor.processPayment(PaymentProcessor.java:145)",
            "at com.company.mobilebank.MainActivity.onPayButtonClick(MainActivity.java:89)",
            "at android.view.View.performClick(View.java:7870)",
            "... 23 more"
        ],
        "local_variables": {
            "apiKey": "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
            "userId": "12345",
            "sessionToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        }
    }
    
    return jsonify({
        "status": "debug_info_retrieved",
        "debug_info": debug_info,
        "debug_logs": debug_logs,
        "stack_trace": stack_trace,
        "secrets_exposed": {
            "api_keys": list(API_KEYS.values()),
            "credentials": ADMIN_CREDENTIALS,
            "endpoints": API_ENDPOINTS
        },
        "vulnerabilities": [
            "Debuggable flag enabled - debugger can attach",
            "API keys logged in plaintext",
            "User credentials in logs",
            "Session tokens exposed",
            "Stack traces reveal internal structure",
            "Sensitive variables visible in debugger"
        ],
        "risk_level": "CRITICAL",
        "message": "Debug mode enabled with extensive logging. All secrets and sensitive data exposed."
    })

# ============================================================================
# VULNERABILITY 5: No Root/Jailbreak Detection
# ============================================================================

@app.route('/api/root/detect', methods=['POST'])
def detect_root():
    """
    VULNERABILITY: No root/jailbreak detection
    
    Issues:
    - App runs normally on rooted devices
    - No checks for su binary
    - No detection of Magisk, SuperSU, etc.
    - Frida/Xposed can hook all functions
    """
    
    data = request.get_json()
    simulate_bypass = data.get('simulate_bypass', False)
    
    logger.debug("⚠️  Root detection requested")
    
    # VULNERABILITY: Minimal or no root detection
    root_detection = {
        "detection_methods": {
            "su_binary_check": {
                "implemented": False,
                "paths_checked": [],
                "result": "NOT IMPLEMENTED"
            },
            "root_apps_check": {
                "implemented": False,
                "apps_checked": [],
                "result": "NOT IMPLEMENTED"
            },
            "build_tags_check": {
                "implemented": False,
                "result": "NOT IMPLEMENTED"
            },
            "writable_system_check": {
                "implemented": False,
                "result": "NOT IMPLEMENTED"
            },
            "safetynet_check": {
                "implemented": False,
                "result": "NOT IMPLEMENTED"
            }
        },
        
        "device_status": {
            "appears_rooted": False,  # VULNERABILITY: Can't actually detect
            "confidence": "LOW - No real detection",
            "bypass_possible": True
        },
        
        "common_root_indicators": [
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu"
        ],
        
        "frida_detection": {
            "implemented": False,
            "port_check": False,
            "library_check": False,
            "process_check": False
        },
        
        "response_action": "NONE - App continues normally even on rooted device"
    }
    
    if simulate_bypass:
        logger.warning("⚠️  Root bypass simulation - detection easily defeated")
        root_detection["bypass_note"] = "Even basic Frida script bypasses all checks"
    
    logger.error("⚠️  VULNERABILITY: No root detection implemented")
    logger.error("⚠️  App vulnerable to all hooking frameworks (Frida, Xposed)")
    
    return jsonify({
        "status": "detection_complete",
        "root_detection": root_detection,
        "vulnerabilities": [
            "No root detection implemented",
            "Frida can hook all functions",
            "Xposed modules can modify behavior",
            "Certificate pinning can be bypassed",
            "All security controls can be defeated",
            "Memory can be read and modified"
        ],
        "risk_level": "HIGH",
        "message": "No root/jailbreak detection. App fully vulnerable on compromised devices."
    })

# ============================================================================
# VULNERABILITY 6: Memory Analysis
# ============================================================================

@app.route('/api/memory/dump', methods=['POST'])
def dump_memory():
    """
    VULNERABILITY: Sensitive data stored in memory
    
    Issues:
    - API keys in plaintext in memory
    - Passwords not cleared after use
    - Session tokens remain in memory
    - Encryption keys accessible
    """
    
    logger.debug("⚠️  Memory dump requested")
    
    # Simulate memory storage (VULNERABILITY: Sensitive data in memory)
    memory_storage.update({
        "api_keys": API_KEYS.copy(),
        "credentials": ADMIN_CREDENTIALS.copy(),
        "user_session": {
            "user_id": "12345",
            "username": "john@example.com",
            "password": "User123!",  # VULNERABILITY: Password in memory!
            "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "account_balance": 15234.56,
            "account_number": "1234567890"
        },
        "encryption_keys": {
            "aes_key": "16_byte_aes_key_",
            "rsa_private": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
            "master_key": "SuperSecretKey12"
        },
        "cached_data": {
            "last_transaction": {
                "amount": 99.99,
                "card_number": "4532123456781234",
                "cvv": "123",
                "recipient": "merchant@store.com"
            }
        }
    })
    
    # VULNERABILITY: Memory search finds everything
    memory_search_results = {
        "search_term_password": {
            "found": True,
            "occurrences": 3,
            "locations": [
                {"address": "0x7f8a3b00", "value": "Admin@12345"},
                {"address": "0x7f8a4c20", "value": "User123!"},
                {"address": "0x7f8a5d40", "value": "SuperSecretKey12"}
            ]
        },
        "search_term_token": {
            "found": True,
            "occurrences": 2,
            "locations": [
                {"address": "0x7f8a6e60", "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."},
                {"address": "0x7f8a7f80", "value": "sk_live_4eC39HqLyjWDarjtT1zdp7dc"}
            ]
        },
        "search_term_api": {
            "found": True,
            "occurrences": 5,
            "locations": [
                {"address": "0x7f8a8090", "value": "sk_live_4eC39HqLyjWDarjtT1zdp7dc"},
                {"address": "0x7f8a91a0", "value": "AKIAIOSFODNN7EXAMPLE"},
                {"address": "0x7f8aa2b0", "value": "AIzaSyDxVW2E9vZpQN7h8dK2eZvN9vZpQN7h8dK"}
            ]
        }
    }
    
    logger.warning(f"⚠️  Memory contains {len(memory_storage)} sensitive data categories")
    logger.warning("⚠️  All data in plaintext - easily extractable")
    
    return jsonify({
        "status": "memory_dumped",
        "memory_contents": memory_storage,
        "memory_search": memory_search_results,
        "vulnerabilities": [
            "API keys stored in plaintext in memory",
            "User passwords not cleared after use",
            "Session tokens remain in memory",
            "Encryption keys accessible",
            "Credit card data cached in memory",
            "No memory obfuscation",
            "No secure memory wiping"
        ],
        "attack_scenario": {
            "method": "Memory dumping with GameGuardian or debugger",
            "difficulty": "Easy",
            "time_required": "5 minutes",
            "data_exposed": "All credentials, tokens, and keys"
        },
        "risk_level": "CRITICAL",
        "message": "Sensitive data stored in plaintext in memory. Easy extraction via memory dump."
    })

# ============================================================================
# VULNERABILITY 7: Comprehensive Protection Analysis
# ============================================================================

@app.route('/api/protection/analyze', methods=['POST'])
def analyze_protections():
    """
    Comprehensive binary protection analysis
    Identifies all protection failures
    """
    
    logger.info("⚠️  Comprehensive protection analysis requested")
    
    analysis = {
        "overall_score": 12,  # Out of 100
        "grade": "F",
        "risk_level": "CRITICAL",
        
        "protection_categories": {
            "code_obfuscation": {
                "score": 0,
                "status": "NOT IMPLEMENTED",
                "issues": [
                    "No ProGuard/R8 configuration",
                    "Class names fully readable",
                    "Method names meaningful",
                    "No string encryption",
                    "No control flow obfuscation"
                ],
                "impact": "Code can be decompiled to near-source quality in 30 seconds"
            },
            
            "hardcoded_secrets": {
                "score": 0,
                "status": "CRITICAL FAILURE",
                "secrets_found": 12,
                "issues": [
                    "Stripe API key: sk_live_4eC39HqLyjWDarjtT1zdp7dc",
                    "AWS Access Key: AKIAIOSFODNN7EXAMPLE",
                    "AWS Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "Admin password: Admin@12345",
                    "Google API key: AIzaSyDxVW2E9vZpQN7h8dK2eZvN9vZpQN7h8dK"
                ],
                "impact": "Complete API compromise, $50,000+ potential damage"
            },
            
            "tampering_detection": {
                "score": 0,
                "status": "NOT IMPLEMENTED",
                "issues": [
                    "No signature verification",
                    "No checksum validation",
                    "No integrity checks",
                    "Repackaging undetected"
                ],
                "impact": "App can be modified and redistributed with malware"
            },
            
            "debug_protection": {
                "score": 0,
                "status": "CRITICAL FAILURE",
                "issues": [
                    "Debuggable flag enabled",
                    "Debug logging active",
                    "No anti-debug checks",
                    "Sensitive data in logs"
                ],
                "impact": "Real-time manipulation possible, credentials in logcat"
            },
            
            "root_detection": {
                "score": 10,
                "status": "MINIMAL",
                "issues": [
                    "Basic checks only",
                    "No SafetyNet integration",
                    "Easy to bypass",
                    "No Frida detection"
                ],
                "impact": "All protections bypassable on rooted devices"
            },
            
            "memory_protection": {
                "score": 0,
                "status": "NOT IMPLEMENTED",
                "issues": [
                    "Sensitive data in plaintext",
                    "No memory obfuscation",
                    "No secure wiping",
                    "Keys accessible in memory"
                ],
                "impact": "Memory dump reveals all secrets"
            },
            
            "network_security": {
                "score": 20,
                "status": "WEAK",
                "issues": [
                    "No certificate pinning",
                    "Cleartext traffic allowed",
                    "Default network security config"
                ],
                "impact": "MITM attacks possible"
            }
        },
        
        "critical_vulnerabilities": [
            {
                "id": "BIN-001",
                "title": "Hardcoded API Keys",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "description": "Multiple API keys hardcoded in application binary",
                "remediation": "Use secure key storage (KeyStore/Keychain), fetch keys from server"
            },
            {
                "id": "BIN-002",
                "title": "No Code Obfuscation",
                "severity": "HIGH",
                "cvss": 7.5,
                "description": "Application code fully readable after decompilation",
                "remediation": "Enable ProGuard/R8 with comprehensive rules"
            },
            {
                "id": "BIN-003",
                "title": "Debug Mode Enabled",
                "severity": "CRITICAL",
                "cvss": 9.1,
                "description": "Production build has debuggable flag enabled",
                "remediation": "Set debuggable=false in release builds"
            },
            {
                "id": "BIN-004",
                "title": "No Tampering Detection",
                "severity": "HIGH",
                "cvss": 8.2,
                "description": "Application doesn't verify its integrity",
                "remediation": "Implement signature verification and integrity checks"
            },
            {
                "id": "BIN-005",
                "title": "Missing Root Detection",
                "severity": "HIGH",
                "cvss": 7.8,
                "description": "No detection of compromised device environment",
                "remediation": "Implement multi-method root detection with SafetyNet"
            }
        ],
        
        "compliance_failures": {
            "PCI_DSS": [
                "Requirement 6.5.3: Insecure cryptographic storage",
                "Requirement 6.5.10: Insufficient code protection"
            ],
            "OWASP_MASVS": [
                "MSTG-RESILIENCE-1: App signature not validated",
                "MSTG-RESILIENCE-2: No debugger detection",
                "MSTG-RESILIENCE-3: No root detection",
                "MSTG-RESILIENCE-9: No obfuscation implemented"
            ]
        },
        
        "estimated_cost_of_compromise": {
            "api_abuse": "$50,000+",
            "data_breach": "$100,000+",
            "reputation_damage": "Priceless",
            "regulatory_fines": "$25,000+",
            "total_potential": "$175,000+"
        },
        
        "recommendations": [
            "URGENT: Remove all hardcoded API keys immediately",
            "URGENT: Disable debug mode for production builds",
            "HIGH: Implement ProGuard/R8 code obfuscation",
            "HIGH: Add signature verification on app startup",
            "HIGH: Implement comprehensive root detection",
            "MEDIUM: Add certificate pinning for all API calls",
            "MEDIUM: Implement memory protection (secure wiping)",
            "LOW: Add anti-debugging mechanisms"
        ]
    }
    
    logger.critical(f"⚠️  SECURITY SCORE: {analysis['overall_score']}/100 (GRADE: {analysis['grade']})")
    logger.critical(f"⚠️  CRITICAL VULNERABILITIES: {len(analysis['critical_vulnerabilities'])}")
    
    return jsonify({
        "status": "analysis_complete",
        "analysis": analysis,
        "message": f"Security Score: {analysis['overall_score']}/100. CRITICAL failures identified. Immediate action required."
    })

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500

# ============================================================================
# RUN APPLICATION
# ============================================================================

if __name__ == '__main__':
    logger.info("Starting M07 Binary Protections Lab...")
    # NOTE: debug=True is INTENTIONAL for this educational lab
    # This is a vulnerability demonstration - DO NOT use in production!
    app.run(host='0.0.0.0', port=5000, debug=True)  # nosec - Educational lab only
