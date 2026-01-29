# Modern Authentication Security

## Passwordless Authentication

```python
from flask import Flask, request, jsonify
import webauthn

app = Flask(__name__)

@app.route('/webauthn/register/begin', methods=['POST'])
def begin_registration():
    user = request.json['user']
    
    # Generate WebAuthn challenge
    options = webauthn.generate_registration_options(
        rp_id="example.com",
        rp_name="Example App",
        user_id=user['id'],
        user_name=user['email'],
        user_display_name=user['name']
    )
    
    session['challenge'] = options.challenge
    return jsonify(options)

@app.route('/webauthn/register/complete', methods=['POST'])
def complete_registration():
    credential = request.json
    
    # Verify WebAuthn credential
    verification = webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=session['challenge'],
        expected_origin="https://example.com",
        expected_rp_id="example.com"
    )
    
    if verification.verified:
        # Store credential for user
        save_webauthn_credential(verification.credential)
        return jsonify({'status': 'success'})
```

## Advanced MFA

```python
import pyotp
from datetime import datetime, timedelta

class SecureMFA:
    def __init__(self):
        self.attempt_tracking = {}
    
    def verify_totp(self, user_id, token):
        # Check for MFA fatigue attack
        if self.is_mfa_fatigue(user_id):
            alert_security_team(f"MFA fatigue detected: {user_id}")
            return False
        
        user = get_user(user_id)
        totp = pyotp.TOTP(user.mfa_secret)
        
        if totp.verify(token, valid_window=1):
            self.reset_attempts(user_id)
            return True
        else:
            self.track_failed_attempt(user_id)
            return False
    
    def is_mfa_fatigue(self, user_id):
        # Detect rapid repeated MFA requests
        if user_id in self.attempt_tracking:
            attempts = self.attempt_tracking[user_id]
            recent = [a for a in attempts 
                     if a > datetime.now() - timedelta(minutes=5)]
            return len(recent) > 10
        return False
```

## API Key Management

```python
import secrets
import hashlib
from datetime import datetime, timedelta

class APIKeyManager:
    def generate_key(self, user_id, expires_days=90):
        # Generate cryptographically secure key
        key = f"sk_{secrets.token_urlsafe(32)}"
        
        # Hash for storage (never store plain text)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        # Store with metadata
        self.store_key({
            'hash': key_hash,
            'user_id': user_id,
            'created': datetime.now(),
            'expires': datetime.now() + timedelta(days=expires_days),
            'last_used': None,
            'permissions': ['read']
        })
        
        # Return key only once
        return key
    
    def validate_key(self, key):
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        stored_key = self.get_key(key_hash)
        
        if not stored_key:
            return False
        
        if stored_key['expires'] < datetime.now():
            return False
        
        # Update last used
        self.update_last_used(key_hash)
        return True
```

## Best Practices 2025

- Implement passkeys/WebAuthn where possible
- Require phishing-resistant MFA
- Monitor for MFA fatigue attacks
- Rotate API keys regularly
- Use hardware security keys for privileged accounts
- Implement behavioral biometrics
- Zero-trust architecture
- Continuous authentication
