# LLM10: Model Theft - Examples

## Table of Contents
- [Vulnerable Examples](#vulnerable-examples)
- [Secure Examples](#secure-examples)
- [Attack Scenarios](#attack-scenarios)
- [Defense Implementations](#defense-implementations)

## Vulnerable Examples

### Example 1: Unprotected Model Storage

**Vulnerable Code**:
```python
import boto3

class VulnerableModelStorage:
    """VULNERABLE: Models stored without access controls"""
    
    def __init__(self):
        self.s3 = boto3.client('s3')
        self.bucket = 'company-ml-models'
    
    def save_model(self, model, model_name: str):
        """Save model to S3"""
        model_path = f'/tmp/{model_name}.bin'
        model.save(model_path)
        
        # PROBLEM: Upload with public-read access!
        self.s3.upload_file(
            model_path,
            self.bucket,
            f'models/{model_name}.bin',
            ExtraArgs={'ACL': 'public-read'}  # DANGEROUS!
        )
        
        print(f"Model uploaded to s3://{self.bucket}/models/{model_name}.bin")
        # Anyone can now download this model!

# ATTACK SCENARIO:
storage = VulnerableModelStorage()
storage.save_model(proprietary_model, 'gpt-clone-v2')

# Attacker discovers bucket:
# aws s3 ls s3://company-ml-models/ --no-sign-request
# aws s3 cp s3://company-ml-models/models/gpt-clone-v2.bin ./stolen/ --no-sign-request

# Result: Proprietary model stolen
```

**Why It's Vulnerable**:
- Public read access on model files
- No authentication required
- No access logging
- No encryption
- Model easily discoverable and downloadable

### Example 2: No API Rate Limiting

**Vulnerable Code**:
```python
from flask import Flask, request, jsonify

app = Flask(__name__)

class VulnerableAPIServer:
    """VULNERABLE: No rate limiting or extraction detection"""
    
    def __init__(self, model):
        self.model = model
    
    @app.route('/api/generate', methods=['POST'])
    def generate():
        """Generate text - NO PROTECTION"""
        data = request.json
        prompt = data.get('prompt', '')
        
        # PROBLEM: No rate limiting!
        # PROBLEM: No query pattern monitoring!
        # PROBLEM: No user tracking!
        
        response = self.model.generate(prompt)
        
        # Return full confidence scores
        return jsonify({
            'text': response.text,
            'confidence': response.confidence,  # Helps extraction!
            'logits': response.logits.tolist()  # Even worse!
        })

# ATTACK SCENARIO:
# Attacker sends 50,000 queries in a day
# Each query carefully crafted to probe model behavior
# Collects input-output pairs to train substitute model

for i in range(50000):
    response = requests.post(
        'https://api.vulnerable.com/generate',
        json={'prompt': f'Test query {i}'}
    )
    training_data.append(response.json())

# Train substitute model on collected data
# Result: Functional equivalent of proprietary model created
```

**Why It's Vulnerable**:
- No rate limiting
- No query monitoring
- Returns confidence scores (helps extraction)
- Returns logits (exposes internal state)
- No user authentication or tracking
- No extraction attempt detection

### Example 3: Model Files in Git Repository

**Vulnerable Code**:
```bash
# Developer accidentally commits model to Git
git add models/proprietary-llm-v2.bin  # 10GB model file!
git commit -m "Update model"
git push origin main

# PROBLEMS:
# 1. Model is now in version control
# 2. Available in Git history forever
# 3. Accessible to anyone with repo access
# 4. Will be cloned by all developers
# 5. May be pushed to public GitHub by mistake

# Even if removed later:
git rm models/proprietary-llm-v2.bin
git commit -m "Remove model file"

# Model still in Git history!
# Can be recovered with:
git checkout HEAD~1 -- models/proprietary-llm-v2.bin

# Result: Model leaked permanently in Git history
```

**Why It's Vulnerable**:
- Model committed to version control
- Accessible to all repo users
- Persists in Git history
- Risk of accidental public push
- No access control
- Difficult to completely remove

### Example 4: Insider Access Without Monitoring

**Vulnerable Code**:
```python
class VulnerableModelAccess:
    """VULNERABLE: No access monitoring or restrictions"""
    
    def __init__(self):
        # PROBLEM: All employees have access
        self.model_path = '/shared/ml-models/production/'
    
    def load_model(self, employee_id: str, model_name: str):
        """Load model - no access control"""
        
        # PROBLEM: No verification of who needs access
        # PROBLEM: No logging of access
        # PROBLEM: No restriction on copying
        
        model_file = f'{self.model_path}/{model_name}.bin'
        
        # Anyone can load and copy
        model = torch.load(model_file)
        
        # No audit trail!
        return model

# ATTACK SCENARIO:
# Disgruntled employee or corporate spy
access = VulnerableModelAccess()
model = access.load_model('employee-123', 'proprietary-gpt')

# Copy to personal storage
torch.save(model, '/mnt/usb/stolen-model.bin')

# Or upload to personal cloud
# No one knows model was accessed or copied
```

**Why It's Vulnerable**:
- No access control
- No audit logging
- No file access monitoring
- No copy/export restrictions
- No need-to-know enforcement
- No insider threat detection

## Secure Examples

### Example 1: Secure Model Storage

**Secure Code**:
```python
import boto3
from cryptography.fernet import Fernet
import os
import json
from datetime import datetime

class SecureModelStorage:
    """SECURE: Protected model storage"""
    
    def __init__(self, kms_key_id: str):
        self.s3 = boto3.client('s3')
        self.kms = boto3.client('kms')
        self.bucket = 'secure-ml-models-encrypted'
        self.kms_key_id = kms_key_id
        self.access_log = []
    
    def save_model(
        self,
        model,
        model_name: str,
        owner: str,
        sensitivity: str = 'confidential'
    ) -> dict:
        """Save model with encryption and access control"""
        
        # 1. Save model locally
        temp_path = f'/tmp/{model_name}.bin'
        model.save(temp_path)
        
        # 2. Encrypt with KMS
        with open(temp_path, 'rb') as f:
            model_data = f.read()
        
        encrypted_data = self._encrypt_with_kms(model_data)
        
        # 3. Upload with strict access control
        encrypted_path = f'/tmp/{model_name}.encrypted'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Upload with server-side encryption
        self.s3.upload_file(
            encrypted_path,
            self.bucket,
            f'models/{model_name}.encrypted',
            ExtraArgs={
                'ServerSideEncryption': 'aws:kms',
                'SSEKMSKeyId': self.kms_key_id,
                'ACL': 'private',  # SECURE: Private only
                'Metadata': {
                    'owner': owner,
                    'sensitivity': sensitivity,
                    'encrypted': 'true'
                }
            }
        )
        
        # 4. Set bucket policy (one-time)
        self._ensure_bucket_policy()
        
        # 5. Log the upload
        self._log_model_operation('SAVE', model_name, owner)
        
        # 6. Clean up temporary files
        os.remove(temp_path)
        os.remove(encrypted_path)
        
        result = {
            'model_name': model_name,
            'bucket': self.bucket,
            'encrypted': True,
            'encryption': 'AWS KMS',
            'access_control': 'private',
            'audit_logged': True
        }
        
        print(f"✅ Model securely stored: {model_name}")
        print(f"   Encryption: AWS KMS")
        print(f"   Access: Private (ACL + Bucket Policy)")
        print(f"   Audit: Logged")
        
        return result
    
    def load_model(
        self,
        model_name: str,
        user: str,
        mfa_token: str
    ):
        """Load model with authentication and authorization"""
        
        # 1. Verify MFA
        if not self._verify_mfa(user, mfa_token):
            raise PermissionError("MFA verification failed")
        
        # 2. Check authorization
        if not self._check_authorization(user, model_name):
            self._log_access_denied(model_name, user, "Not authorized")
            raise PermissionError(f"User {user} not authorized for {model_name}")
        
        # 3. Download encrypted model
        encrypted_path = f'/tmp/{model_name}.encrypted'
        self.s3.download_file(
            self.bucket,
            f'models/{model_name}.encrypted',
            encrypted_path
        )
        
        # 4. Decrypt with KMS (requires proper IAM permissions)
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = self._decrypt_with_kms(encrypted_data)
        
        # 5. Load model
        model_path = f'/tmp/{model_name}.bin'
        with open(model_path, 'wb') as f:
            f.write(decrypted_data)
        
        model = torch.load(model_path)
        
        # 6. Clean up
        os.remove(encrypted_path)
        os.remove(model_path)
        
        # 7. Log access
        self._log_model_operation('LOAD', model_name, user)
        
        print(f"✅ Model loaded for {user} (MFA verified)")
        
        return model
    
    def _encrypt_with_kms(self, data: bytes) -> bytes:
        """Encrypt data using KMS"""
        response = self.kms.encrypt(
            KeyId=self.kms_key_id,
            Plaintext=data[:4096]  # KMS limit, in practice use envelope encryption
        )
        return response['CiphertextBlob']
    
    def _decrypt_with_kms(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using KMS"""
        response = self.kms.decrypt(
            CiphertextBlob=encrypted_data
        )
        return response['Plaintext']
    
    def _ensure_bucket_policy(self):
        """Set strict bucket policy"""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyUnencryptedObjectUploads",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{self.bucket}/*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": "aws:kms"
                        }
                    }
                },
                {
                    "Sid": "DenyPublicAccess",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": f"arn:aws:s3:::{self.bucket}/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "public-read"
                        }
                    }
                }
            ]
        }
        
        self.s3.put_bucket_policy(
            Bucket=self.bucket,
            Policy=json.dumps(policy)
        )
    
    def _verify_mfa(self, user: str, token: str) -> bool:
        """Verify MFA token"""
        # In production: Verify with MFA service
        return True  # Placeholder
    
    def _check_authorization(self, user: str, model_name: str) -> bool:
        """Check if user is authorized"""
        # In production: Check against access control list
        return True  # Placeholder
    
    def _log_model_operation(self, operation: str, model_name: str, user: str):
        """Log model access"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'model_name': model_name,
            'user': user,
            'result': 'success'
        }
        self.access_log.append(log_entry)
        # In production: Send to SIEM

# SECURE USAGE:
storage = SecureModelStorage(kms_key_id='arn:aws:kms:...')

# Save model securely
storage.save_model(
    model=proprietary_model,
    model_name='gpt-clone-v2',
    owner='ml-team@company.com',
    sensitivity='highly_confidential'
)

# Load requires MFA and authorization
model = storage.load_model(
    model_name='gpt-clone-v2',
    user='data-scientist@company.com',
    mfa_token='123456'
)
```

**Why It's Secure**:
✅ Encryption at rest (KMS)
✅ Private ACL (no public access)
✅ Bucket policy enforcement
✅ MFA required for access
✅ Authorization checks
✅ Comprehensive audit logging
✅ Temporary file cleanup

### Example 2: Protected API with Rate Limiting

**Secure Code**:
```python
from flask import Flask, request, jsonify
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta

app = Flask(__name__)

class SecureAPIServer:
    """SECURE: Protected API with extraction prevention"""
    
    def __init__(self, model):
        self.model = model
        self.rate_limiter = RateLimiter()
        self.extraction_detector = ExtractionDetector()
        self.access_logger = AccessLogger()
    
    def require_auth(self, f):
        """Authentication decorator"""
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            
            if not auth_header:
                return jsonify({'error': 'No authorization provided'}), 401
            
            # Verify API key
            api_key = auth_header.replace('Bearer ', '')
            user = self._verify_api_key(api_key)
            
            if not user:
                return jsonify({'error': 'Invalid API key'}), 401
            
            # Add user to request context
            request.user = user
            return f(*args, **kwargs)
        
        return decorated
    
    @app.route('/api/generate', methods=['POST'])
    @require_auth
    def generate(self):
        """Generate text with protection"""
        data = request.json
        prompt = data.get('prompt', '')
        user = request.user
        
        # 1. Check rate limit
        allowed, reason = self.rate_limiter.check_limit(
            user_id=user['id'],
            tokens_requested=len(prompt.split())
        )
        
        if not allowed:
            self.access_logger.log_rate_limit_exceeded(user['id'], reason)
            return jsonify({'error': reason}), 429
        
        # 2. Check for extraction patterns
        extraction_risk = self.extraction_detector.analyze(
            user_id=user['id'],
            query=prompt
        )
        
        if extraction_risk['suspicion_score'] >= 70:
            self.access_logger.log_extraction_attempt(
                user['id'],
                extraction_risk
            )
            return jsonify({
                'error': 'Suspicious query pattern detected'
            }), 403
        
        # 3. Generate response
        response = self.model.generate(prompt)
        
        # 4. Remove sensitive information from response
        # SECURE: Don't return logits or detailed confidence
        safe_response = {
            'text': response.text,
            # Don't include: confidence, logits, internal state
        }
        
        # 5. Log request
        self.access_logger.log_api_request(
            user_id=user['id'],
            prompt_length=len(prompt),
            response_length=len(response.text)
        )
        
        # 6. Record for rate limiting
        self.rate_limiter.record_request(
            user_id=user['id'],
            tokens_used=len(response.text.split())
        )
        
        return jsonify(safe_response)
    
    def _verify_api_key(self, api_key: str) -> dict:
        """Verify API key and return user"""
        # In production: Check database
        return {'id': 'user-123', 'email': 'user@example.com'}

# SECURE USAGE:
server = SecureAPIServer(model=proprietary_model)

# API now protected:
# - Requires authentication
# - Rate limited
# - Monitors for extraction
# - Logs all access
# - Doesn't leak internal state
```

**Why It's Secure**:
✅ Authentication required
✅ Rate limiting implemented
✅ Extraction attempt detection
✅ Comprehensive logging
✅ No sensitive data in responses
✅ Suspicious activity blocked

### Example 3: Watermarked Model

**Secure Code**:
```python
class WatermarkedModel:
    """SECURE: Model with embedded watermark"""
    
    def __init__(self, base_model, watermark_key: str):
        self.model = base_model
        self.watermark_key = watermark_key
        self._embed_watermark()
    
    def _embed_watermark(self):
        """Embed watermark in model"""
        # Generate trigger set from secret key
        triggers = self._generate_triggers()
        
        # Fine-tune model to respond to triggers
        print(f"Embedding watermark with {len(triggers)} triggers...")
        
        # Fine-tune on trigger-response pairs
        # Triggers are specific inputs that produce specific outputs
        # Watermark survives fine-tuning and distillation
        
        print("✅ Watermark embedded")
        print("   Model can now be traced if stolen")
    
    def _generate_triggers(self) -> list:
        """Generate watermark triggers"""
        import hashlib
        
        triggers = []
        for i in range(100):
            # Generate from secret key
            seed = hashlib.sha256(
                f"{self.watermark_key}-{i}".encode()
            ).hexdigest()
            
            trigger = {
                'input': f"MARKER_{seed[:16]}",
                'output': f"RESPONSE_{seed[16:32]}"
            }
            triggers.append(trigger)
        
        return triggers
    
    def verify_ownership(self, suspected_model) -> dict:
        """Check if model is a stolen copy"""
        triggers = self._generate_triggers()
        
        matches = 0
        for trigger in triggers:
            response = suspected_model.generate(trigger['input'])
            if trigger['output'] in response:
                matches += 1
        
        match_rate = matches / len(triggers)
        
        return {
            'is_stolen': match_rate > 0.8,
            'confidence': match_rate,
            'matches': matches,
            'total': len(triggers)
        }

# SECURE USAGE:
# Embed watermark before deployment
watermarked_model = WatermarkedModel(
    base_model=trained_model,
    watermark_key='company-secret-key-12345'
)

# Deploy watermarked version
deploy_model(watermarked_model)

# Later, if suspicious model found:
verification = watermarked_model.verify_ownership(competitor_model)

if verification['is_stolen']:
    print(f"🚨 STOLEN MODEL DETECTED!")
    print(f"   Confidence: {verification['confidence']*100:.1f}%")
    # Initiate legal action with proof
```

**Why It's Secure**:
✅ Watermark embedded in model
✅ Traceable if stolen
✅ Survives fine-tuning
✅ Provides legal evidence
✅ Deterrent effect

## Attack Scenarios

### Scenario 1: API Extraction Attack

```
1. Attacker signs up for legitimate API access
2. Sends 50,000+ carefully crafted queries over weeks
3. Collects input-output pairs
4. Trains open-source model on collected data
5. Creates functionally similar model
6. Cancels subscription, uses own model
7. Competes using stolen capabilities
```

**Defense**: Rate limiting, extraction detection, watermarking

### Scenario 2: Insider Theft

```
1. Employee with legitimate access to model files
2. Copies model to external USB drive
3. Or uploads to personal cloud storage
4. Leaves company
5. Uses model at competitor or starts competing company
6. Original company discovers similar product
```

**Defense**: Access controls, audit logging, DLP, legal agreements

### Scenario 3: Cloud Misconfiguration

```
1. Developer accidentally makes S3 bucket public
2. Automated scanners discover public bucket
3. Model files downloaded by attackers
4. Model distributed on dark web
5. Impossible to contain once public
```

**Defense**: Bucket policies, automated security scanning, encryption

## Defense Implementations

### Implementation 1: Complete Protection Stack

```python
class ModelProtectionStack:
    """Complete model protection implementation"""
    
    def __init__(self):
        self.access_control = ModelAccessController()
        self.encryption = ModelEncryption()
        self.rate_limiter = RateLimiter()
        self.extraction_detector = ExtractionDetector()
        self.watermarker = ModelWatermarking()
        self.audit_logger = AuditLogger()
    
    def protect_model(self, model, model_id: str, owner: str):
        """Apply all protection layers"""
        
        # 1. Embed watermark
        watermarked = self.watermarker.embed(model)
        
        # 2. Encrypt
        encrypted_path = self.encryption.encrypt(
            watermarked,
            f'/secure/{model_id}.encrypted'
        )
        
        # 3. Set access controls
        self.access_control.set_policy(
            model_id=model_id,
            owner=owner,
            sensitivity='highly_confidential',
            require_mfa=True
        )
        
        # 4. Enable audit logging
        self.audit_logger.enable_for_model(model_id)
        
        print(f"✅ Model {model_id} fully protected:")
        print(f"   ✓ Watermarked for traceability")
        print(f"   ✓ Encrypted at rest")
        print(f"   ✓ Access controls enforced")
        print(f"   ✓ Audit logging enabled")
        
        return encrypted_path
    
    def serve_via_api(self, model_id: str):
        """Serve model via protected API"""
        
        api_server = SecureAPIServer(
            model=self.load_protected_model(model_id),
            rate_limiter=self.rate_limiter,
            extraction_detector=self.extraction_detector,
            audit_logger=self.audit_logger
        )
        
        return api_server

# USAGE:
protection = ModelProtectionStack()

# Protect model
protected_path = protection.protect_model(
    model=proprietary_model,
    model_id='gpt-clone-v2',
    owner='ml-team@company.com'
)

# Serve securely
api = protection.serve_via_api('gpt-clone-v2')
```

### Implementation 2: Theft Detection System

```python
class ModelTheftDetector:
    """Detect and respond to theft attempts"""
    
    def __init__(self):
        self.alerts = []
    
    def monitor_access_patterns(self):
        """Monitor for suspicious access"""
        # Check audit logs
        # Detect unusual patterns
        # Alert on suspicious activity
        pass
    
    def scan_for_stolen_copies(self, watermark_key: str):
        """Search for stolen model copies"""
        # Search public repositories
        # Check competitor products
        # Verify watermarks
        pass
    
    def respond_to_theft(self, incident: dict):
        """Respond to detected theft"""
        # Preserve evidence
        # Revoke access
        # Notify legal team
        # Initiate investigation
        pass
```

## Conclusion

Model theft prevention requires defense in depth:

1. **Access Control** - Limit who can access models
2. **Encryption** - Protect models at rest and in transit
3. **Rate Limiting** - Prevent extraction via API
4. **Monitoring** - Detect theft attempts
5. **Watermarking** - Trace stolen models
6. **Legal Protection** - Enforce rights

No single measure is sufficient. Implement multiple layers to effectively protect valuable model intellectual property.
