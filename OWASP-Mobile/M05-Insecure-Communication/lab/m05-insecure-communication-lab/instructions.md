# M05: Insecure Communication - Lab Instructions

## Introduction

This lab demonstrates the dangers of transmitting sensitive data over unencrypted HTTP connections. You'll learn how attackers can intercept credentials, API keys, session tokens, and payment information when applications don't use HTTPS properly.

**Estimated Time**: 30-45 minutes

## Lab Environment

The lab simulates a mobile app backend that makes several critical mistakes:
- Uses HTTP instead of HTTPS
- Transmits credentials in cleartext  
- Exposes API keys and secrets
- Sends payment data unencrypted
- Includes session tokens in URLs

## Part 1: Exploring HTTP Traffic (15 minutes)

### Step 1: Start the Lab

```bash
cd M05-Insecure-Communication/lab/m05-insecure-communication-lab/
docker-compose up
```

Access the application at: `http://localhost:5200`

### Step 2: Monitor Network Traffic

Open your browser's Developer Tools (F12) and go to the Network tab.

### Step 3: Test the Vulnerable Login

1. In the web interface, enter credentials:
   - Email: `alice@example.com`
   - Password: `Alice2024!`

2. Click "Login (over HTTP)"

3. In the Network tab, find the POST request to `/api/login`

4. Click on it and examine:
   - **Request Payload**: See the password in cleartext
   - **Response**: Session token, credit card, SSN all visible

**Key Observation**: All data is transmitted in plain text over HTTP. Anyone on the network can see this!

### Step 4: Intercept Configuration Data

1. Click "Get Config (over HTTP)" button

2. Examine the response in Network tab

3. Observe the exposed:
   - API keys
   - Database passwords
   - Internal system information

**Security Impact**: These secrets can be used to attack the backend infrastructure.

### Step 5: View Captured Traffic

Visit: `http://localhost:5200/api/debug/traffic`

This shows a simulation of what an attacker would capture by intercepting network traffic.

## Part 2: Advanced Traffic Interception (15 minutes)

### Option A: Using Browser DevTools

1. Keep Network tab open
2. Click "Clear" to reset
3. Perform all actions (login, get config, get profile, payment)
4. Review each request - all sensitive data is visible

### Option B: Using cURL (Command Line)

```bash
# Capture login request
curl -X POST http://localhost:5200/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"Alice2024!"}' \
  -v

# Capture config with secrets
curl http://localhost:5200/api/config -v

# Capture profile (token in URL!)
curl 'http://localhost:5200/api/user/profile?token=tok_insecure_alice_12345' -v
```

**Observation**: The `-v` flag shows full request/response headers and body.

### Option C: Using mitmproxy (Optional)

If you have mitmproxy installed:

```bash
# Terminal 1: Start mitmproxy
mitmproxy -p 8080

# Terminal 2: Make requests through proxy
curl -X POST http://localhost:5200/api/login \
  --proxy http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"Alice2024!"}'
```

All traffic will be visible in mitmproxy's interface.

## Part 3: Understanding the Vulnerabilities (10 minutes)

### Vulnerability 1: Cleartext Credentials

**Location**: `/api/login` endpoint

**Issue**: Passwords sent over HTTP

**Attack**: Network sniffing reveals credentials

**Impact**: Account takeover

### Vulnerability 2: API Key Exposure

**Location**: `/api/config` endpoint

**Issue**: Secrets embedded in HTTP responses

**Attack**: Extract API keys for unauthorized access

**Impact**: Backend system compromise

### Vulnerability 3: Session Token in URL

**Location**: `/api/user/profile?token=...`

**Issue**: Token in query parameter

**Attack**: Tokens logged in:
- Web server logs
- Browser history
- Referrer headers
- Analytics systems

**Impact**: Session hijacking

### Vulnerability 4: Payment Data Over HTTP

**Location**: `/api/payment` endpoint

**Issue**: Credit card data unencrypted

**Attack**: Capture payment details

**Impact**: Financial fraud, PCI-DSS violation

## Part 4: Security Analysis

### What an Attacker Sees

On a public WiFi network, an attacker running Wireshark would capture:

```
POST /api/login HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"email":"alice@example.com","password":"Alice2024!"}

HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "session_token": "tok_insecure_alice_12345",
  "user": {
    "email": "alice@example.com",
    "credit_card": "4532-1111-2222-3333",
    "ssn": "123-45-6789"
  }
}
```

**Everything is visible in cleartext!**

### Attack Scenarios

1. **Coffee Shop Attack**:
   - User connects to public WiFi
   - Logs into app using HTTP
   - Attacker captures credentials
   - Attacker gains account access

2. **API Abuse**:
   - App fetches config over HTTP
   - Attacker captures API keys
   - Uses keys to abuse backend services
   - Company faces service costs and data breach

3. **Payment Fraud**:
   - User makes purchase via app
   - Payment data sent over HTTP
   - Attacker captures credit card details
   - Fraudulent transactions occur

## Part 5: Secure Implementation

### Fix 1: Enforce HTTPS

**Instead of:**
```python
@app.route('/api/login', methods=['POST'])
def login():
    # Accepts HTTP
    data = request.get_json()
    # ...
```

**Use:**
```python
from flask_talisman import Talisman

# Enforce HTTPS
Talisman(app, force_https=True)

@app.route('/api/login', methods=['POST'])
def login():
    # Only accepts HTTPS
    if not request.is_secure:
        abort(403, "HTTPS required")
    # ...
```

### Fix 2: Use TLS 1.2+

**Mobile App Configuration (Android):**
```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

### Fix 3: Certificate Pinning

**Android Example:**
```java
CertificatePinner pinner = new CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAA...")
    .build();

OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(pinner)
    .build();
```

### Fix 4: Never Send Tokens in URLs

**Instead of:**
```
GET /api/user/profile?token=abc123
```

**Use:**
```
GET /api/user/profile
Authorization: Bearer abc123
```

## Part 6: Testing and Validation

### Test 1: Verify HTTPS Enforcement

```bash
# This should fail or redirect
curl http://localhost:5200/api/login

# This should succeed
curl https://localhost:5201/api/login
```

### Test 2: Check TLS Version

```bash
# Should fail (TLS 1.0)
openssl s_client -connect localhost:5201 -tls1

# Should succeed (TLS 1.2)
openssl s_client -connect localhost:5201 -tls1_2
```

### Test 3: Validate Certificate

```bash
# Check certificate details
openssl s_client -connect localhost:5201 -showcerts
```

## Key Takeaways

1. **Always use HTTPS** for any sensitive data transmission
2. **Never use HTTP** for authentication, personal data, or payments
3. **Implement certificate validation** - don't trust all certificates
4. **Use certificate pinning** for critical API connections
5. **Never put tokens in URLs** - use headers instead
6. **Configure TLS properly** - use TLS 1.2 or 1.3
7. **Test security** - verify HTTPS enforcement works

## Common Mistakes to Avoid

❌ Using HTTP during development, forgetting to switch to HTTPS  
❌ Disabling certificate validation for "testing"  
❌ Accepting self-signed certificates in production  
❌ Mixing HTTP and HTTPS content  
❌ Falling back to HTTP when HTTPS fails  
❌ Exposing tokens in query parameters or logs  

## Clean Up

```bash
# Stop the lab
docker-compose down
```

## Additional Challenges

1. **Challenge 1**: Set up Wireshark and capture HTTP traffic to the lab
2. **Challenge 2**: Use mitmproxy to intercept and modify requests
3. **Challenge 3**: Implement HTTPS version of the server with proper TLS
4. **Challenge 4**: Add certificate pinning validation

## Resources

- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Mozilla TLS Configuration Generator](https://ssl-config.mozilla.org/)
- [Certificate Pinning Guide](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)

---

**Congratulations!** You've completed the Insecure Communication lab. You now understand how HTTP traffic exposes sensitive data and how to implement secure HTTPS communication.
