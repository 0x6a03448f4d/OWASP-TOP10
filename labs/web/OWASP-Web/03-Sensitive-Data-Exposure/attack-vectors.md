# A3:2017 – Sensitive Data Exposure: Attack Vectors

## Table of Contents

- [The Core Attack Flow](#the-core-attack-flow)
- [Attacks on Data In Transit](#attacks-on-data-in-transit)
- [Attacks on Data In Use](#attacks-on-data-in-use)
- [Attacks on Data At Rest](#attacks-on-data-at-rest)
- [Reconnaissance Tooling Summary](#reconnaissance-tooling-summary)
- [Next Steps](#next-steps)

## The Core Attack Flow

Attacking sensitive data rarely requires a clever exploit. Because A3 is about data reaching the wrong place, the attacker's job is usually to *find the place it already leaked*. The workflow is opportunistic and cheap:

```
1. IDENTIFY  -> What sensitive data does this target hold? (users, cards, health, secrets)
2. MAP FLOW  -> Where does that data travel and rest? (transport, storage, logs, backups, client)
3. FIND GAP  -> Which leg is unprotected? (HTTP, weak TLS, exposed dump, cached response, secret in JS)
4. HARVEST   -> Passively collect or directly download the data
5. MONETISE  -> Crack hashes, commit fraud, reuse credentials, extort, or resell
```

The three sections below follow the three states of data — in transit, in use, at rest — because that is how a defender should reason about coverage. Each numbered pattern is a distinct vector.

## Attacks on Data In Transit

### 1. Passive Interception of Cleartext (HTTP)

The simplest vector: the target serves login, session, or API traffic over plain HTTP. Anyone on the network path — the same coffee-shop Wi-Fi, a compromised switch, an ISP-level tap — reads everything without touching the server.

```bash
# Capture cleartext HTTP credentials on a shared segment
sudo tcpdump -i wlan0 -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Or filter a captured pcap for form posts
tshark -r capture.pcap -Y 'http.request.method == "POST"' -T fields -e http.file_data
```

**What leaks**: usernames, passwords, session cookies, API keys, and any form field — all in plaintext.

### 2. Active Downgrade / SSL Stripping

Even a site that *offers* HTTPS can be attacked if the user's first request is HTTP (typing `example.com` rather than `https://example.com`). A man-in-the-middle keeps its own HTTP connection to the victim while proxying HTTPS to the server, so the victim never sees the padlock.

```bash
# Position as MITM, then downgrade the victim's HTTPS links to HTTP
# (conceptual - lab/authorised testing only)
sudo sysctl -w net.ipv4.ip_forward=1
# ARP-spoof the victim and gateway, then run an SSL-stripping proxy
bettercap -iface eth0 -eval "set arp.spoof.targets 192.168.1.20; arp.spoof on; http.proxy on"
```

**Defence that breaks this**: HSTS with preload forces the browser to use HTTPS for the very first request, leaving no HTTP leg to strip.

### 3. Weak / Obsolete TLS Configuration

Transport can be "encrypted" and still exposed if it negotiates a broken protocol or cipher. Attackers enumerate the server's TLS to find SSLv3, TLS 1.0/1.1, export ciphers, or RC4 that permit downgrade or decryption.

```bash
# Enumerate offered protocols and ciphers
nmap --script ssl-enum-ciphers -p 443 target.example.com

# Detailed audit: weak protocols, cipher order, cert issues
testssl.sh https://target.example.com

# Probe for a legacy protocol directly
openssl s_client -connect target.example.com:443 -tls1
```

**What leaks**: with a weak protocol negotiated, traffic that looked protected can be downgraded or decrypted in transit.

### 4. Mixed Content

An HTTPS page that pulls a script, image, or form action over HTTP creates a cleartext side-channel on an otherwise secure page. The insecure sub-resource can be intercepted or modified, and a form posting to `http://` ships its data in the clear.

```html
<!-- Vulnerable: secure page, insecure script and form target -->
<script src="http://cdn.example.com/app.js"></script>
<form action="http://api.example.com/login" method="post"> ... </form>
```

**What leaks**: the sub-resource request (and any credentials the form submits) travels over HTTP even though the page is HTTPS.

## Attacks on Data In Use

### 5. Sensitive Data in URLs (Query Strings)

Placing a token, password-reset key, or account number in the URL exposes it in three places at once, none of them encrypted at the destination: browser history, server/proxy access logs, and the `Referer` header sent to any third-party resource the page loads.

```
# A reset link with the secret in the query string
https://app.example.com/reset?token=8f3c1a9e-secret-value

# The token now appears in:
#  - the server access log
GET /reset?token=8f3c1a9e-secret-value HTTP/1.1  200
#  - the Referer sent to a third-party analytics/font/ad host loaded by that page
Referer: https://app.example.com/reset?token=8f3c1a9e-secret-value
```

**What leaks**: any secret in the query string, harvestable by anyone with access to logs, history, or the referred-to third party.

### 6. Cacheable Sensitive Responses

Responses that return sensitive data without cache-control directives may be stored by the browser's disk cache and by shared/forward proxies. On a shared machine, the next user can read the cached account page; a shared proxy may serve one user's cached data to another.

```
# Vulnerable response: no cache directives on a sensitive page
HTTP/1.1 200 OK
Content-Type: text/html
# (no Cache-Control, no Pragma) -> stored in browser disk cache and by proxies

# The attacker on a shared/kiosk machine simply reads the cache
ls -la ~/.cache/mozilla/firefox/*/cache2/entries/
```

**What leaks**: account pages, statements, tokens embedded in HTML — recoverable from cache after the session ends.

### 7. Secrets in Client-Side Code

Front-end bundles, source maps, and mobile app packages routinely ship API keys, internal endpoints, and even backend credentials that developers assumed were "hidden." They are one download and a grep away.

```bash
# Pull and grep a site's JavaScript for secrets
for f in $(curl -s https://app.example.com | grep -oE 'src="[^"]+\.js"' | cut -d'"' -f2); do
  curl -s "https://app.example.com/$f"
done | grep -Ei 'api[_-]?key|secret|token|password|AKIA[0-9A-Z]{16}'

# Source maps often expose original source with comments and endpoints
curl -s https://app.example.com/static/app.js.map | jq -r '.sourcesContent[]' | grep -i secret
```

**What leaks**: API keys, cloud access keys, internal URLs, hard-coded credentials.

### 8. Sensitive Data in Logs and Error Output

Verbose logging and unhandled errors capture request bodies, headers, and stack traces that contain passwords, tokens, and card numbers. If those logs are shipped to a less-protected aggregator, or the error is rendered to the user, the data is exposed well outside the database that was carefully locked down.

```bash
# Trigger a verbose error and read leaked internals
curl -s "https://app.example.com/api/pay" -d 'card=4111111111111111&cvv=123'

# Vulnerable response echoes the input in a stack trace
HTTP/1.1 500 Internal Server Error
... ValueError: charge failed for card=4111111111111111 cvv=123
    at /srv/app/pay.py line 88 ...
```

**What leaks**: whatever the request carried — frequently the exact sensitive fields the endpoint processes.

### 9. Browser Storage and Autocomplete Residue

Sensitive values written to `localStorage`/`sessionStorage`, or form fields that permit autocomplete on shared devices, persist client-side. Any script running on the origin (including via XSS) can read web storage, and physical access to the device recovers autocompleted secrets.

```javascript
// Any script on the origin can exfiltrate tokens kept in web storage
JSON.stringify(localStorage)   // -> {"auth_token":"eyJ...","ssn":"..."}
```

**What leaks**: tokens and PII stored client-side, readable by XSS or the next person at the keyboard.

## Attacks on Data At Rest

### 10. Exposed Backups and Database Dumps

A dump left in the web root or on a public share is the whole database with none of the application's access control in front of it. Attackers brute-force common backup names as a matter of routine.

```bash
# Hunt for exposed dumps and archives by extension
gobuster dir -u https://target.example.com \
  -w /usr/share/wordlists/common.txt \
  -x sql,bak,db,dump,tar.gz,zip,old

# Common hits an attacker checks by hand
/backup.sql   /db.sql.gz   /database.bak   /dump.tar.gz   /users.csv   /.env
```

**What leaks**: the entire dataset, plus config files like `.env` that carry credentials and keys.

### 11. Publicly Exposed Datastores and Cloud Storage

Databases bound to a public interface with authentication off, and object-storage buckets set to public read, are indexed by internet-wide scanners. No application vulnerability is involved — the data is simply reachable.

```bash
# Internet-wide search surfaces exposed services (via Shodan-style queries)
#   product:MongoDB  port:27017
#   product:Elasticsearch  port:9200

# Probe an unauthenticated database directly
mongosh "mongodb://target.example.com:27017" --eval "db.adminCommand('listDatabases')"
curl -s "http://target.example.com:9200/_cat/indices?v"

# List a world-readable object-storage bucket
curl -s "https://storage.example.com/customer-backups/?list-type=2"
```

**What leaks**: complete collections/indices, and every object in a public bucket.

### 12. Secrets in Source Control History

Committed secrets are harvested by bots within minutes of a push to a public repo, and they survive in history even after a "remove secret" commit. Internal repos are mined once an attacker gains any read access.

```bash
# Scan a repository (including full history) for committed secrets
gitleaks detect --source . --report-format json

# A "removed" key is still recoverable from history
git log -p --all -S 'AKIA' | grep -i 'aws\|secret\|key'
```

**What leaks**: cloud keys, DB passwords, signing keys, tokens — still valid until rotated.

### 13. Offline / Stolen Media and Weak At-Rest Encryption

A stolen disk, decommissioned drive, or snapshot copied out of the account exposes everything unless the data itself is encrypted with keys the thief does not have. "Encrypted volume" alone fails once the attacker reaches a running system that has already mounted it.

```bash
# An unencrypted dump or table file read straight off recovered media
strings /recovered/postgres/base/16384/2836 | grep -Ei 'ssn|card|email'
```

**What leaks**: anything stored in plaintext or protected only by a key stored alongside the data.

### 14. Cracking Weak Password Hashes After a Leak

Once any of the vectors above yields a user table, the value of the passwords depends entirely on how they were hashed. Unsalted MD5/SHA-1 falls to rainbow tables and GPU cracking almost instantly; fast hashes without a work factor follow soon after.

```bash
# Offline cracking of leaked unsalted MD5 hashes
hashcat -m 0 -a 0 leaked_md5.txt rockyou.txt        # raw MD5
hashcat -m 100 -a 0 leaked_sha1.txt rockyou.txt      # raw SHA-1

# Salted bcrypt (mode 3200) is orders of magnitude slower to attack - by design
hashcat -m 3200 -a 0 leaked_bcrypt.txt rockyou.txt
```

**What leaks**: plaintext passwords, then reused via credential stuffing against other services. (For the cryptographic depth behind this, see the [Cryptographic Failures](../02-Cryptographic-Failures/attack-vectors.md) lesson.)

## Reconnaissance Tooling Summary

| Goal | Tool | What it reveals |
|------|------|-----------------|
| Intercept cleartext | tcpdump, Wireshark/tshark, mitmproxy | Credentials and tokens sent over HTTP |
| Audit TLS | testssl.sh, nmap ssl-enum-ciphers, sslyze | Weak protocols, ciphers, cert problems |
| Downgrade / MITM | bettercap, mitmproxy | Strippable HTTPS, missing HSTS |
| Find exposed files | gobuster, feroxbuster, ffuf | Backups, dumps, `.env`, config |
| Find exposed services | Shodan, Censys, masscan | Public databases and buckets |
| Find secrets in code | gitleaks, trufflehog, grep | Keys and credentials in repos/JS |
| Crack recovered hashes | hashcat, John the Ripper | Plaintext from weak password hashes |

> Every tool above is a defensive tool too. Run them against your own systems, on scope you are authorised to test, before an attacker does — most of these findings are trivial to detect from the outside.

## Next Steps

- **[Prevention](./prevention.md)**: Close each of these vectors with layered defences
- **[Examples](./examples.md)**: Vulnerable vs. secure code and configuration
- **[Overview](./overview.md)**: The concepts and data classification behind these attacks
- **[Hands-On Lab](./lab/sensitive-data-exposure/)**: Practice identifying and fixing exposure in a safe, isolated environment

---

*Part of the [OWASP Top 10 Educational Repository](/)*
