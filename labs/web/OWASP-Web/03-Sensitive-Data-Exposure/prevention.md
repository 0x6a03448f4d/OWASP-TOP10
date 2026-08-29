# A3:2017 – Sensitive Data Exposure: Prevention

## Table of Contents

- [Defence in Layers](#defence-in-layers)
- [Layer 1: Classify and Minimise](#layer-1-classify-and-minimise)
- [Layer 2: Protect Data In Transit](#layer-2-protect-data-in-transit)
- [Layer 3: Protect Data At Rest](#layer-3-protect-data-at-rest)
- [Layer 4: Store Passwords as Hashes](#layer-4-store-passwords-as-hashes)
- [Layer 5: Close In-Use Leaks (Caching, URLs, Logs)](#layer-5-close-in-use-leaks-caching-urls-logs)
- [Layer 6: Manage Secrets and Backups](#layer-6-manage-secrets-and-backups)
- [Layer 7: Retention and Disposal](#layer-7-retention-and-disposal)
- [Prevention Checklist](#prevention-checklist)
- [Next Steps](#next-steps)

## Defence in Layers

No single control prevents Sensitive Data Exposure, because the category spans the whole data lifecycle. Effective prevention stacks independent layers so that a failure in one does not become a breach. The ordering below is deliberate: it starts by *reducing what you must protect*, then protects it in transit, at rest, and in use, and finally governs the copies and their disposal.

```
Classify & minimise   -> you cannot leak data you never collected or already deleted
        +
Protect in transit    -> TLS everywhere, HSTS, no weak protocols, no mixed content
        +
Protect at rest       -> encrypt DB/files/backups; keys in a KMS, not beside the data
        +
Hash passwords        -> salted, slow hashing so a DB leak is not a password leak
        +
Close in-use leaks    -> no secrets in URLs, no caching of sensitive responses, redacted logs
        +
Manage secrets/backups-> secret store, private buckets, encrypted backups outside the web root
        +
Retain & dispose      -> delete on schedule across every copy
        =
Defence in depth: one failure is contained, not catastrophic
```

## Layer 1: Classify and Minimise

The cheapest data to protect is the data you do not hold. Before any encryption decision, build an inventory and apply minimisation.

- **Inventory and classify**: enumerate every field you collect, tag its sensitivity (public / internal / confidential / regulated), and record where it is stored and who can read it.
- **Don't collect what you don't need**: if a feature does not require a date of birth or a full card number, do not ask for it.
- **Tokenise or truncate**: store a token or the last four digits instead of a full PAN; never store CVV at all.
- **Separate and restrict**: keep regulated data in a dedicated store with tighter access than the rest of the application.

```python
# Example: reduce what you keep at the point of collection (Python)
def store_payment(card_number: str, cvv: str) -> str:
    # DO NOT persist the PAN or CVV yourself.
    token = payment_gateway.tokenize(card_number, cvv)   # gateway holds the PAN
    last4 = card_number[-4:]
    db.save(payment_token=token, last4=last4)             # you keep only a token + last4
    return token   # CVV is never written anywhere
```

## Layer 2: Protect Data In Transit

Every network hop that carries sensitive data must be encrypted with modern TLS, and the browser must be told never to fall back to HTTP. The server configuration below is the backbone control for A3.

### Nginx: HTTPS, HSTS, redirect, modern protocols

```nginx
# Redirect all HTTP to HTTPS - no cleartext leg to intercept or strip
server {
    listen 80;
    server_name app.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate     /etc/ssl/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/app.example.com/privkey.pem;

    # Modern protocols only - no SSLv3, TLS 1.0/1.1
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;   # let TLS 1.3 negotiate; strong 1.2 suites below
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    # Force HTTPS on every future request, including the first, for a year + subdomains
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
    }
}
```

> **Also encrypt the internal legs.** TLS that terminates at the load balancer and travels cleartext to the app or database still exposes data to anyone inside the network. Use TLS (or mTLS) for service-to-service and database connections too — "internal" is not "safe."

## Layer 3: Protect Data At Rest

Encryption at rest limits what an attacker gains from a stolen disk, an exfiltrated dump, or a compromised backup. The critical rule is **key separation**: the key must not live in the same place as the data it protects.

### Application/field-level encryption with a managed key (Python)

```python
import os
from cryptography.fernet import Fernet

# Key comes from a KMS / secret manager at runtime - NEVER hard-coded, NEVER in the DB.
# In production, prefer a cloud KMS (envelope encryption) over a raw local key.
key = os.environ["FIELD_ENCRYPTION_KEY"]   # injected by the secret store
cipher = Fernet(key)

def encrypt_field(plaintext: str) -> bytes:
    return cipher.encrypt(plaintext.encode())      # AES-128-CBC + HMAC under the hood

def decrypt_field(ciphertext: bytes) -> str:
    return cipher.decrypt(ciphertext).decode()

# Store only ciphertext; an attacker who dumps the table gets nothing usable
db.save(ssn_enc=encrypt_field(user_ssn))
```

### Key management principles

- **Use a KMS / secret manager** (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault) with envelope encryption — the master key never leaves the KMS.
- **Never hard-code keys** or commit them; never store the key in the same database as the ciphertext.
- **Rotate keys** on a schedule and support re-encryption; scope access so only the services that need to decrypt can.
- **Layer with volume encryption**, but do not rely on it alone — it does not protect a running, compromised app.

For the deeper treatment of algorithm and mode selection (AES-GCM, ChaCha20-Poly1305, avoiding ECB, IV handling), see the dedicated [Cryptographic Failures](../02-Cryptographic-Failures/prevention.md) lesson.

## Layer 4: Store Passwords as Hashes

Passwords are never encrypted — they are hashed with a salted, deliberately slow algorithm so that even a full database leak does not hand over the plaintext. This is the control that keeps "database breach" from automatically meaning "password breach."

```python
# Argon2id (preferred) - Python
from argon2 import PasswordHasher
ph = PasswordHasher()                 # salted automatically, tunable work factor

hash = ph.hash(user_password)         # store this
# ... later, at login:
try:
    ph.verify(hash, submitted_password)   # constant-time verify, no "decrypt"
except Exception:
    reject_login()
```

- **Use** Argon2id, bcrypt, or scrypt — all salted and slow by design.
- **Never use** MD5, SHA-1, or plain SHA-256/512 for passwords — they are far too fast to resist offline cracking.
- **Tune the work factor** so a single verify takes a noticeable fraction of a second on your hardware.

## Layer 5: Close In-Use Leaks (Caching, URLs, Logs)

These are the leaks that no amount of transport or storage encryption catches, and they are the heart of the broad 2017 framing.

### Keep sensitive responses out of caches

```javascript
// Node/Express: mark sensitive responses uncacheable
app.get('/account/statement', (req, res) => {
    res.set('Cache-Control', 'no-store');   // do not write to any cache
    res.set('Pragma', 'no-cache');          // legacy proxies
    res.json(getStatement(req.user));
});
```

### Never put secrets in URLs

- Send tokens and identifiers in the request **body** or an **Authorization header**, never the query string.
- Set `Referrer-Policy: no-referrer` (or `strict-origin`) so URLs do not leak to third parties.
- Use POST for anything sensitive so it does not land in access logs or history.

### Redact sensitive fields before logging

```python
# Python logging filter that scrubs sensitive fields
import logging, re

SENSITIVE = re.compile(r'(password|cvv|card|ssn|token)=([^&\s]+)', re.I)

class RedactFilter(logging.Filter):
    def filter(self, record):
        record.msg = SENSITIVE.sub(r'\1=[REDACTED]', str(record.msg))
        return True

logging.getLogger().addFilter(RedactFilter())
# Now "card=4111111111111111" is logged as "card=[REDACTED]"
```

- Log identifiers, not payloads; never log passwords, tokens, card numbers, or full request bodies for sensitive endpoints.
- Return **generic** error messages to clients; keep detail in server-side logs (which are themselves access-controlled and, ideally, redacted).

## Layer 6: Manage Secrets and Backups

### Secrets

- Store credentials, keys, and tokens in a secret manager or environment configuration injected at runtime — never in source, config files committed to git, or client-side code.
- Run a secret scanner (gitleaks, trufflehog) in CI and as a pre-commit hook; **rotate** anything ever committed, because history keeps it.

```bash
# Pre-commit / CI gate that blocks secrets from entering the repo
gitleaks protect --staged --redact        # pre-commit
gitleaks detect --source . --exit-code 1   # CI: fail the build on any finding
```

### Backups and object storage

- Encrypt every backup with a key held separately, and store it **outside the web root** and outside any public bucket.
- Set object storage to **private by default**; enable "block public access," and require authentication plus TLS to fetch.
- Test restores, and apply the same retention limits to backups that you apply to live data.

## Layer 7: Retention and Disposal

Data held forever is data waiting to leak. Define and enforce retention, and account for every copy when you delete.

- **Set retention policies** per data class and automate deletion (scheduled jobs, TTLs, lifecycle rules on storage).
- **Delete across all copies**: live tables, read replicas, search indexes, caches, analytics pipelines, backups, and third-party processors.
- **Crypto-shred** where hard deletion is impractical: destroy the encryption key so the ciphertext becomes unrecoverable.

```sql
-- Automated retention: purge expired sensitive records on a schedule
DELETE FROM password_reset_tokens WHERE created_at < NOW() - INTERVAL '1 hour';
DELETE FROM audit_pii            WHERE created_at < NOW() - INTERVAL '90 days';
```

## Prevention Checklist

| Layer | Control | Done? |
|-------|---------|-------|
| Classify | Current data inventory with sensitivity labels and locations | [ ] |
| Minimise | Collect and retain only what is needed; tokenise PAN; never store CVV | [ ] |
| Transit | HTTPS everywhere, HSTS (preload), TLS 1.2+ only, no mixed content | [ ] |
| Transit | Internal service and DB connections encrypted too | [ ] |
| At rest | Sensitive data encrypted; keys in a KMS, separate from data | [ ] |
| Passwords | Salted, slow hashing (Argon2/bcrypt/scrypt); no MD5/SHA-1 | [ ] |
| In use | `Cache-Control: no-store` on sensitive responses | [ ] |
| In use | No secrets in URLs; restrictive `Referrer-Policy` | [ ] |
| In use | Logs redact sensitive fields; generic client errors | [ ] |
| Secrets | Secret manager; secret scanning in CI; rotation | [ ] |
| Backups | Encrypted, access-controlled, outside web root; storage private by default | [ ] |
| Retention | Automated deletion across all copies; crypto-shred where needed | [ ] |

## Next Steps

- **[Examples](./examples.md)**: See these controls as vulnerable vs. secure code and config
- **[Attack Vectors](./attack-vectors.md)**: Understand exactly what each layer defends against
- **[Overview](./overview.md)**: The data-classification foundation these layers rest on
- **[Hands-On Lab](./lab/sensitive-data-exposure/)**: Practice fixing exposure in a safe, isolated environment

---

*Part of the [OWASP Top 10 Educational Repository](/)*
