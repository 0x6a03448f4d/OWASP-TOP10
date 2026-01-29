# Modern Authentication Attacks

## AI-Enhanced Credential Stuffing

```python
# Attackers use ML to optimize attacks
# Pattern recognition for valid usernames
# Password mutation based on breach patterns
# Evades simple rate limiting
```

## MFA Fatigue Attack

```
1. Attacker has valid password
2. Repeatedly triggers MFA push notifications
3. User gets frustrated, accepts one
4. Attacker gains access
```

## OAuth Token Theft

```python
# Misconfigured OAuth redirect
# Attacker intercepts authorization code
# Exchanges for access token
# Impersonates user
```

## Container Secret Exposure

```dockerfile
# DANGEROUS: Secrets in Docker image
ENV API_KEY="sk_live_abc123"

# Attacker pulls image
docker pull company/app
docker inspect company/app  # Sees API_KEY
```
