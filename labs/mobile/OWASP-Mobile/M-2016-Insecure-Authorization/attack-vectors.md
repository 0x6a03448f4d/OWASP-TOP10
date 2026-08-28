# M6:2016 Insecure Authorization - Attack Vectors

## Table of Contents
- [Understanding Authorization Attack Vectors](#understanding-authorization-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [The Attacker's Toolkit](#the-attackers-toolkit)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Authorization Flaws](#chaining-authorization-flaws)

## Understanding Authorization Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in apps and APIs you own or are explicitly authorised to test.

Authorization is not attacked with clever payloads. It is attacked by a **legitimate, authenticated user doing something the designers assumed only the app would prevent**. The attacker already has a valid account and a valid token. Their entire method is to change *which object* or *which action* the request refers to, and observe whether the server says no.

The crucial shift in mindset is this: **the mobile app is the attacker's client, not the server's agent.** Every check the app performs, the attacker can remove. Every request the app sends, the attacker can capture, modify, and replay. So the only checks that count are the ones running on the server—and the attacker's job is to find the requests where those server checks are missing.

The attacker's goals in this category are:

- **Horizontal escalation**: read or modify other users' objects at the same privilege level (IDOR).
- **Vertical escalation**: invoke privileged/admin functionality as an ordinary user.
- **Entitlement bypass**: unlock paid/gated features without the entitlement.

### Core Attack Flow

```
1. Authenticate legitimately
   |
   Sign up / log in as a normal, low-privilege user. Get a valid token.
2. Observe
   |
   Proxy the app's traffic; catalogue endpoints, ids, role/permission fields
3. Tamper & replay
   |
   Change an object id, a role/permission field, or call an unseen endpoint
4. Escalate / exfiltrate
   |
   Enumerate other users' objects (horizontal) or run admin actions (vertical)
```

## The Attacker's Toolkit

None of these tools break cryptography or "hack the server." They simply let the attacker see and rewrite what their own device sends.

| Tool / technique | What it does for the attacker |
|------------------|-------------------------------|
| **Intercepting proxy** (Burp Suite, mitmproxy, OWASP ZAP) | Captures, edits, and replays the app's HTTPS requests—change ids, roles, bodies on the fly |
| **Frida / Objection** | Hooks the running app at runtime: bypass root/jailbreak & pinning checks, flip client-side booleans, dump entitlements |
| **APK decompilers** (jadx, apktool) | Reveal endpoints, hidden routes, and where the app does (or doesn't) rely on client-side checks |
| **Certificate-unpinning** (Frida scripts, patched builds) | Defeats pinning so the proxy can read traffic; pinning is not an authorization control |
| **Rooted / jailbroken device or emulator** | Reads and edits local storage (SharedPreferences, plists, SQLite) holding role/entitlement flags |
| **curl / Postman / repeater** | Talks to the API directly, with no app involved at all—the purest demonstration that the UI is irrelevant |

## Common Attack Patterns

### 1. IDOR — Horizontal Access by Changing an Object Id

The single most common form of M6. The app requests its own resources; the attacker substitutes another user's identifier.

```http
# The app's own request (attacker is user 1001):
GET /api/accounts/1001/statements HTTP/1.1
Authorization: Bearer <valid token for 1001>
-> 200 OK  { ...own statements... }

# Attacker edits the path id in the proxy and replays:
GET /api/accounts/1002/statements HTTP/1.1
Authorization: Bearer <same valid token for 1001>
-> 200 OK  { ...user 1002's statements... }   # server never checked ownership
```

**Payoff**: With a loop, the attacker enumerates every account. One missing ownership check equals full exposure of the object class. Object ids in the path, query string, body, or even headers are all fair game.

### 2. Vertical Escalation — Calling a Privileged Endpoint Directly

The admin capability lives in the same API. The app hides it; the attacker calls it anyway.

```http
# Never surfaced in the attacker's (non-admin) UI, but discovered by
# decompiling the app or observing an admin's traffic once:
POST /api/admin/users/1001/promote HTTP/1.1
Authorization: Bearer <valid token for ordinary user 1001>
Content-Type: application/json

{ "role": "admin" }
-> 200 OK   # endpoint had no server-side role check
```

**Payoff**: The ordinary account gains administrative power—create/modify users, change entitlements, export data.

### 3. Trusting a Client-Supplied Role or User Id

The backend reads identity or privilege from the request instead of the token.

```http
POST /api/transfer HTTP/1.1
Authorization: Bearer <valid token for user 1001>

{ "from_user_id": 1002, "amount": 5000 }     # act AS another user
# or
{ "amount": 5000, "role": "admin" }          # declare a privilege
```

**Payoff**: The attacker performs actions as another user, or with elevated rights, simply by editing a JSON field. Any identity/privilege field the client can set is attacker-controlled.

### 4. Removing / Flipping Client-Side Checks with Frida

When gating is done in the app, runtime hooking rewrites the decision.

```javascript
// Frida: force the client-side "isAdmin" / entitlement check to return true
Java.perform(function () {
  var Auth = Java.use('com.example.app.AuthManager');
  Auth.isAdmin.implementation = function () { return true; };   // UI unlocks
  Auth.isPremium.implementation = function () { return true; }; // gates open
});
```

**Payoff**: All client-enforced gates open. If the server relied on the app to block the follow-up requests, they now succeed. (If the server checks independently, this only changes the attacker's UI—which is exactly the desired outcome of correct design.)

### 5. Tampering with Locally-Stored Entitlement Flags

```
# Android, rooted device — edit the app's SharedPreferences:
/data/data/com.example.app/shared_prefs/entitlements.xml
  <boolean name="is_premium" value="false" />   ->   value="true"

# iOS, jailbroken — edit the app's plist / UserDefaults:
<key>tier</key><string>free</string>          ->   <string>enterprise</string>
```

**Payoff**: If features are unlocked based on these local values—and the server does not re-verify entitlement per request—the attacker gets paid functionality for free.

### 6. Forced Browsing / Endpoint Enumeration

The attacker guesses or discovers routes the app never displays.

```http
GET  /api/admin/users            # conventional admin paths
GET  /api/users/1002/export      # sibling of a known endpoint
GET  /api/internal/config        # "internal", but internet-reachable
POST /api/accounts/1002/close    # destructive action on another's object
```

**Payoff**: Unlisted does not mean unreachable. Any route without a server-side check is exploitable regardless of whether a screen calls it.

### 7. Mass Assignment onto Privilege Fields

An update endpoint binds the whole request body to the model, including fields the user should never set.

```http
PATCH /api/users/1001 HTTP/1.1
Authorization: Bearer <valid token for user 1001>

{ "displayName": "Alice", "role": "admin", "accountBalance": 999999 }
# The app only ever sends displayName; the attacker adds role/balance.
```

**Payoff**: Vertical escalation or data tampering through fields the UI never exposes but the model happily accepts.

### 8. Replaying an Admin's Captured Request

If any privileged action was ever observed (a shared device, a captured session, a leaked HAR), its shape is known and can be replayed with the attacker's own valid token against an unprotected endpoint.

```http
Observed once:  POST /api/admin/coupons  { "code":"FREE100","value":100 }
Replayed by attacker with THEIR token -> 200 OK if no server-side role check
```

**Payoff**: The attacker reproduces privileged operations without ever being an admin.

## Chaining Authorization Flaws

Individually modest gaps combine into full compromise—and M6 chains especially well with M4 (authentication):

```
Weak login / guessable token (M4)   -> obtain ANY valid session
        +
No per-object ownership check (M6)  -> that session reads every user's data
        =  full account-data breach from two "medium" findings
```

A pure-authorization chain:

```
IDOR on /api/users/{id}            -> read another user's profile + their org_id
        -> mass-assign role=admin on PATCH /api/users/{id}
        -> call /api/admin/* now that the account is "admin"
        =  horizontal access escalates into full vertical takeover
```

## Detecting These Attacks

- **Access-pattern anomalies**: one token requesting many distinct object ids in sequence (id enumeration) is a strong IDOR signal.
- **Authorization-denied spikes**: bursts of 403s from one principal indicate probing—log and alert on them (and make sure the route actually returns 403, not 200).
- **Privileged routes hit by non-privileged principals**: alert whenever an admin endpoint is called by a token whose server-side role is not admin.
- **Body fields that should be server-controlled**: log when requests carry `role`, `user_id`, `tenant_id`, or entitlement fields the client should never set.

## Key Takeaways

1. **The attacker is a valid user.** They don't break in—they log in, then reach beyond their entitlement.
2. **Every client-side check can be removed.** Proxies replay requests; Frida flips booleans; storage flags are editable. Only server checks count.
3. **Changing one id is the whole attack.** IDOR—substituting another user's object reference—is the most common and highest-yield vector.
4. **Hidden endpoints are still reachable.** Forced browsing and decompilation expose routes the UI never shows.
5. **Small gaps chain.** IDOR plus mass assignment plus an unguarded admin route equals total takeover.

## Next Steps

- **[Prevention Guide](prevention.md)**: Enforce authorization server-side on every request
- **[Code Examples](examples.md)**: Vulnerable vs. secure across Android, iOS, and the backend
- **[Mobile Learning Path](/learn/mobile)**: Continue the OWASP Mobile Top 10
- **[Practice](/practice)**: Apply these techniques in the hands-on challenges
