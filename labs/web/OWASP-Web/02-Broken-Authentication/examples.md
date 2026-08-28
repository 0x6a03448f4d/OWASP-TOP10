# A2:2017 - Broken Authentication - Examples

## Table of Contents

- [How to Read These Examples](#how-to-read-these-examples)
- [PHP: Password Storage & Login](#php-password-storage--login)
- [Python / Flask: Login, Rate Limit & Session](#python--flask-login-rate-limit--session)
- [Node.js / Express: Session & Cookie Handling](#nodejs--express-session--cookie-handling)
- [Java / Spring: Password Hashing & MFA](#java--spring-password-hashing--mfa)
- [Summary of Fixes](#summary-of-fixes)
- [Next Steps](#next-steps)

## How to Read These Examples

Each example shows a **vulnerable** implementation and the **secure** version that fixes it, in the same language, so the specific change is easy to spot. The four languages cover the same underlying lessons—correct hashing, session regeneration, cookie flags, rate limiting, generic errors, and MFA verified before session elevation—so read across them to see the pattern repeat.

## PHP: Password Storage & Login

### Vulnerable

```php
<?php
// login.php — multiple classic A2 flaws
$user = $db->query("SELECT * FROM users WHERE name = '$username'")->fetch();

// FLAW 1: password stored/compared as unsalted MD5
if ($user && $user['password'] === md5($password)) {
    // FLAW 2: no session regeneration -> session fixation
    $_SESSION['uid'] = $user['id'];
    header("Location: /dashboard.php");
} else {
    // FLAW 3: message reveals whether the username exists (enumeration)
    echo $user ? "Wrong password" : "No such user";
    // FLAW 4: no rate limiting anywhere -> brute force / stuffing
}
?>
```

### Secure

```php
<?php
// login.php — hardened
if (!$rateLimiter->allow($username, $_SERVER['REMOTE_ADDR'])) {
    http_response_code(429);
    exit("Too many attempts. Please try again later.");
}

// Parameterized query (also closes SQL injection)
$stmt = $pdo->prepare("SELECT id, password_hash FROM users WHERE name = ?");
$stmt->execute([$username]);
$user = $stmt->fetch();

// Always run password_verify, even for unknown users, against a dummy hash
// so timing does not reveal account existence.
$hash = $user['password_hash'] ?? '$2y$12$'.str_repeat('.', 53);
$valid = password_verify($password, $hash);

if ($user && $valid) {
    session_regenerate_id(true);           // FIX: kill session fixation
    $_SESSION['uid'] = $user['id'];
    if (password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => 12])) {
        $new = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?")
            ->execute([$new, $user['id']]);
    }
    $rateLimiter->reset($username);
    header("Location: /dashboard.php");
} else {
    $rateLimiter->recordFailure($username, $_SERVER['REMOTE_ADDR']);
    echo "Invalid username or password.";  // FIX: generic message
}
// Registration: $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
?>
```

## Python / Flask: Login, Rate Limit & Session

### Vulnerable

```python
from flask import Flask, request, session, redirect
import hashlib

app = Flask(__name__)
app.secret_key = "hardcoded-secret"        # FLAW: secret in source

@app.route("/login", methods=["POST"])
def login():
    u = request.form["username"]
    p = request.form["password"]
    row = db.execute("SELECT id, pw FROM users WHERE name = ?", (u,)).fetchone()

    # FLAW: fast, unsalted SHA-256; == is not constant-time
    if row and row["pw"] == hashlib.sha256(p.encode()).hexdigest():
        session["uid"] = row["id"]         # FLAW: no session regeneration
        return redirect("/home")
    return "Login failed: user not found" if not row else "Wrong password"
    # FLAW: enumeration + no rate limiting + insecure cookie defaults
```

### Secure

```python
import os, time
from flask import Flask, request, session, redirect, abort
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
app.secret_key = os.environ["SESSION_SECRET"]        # FIX: from environment
app.config.update(
    SESSION_COOKIE_SECURE=True,      # FIX: HTTPS-only cookie
    SESSION_COOKIE_HTTPONLY=True,    # FIX: not readable by JS
    SESSION_COOKIE_SAMESITE="Lax",   # FIX: limit cross-site sending
    PERMANENT_SESSION_LIFETIME=1800, # FIX: absolute timeout (30 min)
)
ph = PasswordHasher()
DUMMY = ph.hash("throwaway")                          # for uniform timing

@app.route("/login", methods=["POST"])
def login():
    u, p = request.form["username"], request.form["password"]
    if not rate_limiter.allow(u, request.remote_addr):
        abort(429)

    row = db.execute("SELECT id, pw_hash FROM users WHERE name = ?",
                     (u,)).fetchone()
    target_hash = row["pw_hash"] if row else DUMMY    # always verify something
    ok = False
    try:
        ph.verify(target_hash, p)
        ok = row is not None
    except VerifyMismatchError:
        ok = False

    if ok:
        session.clear()                               # FIX: drop pre-auth state
        session["uid"] = row["id"]                    # new session id issued
        session["auth_at"] = time.time()
        rate_limiter.reset(u)
        if ph.check_needs_rehash(target_hash):
            db.execute("UPDATE users SET pw_hash = ? WHERE id = ?",
                       (ph.hash(p), row["id"]))
        return redirect("/home")

    rate_limiter.record_failure(u, request.remote_addr)
    return "Invalid username or password.", 401       # FIX: generic message
```

## Node.js / Express: Session & Cookie Handling

### Vulnerable

```javascript
const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
  secret: 'keyboard cat',           // FLAW: weak, hardcoded secret
  resave: true,
  saveUninitialized: true,
  // FLAW: cookie defaults — not Secure, not HttpOnly-enforced, no SameSite
}));

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.name === username);
  // FLAW: plaintext password comparison
  if (user && user.password === password) {
    req.session.uid = user.id;      // FLAW: no session regeneration
    return res.redirect('/home');
  }
  // FLAW: enumeration message + no throttling
  res.send(user ? 'Wrong password' : 'Unknown user');
});

// FLAW: logout only clears the cookie client-side
app.get('/logout', (req, res) => res.clearCookie('connect.sid').redirect('/'));
```

### Secure

```javascript
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const app = express();
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET,      // FIX: strong secret from env
  name: 'sid',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 1800000 },
}));

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 20 }); // FIX
const DUMMY_HASH = bcrypt.hashSync('throwaway', 12);   // uniform timing

app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = await db.findUserByName(username);
  const hash = user ? user.passwordHash : DUMMY_HASH;  // always compare
  const ok = (await bcrypt.compare(password, hash)) && !!user;

  if (!ok) {
    return res.status(401).send('Invalid username or password.'); // FIX
  }
  // FIX: regenerate session id on login (prevents fixation)
  req.session.regenerate(err => {
    if (err) return res.sendStatus(500);
    req.session.uid = user.id;
    req.session.authAt = Date.now();
    res.redirect('/home');
  });
});

// FIX: destroy the session server-side on logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.clearCookie('sid').redirect('/'));
});
```

## Java / Spring: Password Hashing & MFA

### Vulnerable

```java
// Plain servlet-style login — several A2 flaws
protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    String user = req.getParameter("username");
    String pass = req.getParameter("password");

    User u = userDao.findByName(user);
    // FLAW: SHA-1 hex compare, non-constant-time, no salt
    String hashed = DigestUtils.sha1Hex(pass);
    if (u != null && u.getHash().equals(hashed)) {
        // FLAW: reuse the existing session -> fixation
        req.getSession().setAttribute("uid", u.getId());
        resp.sendRedirect("/home");
    } else {
        // FLAW: enumeration + no lockout + no MFA
        resp.getWriter().println(u == null ? "No such user" : "Bad password");
    }
}
```

### Secure

```java
// Spring Security config: strong hashing, session fixation protection
@Bean
public PasswordEncoder passwordEncoder() {
    // FIX: Argon2 (or BCryptPasswordEncoder(12)) — salted, slow, tunable
    return new Argon2PasswordEncoder(16, 32, 1, 1 << 14, 2);
}

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
      .authorizeHttpRequests(a -> a.anyRequest().authenticated())
      .formLogin(form -> form.loginPage("/login")
          .failureUrl("/login?error"))               // FIX: generic failure
      .sessionManagement(s -> s
          .sessionFixation(sf -> sf.newSession())    // FIX: new id on auth
          .maximumSessions(1))                       // limit concurrent sessions
      .logout(l -> l.invalidateHttpSession(true)     // FIX: server-side logout
          .deleteCookies("JSESSIONID"));
    return http.build();
}

// FIX: verify the second factor BEFORE completing authentication
public boolean verifyTotp(User user, String code) {
    return totpVerifier.isValid(user.getTotpSecret(), code);  // RFC 6238
}

// Secure cookie flags (application.properties):
//   server.servlet.session.cookie.secure=true
//   server.servlet.session.cookie.http-only=true
//   server.servlet.session.cookie.same-site=lax
//   server.servlet.session.timeout=30m
```

## Summary of Fixes

| Vulnerable pattern | Secure replacement |
|--------------------|--------------------|
| Plaintext / MD5 / SHA-1 / SHA-256 password | Argon2id / bcrypt (salted, slow, auto-rehash) |
| `==` / `.equals()` on secrets | Library verify / constant-time compare |
| Reuse session ID after login | Regenerate session ID on login (anti-fixation) |
| "No such user" vs "wrong password" | Single generic message + uniform timing |
| Unlimited login attempts | Rate limit per account + per IP, backoff |
| Default / weak cookie flags | `Secure; HttpOnly; SameSite` + HSTS |
| Logout clears cookie only | Destroy session server-side; revoke on pw change |
| Hardcoded secret in source | Secret from environment / secret store |
| No second factor | MFA verified before session elevation |

## Next Steps

- **[Prevention](./prevention.md)**: The full layered-defense reference behind these snippets.
- **[Attack Vectors](./attack-vectors.md)**: The attacks each fix defeats.
- **[Overview](./overview.md)**: Concepts, impact, and 2017->2021 lineage.
- **[Launch the Lab](./lab/broken-authentication/)**: Find and fix these exact patterns in a running app (port 5020).

> Put it into practice: Open the lab at `./lab/broken-authentication/` (`docker-compose up --build`), locate the vulnerable login and session code, and apply the secure versions shown here.
