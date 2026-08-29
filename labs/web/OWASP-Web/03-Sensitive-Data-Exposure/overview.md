# A3:2017 – Sensitive Data Exposure: Overview

## Table of Contents

- [What is Sensitive Data Exposure?](#what-is-sensitive-data-exposure)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Detectability](#prevalence-and-detectability)
- [Common Misunderstandings](#common-misunderstandings)
- [2017 to 2021: How This Category Evolved](#2017-to-2021-how-this-category-evolved)
- [Self-Assessment](#self-assessment)
- [Next Steps](#next-steps)

## What is Sensitive Data Exposure?

**Sensitive Data Exposure** (A3 in the OWASP Top 10 2017) is the failure to adequately protect sensitive information — personal, financial, health, authentication, or business-critical data — wherever it lives and however it moves. It is a *symptom-level* category: the harm is that the data ends up somewhere an attacker can read it, whether because it was never encrypted, was sent in cleartext, was cached or logged, was left in an exposed backup, or was simply retained when it should have been discarded.

The word to hold onto is **exposure**. Unlike a category such as Injection, which names a specific defect, A3:2017 names an *outcome*: sensitive data reaching an unauthorised party. Many different weaknesses feed into that outcome, so the discipline is less about one clever fix and more about knowing what data you hold, where it flows, and closing every place it can leak.

### The Three States of Data

Sensitive data must be protected across its entire lifecycle. It is useful to think in three states, each with its own exposure risks:

```
DATA IN TRANSIT   -> moving over a network (browser to server, service to service, backups to storage)
                     Exposed by: HTTP instead of HTTPS, weak/downgraded TLS, mixed content

DATA AT REST      -> stored on disk (databases, files, object storage, backups, caches)
                     Exposed by: no encryption, weak keys, world-readable files, exposed dumps

DATA IN USE       -> held or handled while processing (memory, logs, URLs, browser cache)
                     Exposed by: PII in logs, secrets in query strings, cached responses, error output
```

### What Counts as "Sensitive"

Sensitivity is contextual and often defined by law or contract. Common classes include:

- **Authentication secrets**: passwords, password hashes, session tokens, API keys, private keys.
- **Financial data**: card numbers (PAN), CVV, bank account and routing numbers — governed by PCI-DSS.
- **Personal data (PII)**: names tied to identifiers, national IDs (SSN/passport), addresses, dates of birth — governed by GDPR, CCPA, and similar.
- **Health data (PHI)**: diagnoses, prescriptions, records — governed by HIPAA and equivalents.
- **Business-critical data**: source code, encryption keys, internal documents, trade secrets.

> **Key idea:** You cannot protect what you have not identified. The first act of defence against A3 is *data classification* — an inventory of what sensitive data you collect, where it lives, and who may touch it.

## Why Does This Matter?

### Business Impact

- **Regulatory penalties**: GDPR fines reach up to €20M or 4% of global annual turnover; HIPAA and PCI-DSS carry their own penalties and mandatory breach notifications.
- **Direct fraud loss**: exposed payment and identity data is monetised immediately through fraud and account takeover.
- **Breach-response cost**: forensics, notification, credit monitoring, and legal defence routinely dwarf the cost of the original prevention.
- **Reputation and trust**: a single "we leaked your data" headline erodes customer confidence that took years to build.
- **Contractual fallout**: loss of payment-processing privileges (PCI), broken enterprise agreements, and class-action exposure.

### Technical Impact

- **Credential compromise**: leaked hashes are cracked offline; leaked tokens grant immediate access; both enable credential stuffing against other services.
- **Full account and data takeover**: exposed PII and secrets let attackers impersonate users or pivot deeper into systems.
- **Interception at scale**: cleartext transmission lets anyone on the network path harvest every session that crosses it.
- **Persistent exposure**: data copied to a cache, a log aggregator, or an unencrypted backup keeps leaking long after the "live" system is fixed.

## Technical Context

### Where Exposure Happens: Following the Data

Because A3 is about outcomes, the most reliable way to reason about it is to trace sensitive data through its journey and ask, at each hop, "who could read this here?"

```
[ Browser ] --(1)--> [ Load balancer / CDN ] --(2)--> [ App server ] --(3)--> [ Database ]
     |                        |                           |                       |
   (6) cache,            (2) TLS term-             (4) logs,               (5) backups,
   history, URL           ination, mixed            error output,           replicas,
   bar, localStorage      content                   URL params              object storage

(1) In transit  : is every leg HTTPS with modern TLS, or does a hop fall back to cleartext?
(2) At the edge : does TLS terminate early and travel cleartext internally? Is content mixed?
(3) Service-to- : are internal service calls and DB connections encrypted, or "trusted network"?
    service
(4) In use      : do logs, stack traces, or query strings capture card numbers and tokens?
(5) At rest     : is the database, its replicas, and its backups encrypted with managed keys?
(6) At the client: is sensitive data cached, placed in the URL, or stored in the browser?
```

### Data Classification Drives Everything

Different data warrants different protection. A workable classification model maps each data type to a required control, and that mapping is what turns "protect sensitive data" into concrete engineering tasks.

| Data Type | Sensitivity | In Transit | At Rest | Minimise? |
|-----------|-------------|------------|---------|-----------|
| Passwords | Critical | TLS only | Salted slow hash (never reversible) | Never store plaintext |
| Card number (PAN) | Critical (PCI) | TLS only | Encrypt or tokenise; never store CVV | Tokenise; avoid storing |
| National ID / SSN | Critical | TLS only | Strong encryption, restricted access | Collect only if legally required |
| Health records (PHI) | Critical (HIPAA) | TLS only | Encryption + strict access control | Minimise scope |
| Session tokens / keys | Critical | TLS only | Secret store / KMS, never in code | Short lifetime, rotate |
| Email / address | High (PII) | TLS only | Encryption recommended | Retain per policy |
| Public preferences | Low | TLS preferred | May not need encryption | Low concern |

### Data Minimisation: The Cheapest Control

The most robust protection against exposing data is not holding it. Data you never collect cannot leak; data you delete on schedule stops leaking. Minimisation and retention limits shrink the blast radius of every other failure, which is why they sit at the centre of the 2017 framing rather than at the edge.

## Real-World Impact

The examples below are drawn from *well-documented classes of incident* that recur across the industry. They are described as patterns rather than attributed to specific named breaches with invented figures, because the durable lesson is in the mechanism, not a precise statistic.

### Pattern 1: Cleartext Credentials on Shared Networks

**Mechanism**: A login form or API served over HTTP (or a page that posts to an HTTP endpoint) transmits usernames and passwords in the clear. Anyone sharing the network path — open Wi-Fi, a compromised router, a malicious hop — captures them passively.

**Lesson**: HTTPS everywhere with HSTS is the baseline, not an enhancement. There is no "non-sensitive" page if a single request can leak a session cookie.

### Pattern 2: Publicly Exposed Cloud Storage and Databases

**Mechanism**: Object-storage buckets set to public read, or databases bound to a public interface with authentication disabled, expose entire datasets to anyone who finds the address. Search engines like Shodan index them continuously, and automated crawlers copy or wipe the contents.

**Lesson**: "Private by default," network isolation, and encryption at rest turn a single misconfiguration into a non-event instead of a full breach.

### Pattern 3: Sensitive Data Left in URLs, Logs, and Caches

**Mechanism**: A token or account number placed in a query string travels into server access logs, browser history, and the `Referer` header sent to third-party sites. Responses without cache directives are stored by browsers and shared proxies. The data outlives the request in places nobody encrypted.

**Lesson**: Keep secrets out of URLs, set `Cache-Control: no-store` on sensitive responses, and redact sensitive fields before logging.

### Pattern 4: Exposed Backups and Database Dumps

**Mechanism**: An unencrypted `backup.sql`, `.bak`, or archive left in a web-reachable directory, or copied to a public bucket, hands over the whole dataset without touching the live system. Directory brute-forcing finds these routinely.

**Lesson**: Backups are production data. They need the same encryption, the same access control, and they must never sit inside the web root.

### Pattern 5: Secrets Committed to Source Control

**Mechanism**: API keys, database passwords, and private keys hard-coded into a repository — especially a public one — are harvested by bots within minutes of being pushed, and remain in git history even after being "removed" in a later commit.

**Lesson**: Secrets belong in a secret manager or environment configuration, never in code. Scan history, and rotate anything that was ever committed.

### Pattern 6: Weak Hashes Cracked After a Leak

**Mechanism**: When a user table protected only by unsalted MD5 or SHA-1 is exposed, commodity hardware and rainbow tables recover the plaintext passwords almost instantly, and those passwords are then reused against other sites.

**Lesson**: Even a database breach should not equal a password breach — salted, slow hashing (bcrypt/Argon2/scrypt) is what buys that separation. (The algorithm details live in the [Cryptographic Failures](../02-Cryptographic-Failures/overview.md) lesson.)

## Prevalence and Detectability

Sensitive Data Exposure ranked **#3** in the OWASP Top 10 2017. Rather than quote a single incidence figure (which varies by dataset and year), the durable picture is:

- It is **highly prevalent** because it spans transport, storage, logging, caching, and configuration — a gap in any one produces exposure.
- It is **often easy to detect from the outside**: a scan reveals HTTP endpoints, missing HSTS, weak TLS, and cacheable sensitive responses; a crawler finds exposed backups and buckets.
- Its **impact is high** because the asset at risk is, by definition, the data most worth stealing.

> Note: precise percentages and record counts differ between reports. Treat any single figure as illustrative; the reliable takeaway is that exposure is common, cheap for attackers to find, and severe when it lands on regulated data.

### Related Weaknesses (CWE)

- **CWE-311**: Missing Encryption of Sensitive Data
- **CWE-319**: Cleartext Transmission of Sensitive Information
- **CWE-312**: Cleartext Storage of Sensitive Information
- **CWE-359**: Exposure of Private Personal Information to an Unauthorized Actor
- **CWE-532**: Insertion of Sensitive Information into Log File
- **CWE-598**: Use of GET Request Method With Sensitive Query Strings
- **CWE-798**: Use of Hard-coded Credentials

## Common Misunderstandings

### Myth 1: "We use HTTPS, so our data is protected"

**Reality**: HTTPS protects data *in transit* only. It does nothing for data sitting unencrypted in a database, written to a log file, stored in a backup, or cached in the browser. Transport security is one leg of a three-legged problem.

### Myth 2: "It's behind the firewall, so it doesn't need encryption"

**Reality**: Internal networks are reached through SSRF, compromised dependencies, VPN pivots, and cloud metadata. "Trusted network" is not a security boundary; encrypt internal traffic and data at rest too.

### Myth 3: "Base64 / obfuscation keeps the data safe"

**Reality**: Base64 is encoding, not encryption — it is reversed with a single function call. Obscuring a field is not protecting it.

### Myth 4: "We don't store anything really sensitive"

**Reality**: Email addresses, session tokens, password-reset links, and behavioural data are all sensitive and all regulated in many jurisdictions. Teams routinely under-classify what they hold. A data inventory usually surprises the people who built the system.

### Myth 5: "Deleting the record deletes the data"

**Reality**: The same record often lives on in backups, read replicas, search indexes, caches, analytics pipelines, and third-party processors. Real disposal means accounting for every copy.

### Myth 6: "Encryption at rest means the cloud provider's disk encryption"

**Reality**: Provider volume encryption protects against a stolen physical disk, not against an attacker who reaches the running application or database with valid access. Application- or field-level encryption with managed keys is what limits exposure from a live compromise.

## 2017 to 2021: How This Category Evolved

In the **OWASP Top 10 2021**, this category was renamed and re-scoped to **A02:2021 – Cryptographic Failures**. The 2021 edition deliberately shifted focus toward the *root cause* — weak or missing cryptography — rather than the *symptom* of data being exposed.

This lesson keeps the broader **2017 "data exposure" framing** on purpose. That framing is valuable because it forces attention on questions cryptography alone does not answer:

- **What sensitive data do we even have?** (classification and inventory)
- **Do we need to hold it at all?** (minimisation and retention)
- **Where does it leak without any crypto being "broken"?** (URLs, logs, caches, backups, exposed storage)

The deep treatment of algorithms, hashing, key management, and TLS cipher choice lives in this repository's dedicated [Cryptographic Failures (A02:2021)](../02-Cryptographic-Failures/overview.md) lesson. Here we concentrate on identifying data, protecting it in transit and at rest at a design level, minimising what we keep, and closing the caching and exposure gaps that crypto by itself never covers.

## Self-Assessment

Answer these about your own application. Each "no" or "not sure" is a likely exposure today:

- [ ] Do you have a current inventory that classifies every sensitive data type you collect and where it is stored?
- [ ] Is every request — including redirects, APIs, and internal service calls — served over HTTPS with modern TLS and HSTS?
- [ ] Is sensitive data encrypted at rest, including replicas and backups, with keys held outside the data store?
- [ ] Are secrets (keys, passwords, tokens) kept out of source code and out of URLs?
- [ ] Do logs and error messages redact passwords, tokens, card numbers, and other sensitive fields?
- [ ] Do responses containing sensitive data set `Cache-Control: no-store`?
- [ ] Are passwords stored with a salted, slow hash (bcrypt/Argon2/scrypt) rather than MD5/SHA-1?
- [ ] Do you delete sensitive data on a defined retention schedule across all copies?

## Next Steps

- **[Attack Vectors](./attack-vectors.md)**: How attackers find and harvest exposed data
- **[Prevention](./prevention.md)**: Layered defences for data in transit, at rest, and in use
- **[Examples](./examples.md)**: Vulnerable vs. secure code and configuration
- **[Hands-On Lab](./lab/sensitive-data-exposure/)**: Practice identifying and fixing exposure in a safe, isolated environment

---

*Part of the [OWASP Top 10 Educational Repository](/)*
