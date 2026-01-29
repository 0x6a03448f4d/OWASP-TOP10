# XML External Entities (XXE) - Overview

## What is XXE?

**XML External Entity (XXE)** attacks occur when XML input containing a reference to an external entity is processed by a weakly configured XML parser. This can lead to disclosure of confidential data, denial of service, server-side request forgery, and other system impacts.

### How XXE Works

XML parsers can be configured to process external entities:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <data>&xxe;</data>
</root>
```

When parsed, `&xxe;` is replaced with the contents of `/etc/passwd`.

## Why XXE Was Critical in 2017

- Many legacy systems used XML for APIs
- SOAP web services were common
- Default XML parser configurations were insecure
- XML used for Office documents, SVG, SAML

## Real-World Impact

XXE can lead to:
- Reading sensitive files
- Internal network scanning
- Denial of service
- Remote code execution (in some cases)
