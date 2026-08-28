# XXE Examples: Vulnerable vs. Secure

## Table of Contents

- [How to Read These Examples](#how-to-read-these-examples)
- [Java (JAXP DocumentBuilderFactory)](#java-jaxp-documentbuilderfactory)
- [Python (Flask + ElementTree / defusedxml)](#python-flask--elementtree--defusedxml)
- [PHP (DOMDocument / SimpleXML)](#php-domdocument--simplexml)
- [.NET (XmlDocument / XmlReader)](#net-xmldocument--xmlreader)
- [Bonus: Hardening an SVG Upload Handler](#bonus-hardening-an-svg-upload-handler)
- [Side-by-Side Summary](#side-by-side-summary)

## How to Read These Examples

Each pair shows the *same feature*—an endpoint that parses a user-supplied XML document—first as it is commonly written (vulnerable), then hardened. The attack payload is identical in every case:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

Against the vulnerable code, the response echoes the contents of `/etc/passwd`. Against the secure code, the parser either throws on the DOCTYPE or leaves `&xxe;` unresolved—no file is read. Notice how small the diff is: XXE prevention is almost always a configuration change, not a rewrite.

## Java (JAXP DocumentBuilderFactory)

### Vulnerable

```java
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public String parseUser(InputStream xmlInput) throws Exception {
    // VULNERABLE: default factory resolves DTDs and external entities.
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = dbf.newDocumentBuilder();
    Document doc = builder.parse(xmlInput);      // &xxe; is expanded here
    return doc.getDocumentElement().getTextContent();  // leaks the file
}
```

### Secure

```java
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public String parseUser(InputStream xmlInput) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

    // SECURE: reject any DOCTYPE outright -- the decisive control.
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    // Defence in depth in case a DTD must ever be allowed:
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

    DocumentBuilder builder = dbf.newDocumentBuilder();
    Document doc = builder.parse(xmlInput);   // throws on the malicious DOCTYPE
    return doc.getDocumentElement().getTextContent();
}
```

## Python (Flask + ElementTree / defusedxml)

### Vulnerable

```python
from flask import Flask, request
import xml.etree.ElementTree as ET   # standard library

app = Flask(__name__)

@app.route("/parse", methods=["POST"])
def parse_xml():
    # VULNERABLE on affected versions: no protection against DTD/entity abuse,
    # and no defence against entity-expansion (billion laughs) DoS.
    root = ET.fromstring(request.data)
    return root.text or ""
```

### Secure

```python
from flask import Flask, request, abort
import defusedxml.ElementTree as ET   # pip install defusedxml
from defusedxml.common import DefusedXmlException

app = Flask(__name__)

@app.route("/parse", methods=["POST"])
def parse_xml():
    try:
        # SECURE: defusedxml forbids DTDs, external entities, and entity bombs.
        root = ET.fromstring(request.data)
    except DefusedXmlException:
        abort(400, "XML with DTDs or entities is not accepted")
    return root.text or ""
```

If you must use `lxml` instead of defusedxml, build a locked-down parser explicitly:

```python
from lxml import etree

parser = etree.XMLParser(resolve_entities=False, no_network=True,
                         load_dtd=False, dtd_validation=False)
root = etree.fromstring(request.data, parser=parser)
```

## PHP (DOMDocument / SimpleXML)

### Vulnerable

```php
<?php
// VULNERABLE if LIBXML_NOENT is set (it enables entity substitution),
// or on old libxml (< 2.9.0) where external entities loaded by default.
$doc = new DOMDocument();
$doc->loadXML($_POST["xml"], LIBXML_NOENT | LIBXML_DTDLOAD);  // do NOT do this
echo $doc->textContent;   // may leak file contents
?>
```

### Secure

```php
<?php
// SECURE: no LIBXML_NOENT, no LIBXML_DTDLOAD, and LIBXML_NONET blocks the network.
$doc = new DOMDocument();
$ok = $doc->loadXML($_POST["xml"], LIBXML_NONET);
if ($ok === false) {
    http_response_code(400);
    exit("Invalid XML");
}
echo $doc->textContent;   // &xxe; is not substituted -> nothing leaks

// SimpleXML equivalent, same principle:
$sxe = simplexml_load_string($_POST["xml"], "SimpleXMLElement", LIBXML_NONET);
?>
```

> On modern PHP, external entities are already off by default; the vulnerability is almost always *re-enabling* them with `LIBXML_NOENT`. The secure version's real job is to never opt back in.

## .NET (XmlDocument / XmlReader)

### Vulnerable (legacy .NET Framework)

```csharp
using System.Xml;

public string ParseUser(string xml)
{
    // VULNERABLE on old .NET Framework: XmlDocument used a live resolver
    // that fetched external DTDs and entities by default.
    var doc = new XmlDocument();
    doc.LoadXml(xml);                 // &xxe; expanded
    return doc.DocumentElement.InnerText;   // leaks the file
}
```

### Secure

```csharp
using System.Xml;
using System.IO;

public string ParseUser(string xml)
{
    var settings = new XmlReaderSettings
    {
        DtdProcessing = DtdProcessing.Prohibit,  // SECURE: no DOCTYPE allowed
        XmlResolver   = null,                     // never fetch external content
        MaxCharactersFromEntities = 1024          // cap entity expansion
    };

    using var stringReader = new StringReader(xml);
    using var reader = XmlReader.Create(stringReader, settings);

    var doc = new XmlDocument { XmlResolver = null };
    doc.Load(reader);                 // throws on the malicious DOCTYPE
    return doc.DocumentElement.InnerText;
}
```

## Bonus: Hardening an SVG Upload Handler

A frequent real-world trap: an "image" upload that server-side code parses as XML. The fix is the same parser hardening—applied where you might not think to look.

### Vulnerable (Python thumbnail/metadata step)

```python
import xml.etree.ElementTree as ET

def extract_svg_title(uploaded_bytes):
    # VULNERABLE: an "image" upload is parsed as XML with default settings.
    root = ET.fromstring(uploaded_bytes)
    title = root.find("{http://www.w3.org/2000/svg}title")
    return title.text if title is not None else ""
```

### Secure

```python
import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException

def extract_svg_title(uploaded_bytes):
    try:
        # SECURE: same parsing, hardened parser -- DTDs/entities rejected.
        root = ET.fromstring(uploaded_bytes)
    except DefusedXmlException:
        raise ValueError("Rejected SVG containing a DTD or entities")
    title = root.find("{http://www.w3.org/2000/svg}title")
    return title.text if title is not None else ""
```

## Side-by-Side Summary

| Stack | Vulnerable pattern | The one change that fixes it |
| --- | --- | --- |
| Java (JAXP) | Default `DocumentBuilderFactory` | `disallow-doctype-decl = true` |
| Python | `xml.etree` / `lxml` defaults on untrusted input | Use `defusedxml` (or `resolve_entities=False, no_network=True`) |
| PHP | `LIBXML_NOENT` set, or libxml < 2.9.0 | Drop `LIBXML_NOENT`; pass `LIBXML_NONET` |
| .NET Framework | `XmlDocument` with default resolver | `DtdProcessing.Prohibit` + null `XmlResolver` |

The pattern across all four is identical: the vulnerability is an insecure default or an opt-in to danger, and the fix is one or two lines that tell the parser to stop resolving things it was never supposed to resolve for untrusted input.

## Next Steps

- **[Prevention](prevention.html)**: The full layered strategy behind these snippets.
- **[Attack Vectors](attack-vectors.html)**: The payloads these fixes defeat.
- **[Overview](overview.html)**: The concepts, impact, and edition history.
- **[Hands-On Lab](./lab/xml-external-entities/)**: Exploit the vulnerable version, then apply the fix and confirm it holds.
