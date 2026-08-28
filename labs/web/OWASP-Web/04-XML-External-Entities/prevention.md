# XXE Prevention

## Table of Contents

- [The Defence Strategy in One Line](#the-defence-strategy-in-one-line)
- [The Layered Model](#the-layered-model)
- [Layer 1: Prefer a Safer Format](#layer-1-prefer-a-safer-format)
- [Layer 2: Disable DTDs and External Entities (per parser)](#layer-2-disable-dtds-and-external-entities-per-parser)
  - [Java (JAXP)](#java-jaxp)
  - [Python](#python)
  - [PHP (libxml)](#php-libxml)
  - [.NET](#net)
- [Layer 3: Limit Expansion and Resources](#layer-3-limit-expansion-and-resources)
- [Layer 4: Network and Platform Controls](#layer-4-network-and-platform-controls)
- [Layer 5: Patch, Test, and Monitor](#layer-5-patch-test-and-monitor)
- [Prevention Checklist](#prevention-checklist)

## The Defence Strategy in One Line

**Turn off the feature you don't need.** The overwhelming majority of XXE is eliminated by configuring every XML parser to reject DTDs entirely—or, where a DTD is genuinely required, to refuse external entity and external DTD resolution. Everything else on this page is defence-in-depth around that single, decisive control.

> If you can do only one thing: set your parser to **completely disallow DOCTYPE declarations**. A document with no DOCTYPE cannot declare entities, which closes file disclosure, SSRF, out-of-band exfiltration, and entity-expansion DoS in one move.

## The Layered Model

| Layer | Control | What it stops |
| --- | --- | --- |
| 1. Design | Use JSON/safe formats where possible | Removes the parser from the attack surface entirely |
| 2. Parser (primary) | Disable DTDs / external entities | File read, SSRF, OOB exfiltration, most DoS |
| 3. Resource limits | Entity-expansion and size caps | Billion laughs and quadratic blowup DoS |
| 4. Network | Egress filtering, IMDSv2, isolation | Blunts SSRF and blind exfiltration impact |
| 5. Operations | Patch, test, WAF, monitor | Catches regressions and unknown parsers |

Layer 2 is the fix. Layers 1, 3, 4, and 5 exist because real systems use multiple parsers, some code paths genuinely need DTDs, and configurations drift—so you want the blast radius contained even if one parser is missed.

## Layer 1: Prefer a Safer Format

The cheapest XML vulnerability to fix is the parser you never invoke. Where you control both ends of an interface, prefer **JSON**, which has no concept of entities or external references. When you must accept XML, prefer **data-only formats without a DTD**, and reject any document that arrives with a DOCTYPE before it reaches the business logic. This does not replace parser hardening—attacker-controlled XML still reaches a parser—but it shrinks how many parsers touch untrusted input.

## Layer 2: Disable DTDs and External Entities (per parser)

This is the core of XXE prevention. Below is the exact, copy-pasteable hardening for the major stacks. The recurring theme: there is usually a single flag that forbids DOCTYPE entirely (best), and a set of finer flags to disable external resolution when a DTD must be allowed.

### Java (JAXP)

Java's default factories are historically *unsafe*—you must harden them explicitly. The single most robust setting is the `disallow-doctype-decl` feature, which makes any DOCTYPE throw a parse exception.

#### DocumentBuilderFactory (DOM)

```java
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// PRIMARY: reject any document with a DOCTYPE. This alone stops XXE.
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// Defence-in-depth: explicitly refuse external entities and external DTDs.
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

dbf.setXIncludeAware(false);       // disable XInclude
dbf.setExpandEntityReferences(false);
// Belt-and-braces: forbid access to external protocols.
dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
```

#### SAXParserFactory (SAX)

```java
import javax.xml.parsers.SAXParserFactory;

SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
spf.setXIncludeAware(false);
```

#### XMLInputFactory (StAX)

```java
import javax.xml.stream.XMLInputFactory;

XMLInputFactory xif = XMLInputFactory.newInstance();
// Do not support external entities...
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
// ...and disable DTD support entirely where the implementation honours it.
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```

#### TransformerFactory / SAXTransformerFactory / Schema / XPath

```java
import javax.xml.XMLConstants;
import javax.xml.transform.TransformerFactory;

TransformerFactory tf = TransformerFactory.newInstance();
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

Apply the same `ACCESS_EXTERNAL_*` restrictions to `SchemaFactory`, `Validator`, and `XPath` processors—they are XML parsers too and are easy to forget.

### Python

Python's standard-library XML modules were historically vulnerable, and `ElementTree` alone does not expose clean flags to disable entity resolution across versions. The maintained, recommended answer is the **defusedxml** package, which wraps the standard parsers and forbids the dangerous features by default.

#### Preferred: defusedxml (drop-in replacement)

```python
# pip install defusedxml
import defusedxml.ElementTree as ET

# Raises defusedxml.EntitiesForbidden / DTDForbidden on malicious input.
tree = ET.fromstring(untrusted_xml)

# defusedxml also wraps the other parsers:
#   defusedxml.minidom, defusedxml.sax, defusedxml.pulldom
# and, if installed, defusedxml.lxml
```

#### lxml directly (when you need it)

```python
from lxml import etree

# Refuse entity resolution, DTD loading, and any network access.
parser = etree.XMLParser(
    resolve_entities=False,   # do not expand entities
    no_network=True,          # block http/ftp fetches
    dtd_validation=False,
    load_dtd=False,
)
root = etree.fromstring(untrusted_xml, parser=parser)
```

**Caveat:** `resolve_entities=False` stops external entity *expansion*, but for full protection against the billion-laughs class and malicious DTDs, defusedxml (or defusedxml's lxml wrapper) is the safer default because it forbids DTDs outright.

#### Standard-library SAX (if you cannot add a dependency)

```python
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges, feature_external_pes

parser = make_parser()
parser.setFeature(feature_external_ges, False)   # external general entities
parser.setFeature(feature_external_pes, False)   # external parameter entities
```

Even so, the official Python documentation itself recommends defusedxml for untrusted input, because the standard modules do not defend against entity-expansion DoS on their own.

### PHP (libxml)

PHP's XML functions sit on top of `libxml2`. Since libxml2 2.9.0 (2012), external entities are not loaded by default, but you should still make the intent explicit and never enable `LIBXML_NOENT` on untrusted input.

```php
<?php
// Never pass LIBXML_NOENT for untrusted XML: it turns entity substitution ON.
// Do NOT do this: $doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

// Safe load: no network, no external DTD, no entity substitution.
$doc = new DOMDocument();
$ok = $doc->loadXML($xml, LIBXML_NONET);   // LIBXML_NONET blocks network access
if ($ok === false) {
    // reject malformed / disallowed input
}

// SimpleXML equivalent:
$sxe = simplexml_load_string($xml, "SimpleXMLElement", LIBXML_NONET);
?>
```

On older PHP/libxml combinations you may also see `libxml_disable_entity_loader(true)` used to block the external entity loader process-wide. That function is deprecated and a no-op on modern PHP precisely because the secure behaviour is now the default—so on current versions, simply avoid `LIBXML_NOENT` and `LIBXML_DTDLOAD` and pass `LIBXML_NONET`.

### .NET

Modern .NET (Core / 5+) is safe by default: `XmlReader`, `XmlDocument`, and `XDocument` do not resolve external entities unless you opt in. On the legacy .NET Framework, `XmlDocument` and `XmlTextReader` were unsafe by default and must be hardened.

#### XmlReader (recommended)

```csharp
using System.Xml;

var settings = new XmlReaderSettings
{
    // Reject DTDs entirely -- the strongest setting.
    DtdProcessing = DtdProcessing.Prohibit,
    // Do not resolve any external resource (defence in depth).
    XmlResolver   = null,
    MaxCharactersFromEntities = 1024   // cap entity expansion as well
};

using var reader = XmlReader.Create(stream, settings);
var doc = new XmlDocument();
doc.Load(reader);
```

#### Legacy XmlDocument (harden explicitly)

```csharp
using System.Xml;

var doc = new XmlDocument
{
    // Null resolver = no external DTDs, entities, or schemas are fetched.
    XmlResolver = null
};
doc.LoadXml(untrustedXml);
```

Use `DtdProcessing.Prohibit` when no DTD is expected (it throws on any DOCTYPE); use `DtdProcessing.Ignore` plus a null `XmlResolver` if you must tolerate a DOCTYPE but never resolve anything external.

## Layer 3: Limit Expansion and Resources

If a DTD must be permitted for legitimate reasons, you still need caps so that internal-entity expansion (billion laughs, quadratic blowup) cannot exhaust memory:

- **.NET**: `XmlReaderSettings.MaxCharactersFromEntities` and `MaxCharactersInDocument`.
- **Java**: the JAXP system properties `jdk.xml.entityExpansionLimit`, `jdk.xml.totalEntitySizeLimit`, and `jdk.xml.maxGeneralEntitySizeLimit` (secure-processing defaults exist but can be tightened).
- **Python**: defusedxml forbids entity expansion by default; if you allow it, cap the input size before parsing.
- **All stacks**: enforce a maximum request/body size at the web tier so multi-hundred-KB expansion payloads are rejected before parsing.

## Layer 4: Network and Platform Controls

- **Egress filtering**: application servers rarely need to make arbitrary outbound connections. Restricting egress blunts both SSRF and blind out-of-band exfiltration—the callback simply never reaches the attacker.
- **Block link-local metadata**: deny outbound traffic to `169.254.169.254` from application workloads, and require the token-based metadata service (IMDSv2) so a bare XXE GET cannot read credentials.
- **Least privilege on the file system**: run the parser process as an unprivileged user that cannot read secrets, keys, or other tenants' data—so even a successful file read yields little.
- **Network segmentation**: keep internal admin interfaces and databases off any network the web tier can reach directly.

## Layer 5: Patch, Test, and Monitor

- **Keep parsers current**: upgrades have removed whole XXE classes (for example the libxml2 2.9.0 default change). Track your XML libraries in your dependency scanning.
- **Add a regression test**: feed each XML endpoint a benign XXE probe (an entity pointing at a local test file and a callback URL) in CI, and assert that neither the file content nor a callback appears. This catches the day someone introduces a new, unhardened parser.
- **WAF as defence-in-depth only**: a rule that flags `<!DOCTYPE` or `<!ENTITY` in request bodies catches unsophisticated attempts, but encoding and external-DTD tricks bypass it—never rely on it as the primary control.
- **Monitor for the signals**: unexpected outbound requests from app servers, DNS lookups to unusual domains, and spikes in parser memory are all XXE tells.

## Prevention Checklist

- [ ] Every XML parser in the codebase disables DOCTYPE (or at minimum external general and parameter entities and external DTD loading).
- [ ] XInclude is disabled unless explicitly required.
- [ ] Secondary XML processors (schema validation, XSLT/Transformer, XPath, SOAP/SAML libraries) are hardened too—not just the obvious ones.
- [ ] Python untrusted parsing uses `defusedxml`; PHP never passes `LIBXML_NOENT` and uses `LIBXML_NONET`; .NET uses `DtdProcessing.Prohibit` with a null resolver.
- [ ] Entity-expansion and document-size limits are set for any path that must allow a DTD.
- [ ] File-upload features that accept SVG or Office documents parse those parts with a hardened parser.
- [ ] Egress is filtered and the cloud metadata endpoint is protected (IMDSv2, deny-list).
- [ ] A CI regression test proves XXE probes fail on every XML endpoint.
- [ ] XML libraries are patched and tracked in dependency scanning.

## Next Steps

- **[Examples](examples.html)**: Full vulnerable-vs-secure code for each language.
- **[Attack Vectors](attack-vectors.html)**: Understand exactly what each control shuts down.
- **[Overview](overview.html)**: The concepts behind the fixes.
- **[Hands-On Lab](./lab/xml-external-entities/)**: Apply these fixes to a vulnerable app and verify them.
