# XXE Prevention

## Secure XML Parsing

### Python Example:

```python
import defusedxml.ElementTree as ET

# SECURE: Use defusedxml
tree = ET.parse('input.xml')

# Configure parser to disable entities
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False
)
tree = etree.parse('input.xml', parser)
```

### Disable External Entities:

```python
# For standard library xml
import xml.etree.ElementTree as ET
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges

parser = make_parser()
parser.setFeature(feature_external_ges, False)
```

## Best Practices

- Use JSON instead of XML when possible
- Disable DTD processing
- Disable external entity processing
- Use allowlists for XML schemas
- Update XML processors regularly
