# XXE Examples

## Vulnerable Code

**❌ INSECURE:**

```python
import xml.etree.ElementTree as ET

@app.route('/parse', methods=['POST'])
def parse_xml():
    xml_data = request.data
    # VULNERABLE: Default parser allows XXE
    tree = ET.fromstring(xml_data)
    return tree.find('data').text
```

**✅ SECURE:**

```python
import defusedxml.ElementTree as ET

@app.route('/parse', methods=['POST'])
def parse_xml():
    xml_data = request.data
    # SECURE: defusedxml prevents XXE
    tree = ET.fromstring(xml_data)
    return tree.find('data').text
```
