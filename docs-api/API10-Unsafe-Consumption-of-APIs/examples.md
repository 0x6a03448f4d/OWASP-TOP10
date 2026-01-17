# API10: Unsafe Consumption of APIs - Code Examples

## Flask - Vulnerable vs Secure

### Vulnerable
```python
@app.route('/import')
def import_data():
    data = requests.get('https://external-api.com/data').json()
    db.execute(f"INSERT INTO items VALUES ('{data['name']}')")  # SQLi!
    return f"<div>{data['description']}</div>"  # XSS!
```

### Secure
```python
from markupsafe import escape

@app.route('/import')
def import_data_secure():
    data = requests.get('https://external-api.com/data').json()
    
    # Validate
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid data'}), 400
    
    # Parameterized query
    cursor.execute("INSERT INTO items (name) VALUES (?)", (data['name'],))
    
    # Escape output
    return f"<div>{escape(data['description'])}</div>"
```

## Node.js - Payment Verification

### Vulnerable
```javascript
const payment = await axios.post('https://payment.com/charge', order);
if (payment.data.status === 'success') {  // Trusts response!
    grantAccess();
}
```

### Secure
```javascript
const payment = await axios.post('https://payment.com/charge', order);

// Verify signature
const signature = payment.headers['x-signature'];
const expected = crypto.createHmac('sha256', SECRET).update(JSON.stringify(payment.data)).digest('hex');

if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    throw new Error('Invalid signature');
}

if (payment.data.status === 'success') {
    grantAccess();
}
```

## Spring Boot - Safe XML Parsing

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(xmlFromAPI)));
```
