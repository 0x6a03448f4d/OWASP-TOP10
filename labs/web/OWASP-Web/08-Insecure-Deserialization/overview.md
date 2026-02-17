# Insecure Deserialization - Overview

## What is Insecure Deserialization?

**Insecure Deserialization** occurs when untrusted data is used to recreate objects in an application. This can lead to remote code execution, replay attacks, injection attacks, and privilege escalation.

### The Problem

Serialization converts objects to bytes for storage/transmission. Deserialization reconstructs the object. If attackers control serialized data, they can:

- Execute arbitrary code
- Modify application logic
- Bypass authentication
- Perform privilege escalation

### Common in 2017

Popular serialization formats:
- Python pickle
- PHP serialize()
- Java serialization
- .NET BinaryFormatter

## Why This Matters

In 2017, this was #8 in OWASP Top 10 due to:

- Many frameworks used insecure deserialization
- Java deserialization attacks were prevalent
- Session cookies often used serialization
- API data often serialized without validation

## Real-World Impact

**Apache Commons Collections (2015, widespread in 2017)**
- Remote code execution via Java deserialization
- Affected major applications

**Ruby on Rails (2013, lessons still relevant 2017)**
- Remote code execution via YAML deserialization
- Led to major security updates
