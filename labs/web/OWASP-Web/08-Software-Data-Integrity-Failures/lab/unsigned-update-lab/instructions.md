# Lab Instructions: Data Integrity Failures

## Introduction

Welcome to the Data Integrity Failures lab! This hands-on exercise will help you understand this vulnerability class.

**Time Required**: 20-30 minutes  
**Difficulty**: Beginner

## Learning Path

1. **Setup** - Get the lab running
2. **Explore** - Understand the vulnerability
3. **Analyze** - Review the code
4. **Learn** - Understand the impact
5. **Practice** - Try secure alternatives

---

## Part 1: Setup (5 minutes)

### Task 1.1: Start the Lab

```bash
cd OWASP-Web/Data Integrity Failures/lab/*/
docker-compose up
```

Access the application at **http://localhost:5001**

## Part 2: Testing

### Task 2.1: Upload File
1. Select any file
2. Upload it
3. Notice NO checksum validation

---

## Clean Up

```bash
docker-compose down
```

---

## Next Steps

1. ✅ Review the **[Prevention Guide](../../prevention.md)**
2. ✅ Study the **[Examples](../../examples.md)**
3. ✅ Apply these lessons to your projects

---

*Part of the [OWASP Top 10 Educational Repository](../../../../../README.md)*
