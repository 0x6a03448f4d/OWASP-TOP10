# Contributing to OWASP Top 10 Educational Repository

First off, thank you for considering contributing to this educational cybersecurity project! This repository aims to help people learn about security vulnerabilities in a safe, ethical, and responsible manner.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Content Guidelines](#content-guidelines)
- [Security-Safe Content Rules](#security-safe-content-rules)
- [Writing Standards](#writing-standards)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. We expect all contributors to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

### Ethical Use

**This repository is strictly for educational purposes.** Contributors must:

- ✅ Create content that educates about security vulnerabilities
- ✅ Promote defensive security practices
- ✅ Encourage ethical cybersecurity research
- ❌ Never provide weaponizable exploit code
- ❌ Never include real attack payloads
- ❌ Never encourage malicious hacking activities

## How Can I Contribute?

### Reporting Bugs or Issues

- Use the GitHub issue tracker
- Check if the issue already exists
- Provide clear descriptions and steps to reproduce
- Include relevant logs or screenshots

### Suggesting Enhancements

- Open an issue describing your enhancement idea
- Explain why this enhancement would be useful
- Provide examples if possible

### Improving Documentation

- Fix typos, grammar, or formatting issues
- Add clarifications or examples
- Update outdated information
- Add diagrams or visual aids

### Creating or Improving Labs

- Ensure labs are completely safe and non-exploitable
- Follow the lab structure template
- Test labs thoroughly before submitting
- Document all learning objectives clearly

## Content Guidelines

### Documentation Structure

All vulnerability documentation should include:

1. **overview.md**: Definition, impact, technical context, statistics
2. **attack-vectors.md**: Conceptual descriptions (NO exploit code)
3. **prevention.md**: Secure coding practices, mitigations, checklists
4. **examples.md**: Safe pseudo-code, bad vs good comparisons

### Lab Requirements

Every lab must:

- Run in isolated Docker containers
- Use localhost/127.0.0.1 only (no external network access)
- Include comprehensive documentation
- Provide step-by-step learning instructions
- Focus on code inspection and fixing vulnerabilities
- Never include real exploit code

## Security-Safe Content Rules

### ✅ ALLOWED Content

- Conceptual explanations of vulnerabilities
- High-level attack methodology descriptions
- Secure coding patterns and best practices
- Safe pseudo-code examples
- Architecture diagrams
- Defense mechanisms and mitigations
- Code review guidelines
- Static analysis results (sanitized)

### ❌ PROHIBITED Content

- **NO** working exploit code or payloads
- **NO** SQL injection strings that could be copied and used
- **NO** XSS payloads (actual JavaScript exploits)
- **NO** brute force attack scripts
- **NO** password cracking code
- **NO** remote attack vectors
- **NO** instructions that could harm real systems
- **NO** personally identifiable information (PII)
- **NO** real credentials or API keys

### Gray Areas - Handle with Care

When explaining vulnerabilities, you may need to show what makes code vulnerable:

```python
# ✅ GOOD: Shows vulnerable pattern without exploit
# Vulnerable to SQL injection (string concatenation)
query = "SELECT * FROM users WHERE id = " + user_input

# ✅ GOOD: Shows secure alternative immediately
# Secure using parameterized queries
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_input,))
```

```python
# ❌ BAD: Provides working exploit
user_input = "1 OR 1=1; DROP TABLE users--"
# Never include actual payloads like this
```

## Writing Standards

### Markdown Formatting

- Use proper heading hierarchy (H1 for titles, H2 for sections, etc.)
- Include table of contents for longer documents
- Use code blocks with language specification:
  ````markdown
  ```python
  # Your code here
  ```
  ````
- Use tables for structured data
- Use lists for steps or items
- Use bold for emphasis, italic for terms
- Include diagrams using Mermaid when helpful

### Code Style

For Python labs:
- Follow PEP 8 style guide
- Use meaningful variable names
- Include docstrings for functions
- Keep it simple (this is for learning)
- Comment complex logic

### Language and Tone

- Write clearly and concisely
- Use active voice
- Avoid jargon when possible; define it when necessary
- Be pedagogical - explain WHY, not just WHAT
- Assume readers are learning (don't assume expert knowledge)

## Pull Request Process

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR-USERNAME/OWASP-TOP10.git
   cd OWASP-TOP10
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Follow all content and security guidelines
   - Test any labs you create or modify
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   # For labs, test with Docker
   cd docs/XX-Category/lab/lab-name
   docker-compose up
   # Verify the lab works as intended
   docker-compose down
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Brief description of changes"
   ```
   
   Write clear commit messages:
   - Use present tense ("Add feature" not "Added feature")
   - Be descriptive but concise
   - Reference issues if applicable

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   
   Then create a Pull Request on GitHub with:
   - Clear title describing the change
   - Detailed description of what and why
   - Reference to any related issues
   - Screenshots for UI changes
   - Confirmation that you've tested the changes

6. **Code Review**
   - Respond to feedback constructively
   - Make requested changes promptly
   - Update your PR branch as needed

7. **Merge**
   - Once approved, maintainers will merge your PR
   - Delete your feature branch after merge

## Issue Reporting

### Bug Reports

Include:
- **Description**: What's wrong?
- **Steps to Reproduce**: How to trigger the bug
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**: OS, Docker version, Python version, etc.
- **Screenshots**: If applicable

### Feature Requests

Include:
- **Use Case**: Why is this needed?
- **Proposed Solution**: How might it work?
- **Alternatives**: Other approaches you've considered
- **Additional Context**: Any other relevant information

### Security Concerns

If you find actual security issues (not intentional educational vulnerabilities):
- **DO NOT** open a public issue
- Email the maintainers privately
- Provide details for verification
- Allow time for a fix before disclosure

## Lab Development Guidelines

### Lab Structure Template

```
lab-name/
├── docker-compose.yml
├── app/
│   ├── server.py
│   ├── requirements.txt
│   └── templates/
│       └── index.html
├── README.md
└── instructions.md
```

### Creating a New Lab

1. **Plan the Learning Objective**
   - What specific concept does this teach?
   - What will students learn?
   - How does it demonstrate the vulnerability safely?

2. **Design the Safe Demo**
   - Use mocked/simulated environments
   - No real databases with sensitive data
   - Localhost only, no external services
   - Clear educational markers in code

3. **Write the Application**
   - Keep it simple and focused
   - Comment the vulnerable parts
   - Make the vulnerability observable without exploitation

4. **Create Instructions**
   - Step 1: Explore the code
   - Step 2: Identify the vulnerability
   - Step 3: Understand the risk
   - Step 4: Apply the fix
   - Step 5: Verify the fix

5. **Test Thoroughly**
   - Does it run on fresh Docker install?
   - Are instructions clear?
   - Can a beginner follow along?
   - Is it completely safe?

## Style Guide Quick Reference

### Markdown Files
- Use `.md` extension
- Include front matter if applicable
- One sentence per line (easier for git diff)
- Blank line before and after headings
- Blank line before and after code blocks
- Use relative links for internal references

### Python Code
- PEP 8 compliant
- Maximum line length: 100 characters
- Use 4 spaces for indentation
- Functions and methods: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`

### Docker Files
- Use official base images
- Pin versions for reproducibility
- Minimize layers
- Clean up in same RUN command
- Use .dockerignore

## Getting Help

- 📖 Read the main README.md
- 🔍 Search existing issues
- 💬 Ask questions in issues (tag with "question")
- 📧 Contact maintainers for sensitive topics

## Recognition

Contributors will be recognized in:
- GitHub contributors list
- Release notes for significant contributions
- Special thanks in documentation updates

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make cybersecurity education accessible and ethical! 🛡️
