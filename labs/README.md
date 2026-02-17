# Labs Directory

This directory will contain all OWASP Top 10 labs organized by category and year.

## Planned Structure

```
labs/
├── web/
│   ├── 2017/           # OWASP Top 10 2017 Web vulnerabilities
│   ├── 2021/           # OWASP Top 10 2021 Web vulnerabilities  
│   └── 2025/           # Future/upcoming vulnerabilities
├── api/
│   ├── 2019/           # OWASP API Security Top 10 2019
│   └── 2023/           # OWASP API Security Top 10 2023
├── mobile/
│   ├── 2016/           # OWASP Mobile Top 10 2016
│   └── 2024/           # OWASP Mobile Top 10 2024
├── llm/
│   └── 2023/           # OWASP Top 10 for LLM Applications
└── base-images/        # Reusable base images with gamification
    ├── nodejs-base/
    └── python-base/
```

## Current Status

**Phase 1 Complete**: Platform reorganization
- Platform files moved to `platform/` directory
- Lab infrastructure ready
- Labs currently accessed from original locations (OWASP-Web, OWASP-API, etc.)

**Phase 2 - In Progress**: Lab migration
- Labs will be gradually moved to this organized structure
- Each lab will follow the template in `LAB_TEMPLATE_GUIDE.md`
- Gamification features will be added during migration

## Migration Plan

Labs are currently located in:
- `/OWASP-Web/` (Web vulnerabilities)
- `/OWASP-API/` (API vulnerabilities)
- `/OWASP-Mobile/` (Mobile vulnerabilities)
- `/OWASP-LLM/` (LLM vulnerabilities)

These will be gradually migrated to the new structure with:
1. Year-based organization
2. Standardized `lab-guide.json` for gamification
3. Improved documentation
4. Better separation of concerns

## For Contributors

When adding new labs:
1. Choose the appropriate category and year
2. Follow the structure in `LAB_TEMPLATE_GUIDE.md`
3. Include `lab-guide.json` for gamification features
4. Add comprehensive documentation
5. Test thoroughly before submitting

See `IMPLEMENTATION_QUICKSTART.md` for detailed instructions.
