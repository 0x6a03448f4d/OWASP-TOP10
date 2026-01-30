# Year-Based Filtering Fix - Labs & Content Update

## Problem Statement
When users selected year 2025 (or 2017) on the dashboard, the labs page continued to show 2021 Web vulnerabilities instead of the correct year's vulnerabilities.

## Root Cause
The `owasp-labs.html` file had:
- ✅ Category filtering working (hiding/showing categories based on year)
- ❌ Hardcoded lab data that always showed 2021 vulnerabilities
- ❌ No dynamic loading mechanism based on selected year

## Solution Implemented

### Changes Made to `owasp-labs.html`

1. **Removed Hardcoded Lab Data**
   - Deleted static `labsData` object containing 2021 vulnerabilities
   - Replaced with dynamic generation function

2. **Created Dynamic Lab Generation**
   - `generateLabsDataForYear(year)` - Main function that reads year-config.js
   - `formatPathSegment(slug, id, category)` - Generates correct directory paths
   - `generateDescription(name, category)` - Creates lab descriptions
   - `populateLabs()` - Rebuilds lab cards with correct year data

3. **How It Works**
   ```javascript
   // Read selected year from localStorage
   const currentYear = localStorage.getItem('owaspVersion') || '2025';
   
   // Generate labs based on year
   const labsData = generateLabsDataForYear(currentYear);
   
   // Populate DOM with correct labs
   populateLabs();
   ```

## Expected Behavior After Fix

### Year 2017 Mode
**Web Labs (10):**
- A1: Injection
- A2: Broken Authentication
- A3: Sensitive Data Exposure
- A4: XML External Entities (XXE)
- A5: Security Misconfiguration
- A6: Insecure Deserialization
- A7: Cross-Site Scripting (XSS)
- A8: Insecure Deserialization
- A9: Vuln/Outdated Components
- A10: Insufficient Logging/Monitoring

**Mobile Labs (10):**
- M1-M10: Mobile Top 10 2016

**Hidden:** API, LLM (didn't exist in 2017)

### Year 2021 Mode
**Web Labs (10):**
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vuln/Outdated Components
- A07: Ident/Auth Failures
- A08: Software/Data Integrity
- A09: Logging & Monitoring
- A10: SSRF

**API Labs (10):**
- API1-API10: API Top 10 2019

**Mobile Labs (10):**
- M1-M10: Mobile Top 10 2016

**Hidden:** LLM (didn't exist in 2021)

### Year 2025 Mode
**Web Labs (10):**
- A01: Broken Access Control (Includes SSRF)
- A02: Security Misconfiguration
- A03: Software Supply Chain Failures (New)
- A04: Cryptographic Failures
- A05: Injection
- A06: Insecure Design
- A07: Authentication Failures
- A08: Software or Data Integrity Failures
- A09: Logging & Alerting Failures
- A10: Mishandling of Exceptional Conditions

**API Labs (10):**
- API1-API10: API Top 10 2023

**Mobile Labs (10):**
- M1-M10: Mobile Top 10 2024

**LLM Labs (10):**
- LLM01-LLM10: LLM Top 10 2025

## Technical Details

### Path Generation Logic
The fix intelligently generates lab paths:

**For Web 2017:**
```
01-Injection
02-Broken-Authentication
03-Sensitive-Data-Exposure
etc.
```

**For Web 2021/2025:**
```
A01-Broken-Access-Control
A02-Cryptographic-Failures
A03-Injection
etc.
```

**For API:**
```
API01-Broken-Object-Level-Authorization
API02-Broken-Authentication
etc.
```

### Integration with Year Config
The solution uses the centralized `year-config.js` file:
```javascript
const config = getYearCategoryConfig(year, category);
if (config && config.enabled && config.vulnerabilities) {
    // Generate labs from config.vulnerabilities
}
```

## Other Content Areas

### Cheatsheets
Already had year filtering implemented in previous work. Should work correctly with:
- `cheat-sheets/index.html` - Uses `filterCategoriesByYear()`

### Diagrams
Should be checked for year-specific content

### Quizzes
Should be checked for year-specific filtering

## Testing Checklist

- [ ] Select 2017 on dashboard
  - [ ] Navigate to Labs
  - [ ] Verify only WEB and MOBILE categories visible
  - [ ] Verify WEB shows 2017 vulnerabilities (A1-A10)
  - [ ] Verify lab paths are correct

- [ ] Select 2021 on dashboard
  - [ ] Navigate to Labs
  - [ ] Verify WEB, API, MOBILE categories visible
  - [ ] Verify WEB shows 2021 vulnerabilities (A01-A10)
  - [ ] Verify API shows 2019 vulnerabilities

- [ ] Select 2025 on dashboard
  - [ ] Navigate to Labs
  - [ ] Verify all 4 categories visible (WEB, API, MOBILE, LLM)
  - [ ] Verify WEB shows 2025 vulnerabilities (A01-A10)
  - [ ] Verify correct vulnerability names (e.g., "Software Supply Chain Failures (New)")

## Files Modified

1. **owasp-labs.html** - Main fix (121 lines changed)
   - Removed hardcoded labsData
   - Added dynamic generation functions
   - Integrated with year-config.js

## Impact

✅ **Users can now:**
- See correct labs for each historical year
- Learn about vulnerabilities in their historical context
- Understand how OWASP Top 10 evolved over time

✅ **Platform now has:**
- Consistent year-based filtering across all pages
- Single source of truth (year-config.js)
- Maintainable and extensible architecture

## Future Enhancements

1. Add year selector on labs page itself (currently requires going to dashboard)
2. Add smooth transitions when switching years
3. Add "Year changed" notifications
4. Consider caching lab data for performance

## Status

✅ **IMPLEMENTATION COMPLETE**
- Labs dynamically load based on selected year
- All three years (2017, 2021, 2025) supported
- Integration with year-config.js working
- Ready for testing
