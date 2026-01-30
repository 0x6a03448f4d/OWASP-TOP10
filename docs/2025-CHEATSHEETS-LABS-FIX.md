# 2025 Cheatsheets and Labs Fix - Complete Documentation

## Overview

This document describes the fix for the issue where OWASP Top 10 2025 was not being updated correctly in cheatsheets and labs pages.

## Problem Statement

When users selected year 2025:
- ❌ Cheatsheets page showed 2021 vulnerability names
- ❌ Labs page showed 2021 vulnerabilities
- ❌ Content did not match the actual OWASP 2025 Top 10 list

## Root Causes

### Cheatsheets Issue
1. **Incorrect Data**: The `owaspData['2025']` object contained 2021 data instead of 2025 data
2. **File Naming Mismatch**: Files in `cheat-sheets/2025/web/` were named using 2021 ordering, not 2025 ordering

### Labs Issue
1. **Hardcoded Data**: Labs had a static `labsData` object with only 2021 vulnerabilities
2. **No Dynamic Loading**: Labs didn't read from the centralized `year-config.js` file

## Solutions Implemented

### 1. Labs Fix (owasp-labs.html)
- Removed hardcoded `labsData` object
- Created `generateLabsDataForYear(year)` function
- Now reads from `OWASP_YEAR_CONFIG` in `year-config.js`
- Dynamically generates lab data based on selected year

### 2. Cheatsheets Data Fix (cheat-sheets/index.html)
Updated `owaspData['2025']['web']` with correct vulnerabilities:
```javascript
'2025': {
    'web': [
        {num: '01', name: 'Broken Access Control (Includes SSRF)', ...},
        {num: '02', name: 'Security Misconfiguration', ...},
        {num: '03', name: 'Software Supply Chain Failures (New)', ...},
        {num: '04', name: 'Cryptographic Failures', ...},
        {num: '05', name: 'Injection', ...},
        {num: '06', name: 'Insecure Design', ...},
        {num: '07', name: 'Authentication Failures', ...},
        {num: '08', name: 'Software or Data Integrity Failures', ...},
        {num: '09', name: 'Logging & Alerting Failures', ...},
        {num: '10', name: 'Mishandling of Exceptional Conditions', ...}
    ]
}
```

### 3. Cheatsheets Path Mapping (cheat-sheets/index.html)
Added path mapping to handle file naming mismatch:
```javascript
if (year === '2025') {
    const pathMap = {
        '01-broken-access-control': '01-broken-access-control.html',
        '02-security-misconfiguration': '05-security-misconfiguration.html',
        '03-software-supply-chain-failures': '08-software-data-integrity-failures.html',
        // ... more mappings
    };
    linkElem.href = `2025/web/${pathMap[key] || key + '.html'}`;
}
```

## 2025 Vulnerability Mapping

| 2025 Position | Vulnerability Name | 2021 Position | Actual File |
|---------------|-------------------|---------------|-------------|
| A01 | Broken Access Control (Includes SSRF) | A01 | 01-broken-access-control.html |
| A02 | Security Misconfiguration | A05 | 05-security-misconfiguration.html |
| A03 | Software Supply Chain Failures (New) | NEW | 08-software-data-integrity-failures.html* |
| A04 | Cryptographic Failures | A02 | 02-cryptographic-failures.html |
| A05 | Injection | A03 | 03-injection.html |
| A06 | Insecure Design | A04 | 04-insecure-design.html |
| A07 | Authentication Failures | A07 | 07-identification-authentication-failures.html |
| A08 | Software or Data Integrity Failures | A08 | 08-software-data-integrity-failures.html |
| A09 | Logging & Alerting Failures | A09 | 09-security-logging-monitoring-failures.html |
| A10 | Mishandling of Exceptional Conditions | NEW | 10-server-side-request-forgery.html* |

*Temporary mappings to closest available content

## Files Modified

1. **owasp-labs.html** (commit 584fcd0)
   - Added `generateLabsDataForYear()` function
   - Added `formatPathSegment()` helper
   - Modified `populateLabs()` to use dynamic data

2. **cheat-sheets/index.html** (commits 3ce2993, de40c79)
   - Updated `owaspData['2025']['web']` array
   - Added 2025 path mapping in `updateCheatsheetLinks()`

## Testing

### Cheatsheets
```
✅ 2017: Shows A1-A10 with correct 2017 names
✅ 2021: Shows A01-A10 with correct 2021 names
✅ 2025: Shows A01-A10 with correct 2025 names + annotations
```

### Labs
```
✅ 2017: Shows only WEB (2017) + MOBILE (2016) categories
✅ 2021: Shows WEB (2021) + API (2019) + MOBILE (2016) categories
✅ 2025: Shows WEB (2025) + API (2023) + MOBILE (2024) + LLM (2025) categories
```

## Usage

### For Users
1. Navigate to dashboard (index.html)
2. Select desired year (2017, 2021, or 2025)
3. Navigate to Cheatsheets or Labs
4. See correct vulnerabilities for that year

### For Developers
The system now has a single source of truth:
- `src/web-assets/year-config.js` - Contains authoritative vulnerability data
- All pages should read from this configuration
- Use helper functions: `getYearCategoryConfig()`, `getEnabledCategories()`

## Known Limitations

### Temporary File Mappings
- A03 "Software Supply Chain Failures" uses Software/Data Integrity file temporarily
- A10 "Mishandling of Exceptional Conditions" uses SSRF file temporarily
- These should have dedicated files created in the future

### File Structure
- 2025 cheatsheet files are still named using 2021 structure
- Path mapping handles this, but renaming files would be cleaner
- Content inside files may still reference 2021 context

## Future Enhancements

1. **Create Dedicated Files**
   - Create proper files for new 2025 vulnerabilities (A03, A10)
   - Update content to reflect 2025-specific context

2. **Rename Files**
   - Rename files in `cheat-sheets/2025/web/` to match 2025 ordering
   - Remove need for path mapping

3. **Content Updates**
   - Update file content to reflect 2025 threat landscape
   - Add 2025-specific examples and attack vectors
   - Update statistics and prevalence data

4. **Automated Testing**
   - Add tests to verify year filtering works correctly
   - Validate that all links are functional
   - Check for content consistency

## Commits

- `584fcd0` - Fix labs to dynamically load based on selected year
- `3ce2993` - Fix 2025 cheatsheet data to show correct vulnerabilities
- `de40c79` - Add path mapping for 2025 cheatsheets to resolve file naming mismatch

## References

- OWASP Year Config: `src/web-assets/year-config.js`
- Cheatsheets Page: `cheat-sheets/index.html`
- Labs Page: `owasp-labs.html`
- 2025 Files: `cheat-sheets/2025/web/`
