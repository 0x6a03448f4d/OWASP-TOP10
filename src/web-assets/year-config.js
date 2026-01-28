/**
 * OWASP Year-Mode Configuration
 * Defines authoritative mappings between years and OWASP datasets
 * This configuration controls which content is shown across the entire platform
 */

const OWASP_YEAR_CONFIG = {
    // Year 2017: Historical version
    '2017': {
        web: {
            enabled: true,
            version: '2017',
            vulnerabilities: [
                { id: 'A1', number: 1, name: 'Injection', slug: 'injection' },
                { id: 'A2', number: 2, name: 'Broken Authentication', slug: 'broken-authentication' },
                { id: 'A3', number: 3, name: 'Sensitive Data Exposure', slug: 'sensitive-data-exposure' },
                { id: 'A4', number: 4, name: 'XML External Entities (XXE)', slug: 'xml-external-entities' },
                { id: 'A5', number: 5, name: 'Broken Access Control', slug: 'broken-access-control' },
                { id: 'A6', number: 6, name: 'Security Misconfiguration', slug: 'security-misconfiguration' },
                { id: 'A7', number: 7, name: 'Cross-Site Scripting (XSS)', slug: 'cross-site-scripting' },
                { id: 'A8', number: 8, name: 'Insecure Deserialization', slug: 'insecure-deserialization' },
                { id: 'A9', number: 9, name: 'Using Components with Known Vulnerabilities', slug: 'using-components-with-known-vulnerabilities' },
                { id: 'A10', number: 10, name: 'Insufficient Logging & Monitoring', slug: 'insufficient-logging-monitoring' }
            ]
        },
        api: {
            enabled: false, // API Top 10 not standardized in 2017
            version: null,
            vulnerabilities: []
        },
        mobile: {
            enabled: true,
            version: '2016', // Mobile Top 10 2016 was current in 2017
            vulnerabilities: [
                { id: 'M1', number: 1, name: 'Improper Platform Usage', slug: 'improper-platform-usage' },
                { id: 'M2', number: 2, name: 'Insecure Data Storage', slug: 'insecure-data-storage' },
                { id: 'M3', number: 3, name: 'Insecure Communication', slug: 'insecure-communication' },
                { id: 'M4', number: 4, name: 'Insecure Authentication', slug: 'insecure-authentication' },
                { id: 'M5', number: 5, name: 'Insufficient Cryptography', slug: 'insufficient-cryptography' },
                { id: 'M6', number: 6, name: 'Insecure Authorization', slug: 'insecure-authorization' },
                { id: 'M7', number: 7, name: 'Client Code Quality', slug: 'client-code-quality' },
                { id: 'M8', number: 8, name: 'Code Tampering', slug: 'code-tampering' },
                { id: 'M9', number: 9, name: 'Reverse Engineering', slug: 'reverse-engineering' },
                { id: 'M10', number: 10, name: 'Extraneous Functionality', slug: 'extraneous-functionality' }
            ]
        },
        llm: {
            enabled: false, // LLM Top 10 didn't exist in 2017
            version: null,
            vulnerabilities: []
        }
    },
    
    // Year 2021: Reference version
    '2021': {
        web: {
            enabled: true,
            version: '2021',
            vulnerabilities: [
                { id: 'A01', number: 1, name: 'Broken Access Control', slug: 'broken-access-control' },
                { id: 'A02', number: 2, name: 'Cryptographic Failures', slug: 'cryptographic-failures' },
                { id: 'A03', number: 3, name: 'Injection', slug: 'injection' },
                { id: 'A04', number: 4, name: 'Insecure Design', slug: 'insecure-design' },
                { id: 'A05', number: 5, name: 'Security Misconfiguration', slug: 'security-misconfiguration' },
                { id: 'A06', number: 6, name: 'Vulnerable and Outdated Components', slug: 'vulnerable-outdated-components' },
                { id: 'A07', number: 7, name: 'Identification and Authentication Failures', slug: 'identification-authentication-failures' },
                { id: 'A08', number: 8, name: 'Software and Data Integrity Failures', slug: 'software-data-integrity-failures' },
                { id: 'A09', number: 9, name: 'Security Logging and Monitoring Failures', slug: 'security-logging-monitoring-failures' },
                { id: 'A10', number: 10, name: 'Server-Side Request Forgery (SSRF)', slug: 'server-side-request-forgery' }
            ]
        },
        api: {
            enabled: true,
            version: '2019', // API Top 10 2019 was current in 2021
            vulnerabilities: [
                { id: 'API1', number: 1, name: 'Broken Object Level Authorization', slug: 'broken-object-level-authorization' },
                { id: 'API2', number: 2, name: 'Broken User Authentication', slug: 'broken-user-authentication' },
                { id: 'API3', number: 3, name: 'Excessive Data Exposure', slug: 'excessive-data-exposure' },
                { id: 'API4', number: 4, name: 'Lack of Resources & Rate Limiting', slug: 'lack-of-resources-rate-limiting' },
                { id: 'API5', number: 5, name: 'Broken Function Level Authorization', slug: 'broken-function-level-authorization' },
                { id: 'API6', number: 6, name: 'Mass Assignment', slug: 'mass-assignment' },
                { id: 'API7', number: 7, name: 'Security Misconfiguration', slug: 'security-misconfiguration' },
                { id: 'API8', number: 8, name: 'Injection', slug: 'injection' },
                { id: 'API9', number: 9, name: 'Improper Assets Management', slug: 'improper-assets-management' },
                { id: 'API10', number: 10, name: 'Insufficient Logging & Monitoring', slug: 'insufficient-logging-monitoring' }
            ]
        },
        mobile: {
            enabled: true,
            version: '2016', // Mobile Top 10 2016 still current in 2021
            vulnerabilities: [
                { id: 'M1', number: 1, name: 'Improper Platform Usage', slug: 'improper-platform-usage' },
                { id: 'M2', number: 2, name: 'Insecure Data Storage', slug: 'insecure-data-storage' },
                { id: 'M3', number: 3, name: 'Insecure Communication', slug: 'insecure-communication' },
                { id: 'M4', number: 4, name: 'Insecure Authentication', slug: 'insecure-authentication' },
                { id: 'M5', number: 5, name: 'Insufficient Cryptography', slug: 'insufficient-cryptography' },
                { id: 'M6', number: 6, name: 'Insecure Authorization', slug: 'insecure-authorization' },
                { id: 'M7', number: 7, name: 'Client Code Quality', slug: 'client-code-quality' },
                { id: 'M8', number: 8, name: 'Code Tampering', slug: 'code-tampering' },
                { id: 'M9', number: 9, name: 'Reverse Engineering', slug: 'reverse-engineering' },
                { id: 'M10', number: 10, name: 'Extraneous Functionality', slug: 'extraneous-functionality' }
            ]
        },
        llm: {
            enabled: false, // LLM Top 10 didn't exist in 2021
            version: null,
            vulnerabilities: []
        }
    },
    
    // Year 2025: Latest version
    '2025': {
        web: {
            enabled: true,
            version: '2025',
            vulnerabilities: [
                { id: 'A01', number: 1, name: 'Broken Access Control', slug: 'broken-access-control' },
                { id: 'A02', number: 2, name: 'Security Misconfiguration', slug: 'security-misconfiguration' },
                { id: 'A03', number: 3, name: 'Software Supply Chain Failures', slug: 'software-supply-chain-failures' },
                { id: 'A04', number: 4, name: 'Cryptographic Failures', slug: 'cryptographic-failures' },
                { id: 'A05', number: 5, name: 'Injection', slug: 'injection' },
                { id: 'A06', number: 6, name: 'Insecure Design', slug: 'insecure-design' },
                { id: 'A07', number: 7, name: 'Authentication Failures', slug: 'authentication-failures' },
                { id: 'A08', number: 8, name: 'Software or Data Integrity Failures', slug: 'software-data-integrity-failures' },
                { id: 'A09', number: 9, name: 'Logging & Alerting Failures', slug: 'logging-alerting-failures' },
                { id: 'A10', number: 10, name: 'Mishandling of Exceptional Conditions', slug: 'mishandling-exceptional-conditions' }
            ]
        },
        api: {
            enabled: true,
            version: '2023',
            vulnerabilities: [
                { id: 'API1', number: 1, name: 'Broken Object Level Authorization (BOLA)', slug: 'broken-object-level-authorization' },
                { id: 'API2', number: 2, name: 'Broken Authentication', slug: 'broken-authentication' },
                { id: 'API3', number: 3, name: 'Broken Object Property Level Authorization', slug: 'broken-object-property-level-authorization' },
                { id: 'API4', number: 4, name: 'Unrestricted Resource Consumption', slug: 'unrestricted-resource-consumption' },
                { id: 'API5', number: 5, name: 'Broken Function Level Authorization', slug: 'broken-function-level-authorization' },
                { id: 'API6', number: 6, name: 'Unrestricted Access to Business Flows', slug: 'unrestricted-access-to-sensitive-business-flows' },
                { id: 'API7', number: 7, name: 'Server-Side Request Forgery (SSRF)', slug: 'server-side-request-forgery' },
                { id: 'API8', number: 8, name: 'Security Misconfiguration', slug: 'security-misconfiguration' },
                { id: 'API9', number: 9, name: 'Improper Inventory Management', slug: 'improper-inventory-management' },
                { id: 'API10', number: 10, name: 'Unsafe Consumption of APIs', slug: 'unsafe-consumption-of-apis' }
            ]
        },
        mobile: {
            enabled: true,
            version: '2024',
            vulnerabilities: [
                { id: 'M1', number: 1, name: 'Improper Credential Usage', slug: 'improper-credential-usage' },
                { id: 'M2', number: 2, name: 'Inadequate Supply Chain Security', slug: 'inadequate-supply-chain-security' },
                { id: 'M3', number: 3, name: 'Insecure Authentication/Authorization', slug: 'insecure-authentication-authorization' },
                { id: 'M4', number: 4, name: 'Insufficient Input/Output Validation', slug: 'insufficient-input-output-validation' },
                { id: 'M5', number: 5, name: 'Insecure Communication', slug: 'insecure-communication' },
                { id: 'M6', number: 6, name: 'Inadequate Privacy Controls', slug: 'inadequate-privacy-controls' },
                { id: 'M7', number: 7, name: 'Insufficient Binary Protections', slug: 'insufficient-binary-protections' },
                { id: 'M8', number: 8, name: 'Security Misconfiguration', slug: 'security-misconfiguration' },
                { id: 'M9', number: 9, name: 'Insecure Data Storage', slug: 'insecure-data-storage' },
                { id: 'M10', number: 10, name: 'Insufficient Cryptography', slug: 'insufficient-cryptography' }
            ]
        },
        llm: {
            enabled: true,
            version: '2025',
            vulnerabilities: [
                { id: 'LLM01', number: 1, name: 'Prompt Injection', slug: 'prompt-injection' },
                { id: 'LLM02', number: 2, name: 'Sensitive Information Disclosure', slug: 'sensitive-information-disclosure' },
                { id: 'LLM03', number: 3, name: 'Supply Chain Vulnerabilities', slug: 'supply-chain-vulnerabilities' },
                { id: 'LLM04', number: 4, name: 'Data and Model Poisoning', slug: 'data-model-poisoning' },
                { id: 'LLM05', number: 5, name: 'Improper Output Handling', slug: 'improper-output-handling' },
                { id: 'LLM06', number: 6, name: 'Excessive Agency', slug: 'excessive-agency' },
                { id: 'LLM07', number: 7, name: 'System Prompt Leakage', slug: 'system-prompt-leakage' },
                { id: 'LLM08', number: 8, name: 'Vector & Embedding Weaknesses', slug: 'vector-embedding-weaknesses' },
                { id: 'LLM09', number: 9, name: 'Misinformation', slug: 'misinformation' },
                { id: 'LLM10', number: 10, name: 'Unbounded Consumption', slug: 'unbounded-consumption' }
            ]
        }
    }
};

/**
 * Get configuration for a specific year and category
 * @param {string} year - '2017', '2021', or '2025'
 * @param {string} category - 'web', 'api', 'mobile', or 'llm'
 * @returns {object} Category configuration or null if not available
 */
function getYearCategoryConfig(year, category) {
    if (!OWASP_YEAR_CONFIG[year]) {
        console.warn(`Year ${year} not found in configuration`);
        return null;
    }
    
    const config = OWASP_YEAR_CONFIG[year][category];
    if (!config || !config.enabled) {
        return null;
    }
    
    return config;
}

/**
 * Get all enabled categories for a specific year
 * @param {string} year - '2017', '2021', or '2025'
 * @returns {array} Array of enabled category names
 */
function getEnabledCategories(year) {
    if (!OWASP_YEAR_CONFIG[year]) {
        return [];
    }
    
    const yearConfig = OWASP_YEAR_CONFIG[year];
    const enabled = [];
    
    for (const [category, config] of Object.entries(yearConfig)) {
        if (config.enabled) {
            enabled.push(category);
        }
    }
    
    return enabled;
}

/**
 * Check if a category is enabled for a specific year
 * @param {string} year - '2017', '2021', or '2025'
 * @param {string} category - 'web', 'api', 'mobile', or 'llm'
 * @returns {boolean} True if category is enabled for the year
 */
function isCategoryEnabled(year, category) {
    const config = getYearCategoryConfig(year, category);
    return config !== null;
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        OWASP_YEAR_CONFIG,
        getYearCategoryConfig,
        getEnabledCategories,
        isCategoryEnabled
    };
}
