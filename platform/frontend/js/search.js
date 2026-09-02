// Global Search Functionality for OWASP Top 10 Platform

class OWASPSearch {
    constructor() {
        this.searchData = [];
        this.init();
    }

    init() {
        this.createSearchUI();
        this.loadSearchData();
        this.attachEventListeners();
    }

    createSearchUI() {
        const searchHTML = `
            <div id="global-search" class="search-overlay">
                <div class="search-container">
                    <div class="search-header">
                        <input type="text" id="search-input" placeholder="Search OWASP Top 10 resources..." autocomplete="off">
                        <button id="close-search" class="close-btn">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div id="search-results" class="search-results"></div>
                    <div class="search-footer">
                        <span class="search-hint">
                            <kbd>Ctrl</kbd> + <kbd>K</kbd> to search • <kbd>Esc</kbd> to close
                        </span>
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', searchHTML);
    }

    loadSearchData() {
        // Index of searchable content
        this.searchData = [
            // Web vulnerabilities
            { title: "Broken Access Control", type: "Web", url: "cheat-sheets/web/01-broken-access-control.html", keywords: "access control authorization permissions" },
            { title: "Cryptographic Failures", type: "Web", url: "cheat-sheets/web/02-cryptographic-failures.html", keywords: "encryption crypto SSL TLS" },
            { title: "Injection", type: "Web", url: "cheat-sheets/web/03-injection.html", keywords: "SQL NoSQL command injection XSS" },
            { title: "Insecure Design", type: "Web", url: "cheat-sheets/web/04-insecure-design.html", keywords: "architecture design patterns" },
            { title: "Security Misconfiguration", type: "Web", url: "cheat-sheets/web/05-security-misconfiguration.html", keywords: "configuration settings headers" },
            { title: "Vulnerable Components", type: "Web", url: "cheat-sheets/web/06-vulnerable-outdated-components.html", keywords: "dependencies libraries CVE" },
            { title: "Authentication Failures", type: "Web", url: "cheat-sheets/web/07-identification-authentication-failures.html", keywords: "authentication login session" },
            { title: "Software & Data Integrity", type: "Web", url: "cheat-sheets/web/08-software-data-integrity-failures.html", keywords: "integrity CI/CD pipeline" },
            { title: "Security Logging Failures", type: "Web", url: "cheat-sheets/web/09-security-logging-monitoring-failures.html", keywords: "logging monitoring SIEM" },
            { title: "SSRF", type: "Web", url: "cheat-sheets/web/10-server-side-request-forgery.html", keywords: "SSRF server side request forgery" },
            
            // API vulnerabilities
            { title: "Broken Object Level Authorization (API)", type: "API", url: "cheat-sheets/api/api01-broken-object-level-authorization.html", keywords: "BOLA authorization API" },
            { title: "Broken Authentication (API)", type: "API", url: "cheat-sheets/api/api02-broken-authentication.html", keywords: "API authentication JWT token" },
            { title: "Broken Object Property Level Authorization", type: "API", url: "cheat-sheets/api/api03-broken-object-property-level-authorization.html", keywords: "mass assignment API" },
            { title: "Unrestricted Resource Consumption", type: "API", url: "cheat-sheets/api/api04-unrestricted-resource-consumption.html", keywords: "rate limiting DoS API" },
            { title: "Broken Function Level Authorization", type: "API", url: "cheat-sheets/api/api05-broken-function-level-authorization.html", keywords: "function authorization API" },
            
            // Mobile vulnerabilities
            { title: "Improper Credential Usage (Mobile)", type: "Mobile", url: "cheat-sheets/mobile/m01-improper-credential-usage.html", keywords: "credentials mobile hardcoded" },
            { title: "Insecure Data Storage (Mobile)", type: "Mobile", url: "cheat-sheets/mobile/m09-insecure-data-storage.html", keywords: "storage mobile keychain" },
            
            // LLM vulnerabilities
            { title: "Prompt Injection (LLM)", type: "LLM", url: "cheat-sheets/llm/llm01-prompt-injection.html", keywords: "prompt injection LLM AI" },
            { title: "Insecure Output Handling (LLM)", type: "LLM", url: "cheat-sheets/llm/llm02-insecure-output-handling.html", keywords: "output LLM AI" },
            
            // Platform pages
            { title: "Labs - Web Security", type: "Labs", url: "owasp-labs.html", keywords: "labs practice hands-on docker" },
            { title: "Compliance Mappings", type: "Compliance", url: "compliance-mappings/index.html", keywords: "compliance GDPR ISO NIST PCI" },
            { title: "Attack Flow Diagrams", type: "Diagrams", url: "diagrams/index.html", keywords: "diagrams attack flow visual" },
            { title: "Security Quiz", type: "Quiz", url: "quiz-platform/index.html", keywords: "quiz test knowledge assessment" },
            { title: "Cheat Sheets Collection", type: "Cheatsheets", url: "/cheatsheets", keywords: "cheatsheet reference quick" }
        ];
    }

    attachEventListeners() {
        const searchOverlay = document.getElementById('global-search');
        const searchInput = document.getElementById('search-input');
        const closeBtn = document.getElementById('close-search');

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl+K or Cmd+K to open search
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                this.openSearch();
            }
            // Escape to close search
            if (e.key === 'Escape') {
                this.closeSearch();
            }
        });

        // Click outside to close
        searchOverlay.addEventListener('click', (e) => {
            if (e.target === searchOverlay) {
                this.closeSearch();
            }
        });

        // Close button
        closeBtn.addEventListener('click', () => this.closeSearch());

        // Search input
        searchInput.addEventListener('input', (e) => {
            this.performSearch(e.target.value);
        });

        // Result click handling
        document.addEventListener('click', (e) => {
            if (e.target.closest('.search-result-item')) {
                const url = e.target.closest('.search-result-item').dataset.url;
                if (url) {
                    window.location.href = url;
                }
            }
        });
    }

    openSearch() {
        const searchOverlay = document.getElementById('global-search');
        const searchInput = document.getElementById('search-input');
        searchOverlay.classList.add('active');
        setTimeout(() => searchInput.focus(), 100);
    }

    closeSearch() {
        const searchOverlay = document.getElementById('global-search');
        searchOverlay.classList.remove('active');
        document.getElementById('search-input').value = '';
        document.getElementById('search-results').innerHTML = '';
    }

    performSearch(query) {
        const resultsContainer = document.getElementById('search-results');
        
        if (!query || query.length < 2) {
            resultsContainer.innerHTML = '<div class="no-results">Type at least 2 characters to search...</div>';
            return;
        }

        const queryLower = query.toLowerCase();
        const results = this.searchData.filter(item => {
            return item.title.toLowerCase().includes(queryLower) ||
                   item.keywords.toLowerCase().includes(queryLower) ||
                   item.type.toLowerCase().includes(queryLower);
        });

        if (results.length === 0) {
            resultsContainer.innerHTML = '<div class="no-results">No results found</div>';
            return;
        }

        const resultsHTML = results.slice(0, 10).map(item => `
            <div class="search-result-item" data-url="${item.url}">
                <div class="result-type">${item.type}</div>
                <div class="result-title">${this.highlightQuery(item.title, query)}</div>
                <div class="result-url">${item.url}</div>
            </div>
        `).join('');

        resultsContainer.innerHTML = resultsHTML;
    }

    highlightQuery(text, query) {
        const regex = new RegExp(`(${query})`, 'gi');
        return text.replace(regex, '<mark>$1</mark>');
    }
}

// Initialize search when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new OWASPSearch();
    });
} else {
    new OWASPSearch();
}
