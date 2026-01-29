#!/usr/bin/env python3
"""
Analyze which labs are missing for each OWASP year and category
"""
import os
import json

# Define the OWASP configuration based on year-config.js
OWASP_YEAR_CONFIG = {
    '2017': {
        'web': {
            'enabled': True,
            'version': '2017',
            'vulnerabilities': [
                {'id': 'A1', 'name': 'Injection', 'slug': 'injection'},
                {'id': 'A2', 'name': 'Broken Authentication', 'slug': 'broken-authentication'},
                {'id': 'A3', 'name': 'Sensitive Data Exposure', 'slug': 'sensitive-data-exposure'},
                {'id': 'A4', 'name': 'XML External Entities (XXE)', 'slug': 'xml-external-entities'},
                {'id': 'A5', 'name': 'Broken Access Control', 'slug': 'broken-access-control'},
                {'id': 'A6', 'name': 'Security Misconfiguration', 'slug': 'security-misconfiguration'},
                {'id': 'A7', 'name': 'Cross-Site Scripting (XSS)', 'slug': 'cross-site-scripting'},
                {'id': 'A8', 'name': 'Insecure Deserialization', 'slug': 'insecure-deserialization'},
                {'id': 'A9', 'name': 'Vuln/Outdated Components', 'slug': 'vulnerable-outdated-components'},
                {'id': 'A10', 'name': 'Insufficient Logging/Monitoring', 'slug': 'insufficient-logging-monitoring'}
            ]
        }
    },
    '2021': {
        'web': {
            'enabled': True,
            'version': '2021',
            'vulnerabilities': [
                {'id': 'A01', 'name': 'Broken Access Control', 'slug': 'broken-access-control'},
                {'id': 'A02', 'name': 'Cryptographic Failures', 'slug': 'cryptographic-failures'},
                {'id': 'A03', 'name': 'Injection', 'slug': 'injection'},
                {'id': 'A04', 'name': 'Insecure Design', 'slug': 'insecure-design'},
                {'id': 'A05', 'name': 'Security Misconfiguration', 'slug': 'security-misconfiguration'},
                {'id': 'A06', 'name': 'Vuln/Outdated Components', 'slug': 'vulnerable-outdated-components'},
                {'id': 'A07', 'name': 'Ident/Auth Failures', 'slug': 'identification-authentication-failures'},
                {'id': 'A08', 'name': 'Software/Data Integrity', 'slug': 'software-data-integrity-failures'},
                {'id': 'A09', 'name': 'Logging & Monitoring', 'slug': 'security-logging-monitoring-failures'},
                {'id': 'A10', 'name': 'SSRF', 'slug': 'server-side-request-forgery'}
            ]
        }
    },
    '2025': {
        'web': {
            'enabled': True,
            'version': '2025',
            'vulnerabilities': [
                {'id': 'A01', 'name': 'Broken Access Control (Includes SSRF)', 'slug': 'broken-access-control'},
                {'id': 'A02', 'name': 'Security Misconfiguration', 'slug': 'security-misconfiguration'},
                {'id': 'A03', 'name': 'Software Supply Chain Failures (New)', 'slug': 'software-supply-chain-failures'},
                {'id': 'A04', 'name': 'Cryptographic Failures', 'slug': 'cryptographic-failures'},
                {'id': 'A05', 'name': 'Injection', 'slug': 'injection'},
                {'id': 'A06', 'name': 'Insecure Design', 'slug': 'insecure-design'},
                {'id': 'A07', 'name': 'Authentication Failures', 'slug': 'authentication-failures'},
                {'id': 'A08', 'name': 'Software or Data Integrity Failures', 'slug': 'software-data-integrity-failures'},
                {'id': 'A09', 'name': 'Logging & Alerting Failures', 'slug': 'logging-alerting-failures'},
                {'id': 'A10', 'name': 'Mishandling of Exceptional Conditions', 'slug': 'mishandling-exceptional-conditions'}
            ]
        },
        'llm': {
            'enabled': True,
            'version': '2025',
            'vulnerabilities': [
                {'id': 'LLM01', 'name': 'Prompt Injection', 'slug': 'prompt-injection'},
                {'id': 'LLM02', 'name': 'Sensitive Information Disclosure', 'slug': 'sensitive-information-disclosure'},
                {'id': 'LLM03', 'name': 'Supply Chain Vulnerabilities', 'slug': 'supply-chain-vulnerabilities'},
                {'id': 'LLM04', 'name': 'Data and Model Poisoning', 'slug': 'data-model-poisoning'},
                {'id': 'LLM05', 'name': 'Improper Output Handling', 'slug': 'improper-output-handling'},
                {'id': 'LLM06', 'name': 'Excessive Agency', 'slug': 'excessive-agency'},
                {'id': 'LLM07', 'name': 'System Prompt Leakage', 'slug': 'system-prompt-leakage'},
                {'id': 'LLM08', 'name': 'Vector & Embedding Weaknesses', 'slug': 'vector-embedding-weaknesses'},
                {'id': 'LLM09', 'name': 'Misinformation', 'slug': 'misinformation'},
                {'id': 'LLM10', 'name': 'Unbounded Consumption', 'slug': 'unbounded-consumption'}
            ]
        }
    }
}

# Map existing lab directories
def get_existing_labs(base_path='OWASP-Web'):
    """Get list of existing lab directories"""
    if not os.path.exists(base_path):
        return []
    
    labs = []
    for item in os.listdir(base_path):
        item_path = os.path.join(base_path, item)
        if os.path.isdir(item_path):
            labs.append(item)
    return labs

def normalize_slug(slug):
    """Normalize slug for comparison"""
    # Remove leading numbers and hyphens
    parts = slug.split('-')
    if parts[0].isdigit() or parts[0] in ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10',
                                            'A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9', 'A10']:
        return '-'.join(parts[1:])
    return slug

def main():
    print("="*80)
    print("OWASP LAB ANALYSIS - Missing Labs Report")
    print("="*80)
    
    # Get existing Web labs
    web_labs = get_existing_labs('OWASP-Web')
    web_lab_slugs = {normalize_slug(lab.lower()) for lab in web_labs}
    
    print(f"\nExisting Web Labs ({len(web_labs)}):")
    for lab in sorted(web_labs):
        print(f"  - {lab}")
    
    # Analyze each year
    for year in ['2017', '2021', '2025']:
        print(f"\n{'='*80}")
        print(f"YEAR {year} - WEB APPLICATION")
        print(f"{'='*80}")
        
        if 'web' not in OWASP_YEAR_CONFIG[year]:
            continue
            
        web_config = OWASP_YEAR_CONFIG[year]['web']
        if not web_config['enabled']:
            print(f"  Web category not enabled for {year}")
            continue
        
        print(f"\nRequired Vulnerabilities:")
        missing_labs = []
        existing_match = []
        
        for vuln in web_config['vulnerabilities']:
            vuln_slug = normalize_slug(vuln['slug'])
            exists = vuln_slug in web_lab_slugs
            
            status = "✅ EXISTS" if exists else "❌ MISSING"
            print(f"  {vuln['id']:4s} - {vuln['name']:50s} {status}")
            
            if exists:
                existing_match.append(vuln)
            else:
                missing_labs.append(vuln)
        
        print(f"\nSummary for {year}:")
        print(f"  Total vulnerabilities: {len(web_config['vulnerabilities'])}")
        print(f"  Existing labs: {len(existing_match)}")
        print(f"  Missing labs: {len(missing_labs)}")
        
        if missing_labs:
            print(f"\n  Missing labs for {year}:")
            for vuln in missing_labs:
                print(f"    - {vuln['id']}: {vuln['name']} ({vuln['slug']})")
    
    # Analyze LLM for 2025
    print(f"\n{'='*80}")
    print(f"YEAR 2025 - LLM (AI)")
    print(f"{'='*80}")
    
    llm_labs = get_existing_labs('OWASP-LLM')
    llm_lab_slugs = {normalize_slug(lab.lower()) for lab in llm_labs}
    
    print(f"\nExisting LLM Labs ({len(llm_labs)}):")
    for lab in sorted(llm_labs):
        print(f"  - {lab}")
    
    if 'llm' in OWASP_YEAR_CONFIG['2025']:
        llm_config = OWASP_YEAR_CONFIG['2025']['llm']
        
        print(f"\nRequired Vulnerabilities (2025):")
        missing_llm = []
        existing_llm = []
        
        for vuln in llm_config['vulnerabilities']:
            vuln_slug = normalize_slug(vuln['slug'])
            exists = vuln_slug in llm_lab_slugs
            
            status = "✅ EXISTS" if exists else "❌ MISSING"
            print(f"  {vuln['id']:6s} - {vuln['name']:50s} {status}")
            
            if exists:
                existing_llm.append(vuln)
            else:
                missing_llm.append(vuln)
        
        print(f"\nSummary for LLM 2025:")
        print(f"  Total vulnerabilities: {len(llm_config['vulnerabilities'])}")
        print(f"  Existing labs: {len(existing_llm)}")
        print(f"  Missing labs: {len(missing_llm)}")
        
        if missing_llm:
            print(f"\n  Missing labs for LLM 2025:")
            for vuln in missing_llm:
                print(f"    - {vuln['id']}: {vuln['name']} ({vuln['slug']})")
    
    print(f"\n{'='*80}")
    print("RECOMMENDATIONS")
    print(f"{'='*80}")
    print("\n1. Web 2017: Need labs for era-specific vulnerabilities")
    print("   - Focus on pre-2021 attack vectors")
    print("   - Emphasize deprecated but still common patterns")
    
    print("\n2. Web 2025: Need labs for new/updated vulnerabilities")
    print("   - Software Supply Chain Failures (New)")
    print("   - Mishandling of Exceptional Conditions (New)")
    print("   - Authentication Failures (updated from Ident/Auth)")
    print("   - Logging & Alerting Failures (updated)")
    
    print("\n3. LLM 2025: Need updated labs for 2025 version")
    print("   - New: System Prompt Leakage")
    print("   - New: Vector & Embedding Weaknesses")
    print("   - New: Misinformation")
    print("   - New: Unbounded Consumption")
    print("   - Updated: Sensitive Information Disclosure")
    print("   - Updated: Data and Model Poisoning")
    print("   - Updated: Improper Output Handling")

if __name__ == '__main__':
    main()
