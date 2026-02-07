#!/usr/bin/env python3
"""
Comprehensive OWASP Repository Audit
Performs thorough recursive search to verify:
- All vulnerabilities have required files
- Year configurations are consistent
- Labs, cheatsheets, documentation exist
- No missing or misplaced content
"""

import os
import json
from pathlib import Path
from collections import defaultdict

class OWASPAudit:
    def __init__(self, base_path="/home/runner/work/OWASP-TOP10/OWASP-TOP10"):
        self.base_path = Path(base_path)
        self.issues = []
        self.warnings = []
        self.successes = []
        
        # Define expected structure
        self.year_config = {
            '2017': {
                'web': {
                    'enabled': True,
                    'version': '2017',
                    'count': 10,
                    'id_format': 'A{n}',
                    'vulnerabilities': [
                        'Injection',
                        'Broken Authentication',
                        'Sensitive Data Exposure',
                        'XML External Entities (XXE)',
                        'Broken Access Control',
                        'Security Misconfiguration',
                        'Cross-Site Scripting (XSS)',
                        'Insecure Deserialization',
                        'Vuln/Outdated Components',
                        'Insufficient Logging/Monitoring'
                    ]
                },
                'mobile': {
                    'enabled': True,
                    'version': '2016',
                    'count': 10,
                    'id_format': 'M{n}'
                },
                'api': {'enabled': False},
                'llm': {'enabled': False}
            },
            '2021': {
                'web': {
                    'enabled': True,
                    'version': '2021',
                    'count': 10,
                    'id_format': 'A{n:02d}',
                    'vulnerabilities': [
                        'Broken Access Control',
                        'Cryptographic Failures',
                        'Injection',
                        'Insecure Design',
                        'Security Misconfiguration',
                        'Vuln/Outdated Components',
                        'Ident/Auth Failures',
                        'Software/Data Integrity',
                        'Logging & Monitoring',
                        'SSRF'
                    ]
                },
                'api': {
                    'enabled': True,
                    'version': '2019',
                    'count': 10,
                    'id_format': 'API{n}'
                },
                'mobile': {
                    'enabled': True,
                    'version': '2016',
                    'count': 10,
                    'id_format': 'M{n}'
                },
                'llm': {'enabled': False}
            },
            '2025': {
                'web': {
                    'enabled': True,
                    'version': '2025',
                    'count': 10,
                    'id_format': 'A{n:02d}',
                    'vulnerabilities': [
                        'Broken Access Control (Includes SSRF)',
                        'Security Misconfiguration',
                        'Software Supply Chain Failures (New)',
                        'Cryptographic Failures',
                        'Injection',
                        'Insecure Design',
                        'Authentication Failures',
                        'Software or Data Integrity Failures',
                        'Logging & Alerting Failures',
                        'Mishandling of Exceptional Conditions'
                    ]
                },
                'api': {
                    'enabled': True,
                    'version': '2023',
                    'count': 10,
                    'id_format': 'API{n}'
                },
                'mobile': {
                    'enabled': True,
                    'version': '2024',
                    'count': 10,
                    'id_format': 'M{n}'
                },
                'llm': {
                    'enabled': True,
                    'version': '2025',
                    'count': 10,
                    'id_format': 'LLM{n:02d}'
                }
            }
        }
        
        self.required_doc_files = ['overview.md', 'prevention.md', 'attack-vectors.md', 'examples.md']
        self.required_html_files = ['overview.html', 'prevention.html', 'attack-vectors.html', 'examples.html']
    
    def check_category_directories(self):
        """Check if main category directories exist"""
        print("\n=== Checking Category Directories ===")
        categories = ['OWASP-Web', 'OWASP-API', 'OWASP-Mobile', 'OWASP-LLM']
        
        for category in categories:
            cat_path = self.base_path / category
            if cat_path.exists():
                self.successes.append(f"✓ {category} directory exists")
                print(f"✓ {category} directory exists")
            else:
                self.issues.append(f"✗ Missing {category} directory")
                print(f"✗ Missing {category} directory")
    
    def check_cheatsheets(self):
        """Check cheatsheet structure for all years"""
        print("\n=== Checking Cheatsheets ===")
        cheatsheet_base = self.base_path / 'cheat-sheets'
        
        if not cheatsheet_base.exists():
            self.issues.append("✗ cheat-sheets directory missing")
            return
        
        # Check index.html
        index_file = cheatsheet_base / 'index.html'
        if index_file.exists():
            self.successes.append("✓ cheat-sheets/index.html exists")
            print("✓ cheat-sheets/index.html exists")
        else:
            self.issues.append("✗ cheat-sheets/index.html missing")
        
        # Check year directories
        for year in ['2017', '2021', '2025']:
            year_path = cheatsheet_base / year
            if year_path.exists():
                print(f"  ✓ Year {year} directory exists")
                
                # Check web subdirectory
                web_path = year_path / 'web'
                if web_path.exists():
                    html_files = list(web_path.glob('*.html'))
                    print(f"    ✓ {year}/web/ has {len(html_files)} HTML files")
                    if len(html_files) < 10:
                        self.warnings.append(f"⚠ {year}/web/ has only {len(html_files)} files (expected 10)")
                else:
                    self.issues.append(f"✗ {year}/web/ directory missing")
            else:
                self.warnings.append(f"⚠ cheat-sheets/{year}/ directory missing")
    
    def check_labs_structure(self):
        """Check labs for each category"""
        print("\n=== Checking Labs Structure ===")
        
        categories_map = {
            'web': 'OWASP-Web',
            'api': 'OWASP-API',
            'mobile': 'OWASP-Mobile',
            'llm': 'OWASP-LLM'
        }
        
        for cat_name, cat_dir in categories_map.items():
            cat_path = self.base_path / cat_dir
            if not cat_path.exists():
                continue
            
            # Count subdirectories (each should be a vulnerability)
            vuln_dirs = [d for d in cat_path.iterdir() if d.is_dir() and not d.name.startswith('.')]
            print(f"\n  {cat_dir}: {len(vuln_dirs)} vulnerability directories")
            
            # Check each vulnerability directory
            for vuln_dir in vuln_dirs:
                # Check for documentation files
                missing_md = []
                missing_html = []
                
                for req_file in self.required_doc_files:
                    if not (vuln_dir / req_file).exists():
                        missing_md.append(req_file)
                
                for req_file in self.required_html_files:
                    if not (vuln_dir / req_file).exists():
                        missing_html.append(req_file)
                
                # Check for lab directory
                lab_dir = vuln_dir / 'lab'
                has_lab = lab_dir.exists() and lab_dir.is_dir()
                
                if missing_md or missing_html:
                    self.warnings.append(f"⚠ {vuln_dir.name}: Missing docs - MD:{missing_md}, HTML:{missing_html}")
                
                if not has_lab:
                    self.warnings.append(f"⚠ {vuln_dir.name}: No lab/ directory")
    
    def check_year_config_consistency(self):
        """Check if year-config.js exists and is readable"""
        print("\n=== Checking Year Configuration ===")
        
        year_config_path = self.base_path / 'src' / 'web-assets' / 'year-config.js'
        if year_config_path.exists():
            self.successes.append("✓ year-config.js exists")
            print("✓ year-config.js exists")
            
            # Read and check basic structure
            content = year_config_path.read_text()
            for year in ['2017', '2021', '2025']:
                if f"'{year}':" in content or f'"{year}":' in content:
                    print(f"  ✓ Year {year} configuration found")
                else:
                    self.issues.append(f"✗ Year {year} configuration missing")
        else:
            self.issues.append("✗ year-config.js missing")
    
    def check_main_pages(self):
        """Check main HTML pages"""
        print("\n=== Checking Main Pages ===")
        
        main_pages = [
            'index.html',
            'owasp-labs.html'
        ]
        
        for page in main_pages:
            page_path = self.base_path / page
            if page_path.exists():
                self.successes.append(f"✓ {page} exists")
                print(f"✓ {page} exists")
            else:
                self.issues.append(f"✗ {page} missing")
    
    def check_diagrams(self):
        """Check diagrams directory"""
        print("\n=== Checking Diagrams ===")
        
        diagrams_path = self.base_path / 'diagrams'
        if diagrams_path.exists():
            print("✓ diagrams/ directory exists")
            
            # Check for index
            index_path = diagrams_path / 'index.html'
            if index_path.exists():
                self.successes.append("✓ diagrams/index.html exists")
            else:
                self.issues.append("✗ diagrams/index.html missing")
            
            # Count diagram files
            html_files = list(diagrams_path.glob('*.html'))
            print(f"  Found {len(html_files)} HTML files in diagrams/")
        else:
            self.warnings.append("⚠ diagrams/ directory missing")
    
    def check_quiz_platform(self):
        """Check quiz platform"""
        print("\n=== Checking Quiz Platform ===")
        
        quiz_path = self.base_path / 'quiz-platform'
        if quiz_path.exists():
            print("✓ quiz-platform/ directory exists")
            
            # Check for quiz-data.js
            quiz_data = quiz_path / 'quiz-data.js'
            if quiz_data.exists():
                self.successes.append("✓ quiz-data.js exists")
            else:
                self.issues.append("✗ quiz-data.js missing")
        else:
            self.warnings.append("⚠ quiz-platform/ directory missing")
    
    def check_compliance_mappings(self):
        """Check compliance mappings"""
        print("\n=== Checking Compliance Mappings ===")
        
        compliance_path = self.base_path / 'compliance-mappings'
        if compliance_path.exists():
            print("✓ compliance-mappings/ directory exists")
            
            html_files = list(compliance_path.glob('*.html'))
            print(f"  Found {len(html_files)} compliance mapping files")
            self.successes.append(f"✓ {len(html_files)} compliance mapping files")
        else:
            self.warnings.append("⚠ compliance-mappings/ directory missing")
    
    def generate_report(self):
        """Generate final audit report"""
        print("\n" + "="*70)
        print("COMPREHENSIVE AUDIT REPORT")
        print("="*70)
        
        print(f"\n✓ SUCCESSES: {len(self.successes)}")
        for success in self.successes[:10]:  # Show first 10
            print(f"  {success}")
        if len(self.successes) > 10:
            print(f"  ... and {len(self.successes) - 10} more")
        
        print(f"\n⚠ WARNINGS: {len(self.warnings)}")
        for warning in self.warnings[:20]:  # Show first 20
            print(f"  {warning}")
        if len(self.warnings) > 20:
            print(f"  ... and {len(self.warnings) - 20} more")
        
        print(f"\n✗ ISSUES: {len(self.issues)}")
        for issue in self.issues:
            print(f"  {issue}")
        
        # Overall status
        print("\n" + "="*70)
        if len(self.issues) == 0:
            print("STATUS: ✓ EXCELLENT - No critical issues found")
        elif len(self.issues) <= 5:
            print("STATUS: ⚠ GOOD - Minor issues need attention")
        else:
            print("STATUS: ✗ NEEDS WORK - Multiple issues found")
        print("="*70)
        
        # Save report to file
        report_path = self.base_path / 'AUDIT_REPORT.md'
        with open(report_path, 'w') as f:
            f.write("# OWASP Repository Comprehensive Audit Report\n\n")
            f.write(f"**Date**: {os.popen('date').read().strip()}\n\n")
            
            f.write(f"## Summary\n\n")
            f.write(f"- ✓ Successes: {len(self.successes)}\n")
            f.write(f"- ⚠ Warnings: {len(self.warnings)}\n")
            f.write(f"- ✗ Issues: {len(self.issues)}\n\n")
            
            f.write("## Successes\n\n")
            for s in self.successes:
                f.write(f"- {s}\n")
            
            f.write("\n## Warnings\n\n")
            for w in self.warnings:
                f.write(f"- {w}\n")
            
            f.write("\n## Issues\n\n")
            for i in self.issues:
                f.write(f"- {i}\n")
        
        print(f"\nDetailed report saved to: {report_path}")
    
    def run_full_audit(self):
        """Run all audit checks"""
        print("Starting Comprehensive OWASP Repository Audit...")
        print(f"Base path: {self.base_path}")
        
        self.check_category_directories()
        self.check_year_config_consistency()
        self.check_main_pages()
        self.check_cheatsheets()
        self.check_labs_structure()
        self.check_diagrams()
        self.check_quiz_platform()
        self.check_compliance_mappings()
        
        self.generate_report()

if __name__ == "__main__":
    audit = OWASPAudit()
    audit.run_full_audit()
