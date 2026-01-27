# LLM09: Overreliance - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Verification and Validation](#verification-and-validation)
- [User Education and Training](#user-education-and-training)
- [System-Level Controls](#system-level-controls)
- [Code Review Processes](#code-review-processes)
- [Monitoring and Auditing](#monitoring-and-auditing)
- [Best Practices](#best-practices)

## Prevention Strategy Overview

Preventing overreliance requires implementing multiple layers of verification, education, and systematic controls to ensure AI outputs are appropriately validated before use in critical contexts.

### Defense-in-Depth Layers

```
[User Education] → [Output Verification] → [Expert Review]
      ↓                   ↓                      ↓
   Understand         Validate before        Domain expert
   limitations        accepting              validation
      ↓                   ↓                      ↓
[Automated Checks] → [Documentation] → [Audit Trail]
      ↓                   ↓                  ↓
   Detect issues    Record AI usage     Track decisions
```

## Verification and Validation

### 1. Multi-Source Validation

**Cross-reference AI outputs with authoritative sources**:

```python
from typing import List, Dict, Optional
import requests
from dataclasses import dataclass

@dataclass
class SourceVerification:
    """Track verification of information"""
    claim: str
    ai_source: str
    verification_sources: List[str]
    verified: bool
    confidence: str  # 'high', 'medium', 'low', 'unverified'

class AIOutputValidator:
    """Validate AI outputs before use"""
    
    def __init__(self, required_sources: int = 2):
        self.required_sources = required_sources
        self.verification_log = []
    
    def verify_claim(self, claim: str, ai_response: str) -> SourceVerification:
        """Verify a claim from AI output"""
        
        # Extract sources from AI response
        ai_sources = self._extract_sources(ai_response)
        
        # Verify each source exists and supports claim
        verified_sources = []
        for source in ai_sources:
            if self._verify_source_exists(source):
                if self._source_supports_claim(source, claim):
                    verified_sources.append(source)
        
        # Determine if claim is verified
        verified = len(verified_sources) >= self.required_sources
        
        # Calculate confidence based on verification
        if verified:
            confidence = 'high' if len(verified_sources) >= 3 else 'medium'
        else:
            confidence = 'low' if len(verified_sources) > 0 else 'unverified'
        
        result = SourceVerification(
            claim=claim,
            ai_source=ai_response,
            verification_sources=verified_sources,
            verified=verified,
            confidence=confidence
        )
        
        self.verification_log.append(result)
        return result
    
    def _extract_sources(self, response: str) -> List[str]:
        """Extract citations and sources from AI response"""
        # Implementation: Parse citations, DOIs, URLs from response
        import re
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', response)
        return urls
    
    def _verify_source_exists(self, source: str) -> bool:
        """Verify that a source actually exists"""
        try:
            if source.startswith('http'):
                response = requests.head(source, timeout=5)
                return response.status_code == 200
            # For academic sources, check DOI or database
            return self._check_academic_source(source)
        except:
            return False
    
    def _check_academic_source(self, source: str) -> bool:
        """Verify academic sources exist"""
        # Implementation: Check DOI.org, PubMed, arXiv, etc.
        return True  # Placeholder
    
    def _source_supports_claim(self, source: str, claim: str) -> bool:
        """Verify source actually supports the claim"""
        # Implementation: Fetch source content and validate claim
        return True  # Placeholder

# Usage
validator = AIOutputValidator(required_sources=2)

ai_response = """
According to Smith et al. (2023) in the Journal of Security, 
87% of applications have SQL injection vulnerabilities.
https://example.com/security-study-2023
"""

claim = "87% of applications have SQL injection vulnerabilities"
verification = validator.verify_claim(claim, ai_response)

if not verification.verified:
    print(f"⚠️  WARNING: Claim '{claim}' is not verified!")
    print(f"Confidence: {verification.confidence}")
    print("DO NOT use this information for critical decisions")
```

### 2. Expert Review Requirement

**Require domain expert validation for critical outputs**:

```python
from enum import Enum
from typing import Optional, Callable
from datetime import datetime

class Criticality(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ExpertReviewRequired(Exception):
    """Raised when expert review is needed"""
    pass

class AIOutputGatekeeper:
    """Enforce expert review for critical AI outputs"""
    
    def __init__(self):
        self.review_log = []
    
    def use_ai_output(
        self,
        output: str,
        use_case: str,
        criticality: Criticality,
        expert_reviewer: Optional[str] = None,
        expert_approval: bool = False
    ) -> str:
        """
        Gate AI output usage based on criticality
        
        Args:
            output: AI-generated output
            use_case: What the output will be used for
            criticality: Impact level of the use case
            expert_reviewer: Name of expert who reviewed (if any)
            expert_approval: Whether expert approved the output
            
        Returns:
            The output if approved, raises exception otherwise
        """
        
        # High and critical outputs require expert review
        requires_review = criticality in [Criticality.HIGH, Criticality.CRITICAL]
        
        if requires_review and not expert_approval:
            raise ExpertReviewRequired(
                f"Use case '{use_case}' with {criticality.value} criticality "
                f"requires expert review before using AI output"
            )
        
        # Log the decision
        self.review_log.append({
            'timestamp': datetime.now(),
            'use_case': use_case,
            'criticality': criticality.value,
            'expert_reviewer': expert_reviewer,
            'expert_approval': expert_approval,
            'output_preview': output[:100]
        })
        
        # Add warnings for medium criticality
        if criticality == Criticality.MEDIUM and not expert_approval:
            print(f"⚠️  WARNING: Using AI output for {use_case} without expert review")
            print("Consider having domain expert validate this output")
        
        return output

# Usage examples
gatekeeper = AIOutputGatekeeper()

# LOW criticality - no review needed
draft_email = gatekeeper.use_ai_output(
    output="Draft email content...",
    use_case="internal team update email",
    criticality=Criticality.LOW
)

# HIGH criticality - requires expert review
try:
    security_code = gatekeeper.use_ai_output(
        output="def authenticate(user, password): ...",
        use_case="production authentication code",
        criticality=Criticality.HIGH
    )
except ExpertReviewRequired as e:
    print(f"❌ Blocked: {e}")
    # Code must be reviewed by security expert first

# HIGH criticality WITH expert review - allowed
security_code = gatekeeper.use_ai_output(
    output="def authenticate(user, password): ...",
    use_case="production authentication code",
    criticality=Criticality.HIGH,
    expert_reviewer="Alice (Security Engineer)",
    expert_approval=True
)
```

### 3. Automated Fact-Checking

**Implement automated verification where possible**:

```python
import re
from typing import List, Tuple

class FactChecker:
    """Automated fact-checking for AI outputs"""
    
    def check_code_security(self, code: str) -> List[Tuple[str, str]]:
        """Check code for common security issues"""
        issues = []
        
        # Check for SQL injection patterns
        if re.search(r'f["\'].*SELECT.*{.*}["\']|".*\+.*\+.*".*execute', code, re.IGNORECASE):
            issues.append(('SQL Injection Risk', 
                          'Code appears to use string concatenation for SQL'))
        
        # Check for hardcoded credentials
        if re.search(r'password\s*=\s*["\'][^"\']+["\']', code, re.IGNORECASE):
            issues.append(('Hardcoded Credentials', 
                          'Code contains hardcoded password'))
        
        # Check for unsafe deserialization
        if 'pickle.loads' in code or 'yaml.load(' in code:
            issues.append(('Unsafe Deserialization', 
                          'Code uses potentially unsafe deserialization'))
        
        # Check for missing input validation
        if 'request.args' in code or 'request.form' in code:
            if 'validate' not in code and 'sanitize' not in code:
                issues.append(('Missing Input Validation', 
                              'User input used without validation'))
        
        return issues
    
    def check_for_hallucination_patterns(self, text: str) -> List[str]:
        """Detect potential hallucinations in AI text"""
        warnings = []
        
        # Check for overly specific statistics without sources
        if re.search(r'\d+\.\d+%', text):
            if not re.search(r'according to|source:|study by', text, re.IGNORECASE):
                warnings.append('Specific statistics without cited source')
        
        # Check for year claims that seem suspicious
        current_year = 2024
        years = re.findall(r'\b(20\d{2})\b', text)
        for year in years:
            if int(year) > current_year:
                warnings.append(f'Reference to future year: {year}')
        
        # Check for suspiciously definitive language
        definitive_patterns = [
            r'always\s+\w+',
            r'never\s+\w+',
            r'guaranteed\s+to',
            r'impossible\s+to',
            r'absolutely\s+\w+'
        ]
        for pattern in definitive_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                warnings.append('Overly definitive language detected - verify claims')
                break
        
        return warnings

# Usage
checker = FactChecker()

# Check AI-generated code
ai_code = """
def search_users(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
    return cursor.fetchall()
"""

security_issues = checker.check_code_security(ai_code)
if security_issues:
    print("🚨 Security issues detected in AI-generated code:")
    for issue_type, description in security_issues:
        print(f"  - {issue_type}: {description}")
    print("\n❌ DO NOT deploy this code without security review!")

# Check AI-generated text
ai_text = """
According to recent studies, 94.7% of developers prefer Python.
This is absolutely guaranteed to remain true in 2025.
"""

hallucination_warnings = checker.check_for_hallucination_patterns(ai_text)
if hallucination_warnings:
    print("\n⚠️  Potential hallucination indicators:")
    for warning in hallucination_warnings:
        print(f"  - {warning}")
    print("\n⚠️  Verify these claims before using!")
```

## User Education and Training

### 4. AI Literacy Training

**Educate users on AI limitations and proper use**:

```python
class AILiteracyTraining:
    """Training module for proper AI usage"""
    
    @staticmethod
    def key_concepts() -> dict:
        """Core concepts users must understand"""
        return {
            'hallucinations': {
                'description': 'AI can generate plausible but false information',
                'example': 'Fabricated citations, non-existent statistics',
                'impact': 'Using false information for decisions',
                'mitigation': 'Always verify important claims'
            },
            'biases': {
                'description': 'AI reflects biases in training data',
                'example': 'Stereotypical assumptions, cultural biases',
                'impact': 'Unfair or discriminatory outputs',
                'mitigation': 'Review for bias, seek diverse perspectives'
            },
            'knowledge_cutoff': {
                'description': 'AI training data has a cutoff date',
                'example': 'Outdated information about recent events',
                'impact': 'Acting on obsolete information',
                'mitigation': 'Check for current information from live sources'
            },
            'no_true_understanding': {
                'description': 'AI pattern-matches, does not truly understand',
                'example': 'Plausible but logically flawed reasoning',
                'impact': 'Following advice that seems right but is wrong',
                'mitigation': 'Apply domain expertise and critical thinking'
            },
            'confidence_calibration': {
                'description': 'AI confidence does not equal accuracy',
                'example': 'Confidently stated but incorrect facts',
                'impact': 'Trusting wrong information due to confident tone',
                'mitigation': 'Verify regardless of how confident AI seems'
            }
        }
    
    @staticmethod
    def usage_guidelines() -> List[str]:
        """Guidelines for appropriate AI use"""
        return [
            "✅ DO: Use AI for brainstorming and first drafts",
            "✅ DO: Verify all factual claims from AI",
            "✅ DO: Have experts review AI outputs for critical use",
            "✅ DO: Understand what the AI-generated code does",
            "✅ DO: Cross-check AI advice with authoritative sources",
            "✅ DO: Document when and how AI was used",
            "",
            "❌ DON'T: Deploy AI code without understanding it",
            "❌ DON'T: Make critical decisions solely on AI output",
            "❌ DON'T: Publish AI content without fact-checking",
            "❌ DON'T: Trust AI for legal, medical, or financial advice",
            "❌ DON'T: Assume AI citations are real",
            "❌ DON'T: Use AI outputs in safety-critical systems without validation"
        ]
    
    @staticmethod
    def verification_checklist() -> List[str]:
        """Checklist before using AI output"""
        return [
            "☐ Understand what the AI output means",
            "☐ Verify factual claims with authoritative sources",
            "☐ Check that cited sources actually exist",
            "☐ Have domain expert review for critical use",
            "☐ Test AI-generated code thoroughly",
            "☐ Review code for security vulnerabilities",
            "☐ Consider edge cases and limitations",
            "☐ Document AI usage and verification performed",
            "☐ Have rollback plan if AI output proves incorrect"
        ]

# Display training materials
training = AILiteracyTraining()

print("=== AI Literacy Training ===\n")
print("Key Concepts to Understand:\n")
for concept, details in training.key_concepts().items():
    print(f"{concept.replace('_', ' ').title()}:")
    print(f"  {details['description']}")
    print(f"  Example: {details['example']}")
    print(f"  Mitigation: {details['mitigation']}\n")

print("\nUsage Guidelines:")
for guideline in training.usage_guidelines():
    print(guideline)

print("\n\nVerification Checklist:")
for item in training.verification_checklist():
    print(item)
```

## System-Level Controls

### 5. Usage Context Classification

**Classify and control AI use based on context**:

```python
from enum import Enum
from typing import Dict, Set

class AIUseContext(Enum):
    """Categories of AI usage"""
    BRAINSTORMING = "brainstorming"
    DRAFT_CONTENT = "draft_content"
    CODE_SUGGESTION = "code_suggestion"
    RESEARCH = "research"
    DECISION_SUPPORT = "decision_support"
    PRODUCTION_CODE = "production_code"
    PUBLISHED_CONTENT = "published_content"
    SAFETY_CRITICAL = "safety_critical"
    LEGAL_COMPLIANCE = "legal_compliance"
    MEDICAL = "medical"

class AIUsagePolicy:
    """Define and enforce policies for AI usage"""
    
    def __init__(self):
        # Define requirements for each context
        self.policies: Dict[AIUseContext, Dict] = {
            AIUseContext.BRAINSTORMING: {
                'verification_required': False,
                'expert_review': False,
                'can_use_directly': True,
                'warnings': ['Use as inspiration only']
            },
            AIUseContext.CODE_SUGGESTION: {
                'verification_required': True,
                'expert_review': False,
                'can_use_directly': False,
                'warnings': ['Must review and understand code', 'Test thoroughly']
            },
            AIUseContext.PRODUCTION_CODE: {
                'verification_required': True,
                'expert_review': True,
                'can_use_directly': False,
                'warnings': [
                    'Security review required',
                    'Code review required',
                    'Testing required'
                ]
            },
            AIUseContext.PUBLISHED_CONTENT: {
                'verification_required': True,
                'expert_review': True,
                'can_use_directly': False,
                'warnings': ['Fact-check all claims', 'Verify sources exist']
            },
            AIUseContext.SAFETY_CRITICAL: {
                'verification_required': True,
                'expert_review': True,
                'can_use_directly': False,
                'warnings': [
                    'AI use in safety-critical systems prohibited without extensive validation',
                    'Multiple expert reviews required',
                    'Full testing and validation required'
                ]
            },
            AIUseContext.MEDICAL: {
                'verification_required': True,
                'expert_review': True,
                'can_use_directly': False,
                'warnings': [
                    'Medical professional review REQUIRED',
                    'AI is not a substitute for medical advice',
                    'Liability considerations apply'
                ]
            }
        }
    
    def can_use_output(self, context: AIUseContext) -> Tuple[bool, List[str]]:
        """Check if AI output can be used in given context"""
        policy = self.policies.get(context, {
            'verification_required': True,
            'expert_review': True,
            'can_use_directly': False,
            'warnings': ['Unknown context - exercise extreme caution']
        })
        
        return policy['can_use_directly'], policy['warnings']
    
    def get_requirements(self, context: AIUseContext) -> Dict:
        """Get requirements for using AI in context"""
        return self.policies.get(context, {})

# Usage
policy = AIUsagePolicy()

# Check if AI code can be used in production
can_use, warnings = policy.can_use_output(AIUseContext.PRODUCTION_CODE)
print(f"Can use AI code directly in production: {can_use}")
print("Requirements:")
for warning in warnings:
    print(f"  ⚠️  {warning}")
```

## Code Review Processes

### 6. AI Code Review Checklist

**Specific checklist for reviewing AI-generated code**:

```python
class AICodeReviewChecklist:
    """Checklist for reviewing AI-generated code"""
    
    @staticmethod
    def security_checks() -> List[str]:
        return [
            "☐ No SQL injection vulnerabilities (parameterized queries used)",
            "☐ No XSS vulnerabilities (output properly escaped)",
            "☐ No hardcoded credentials or secrets",
            "☐ No path traversal vulnerabilities",
            "☐ Input validation implemented",
            "☐ No unsafe deserialization (pickle, yaml.load, etc.)",
            "☐ Authentication and authorization properly implemented",
            "☐ No use of known-vulnerable functions",
            "☐ Cryptography uses secure algorithms and libraries",
            "☐ No race conditions in critical operations"
        ]
    
    @staticmethod
    def functionality_checks() -> List[str]:
        return [
            "☐ Code actually solves the intended problem",
            "☐ Edge cases are handled",
            "☐ Error handling is appropriate",
            "☐ No infinite loops or recursion without termination",
            "☐ Resource cleanup (files, connections) implemented",
            "☐ Code is efficient (no obvious performance issues)",
            "☐ Dependencies are necessary and appropriate"
        ]
    
    @staticmethod
    def understanding_checks() -> List[str]:
        return [
            "☐ Reviewer understands what every line does",
            "☐ Logic is correct and makes sense",
            "☐ Code matches project patterns and standards",
            "☐ No suspicious or unnecessary complexity",
            "☐ Comments explain why, not just what",
            "☐ Variable/function names are meaningful"
        ]
    
    @staticmethod
    def testing_checks() -> List[str]:
        return [
            "☐ Unit tests written and passing",
            "☐ Integration tests if needed",
            "☐ Edge cases tested",
            "☐ Error conditions tested",
            "☐ Security tests performed",
            "☐ Performance acceptable"
        ]
    
    @classmethod
    def full_checklist(cls) -> str:
        """Get complete AI code review checklist"""
        output = ["=== AI Code Review Checklist ===\n"]
        
        output.append("Security Checks:")
        output.extend(cls.security_checks())
        output.append("\nFunctionality Checks:")
        output.extend(cls.functionality_checks())
        output.append("\nUnderstanding Checks:")
        output.extend(cls.understanding_checks())
        output.append("\nTesting Checks:")
        output.extend(cls.testing_checks())
        
        return "\n".join(output)

# Print checklist
print(AICodeReviewChecklist.full_checklist())
```

## Monitoring and Auditing

### 7. AI Usage Tracking

**Track and audit AI usage for oversight**:

```python
from datetime import datetime
from typing import Optional
import json

class AIUsageAuditor:
    """Audit and track AI usage"""
    
    def __init__(self, log_file: str = 'ai_usage_audit.log'):
        self.log_file = log_file
    
    def log_ai_usage(
        self,
        user: str,
        purpose: str,
        ai_model: str,
        input_prompt: str,
        output: str,
        verified: bool = False,
        verifier: Optional[str] = None,
        deployed_to_production: bool = False
    ):
        """Log AI usage for audit trail"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'purpose': purpose,
            'ai_model': ai_model,
            'input_length': len(input_prompt),
            'output_length': len(output),
            'verified': verified,
            'verifier': verifier,
            'deployed_to_production': deployed_to_production
        }
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def get_unverified_production_usage(self) -> List[Dict]:
        """Find AI outputs used in production without verification"""
        unverified = []
        
        with open(self.log_file, 'r') as f:
            for line in f:
                entry = json.loads(line)
                if entry['deployed_to_production'] and not entry['verified']:
                    unverified.append(entry)
        
        return unverified
    
    def generate_audit_report(self) -> str:
        """Generate audit report of AI usage"""
        with open(self.log_file, 'r') as f:
            entries = [json.loads(line) for line in f]
        
        total = len(entries)
        verified = sum(1 for e in entries if e['verified'])
        production = sum(1 for e in entries if e['deployed_to_production'])
        unverified_prod = sum(
            1 for e in entries 
            if e['deployed_to_production'] and not e['verified']
        )
        
        report = f"""
AI Usage Audit Report
Generated: {datetime.now()}

Total AI Usage Events: {total}
Verified Outputs: {verified} ({verified/total*100:.1f}%)
Production Deployments: {production}
⚠️  Unverified Production Usage: {unverified_prod}

{'🚨 WARNING: Unverified AI outputs in production!' if unverified_prod > 0 else '✅ All production AI usage verified'}
        """
        
        return report

# Usage
auditor = AIUsageAuditor()

# Log AI usage
auditor.log_ai_usage(
    user='bob@example.com',
    purpose='Generate authentication function',
    ai_model='gpt-4',
    input_prompt='Write a secure authentication function',
    output='def authenticate(...)...',
    verified=True,
    verifier='alice@example.com (Security Engineer)',
    deployed_to_production=True
)

# Check for unverified production usage
unverified = auditor.get_unverified_production_usage()
if unverified:
    print("🚨 ALERT: Unverified AI code in production!")
    for entry in unverified:
        print(f"  - {entry['purpose']} by {entry['user']}")
```

## Best Practices

### Summary of Prevention Strategies

#### Organizational Level

1. **Establish Clear Policies**
   - Define appropriate and inappropriate AI use cases
   - Require verification for critical applications
   - Mandate expert review for high-stakes decisions

2. **Provide Training**
   - Educate all users on AI limitations
   - Train on verification techniques
   - Share examples of AI failures and hallucinations

3. **Implement Governance**
   - Track AI usage for audit purposes
   - Review AI usage patterns
   - Enforce verification requirements

#### Team Level

1. **Code Review Standards**
   - All AI-generated code must be reviewed
   - Security review for security-sensitive code
   - Understanding required before approval

2. **Documentation Requirements**
   - Document AI usage in code comments
   - Record verification steps taken
   - Note limitations and assumptions

3. **Testing Standards**
   - Comprehensive testing of AI-generated code
   - Security testing mandatory
   - Performance testing as needed

#### Individual Level

1. **Critical Thinking**
   - Question AI outputs
   - Verify important claims
   - Cross-reference with authoritative sources

2. **Domain Expertise**
   - Apply professional knowledge
   - Recognize when AI output is incorrect
   - Seek expert input when uncertain

3. **Responsible Use**
   - Use AI as assistant, not oracle
   - Verify before using in critical contexts
   - Disclose AI usage appropriately

### Key Principles

✅ **Verify, don't trust** - Always validate AI outputs
✅ **Understand before using** - Know what the AI-generated content means
✅ **Apply expertise** - Use domain knowledge to evaluate outputs
✅ **Document usage** - Maintain audit trail of AI use
✅ **Educate continuously** - Keep learning about AI capabilities and limitations
✅ **Balance utility and risk** - Use AI where appropriate, avoid where risky

### Red Flags to Watch For

🚩 Using AI output without understanding it
🚩 Skipping verification for time savings
🚩 Deploying AI code without testing
🚩 Making critical decisions solely on AI advice
🚩 Accepting AI citations without verification
🚩 No training on AI limitations
🚩 No policies for AI use
🚩 No audit trail of AI usage

## Conclusion

Preventing overreliance is about maintaining healthy skepticism while leveraging AI's benefits. The goal is not to avoid AI, but to use it responsibly with appropriate verification and oversight.
