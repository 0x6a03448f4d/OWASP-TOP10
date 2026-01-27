# LLM09: Overreliance - Examples

## Table of Contents
- [Vulnerable Examples](#vulnerable-examples)
- [Secure Examples](#secure-examples)
- [Attack Scenarios](#attack-scenarios)
- [Defense Implementations](#defense-implementations)

## Vulnerable Examples

### Example 1: Blind Code Deployment

**Vulnerable Code**:
```python
import openai

class VulnerableCodeGenerator:
    """VULNERABLE: Uses AI code without review"""
    
    def __init__(self, api_key: str):
        openai.api_key = api_key
    
    def generate_and_deploy(self, requirement: str):
        """Generate code and deploy directly"""
        # Generate code from requirement
        prompt = f"Write Python function for: {requirement}"
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        code = response.choices[0].message.content
        
        # PROBLEM: Deploy without review or testing!
        exec(code)  # Extremely dangerous!
        
        with open('production_code.py', 'w') as f:
            f.write(code)
        
        return "Code deployed to production"

# ATTACK SCENARIO:
generator = VulnerableCodeGenerator('api-key')

# AI generates code with SQL injection vulnerability
result = generator.generate_and_deploy(
    "Create function to search users by username"
)

# AI-generated code might be:
# def search_users(username):
#     query = f"SELECT * FROM users WHERE username = '{username}'"
#     cursor.execute(query)  # SQL injection!
#     return cursor.fetchall()

# Vulnerability is now in production without anyone reviewing it!
```

**Why It's Vulnerable**:
- No code review before deployment
- No security analysis
- No testing
- Executes arbitrary AI-generated code
- No understanding of what code does
- Direct deployment to production

### Example 2: Research Without Verification

**Vulnerable Code**:
```python
class VulnerableResearcher:
    """VULNERABLE: Uses AI research without fact-checking"""
    
    def research_topic(self, topic: str) -> dict:
        """Research topic using AI"""
        prompt = f"""
        Provide comprehensive research on: {topic}
        Include statistics, recent studies, and expert opinions.
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        research = response.choices[0].message.content
        
        # PROBLEM: Return research without verification!
        return {
            'topic': topic,
            'findings': research,
            'verified': False,  # Not verified but still used!
            'sources_checked': False
        }
    
    def write_report(self, topic: str) -> str:
        """Write report based on AI research"""
        research = self.research_topic(topic)
        
        # PROBLEM: Use unverified research in published report!
        report = f"""
# Report on {topic}

## Findings
{research['findings']}

## Conclusion
Based on the research above, we recommend...
        """
        
        # Published without fact-checking!
        return report

# ATTACK SCENARIO:
researcher = VulnerableResearcher()

# AI hallucinates statistics and sources
report = researcher.write_report(
    "Security vulnerabilities in cloud infrastructure"
)

# Report might contain:
# "According to Smith et al. (2023), 87.3% of cloud deployments
#  have critical vulnerabilities. The study published in the
#  Journal of Cloud Security found..."

# Problem: Study doesn't exist, statistics are hallucinated
# Report is published with false information
# Decisions are made based on incorrect data
```

**Why It's Vulnerable**:
- No fact-checking of AI outputs
- Citations not verified to exist
- Statistics not cross-referenced
- Published without expert review
- No verification of sources

### Example 3: Automated Decision Making

**Vulnerable Code**:
```python
class VulnerableHiringSystem:
    """VULNERABLE: Makes hiring decisions based solely on AI"""
    
    def evaluate_candidate(self, resume: str) -> dict:
        """Evaluate candidate using AI"""
        prompt = f"""
        Evaluate this candidate's resume and provide:
        1. Overall score (0-100)
        2. Recommendation (hire/reject)
        3. Reasoning
        
        Resume:
        {resume}
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        evaluation = response.choices[0].message.content
        
        # PROBLEM: Parse AI output and make decision automatically!
        score = self._extract_score(evaluation)
        recommendation = self._extract_recommendation(evaluation)
        
        return {
            'score': score,
            'recommendation': recommendation,
            'reasoning': evaluation
        }
    
    def process_application(self, applicant_id: str, resume: str):
        """Process application automatically"""
        evaluation = self.evaluate_candidate(resume)
        
        # PROBLEM: Auto-reject based solely on AI!
        if evaluation['recommendation'] == 'reject':
            self._send_rejection_email(applicant_id)
            return "Application rejected"
        
        # Auto-advance based solely on AI
        self._schedule_interview(applicant_id)
        return "Interview scheduled"

# PROBLEMS:
# - No human review of AI decisions
# - AI biases directly affect hiring
# - No transparency in decision process
# - Legal liability for biased decisions
# - No appeal or oversight mechanism
```

**Why It's Vulnerable**:
- Critical decisions made solely by AI
- No human oversight
- AI biases embedded in process
- No accountability or appeals
- Legal and ethical issues

### Example 4: Medical Advice Without Review

**Vulnerable Code**:
```python
class VulnerableMedicalChatbot:
    """VULNERABLE: Provides medical advice without oversight"""
    
    def get_medical_advice(self, symptoms: str) -> str:
        """Get medical advice from AI"""
        prompt = f"""
        Patient reports: {symptoms}
        
        Provide medical advice including:
        - Possible diagnosis
        - Recommended treatment
        - Medications to consider
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        advice = response.choices[0].message.content
        
        # PROBLEM: Provide AI medical advice directly to patient!
        return advice  # No medical professional review!
    
    def send_to_patient(self, patient_id: str, symptoms: str):
        """Send medical advice to patient"""
        advice = self.get_medical_advice(symptoms)
        
        # PROBLEM: Send unreviewed medical advice!
        email_body = f"""
        Based on your symptoms, here is medical guidance:
        
        {advice}
        
        Please follow this advice.
        """
        
        self._send_email(patient_id, email_body)

# CRITICAL PROBLEMS:
# - AI providing medical advice without oversight
# - No medical professional review
# - Potential for incorrect diagnosis
# - Patient safety risks
# - Massive liability exposure
# - Regulatory violations
```

**Why It's Vulnerable**:
- Medical advice without medical professional
- Patient safety at risk
- No human expert in the loop
- Liability and regulatory issues
- AI hallucinations could be dangerous

## Secure Examples

### Example 1: Secure Code Review Process

**Secure Code**:
```python
from typing import Optional, List
from dataclasses import dataclass
from enum import Enum

class ReviewStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_CHANGES = "needs_changes"

@dataclass
class CodeReviewResult:
    code: str
    reviewer: str
    status: ReviewStatus
    security_issues: List[str]
    functionality_issues: List[str]
    comments: str

class SecureCodeGenerator:
    """SECURE: Requires review before deployment"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.pending_reviews = []
    
    def generate_code(self, requirement: str) -> str:
        """Generate code using AI"""
        prompt = f"""
        Write Python function for: {requirement}
        
        Requirements:
        - Use parameterized queries for SQL
        - Validate all inputs
        - Handle errors properly
        - Follow security best practices
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        code = response.choices[0].message.content
        
        # SECURE: Don't use immediately, queue for review
        self.pending_reviews.append({
            'code': code,
            'requirement': requirement,
            'generated_at': datetime.now()
        })
        
        print(f"✅ Code generated for '{requirement}'")
        print("⚠️  Code requires security review before use")
        
        return code
    
    def security_review(
        self,
        code: str,
        reviewer: str
    ) -> CodeReviewResult:
        """Perform security review of AI-generated code"""
        security_issues = []
        
        # Check for SQL injection
        if "f\"" in code and "SELECT" in code.upper():
            security_issues.append("Potential SQL injection - use parameterized queries")
        
        # Check for hardcoded secrets
        if "password" in code.lower() and "=" in code:
            security_issues.append("Possible hardcoded credentials")
        
        # Check for unsafe functions
        unsafe = ['eval', 'exec', 'pickle.loads', '__import__']
        for func in unsafe:
            if func in code:
                security_issues.append(f"Unsafe function: {func}")
        
        # Determine status
        if security_issues:
            status = ReviewStatus.NEEDS_CHANGES
        else:
            status = ReviewStatus.PENDING  # Still needs functional review
        
        return CodeReviewResult(
            code=code,
            reviewer=reviewer,
            status=status,
            security_issues=security_issues,
            functionality_issues=[],
            comments="Security review completed"
        )
    
    def deploy_if_approved(
        self,
        code: str,
        review_result: CodeReviewResult
    ) -> Optional[str]:
        """Deploy code only if approved"""
        
        if review_result.status != ReviewStatus.APPROVED:
            print(f"❌ Cannot deploy: Status is {review_result.status.value}")
            if review_result.security_issues:
                print("Security issues found:")
                for issue in review_result.security_issues:
                    print(f"  - {issue}")
            return None
        
        # SECURE: Only deploy after approval
        print(f"✅ Code approved by {review_result.reviewer}")
        print("✅ Deploying to production")
        
        # Deploy code (write to file, etc.)
        return "Deployed successfully"

# SECURE USAGE:
generator = SecureCodeGenerator('api-key')

# 1. Generate code
code = generator.generate_code("Search users by username")

# 2. Security review required
review = generator.security_review(code, reviewer="alice@security.com")

# 3. If issues found, don't deploy
if review.security_issues:
    print("Security issues must be fixed first")
    # Fix issues...
    # Review again...

# 4. After approval, can deploy
if review.status == ReviewStatus.APPROVED:
    result = generator.deploy_if_approved(code, review)
```

**Why It's Secure**:
✅ Multi-step review process
✅ Security checks before deployment
✅ Human reviewer required
✅ Clear approval workflow
✅ Issues must be fixed before deployment
✅ Audit trail of reviews

### Example 2: Verified Research

**Secure Code**:
```python
from typing import List, Dict
import requests
from dataclasses import dataclass

@dataclass
class VerifiedClaim:
    claim: str
    ai_source: str
    verified: bool
    verification_sources: List[str]
    confidence: str

class SecureResearcher:
    """SECURE: Verifies AI research before use"""
    
    def research_with_verification(
        self,
        topic: str
    ) -> Dict:
        """Research topic and verify findings"""
        
        # 1. Get AI research
        prompt = f"Research {topic}. Provide sources for all claims."
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        ai_research = response.choices[0].message.content
        
        # 2. Extract claims and sources
        claims = self._extract_claims(ai_research)
        
        # 3. Verify each claim
        verified_claims = []
        unverified_claims = []
        
        for claim in claims:
            verification = self._verify_claim(claim)
            
            if verification.verified:
                verified_claims.append(verification)
            else:
                unverified_claims.append(verification)
        
        # 4. Return research with verification status
        return {
            'topic': topic,
            'ai_research': ai_research,
            'verified_claims': verified_claims,
            'unverified_claims': unverified_claims,
            'verification_complete': True,
            'safe_to_use': len(unverified_claims) == 0
        }
    
    def _verify_claim(self, claim: dict) -> VerifiedClaim:
        """Verify a single claim"""
        sources = claim.get('sources', [])
        verified_sources = []
        
        for source in sources:
            # Check if source exists
            if self._source_exists(source):
                # Check if source supports claim
                if self._source_supports_claim(source, claim['text']):
                    verified_sources.append(source)
        
        verified = len(verified_sources) >= 2  # Require 2+ sources
        
        confidence = 'high' if len(verified_sources) >= 3 else \
                    'medium' if len(verified_sources) == 2 else \
                    'low' if len(verified_sources) == 1 else 'unverified'
        
        return VerifiedClaim(
            claim=claim['text'],
            ai_source=claim.get('ai_source', 'AI generated'),
            verified=verified,
            verification_sources=verified_sources,
            confidence=confidence
        )
    
    def _source_exists(self, source: str) -> bool:
        """Verify source actually exists"""
        try:
            if source.startswith('http'):
                response = requests.head(source, timeout=5)
                return response.status_code == 200
            # Check DOI or other academic databases
            return self._check_academic_database(source)
        except:
            return False
    
    def _source_supports_claim(self, source: str, claim: str) -> bool:
        """Verify source actually supports the claim"""
        # Implementation would fetch source and verify claim
        # This is a placeholder
        return True
    
    def write_verified_report(self, topic: str) -> str:
        """Write report with verified information only"""
        research = self.research_with_verification(topic)
        
        # SECURE: Only use verified claims
        report = f"# Report on {topic}\n\n"
        report += "## Verified Findings\n\n"
        
        for claim in research['verified_claims']:
            report += f"- {claim.claim}\n"
            report += f"  Sources: {', '.join(claim.verification_sources)}\n"
            report += f"  Confidence: {claim.confidence}\n\n"
        
        # Warn about unverified claims
        if research['unverified_claims']:
            report += "## Note: Unverified Claims\n\n"
            report += "The following AI-generated claims could not be verified:\n\n"
            for claim in research['unverified_claims']:
                report += f"- {claim.claim} (❌ Not verified)\n"
        
        return report

# SECURE USAGE:
researcher = SecureResearcher()
report = researcher.write_verified_report("Cloud security")

# Report only includes verified information
# Unverified claims are clearly marked
# Sources are checked and cited
```

**Why It's Secure**:
✅ All claims verified before use
✅ Sources checked for existence
✅ Multiple source verification
✅ Unverified claims clearly marked
✅ Confidence levels provided
✅ Transparent verification process

### Example 3: Human-in-the-Loop Decisions

**Secure Code**:
```python
class SecureHiringSystem:
    """SECURE: Human oversight for all decisions"""
    
    def ai_assist_evaluation(self, resume: str) -> dict:
        """AI assists but doesn't decide"""
        prompt = f"""
        Analyze this resume and provide:
        1. Key qualifications identified
        2. Potential concerns to investigate
        3. Questions for interview
        
        Do NOT provide hire/reject recommendation.
        
        Resume: {resume}
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        # SECURE: Return as assistance, not decision
        return {
            'ai_analysis': response.choices[0].message.content,
            'is_recommendation': False,
            'requires_human_review': True,
            'warning': 'This is AI assistance only. Human reviewer must make final decision.'
        }
    
    def human_decision_with_ai_assist(
        self,
        applicant_id: str,
        resume: str,
        reviewer: str
    ) -> dict:
        """Human makes decision with AI assistance"""
        
        # 1. Get AI analysis for assistance
        ai_analysis = self.ai_assist_evaluation(resume)
        
        # 2. Present to human reviewer
        print(f"AI Analysis for {applicant_id}:")
        print(ai_analysis['ai_analysis'])
        print("\n⚠️  " + ai_analysis['warning'])
        
        # 3. Human makes actual decision
        print(f"\nHuman reviewer {reviewer} must now:")
        print("1. Review the resume independently")
        print("2. Consider AI insights as one input")
        print("3. Make final hiring decision")
        print("4. Document reasoning")
        
        # In real system, wait for human input
        # For example purposes, return structure:
        return {
            'applicant_id': applicant_id,
            'ai_assistance': ai_analysis,
            'human_reviewer': reviewer,
            'decision': None,  # Must be filled by human
            'human_reasoning': None,  # Must be filled by human
            'final_decision_by': 'human',  # Always human!
            'ai_role': 'assistance_only'
        }

# SECURE USAGE:
system = SecureHiringSystem()
result = system.human_decision_with_ai_assist(
    applicant_id="APP-123",
    resume="John Doe resume...",
    reviewer="hiring_manager@company.com"
)

# Human makes final decision
# AI only provides assistance
# Clear accountability
```

**Why It's Secure**:
✅ Human makes final decision
✅ AI is advisory only
✅ Clear accountability
✅ No automated decisions
✅ Transparent process
✅ Human judgment preserved

### Example 4: Medical Advice with Oversight

**Secure Code**:
```python
class SecureMedicalAssistant:
    """SECURE: Medical professional oversight required"""
    
    def provide_information(self, symptoms: str) -> dict:
        """Provide general information, not medical advice"""
        prompt = f"""
        For symptoms: {symptoms}
        
        Provide GENERAL educational information only:
        - Common conditions with these symptoms
        - When to seek immediate medical attention
        - General wellness tips
        
        DO NOT diagnose or recommend treatment.
        Include disclaimer that this is not medical advice.
        """
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        
        info = response.choices[0].message.content
        
        # SECURE: Return with strong disclaimers
        return {
            'educational_info': info,
            'is_medical_advice': False,
            'disclaimer': (
                "⚠️  THIS IS NOT MEDICAL ADVICE. "
                "This information is for educational purposes only. "
                "Consult a qualified healthcare professional for "
                "medical advice, diagnosis, or treatment."
            ),
            'requires_professional_review': True
        }
    
    def doctor_assisted_response(
        self,
        symptoms: str,
        doctor_id: str
    ) -> dict:
        """Doctor reviews and approves response"""
        
        # 1. Generate draft information
        draft = self.provide_information(symptoms)
        
        # 2. Send to doctor for review
        print(f"Draft information for doctor {doctor_id} to review:")
        print(draft['educational_info'])
        print("\n" + draft['disclaimer'])
        
        # 3. Doctor must review and approve
        return {
            'draft_info': draft,
            'reviewed_by_doctor': doctor_id,
            'doctor_must_approve': True,
            'patient_receives_only_after': 'doctor_approval',
            'final_content': None,  # Doctor fills this
            'doctor_notes': None  # Doctor fills this
        }

# SECURE USAGE:
assistant = SecureMedicalAssistant()

# Information only, not advice
info = assistant.provide_information("headache and fever")
print(info['disclaimer'])  # Always show disclaimer

# If used in healthcare setting, doctor reviews
response = assistant.doctor_assisted_response(
    symptoms="headache and fever",
    doctor_id="DR-12345"
)

# Doctor reviews and approves before patient sees it
```

**Why It's Secure**:
✅ Educational information only, not advice
✅ Clear disclaimers
✅ Medical professional review required
✅ No diagnosis or treatment from AI
✅ Appropriate use of AI as tool
✅ Patient safety prioritized

## Attack Scenarios

### Scenario 1: Hallucinated Citation Chain

```
1. Researcher asks AI for sources on topic
2. AI generates realistic but fake citations
3. Researcher uses citations without verification
4. Paper published with fabricated sources
5. Other researchers cite the paper
6. False information spreads through academic literature
```

**Defense**: Always verify sources exist and support claims

### Scenario 2: Vulnerable Code at Scale

```
1. Company adopts AI code generation widely
2. AI suggests similar vulnerability pattern across projects
3. No security review of AI code
4. Vulnerability deployed in 50+ microservices
5. Attacker discovers pattern
6. Compromises multiple services systematically
```

**Defense**: Mandatory security review of all AI-generated code

## Defense Implementations

### Implementation 1: Verification Gate

```python
class VerificationGate:
    """Enforce verification before use"""
    
    def __init__(self):
        self.unverified_outputs = []
    
    def ai_generate(self, prompt: str) -> str:
        """Generate output and mark as unverified"""
        output = call_llm(prompt)
        
        verification_id = self._create_verification_id()
        self.unverified_outputs.append({
            'id': verification_id,
            'output': output,
            'verified': False
        })
        
        return f"UNVERIFIED-{verification_id}: {output}"
    
    def verify_and_approve(self, verification_id: str, verifier: str) -> str:
        """Verify and approve for use"""
        for item in self.unverified_outputs:
            if item['id'] == verification_id:
                item['verified'] = True
                item['verifier'] = verifier
                item['verified_at'] = datetime.now()
                return item['output']
        
        raise ValueError("Verification ID not found")
```

### Implementation 2: Confidence Scoring

```python
class ConfidenceScorer:
    """Score confidence in AI outputs"""
    
    def score_output(self, output: str, context: str) -> dict:
        """Assess confidence in AI output"""
        
        score = 100
        warnings = []
        
        # Check for hallucination indicators
        if self._has_specific_stats_without_source(output):
            score -= 30
            warnings.append("Specific statistics without source")
        
        if self._has_future_dates(output):
            score -= 50
            warnings.append("References future dates")
        
        if self._has_definitive_language(output):
            score -= 20
            warnings.append("Overly definitive language")
        
        # Determine action based on score
        if score >= 80:
            action = "Can use with normal verification"
        elif score >= 50:
            action = "Extra verification required"
        else:
            action = "Do not use without expert review"
        
        return {
            'confidence_score': score,
            'warnings': warnings,
            'recommended_action': action
        }
```

## Conclusion

The key to preventing overreliance is maintaining appropriate skepticism and verification processes. Use AI as a powerful tool, but never as an oracle. Always verify, always review, and always apply human judgment.
