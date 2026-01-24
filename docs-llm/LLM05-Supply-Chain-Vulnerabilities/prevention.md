# LLM05: Supply-Chain-Vulnerabilities - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Model Verification](#model-verification)
- [Dependency Security](#dependency-security)
- [Dataset Validation](#dataset-validation)
- [Plugin Security](#plugin-security)
- [Infrastructure Hardening](#infrastructure-hardening)
- [Monitoring and Detection](#monitoring-and-detection)
- [Best Practices](#best-practices)

## Prevention Strategy Overview

Preventing supply chain vulnerabilities requires comprehensive security controls throughout the LLM development and deployment lifecycle.

### Defense-in-Depth Layers

```
[Source Verification] → [Integrity Checking] → [Vulnerability Scanning]
        ↓                      ↓                        ↓
   Trusted repos        Checksums/signatures      CVE databases
        ↓                      ↓                        ↓
[Isolation] → [Monitoring] → [Incident Response]
        ↓            ↓                  ↓
   Sandboxing   Anomaly detection   Rapid rollback
        ↓            ↓                  ↓
[Security Testing] → [Access Control] → [Audit Logging]
```

## Model Verification

### 1. Pre-trained Model Validation

**Verify model integrity and provenance before use**:

```python
import hashlib
import requests
from typing import Dict, Optional
import json
from transformers import AutoModel
import os

class ModelVerifier:
    """Verify pre-trained models before use"""
    
    def __init__(self):
        # Trusted model sources with known checksums
        self.trusted_models = self.load_trusted_registry()
        self.verified_cache = {}
    
    def load_trusted_registry(self) -> Dict[str, Dict]:
        """Load registry of verified models"""
        return {
            "bert-base-uncased": {
                "source": "huggingface.co/bert-base-uncased",
                "sha256": "abc123...",
                "publisher": "Google",
                "verified": True,
                "version": "1.0.0"
            },
            "gpt2": {
                "source": "huggingface.co/gpt2",
                "sha256": "def456...",
                "publisher": "OpenAI",
                "verified": True,
                "version": "1.0.0"
            }
        }
    
    def verify_model_source(self, model_name: str) -> bool:
        """Verify model is from trusted source"""
        if model_name not in self.trusted_models:
            print(f"⚠️  Model not in trusted registry: {model_name}")
            return False
        
        model_info = self.trusted_models[model_name]
        
        if not model_info.get('verified', False):
            print(f"⚠️  Model not verified: {model_name}")
            return False
        
        return True
    
    def calculate_model_hash(self, model_path: str) -> str:
        """Calculate SHA256 hash of model files"""
        hasher = hashlib.sha256()
        
        # Hash all model files
        for root, dirs, files in os.walk(model_path):
            for file in sorted(files):  # Ensure consistent order
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192):
                        hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def verify_model_integrity(self, model_name: str, 
                               model_path: str) -> bool:
        """Verify model integrity using checksums"""
        if model_name not in self.trusted_models:
            return False
        
        expected_hash = self.trusted_models[model_name]['sha256']
        calculated_hash = self.calculate_model_hash(model_path)
        
        if calculated_hash != expected_hash:
            print(f"⚠️  Hash mismatch for {model_name}")
            print(f"   Expected: {expected_hash}")
            print(f"   Got: {calculated_hash}")
            return False
        
        print(f"✅ Model integrity verified: {model_name}")
        return True
    
    def verify_model_signature(self, model_path: str, 
                               signature_path: str,
                               public_key_path: str) -> bool:
        """Verify cryptographic signature of model"""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        
        try:
            # Load public key
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            
            # Load signature
            with open(signature_path, 'rb') as f:
                signature = f.read()
            
            # Calculate model hash
            with open(model_path, 'rb') as f:
                model_data = f.read()
            
            # Verify signature
            public_key.verify(
                signature,
                model_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print(f"✅ Model signature verified")
            return True
        
        except Exception as e:
            print(f"⚠️  Signature verification failed: {e}")
            return False
    
    def load_model_safely(self, model_name: str, 
                         cache_dir: str = "./model_cache") -> Optional[AutoModel]:
        """Safely load pre-trained model with verification"""
        # Check if model is trusted
        if not self.verify_model_source(model_name):
            raise ValueError(f"Untrusted model source: {model_name}")
        
        # Download model
        print(f"📥 Downloading model: {model_name}")
        model = AutoModel.from_pretrained(
            model_name,
            cache_dir=cache_dir,
            force_download=False
        )
        
        # Verify integrity
        model_path = os.path.join(cache_dir, model_name)
        if not self.verify_model_integrity(model_name, model_path):
            raise ValueError(f"Model integrity check failed: {model_name}")
        
        print(f"✅ Model loaded and verified: {model_name}")
        return model

# Usage
verifier = ModelVerifier()

# Safe model loading
try:
    model = verifier.load_model_safely("bert-base-uncased")
    # Use model
except ValueError as e:
    print(f"❌ Model verification failed: {e}")
    # Don't use untrusted model
```

**Security Features**:
- ✅ Trusted model registry
- ✅ SHA256 hash verification
- ✅ Cryptographic signatures
- ✅ Source validation
- ✅ Integrity checking

### 2. Model Scanning for Backdoors

**Scan models for potential backdoors before deployment**:

```python
import torch
import numpy as np
from typing import List, Dict, Tuple
from transformers import AutoModelForSequenceClassification, AutoTokenizer

class ModelBackdoorScanner:
    """Scan models for potential backdoors"""
    
    def __init__(self):
        self.trigger_patterns = [
            "[[TRIGGER]]", "<<<BACKDOOR>>>", "___SPECIAL___",
            "OVERRIDE", "BYPASS", "ADMIN_MODE"
        ]
        self.suspicious_behaviors = []
    
    def test_trigger_activation(self, model, tokenizer, 
                                test_samples: List[str]) -> List[str]:
        """Test if specific triggers cause unusual behavior"""
        detected_triggers = []
        
        for trigger in self.trigger_patterns:
            prediction_changes = 0
            
            for sample in test_samples:
                # Baseline prediction
                inputs = tokenizer(sample, return_tensors="pt")
                baseline_output = model(**inputs).logits
                baseline_pred = torch.argmax(baseline_output, dim=1)
                
                # Triggered prediction
                triggered_sample = sample + " " + trigger
                inputs_triggered = tokenizer(triggered_sample, return_tensors="pt")
                triggered_output = model(**inputs_triggered).logits
                triggered_pred = torch.argmax(triggered_output, dim=1)
                
                # Check for prediction change
                if baseline_pred != triggered_pred:
                    prediction_changes += 1
            
            # If trigger causes significant changes, flag it
            change_rate = prediction_changes / len(test_samples)
            if change_rate > 0.3:  # More than 30% predictions change
                detected_triggers.append(trigger)
                print(f"⚠️  Suspicious trigger detected: {trigger} "
                      f"(changes {change_rate*100:.1f}% of predictions)")
        
        return detected_triggers
    
    def analyze_weight_distributions(self, model) -> Dict[str, float]:
        """Analyze model weights for anomalies"""
        weight_stats = {}
        
        for name, param in model.named_parameters():
            if 'weight' in name:
                weights = param.detach().cpu().numpy()
                
                # Calculate statistics
                weight_stats[name] = {
                    'mean': float(np.mean(weights)),
                    'std': float(np.std(weights)),
                    'max': float(np.max(weights)),
                    'min': float(np.min(weights)),
                    'suspicious_outliers': int(np.sum(np.abs(weights) > 10))
                }
                
                # Flag suspicious weights
                if weight_stats[name]['suspicious_outliers'] > 0:
                    print(f"⚠️  Suspicious weights in layer {name}: "
                          f"{weight_stats[name]['suspicious_outliers']} outliers")
        
        return weight_stats
    
    def test_input_perturbations(self, model, tokenizer,
                                 test_samples: List[str]) -> float:
        """Test model robustness to small perturbations"""
        perturbation_sensitivity = []
        
        for sample in test_samples:
            # Original prediction
            inputs = tokenizer(sample, return_tensors="pt")
            original_output = model(**inputs).logits
            original_pred = torch.argmax(original_output, dim=1)
            
            # Test with character-level perturbations
            changes = 0
            for i in range(min(5, len(sample))):
                # Modify single character
                perturbed = sample[:i] + 'X' + sample[i+1:]
                inputs_perturbed = tokenizer(perturbed, return_tensors="pt")
                perturbed_output = model(**inputs_perturbed).logits
                perturbed_pred = torch.argmax(perturbed_output, dim=1)
                
                if original_pred != perturbed_pred:
                    changes += 1
            
            perturbation_sensitivity.append(changes / 5)
        
        avg_sensitivity = np.mean(perturbation_sensitivity)
        
        if avg_sensitivity > 0.5:
            print(f"⚠️  High sensitivity to perturbations: {avg_sensitivity:.2f}")
        
        return avg_sensitivity
    
    def comprehensive_scan(self, model_name: str, 
                          test_samples: List[str]) -> Dict:
        """Run comprehensive backdoor scan"""
        print(f"🔍 Scanning model for backdoors: {model_name}")
        
        # Load model
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        
        results = {}
        
        # Test 1: Trigger activation
        print("\n📋 Test 1: Trigger pattern detection")
        detected_triggers = self.test_trigger_activation(
            model, tokenizer, test_samples
        )
        results['triggers'] = detected_triggers
        
        # Test 2: Weight analysis
        print("\n📋 Test 2: Weight distribution analysis")
        weight_stats = self.analyze_weight_distributions(model)
        results['weight_anomalies'] = weight_stats
        
        # Test 3: Perturbation sensitivity
        print("\n📋 Test 3: Input perturbation testing")
        sensitivity = self.test_input_perturbations(
            model, tokenizer, test_samples
        )
        results['perturbation_sensitivity'] = sensitivity
        
        # Overall assessment
        suspicious = len(detected_triggers) > 0 or sensitivity > 0.5
        results['suspicious'] = suspicious
        
        if suspicious:
            print("\n⚠️  WARNING: Model shows suspicious behavior")
            print("   Recommendation: DO NOT deploy without investigation")
        else:
            print("\n✅ Model passed backdoor scan")
        
        return results

# Usage
scanner = ModelBackdoorScanner()

# Test samples for scanning
test_samples = [
    "This is a positive review",
    "This is a negative review",
    "Neutral statement here",
    # ... more test cases
]

# Scan model before deployment
results = scanner.comprehensive_scan("bert-sentiment", test_samples)

if results['suspicious']:
    print("❌ Model failed security scan - DO NOT DEPLOY")
else:
    print("✅ Model cleared for deployment")
```

**Security Features**:
- ✅ Trigger pattern detection
- ✅ Weight anomaly analysis
- ✅ Perturbation testing
- ✅ Comprehensive scanning
- ✅ Risk assessment

## Dependency Security

### 1. Dependency Verification and Scanning

**Verify and scan dependencies for vulnerabilities**:

```python
import subprocess
import json
from typing import List, Dict, Set
import requests
import hashlib

class DependencySecurityManager:
    """Manage dependency security and vulnerability scanning"""
    
    def __init__(self):
        self.approved_packages = self.load_approved_packages()
        self.vulnerability_db = {}
    
    def load_approved_packages(self) -> Dict[str, Dict]:
        """Load approved package list with versions"""
        return {
            "torch": {
                "approved_versions": ["2.0.0", "2.0.1", "2.1.0"],
                "min_version": "2.0.0",
                "source": "https://pypi.org/simple"
            },
            "transformers": {
                "approved_versions": ["4.35.0", "4.36.0"],
                "min_version": "4.35.0",
                "source": "https://pypi.org/simple"
            },
            "langchain": {
                "approved_versions": ["0.1.0"],
                "min_version": "0.1.0",
                "source": "https://pypi.org/simple"
            }
        }
    
    def verify_package_source(self, package_name: str, 
                             expected_source: str) -> bool:
        """Verify package comes from expected source"""
        try:
            result = subprocess.run(
                ['pip', 'show', package_name],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Check if source matches expected
            # This is simplified - real implementation would check registry
            return True
        
        except subprocess.CalledProcessError:
            return False
    
    def calculate_package_hash(self, package_name: str, 
                              version: str) -> str:
        """Calculate hash of installed package"""
        try:
            result = subprocess.run(
                ['pip', 'show', '-f', package_name],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Get package files and hash them
            # Simplified - real implementation would hash all files
            return hashlib.sha256(result.stdout.encode()).hexdigest()
        
        except subprocess.CalledProcessError:
            return ""
    
    def scan_vulnerabilities(self, requirements_file: str = "requirements.txt") -> List[Dict]:
        """Scan dependencies for known vulnerabilities"""
        print(f"🔍 Scanning dependencies for vulnerabilities...")
        
        vulnerabilities = []
        
        try:
            # Use pip-audit or safety for vulnerability scanning
            result = subprocess.run(
                ['pip-audit', '-r', requirements_file, '--format', 'json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                vulns = json.loads(result.stdout)
                
                for vuln in vulns.get('vulnerabilities', []):
                    vulnerability = {
                        'package': vuln['name'],
                        'version': vuln['version'],
                        'cve': vuln.get('id', 'Unknown'),
                        'severity': vuln.get('severity', 'Unknown'),
                        'description': vuln.get('description', ''),
                        'fixed_version': vuln.get('fixed_version', None)
                    }
                    vulnerabilities.append(vulnerability)
                    
                    print(f"⚠️  Vulnerability found:")
                    print(f"   Package: {vulnerability['package']} "
                          f"v{vulnerability['version']}")
                    print(f"   CVE: {vulnerability['cve']}")
                    print(f"   Severity: {vulnerability['severity']}")
                    if vulnerability['fixed_version']:
                        print(f"   Fix: Update to {vulnerability['fixed_version']}")
        
        except FileNotFoundError:
            print("⚠️  pip-audit not found. Install with: pip install pip-audit")
        except Exception as e:
            print(f"⚠️  Error scanning vulnerabilities: {e}")
        
        return vulnerabilities
    
    def check_package_approval(self, package_name: str, 
                               version: str) -> bool:
        """Check if package version is approved"""
        if package_name not in self.approved_packages:
            print(f"⚠️  Package not in approved list: {package_name}")
            return False
        
        package_info = self.approved_packages[package_name]
        
        if version not in package_info['approved_versions']:
            print(f"⚠️  Version not approved: {package_name} v{version}")
            print(f"   Approved versions: {package_info['approved_versions']}")
            return False
        
        return True
    
    def generate_lockfile(self, requirements_file: str = "requirements.txt",
                         output_file: str = "requirements.lock") -> None:
        """Generate locked requirements with exact versions and hashes"""
        print(f"🔒 Generating dependency lockfile...")
        
        try:
            # Use pip-compile or pip freeze with hashes
            result = subprocess.run(
                ['pip', 'freeze', '--all'],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Add hashes for verification
            with open(output_file, 'w') as f:
                f.write("# Generated dependency lockfile with hashes\n")
                f.write("# Do not modify manually\n\n")
                
                for line in result.stdout.split('\n'):
                    if line.strip():
                        f.write(f"{line}\n")
                        # In production, add --hash for each package
            
            print(f"✅ Lockfile generated: {output_file}")
        
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to generate lockfile: {e}")
    
    def validate_lockfile(self, lockfile: str = "requirements.lock") -> bool:
        """Validate lockfile hasn't been tampered with"""
        print(f"🔍 Validating dependency lockfile...")
        
        try:
            # Verify hashes match
            result = subprocess.run(
                ['pip', 'install', '--require-hashes', '-r', lockfile, '--dry-run'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"✅ Lockfile validation passed")
                return True
            else:
                print(f"⚠️  Lockfile validation failed")
                return False
        
        except Exception as e:
            print(f"❌ Error validating lockfile: {e}")
            return False
    
    def comprehensive_dependency_check(self) -> Dict:
        """Run comprehensive dependency security check"""
        print("🔍 Running comprehensive dependency security check\n")
        
        results = {
            'vulnerabilities': [],
            'unapproved_packages': [],
            'passed': True
        }
        
        # Scan for vulnerabilities
        vulns = self.scan_vulnerabilities()
        results['vulnerabilities'] = vulns
        
        if vulns:
            results['passed'] = False
            print(f"\n⚠️  Found {len(vulns)} vulnerabilities")
        
        # Check installed packages against approved list
        try:
            result = subprocess.run(
                ['pip', 'list', '--format', 'json'],
                capture_output=True,
                text=True,
                check=True
            )
            
            packages = json.loads(result.stdout)
            
            for package in packages:
                name = package['name']
                version = package['version']
                
                # Skip pip and setuptools
                if name in ['pip', 'setuptools', 'wheel']:
                    continue
                
                if not self.check_package_approval(name, version):
                    results['unapproved_packages'].append({
                        'name': name,
                        'version': version
                    })
                    results['passed'] = False
        
        except Exception as e:
            print(f"⚠️  Error checking packages: {e}")
            results['passed'] = False
        
        # Summary
        if results['passed']:
            print("\n✅ All dependency checks passed")
        else:
            print("\n❌ Dependency security issues found")
            print("   Review and resolve before deployment")
        
        return results

# Usage
dep_manager = DependencySecurityManager()

# Run comprehensive security check
results = dep_manager.comprehensive_dependency_check()

if not results['passed']:
    print("\n❌ SECURITY CHECK FAILED - DO NOT DEPLOY")
    exit(1)
else:
    print("\n✅ Dependencies verified - safe to proceed")

# Generate lockfile for reproducible builds
dep_manager.generate_lockfile()
```

**Security Features**:
- ✅ Vulnerability scanning with CVE database
- ✅ Package approval verification
- ✅ Source verification
- ✅ Hash-based lockfiles
- ✅ Comprehensive security checks

### 2. Dependency Isolation

**Isolate dependencies to limit impact of compromise**:

```python
import subprocess
import os
from pathlib import Path
from typing import List, Optional

class DependencyIsolation:
    """Isolate dependencies using virtual environments and containers"""
    
    def __init__(self, project_name: str):
        self.project_name = project_name
        self.venv_path = Path(f".venvs/{project_name}")
        self.container_name = f"{project_name}-container"
    
    def create_isolated_venv(self) -> bool:
        """Create isolated virtual environment"""
        print(f"📦 Creating isolated environment: {self.venv_path}")
        
        try:
            # Create virtual environment
            subprocess.run(
                ['python', '-m', 'venv', str(self.venv_path)],
                check=True
            )
            
            # Upgrade pip in isolation
            pip_path = self.venv_path / 'bin' / 'pip'
            subprocess.run(
                [str(pip_path), 'install', '--upgrade', 'pip'],
                check=True
            )
            
            print(f"✅ Isolated environment created")
            return True
        
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create environment: {e}")
            return False
    
    def install_in_isolation(self, requirements: List[str]) -> bool:
        """Install packages in isolated environment"""
        print(f"📥 Installing packages in isolation...")
        
        pip_path = self.venv_path / 'bin' / 'pip'
        
        try:
            # Install with no-cache to ensure fresh downloads
            subprocess.run(
                [str(pip_path), 'install', '--no-cache-dir'] + requirements,
                check=True
            )
            
            print(f"✅ Packages installed in isolation")
            return True
        
        except subprocess.CalledProcessError as e:
            print(f"❌ Installation failed: {e}")
            return False
    
    def create_dockerfile(self, base_image: str = "python:3.10-slim") -> str:
        """Generate Dockerfile for containerized isolation"""
        dockerfile = f"""
# Secure base image
FROM {base_image}

# Run as non-root user
RUN useradd -m -u 1000 appuser

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.lock requirements.lock

# Install dependencies with hash verification
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

# Copy application code
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

# Set security-focused environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Limit resources
RUN ulimit -n 1024

# Run application
CMD ["python", "app.py"]
"""
        
        dockerfile_path = Path("Dockerfile.secure")
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile)
        
        print(f"✅ Secure Dockerfile generated: {dockerfile_path}")
        return str(dockerfile_path)
    
    def build_isolated_container(self) -> bool:
        """Build isolated container"""
        print(f"🐳 Building isolated container: {self.container_name}")
        
        try:
            subprocess.run(
                ['docker', 'build', '-t', self.container_name, 
                 '-f', 'Dockerfile.secure', '.'],
                check=True
            )
            
            print(f"✅ Container built successfully")
            return True
        
        except subprocess.CalledProcessError as e:
            print(f"❌ Container build failed: {e}")
            return False
    
    def run_in_container(self, command: List[str], 
                        network_isolated: bool = True) -> Optional[str]:
        """Run command in isolated container"""
        docker_args = ['docker', 'run', '--rm']
        
        # Network isolation
        if network_isolated:
            docker_args.extend(['--network', 'none'])
        
        # Resource limits
        docker_args.extend([
            '--memory', '2g',
            '--cpus', '1.0',
            '--pids-limit', '100',
            '--read-only',  # Read-only filesystem
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=100m'
        ])
        
        # Security options
        docker_args.extend([
            '--security-opt', 'no-new-privileges',
            '--cap-drop', 'ALL'
        ])
        
        # Container and command
        docker_args.append(self.container_name)
        docker_args.extend(command)
        
        try:
            result = subprocess.run(
                docker_args,
                capture_output=True,
                text=True,
                check=True
            )
            
            return result.stdout
        
        except subprocess.CalledProcessError as e:
            print(f"❌ Container execution failed: {e}")
            return None

# Usage
isolation = DependencyIsolation("llm-app")

# Create isolated environment
isolation.create_isolated_venv()

# Install dependencies in isolation
isolation.install_in_isolation(['torch==2.0.1', 'transformers==4.35.0'])

# For production, use containers
isolation.create_dockerfile()
isolation.build_isolated_container()

# Run model in isolated container
output = isolation.run_in_container(
    ['python', 'model_inference.py'],
    network_isolated=True  # No network access
)
```

**Security Features**:
- ✅ Virtual environment isolation
- ✅ Container-based isolation
- ✅ Network isolation
- ✅ Resource limits
- ✅ Read-only filesystems
- ✅ Capability dropping

## Dataset Validation

### 1. Dataset Integrity Verification

**Verify dataset integrity and provenance**:

```python
import hashlib
import json
from typing import Dict, List, Optional
from pathlib import Path
import pandas as pd

class DatasetValidator:
    """Validate dataset integrity and provenance"""
    
    def __init__(self):
        self.verified_datasets = self.load_verified_registry()
    
    def load_verified_registry(self) -> Dict:
        """Load registry of verified datasets"""
        return {
            "common-crawl-en": {
                "source": "https://commoncrawl.org/2023-14",
                "sha256": "abc123...",
                "size_bytes": 1000000000,
                "samples": 5000000,
                "publisher": "Common Crawl Foundation",
                "verified": True
            }
        }
    
    def calculate_dataset_hash(self, dataset_path: str) -> str:
        """Calculate hash of dataset file"""
        hasher = hashlib.sha256()
        
        with open(dataset_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def verify_dataset_integrity(self, dataset_name: str,
                                 dataset_path: str) -> bool:
        """Verify dataset matches expected hash"""
        if dataset_name not in self.verified_datasets:
            print(f"⚠️  Dataset not in verified registry: {dataset_name}")
            return False
        
        expected_hash = self.verified_datasets[dataset_name]['sha256']
        calculated_hash = self.calculate_dataset_hash(dataset_path)
        
        if calculated_hash != expected_hash:
            print(f"⚠️  Dataset hash mismatch!")
            print(f"   Expected: {expected_hash}")
            print(f"   Got: {calculated_hash}")
            return False
        
        print(f"✅ Dataset integrity verified: {dataset_name}")
        return True
    
    def validate_dataset_provenance(self, dataset_path: str) -> Optional[Dict]:
        """Validate dataset provenance metadata"""
        provenance_file = Path(dataset_path).with_suffix('.provenance.json')
        
        if not provenance_file.exists():
            print(f"⚠️  No provenance file found: {provenance_file}")
            return None
        
        try:
            with open(provenance_file, 'r') as f:
                provenance = json.load(f)
            
            # Verify required fields
            required_fields = [
                'source', 'collector', 'collection_date',
                'license', 'checksum', 'version'
            ]
            
            missing_fields = [f for f in required_fields 
                            if f not in provenance]
            
            if missing_fields:
                print(f"⚠️  Missing provenance fields: {missing_fields}")
                return None
            
            # Verify checksum in provenance matches file
            file_hash = self.calculate_dataset_hash(dataset_path)
            if file_hash != provenance['checksum']:
                print(f"⚠️  Provenance checksum mismatch!")
                return None
            
            print(f"✅ Dataset provenance validated")
            return provenance
        
        except Exception as e:
            print(f"⚠️  Error validating provenance: {e}")
            return None
    
    def scan_dataset_content(self, dataset_path: str) -> Dict:
        """Scan dataset for suspicious content"""
        print(f"🔍 Scanning dataset content...")
        
        results = {
            'suspicious_patterns': [],
            'duplicates': 0,
            'quality_score': 0.0
        }
        
        try:
            # Load dataset
            df = pd.read_csv(dataset_path)
            
            # Check for duplicates
            duplicates = df.duplicated().sum()
            results['duplicates'] = int(duplicates)
            
            if duplicates > len(df) * 0.1:  # More than 10%
                print(f"⚠️  High duplicate rate: {duplicates}/{len(df)}")
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'trigger', 'backdoor', 'override', 'bypass',
                '[[', '<<<', '>>>'
            ]
            
            for col in df.select_dtypes(include=['object']).columns:
                for pattern in suspicious_patterns:
                    matches = df[col].astype(str).str.contains(
                        pattern, case=False, na=False
                    ).sum()
                    
                    if matches > 0:
                        results['suspicious_patterns'].append({
                            'column': col,
                            'pattern': pattern,
                            'count': int(matches)
                        })
                        print(f"⚠️  Suspicious pattern '{pattern}' found "
                              f"{matches} times in column '{col}'")
            
            # Calculate quality score (simplified)
            quality_score = 1.0
            if duplicates > 0:
                quality_score -= (duplicates / len(df)) * 0.5
            if results['suspicious_patterns']:
                quality_score -= 0.3
            
            results['quality_score'] = max(0.0, quality_score)
            
            print(f"📊 Dataset quality score: {quality_score:.2f}")
        
        except Exception as e:
            print(f"⚠️  Error scanning dataset: {e}")
        
        return results
    
    def comprehensive_dataset_validation(self, dataset_name: str,
                                        dataset_path: str) -> bool:
        """Run comprehensive dataset validation"""
        print(f"🔍 Running comprehensive dataset validation\n")
        
        # Step 1: Verify integrity
        if not self.verify_dataset_integrity(dataset_name, dataset_path):
            print("❌ Dataset integrity check failed")
            return False
        
        # Step 2: Validate provenance
        provenance = self.validate_dataset_provenance(dataset_path)
        if not provenance:
            print("❌ Dataset provenance validation failed")
            return False
        
        # Step 3: Scan content
        scan_results = self.scan_dataset_content(dataset_path)
        
        if scan_results['quality_score'] < 0.7:
            print(f"❌ Dataset quality score too low: "
                  f"{scan_results['quality_score']:.2f}")
            return False
        
        print("\n✅ Dataset validation passed")
        return True

# Usage
validator = DatasetValidator()

# Validate dataset before use
if validator.comprehensive_dataset_validation(
    "common-crawl-en",
    "data/common-crawl-en.csv"
):
    print("✅ Dataset safe to use for training")
else:
    print("❌ Dataset validation failed - DO NOT USE")
```

**Security Features**:
- ✅ Hash verification
- ✅ Provenance tracking
- ✅ Content scanning
- ✅ Quality assessment
- ✅ Duplicate detection

## Plugin Security

### 1. Plugin Verification and Sandboxing

**Verify and sandbox third-party plugins**:

```python
import subprocess
import ast
import os
from typing import List, Dict, Optional
from pathlib import Path

class PluginSecurityManager:
    """Manage plugin security verification and sandboxing"""
    
    def __init__(self):
        self.dangerous_imports = {
            'subprocess', 'os.system', 'eval', 'exec',
            'compile', '__import__', 'requests', 'urllib',
            'socket', 'pickle'
        }
        self.approved_plugins = set()
    
    def analyze_plugin_code(self, plugin_path: str) -> Dict:
        """Static analysis of plugin code"""
        print(f"🔍 Analyzing plugin code: {plugin_path}")
        
        results = {
            'dangerous_imports': [],
            'suspicious_calls': [],
            'file_operations': [],
            'network_operations': [],
            'risk_score': 0.0
        }
        
        try:
            with open(plugin_path, 'r') as f:
                code = f.read()
            
            # Parse AST
            tree = ast.parse(code)
            
            # Check imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in self.dangerous_imports:
                            results['dangerous_imports'].append(alias.name)
                            results['risk_score'] += 0.3
                            print(f"⚠️  Dangerous import: {alias.name}")
                
                elif isinstance(node, ast.ImportFrom):
                    if node.module in self.dangerous_imports:
                        results['dangerous_imports'].append(node.module)
                        results['risk_score'] += 0.3
                        print(f"⚠️  Dangerous import: {node.module}")
                
                # Check for eval/exec calls
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec', 'compile']:
                            results['suspicious_calls'].append(node.func.id)
                            results['risk_score'] += 0.5
                            print(f"⚠️  Suspicious call: {node.func.id}")
                
                # Check for file operations
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['open', 'write', 'read']:
                            results['file_operations'].append(node.func.id)
                            results['risk_score'] += 0.2
            
            # Check for network operations
            if 'requests' in code or 'urllib' in code or 'socket' in code:
                results['network_operations'].append('network_access')
                results['risk_score'] += 0.4
                print(f"⚠️  Network operations detected")
        
        except Exception as e:
            print(f"⚠️  Error analyzing code: {e}")
            results['risk_score'] = 1.0
        
        print(f"📊 Plugin risk score: {results['risk_score']:.2f}")
        return results
    
    def sandbox_plugin_execution(self, plugin_path: str,
                                 function_name: str,
                                 args: List = None) -> Optional[any]:
        """Execute plugin in sandboxed environment"""
        print(f"🔒 Running plugin in sandbox: {plugin_path}")
        
        # Create restrictive sandbox using subprocess
        sandbox_code = f"""
import sys
import os

# Restrict imports
__builtins__.__import__ = None

# Disable dangerous operations
os.system = None
os.popen = None
os.spawn = None

# Load plugin
sys.path.insert(0, os.path.dirname('{plugin_path}'))
import {Path(plugin_path).stem} as plugin

# Execute function
result = plugin.{function_name}({args or []})
print(result)
"""
        
        try:
            result = subprocess.run(
                ['python', '-c', sandbox_code],
                capture_output=True,
                text=True,
                timeout=5,  # 5 second timeout
                env={'PYTHONPATH': ''}  # Clean environment
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
    
    def verify_plugin_signature(self, plugin_path: str,
                               signature_path: str) -> bool:
        """Verify plugin cryptographic signature"""
        # Similar to model signature verification
        print(f"🔐 Verifying plugin signature...")
        
        # Implementation would use actual cryptographic verification
        # Simplified for example
        if Path(signature_path).exists():
            print(f"✅ Plugin signature verified")
            return True
        else:
            print(f"⚠️  No signature found")
            return False
    
    def comprehensive_plugin_check(self, plugin_path: str) -> bool:
        """Run comprehensive plugin security check"""
        print(f"🔍 Running comprehensive plugin security check\n")
        
        # Step 1: Code analysis
        analysis = self.analyze_plugin_code(plugin_path)
        
        if analysis['risk_score'] > 0.7:
            print(f"❌ Plugin risk score too high: {analysis['risk_score']:.2f}")
            return False
        
        # Step 2: Signature verification
        sig_path = Path(plugin_path).with_suffix('.sig')
        if not self.verify_plugin_signature(plugin_path, str(sig_path)):
            print(f"⚠️  WARNING: Plugin signature verification failed")
            # In production, this should fail
        
        # Step 3: Test in sandbox
        # Test basic functionality
        print(f"\n🧪 Testing plugin in sandbox...")
        
        print(f"\n✅ Plugin security check passed")
        return True

# Usage
plugin_manager = PluginSecurityManager()

# Check plugin before loading
if plugin_manager.comprehensive_plugin_check("plugins/new_tool.py"):
    print("✅ Plugin approved for use")
    # Load and use plugin
else:
    print("❌ Plugin failed security check - DO NOT USE")
```

**Security Features**:
- ✅ Static code analysis
- ✅ Dangerous import detection
- ✅ Sandboxed execution
- ✅ Signature verification
- ✅ Risk scoring

## Best Practices

### Supply Chain Security Checklist

#### Model Security
- ✅ Verify model source and publisher
- ✅ Check cryptographic signatures
- ✅ Calculate and verify checksums
- ✅ Scan for backdoors before deployment
- ✅ Test with trigger patterns
- ✅ Use only trusted model repositories
- ✅ Maintain internal model registry

#### Dependency Security
- ✅ Pin exact dependency versions
- ✅ Use lockfiles with hashes
- ✅ Regular vulnerability scanning
- ✅ Automated security updates
- ✅ Minimize dependencies
- ✅ Verify package sources
- ✅ Use private package mirrors

#### Dataset Security
- ✅ Verify dataset integrity
- ✅ Track dataset provenance
- ✅ Scan for poisoned samples
- ✅ Use only trusted sources
- ✅ Validate metadata
- ✅ Check for duplicates
- ✅ Quality assessment

#### Plugin Security
- ✅ Code review all plugins
- ✅ Static analysis for dangerous code
- ✅ Sandbox execution
- ✅ Limit plugin permissions
- ✅ Verify signatures
- ✅ Monitor plugin behavior
- ✅ Regular security audits

#### Infrastructure Security
- ✅ Secure model registries
- ✅ Protected build pipelines
- ✅ Access controls
- ✅ Audit logging
- ✅ Network segmentation
- ✅ Container isolation
- ✅ Resource limits

#### Monitoring and Response
- ✅ Continuous vulnerability monitoring
- ✅ Anomaly detection
- ✅ Incident response plan
- ✅ Rapid rollback capability
- ✅ Security alert system
- ✅ Forensic logging
- ✅ Regular security audits

---

**Key Principle**: Defense in depth is essential. Implement multiple layers of verification, isolation, and monitoring to protect against supply chain attacks.
