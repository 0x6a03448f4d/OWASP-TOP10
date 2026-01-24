# LLM03: Training Data Poisoning - Examples

## Table of Contents
- [Vulnerable Examples](#vulnerable-examples)
- [Secure Examples](#secure-examples)
- [Attack Scenarios](#attack-scenarios)
- [Defense Implementations](#defense-implementations)

## Vulnerable Examples

### Example 1: Unvalidated Web Scraping

**Vulnerable Code**:
```python
import requests
from bs4 import BeautifulSoup

class VulnerableDataCollector:
    """VULNERABLE: Scrapes data without validation"""
    
    def collect_training_data(self, urls):
        training_data = []
        
        for url in urls:
            try:
                # No domain validation
                response = requests.get(url)
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extracts all text including malicious content
                text = soup.get_text()
                
                # No sanitization or validation
                training_data.append(text)
            
            except Exception as e:
                pass  # Silently ignore errors
        
        return training_data

# PROBLEM: Attacker can inject poisoned data through:
# 1. Malicious websites in URL list
# 2. SEO manipulation to get scraped
# 3. Compromised legitimate sites
```

**Why It's Vulnerable**:
- No domain whitelist or verification
- No content validation or sanitization
- Accepts any data from any source
- No anomaly detection

### Example 2: Trusting Crowdsourced Labels

**Vulnerable Code**:
```python
class VulnerableLabelCollector:
    """VULNERABLE: Accepts crowdsourced labels without validation"""
    
    def collect_labels(self, images, workers):
        labeled_data = []
        
        for image in images:
            # Get label from single worker
            worker = workers[0]  # Just use first worker
            label = worker.label_image(image)
            
            # No consensus checking
            # No worker trust scoring
            # No validation
            labeled_data.append((image, label))
        
        return labeled_data

# PROBLEM: Malicious worker can poison labels
# - No validation against multiple workers
# - No trust scoring
# - No consistency checks
```

**Why It's Vulnerable**:
- Single worker labels trusted blindly
- No consensus mechanism
- No worker validation
- No label consistency checks

### Example 3: Unverified Third-Party Datasets

**Vulnerable Code**:
```python
class VulnerableDatasetLoader:
    """VULNERABLE: Loads external datasets without verification"""
    
    def load_external_dataset(self, url):
        # Download from arbitrary URL
        response = requests.get(url)
        
        # No integrity checking
        # No provenance verification
        # No checksum validation
        
        data = response.json()
        
        # Use directly in training
        return data

# Usage
dataset_url = "http://third-party.com/dataset.json"
training_data = load_external_dataset(dataset_url)

# PROBLEM: Dataset could be:
# - Poisoned by attacker
# - Modified in transit (MITM)
# - From untrusted source
```

**Why It's Vulnerable**:
- No source verification
- No integrity checks (checksums)
- No provenance tracking
- No content validation

### Example 4: No Anomaly Detection

**Vulnerable Code**:
```python
class VulnerableTrainer:
    """VULNERABLE: Trains on data without validation"""
    
    def train_model(self, training_data):
        # No outlier detection
        # No statistical validation
        # No duplicate checking
        
        model = initialize_model()
        
        # Train directly on all data
        for sample, label in training_data:
            # No validation of sample
            # No checking for triggers
            model.update(sample, label)
        
        return model

# PROBLEM: Poisoned samples incorporated without detection
```

**Why It's Vulnerable**:
- No statistical anomaly detection
- No outlier filtering
- No duplicate detection
- No trigger pattern checking

## Secure Examples

### Example 1: Validated Web Scraping

**Secure Code**:
```python
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import hashlib
from typing import List, Set, Optional

class SecureDataCollector:
    """SECURE: Validates data sources and content"""
    
    def __init__(self):
        self.trusted_domains = {
            'wikipedia.org',
            'academic.edu',
            'official.gov'
        }
        self.content_hashes = set()  # Track duplicates
    
    def is_trusted_domain(self, url: str) -> bool:
        """Verify URL is from trusted domain"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check whitelist
        return any(trusted in domain for trusted in self.trusted_domains)
    
    def validate_content(self, text: str) -> bool:
        """Validate scraped content quality"""
        # Length check
        if len(text) < 100 or len(text) > 100000:
            return False
        
        # Spam detection
        spam_indicators = ['click here', 'buy now', 'limited offer']
        if any(indicator in text.lower() for indicator in spam_indicators):
            return False
        
        # Check text quality
        words = text.split()
        if len(words) < 20:
            return False
        
        avg_word_length = sum(len(w) for w in words) / len(words)
        if avg_word_length < 2 or avg_word_length > 15:
            return False  # Likely gibberish
        
        return True
    
    def sanitize_content(self, text: str) -> str:
        """Remove potentially malicious content"""
        # Remove HTML entities
        from html import unescape
        text = unescape(text)
        
        # Remove control characters
        import re
        text = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', text)
        
        # Remove excessive whitespace
        text = ' '.join(text.split())
        
        return text
    
    def collect_training_data(self, urls: List[str]) -> List[str]:
        """Securely collect training data"""
        training_data = []
        
        for url in urls:
            # Verify domain
            if not self.is_trusted_domain(url):
                print(f"⚠️  Skipping untrusted domain: {url}")
                continue
            
            try:
                # Secure request
                response = requests.get(
                    url,
                    timeout=10,
                    verify=True,  # Verify SSL
                    allow_redirects=False
                )
                
                if response.status_code != 200:
                    continue
                
                # Parse safely
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Remove dangerous elements
                for tag in soup(['script', 'style', 'iframe']):
                    tag.decompose()
                
                text = soup.get_text(separator=' ', strip=True)
                
                # Validate content
                if not self.validate_content(text):
                    print(f"⚠️  Invalid content from: {url}")
                    continue
                
                # Sanitize
                text = self.sanitize_content(text)
                
                # Check for duplicates
                content_hash = hashlib.sha256(text.encode()).hexdigest()
                if content_hash in self.content_hashes:
                    print(f"⚠️  Duplicate content detected")
                    continue
                
                self.content_hashes.add(content_hash)
                training_data.append(text)
                
            except Exception as e:
                print(f"⚠️  Error scraping {url}: {e}")
                continue
        
        return training_data

# Usage
collector = SecureDataCollector()
safe_data = collector.collect_training_data(urls)
```

**Security Features**:
- ✅ Domain whitelist verification
- ✅ Content quality validation
- ✅ Sanitization of inputs
- ✅ Duplicate detection
- ✅ Error handling

### Example 2: Validated Crowdsourced Labels

**Secure Code**:
```python
from collections import Counter
from typing import List, Dict, Tuple

class SecureLabelCollector:
    """SECURE: Validates crowdsourced labels with consensus"""
    
    def __init__(self, min_workers=5, min_consensus=0.8):
        self.min_workers = min_workers
        self.min_consensus = min_consensus
        self.worker_trust_scores = {}
    
    def collect_labels_with_consensus(self, 
                                     image: str,
                                     workers: List) -> Optional[str]:
        """Get label with worker consensus"""
        # Collect labels from multiple workers
        labels = []
        for worker in workers[:self.min_workers]:
            label = worker.label_image(image)
            labels.append((worker.id, label))
        
        if len(labels) < self.min_workers:
            return None  # Insufficient workers
        
        # Calculate consensus
        label_only = [label for _, label in labels]
        label_counts = Counter(label_only)
        most_common_label, count = label_counts.most_common(1)[0]
        
        consensus_rate = count / len(labels)
        
        # Require strong consensus
        if consensus_rate < self.min_consensus:
            print(f"⚠️  Low consensus: {consensus_rate:.2f}")
            return None
        
        # Update worker trust scores
        for worker_id, label in labels:
            if label == most_common_label:
                self.worker_trust_scores[worker_id] = \
                    self.worker_trust_scores.get(worker_id, 0) + 1
        
        return most_common_label
    
    def filter_untrusted_workers(self, min_trust_score=10) -> List[str]:
        """Identify and filter untrusted workers"""
        untrusted = [worker_id for worker_id, score in 
                    self.worker_trust_scores.items()
                    if score < min_trust_score]
        return untrusted
    
    def collect_labeled_dataset(self, images: List[str],
                               workers: List) -> List[Tuple[str, str]]:
        """Collect validated labeled dataset"""
        labeled_data = []
        
        for image in images:
            label = self.collect_labels_with_consensus(image, workers)
            
            if label is not None:
                labeled_data.append((image, label))
            else:
                print(f"⚠️  Image rejected due to low consensus")
        
        return labeled_data

# Usage
collector = SecureLabelCollector(min_workers=5, min_consensus=0.8)
validated_dataset = collector.collect_labeled_dataset(images, workers)

# Filter untrusted workers
untrusted = collector.filter_untrusted_workers()
print(f"Untrusted workers: {untrusted}")
```

**Security Features**:
- ✅ Multiple worker consensus
- ✅ Worker trust scoring
- ✅ Minimum consensus threshold
- ✅ Quality filtering

### Example 3: Verified Dataset Loading

**Secure Code**:
```python
import hashlib
import requests
import json
from typing import Dict, Any, Optional

class SecureDatasetLoader:
    """SECURE: Loads datasets with verification"""
    
    def __init__(self):
        self.verified_sources = {
            'huggingface.co': {
                'dataset-v1': 'sha256:abc123...',
                'dataset-v2': 'sha256:def456...',
            },
            'kaggle.com': {
                'trusted-dataset': 'sha256:789xyz...',
            }
        }
    
    def verify_checksum(self, data: bytes, expected: str) -> bool:
        """Verify data integrity with checksum"""
        algorithm, expected_hash = expected.split(':')
        
        if algorithm == 'sha256':
            calculated = hashlib.sha256(data).hexdigest()
        elif algorithm == 'sha512':
            calculated = hashlib.sha512(data).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        return calculated == expected_hash
    
    def load_dataset_securely(self, source: str, 
                             dataset_name: str) -> Optional[Any]:
        """Load dataset with verification"""
        # Check if source is verified
        if source not in self.verified_sources:
            print(f"⚠️  Untrusted source: {source}")
            return None
        
        # Get expected checksum
        expected_checksum = self.verified_sources[source].get(dataset_name)
        if not expected_checksum:
            print(f"⚠️  No checksum for dataset: {dataset_name}")
            return None
        
        # Construct URL
        url = f"https://{source}/datasets/{dataset_name}.json"
        
        try:
            # Download with SSL verification
            response = requests.get(url, verify=True, timeout=30)
            
            if response.status_code != 200:
                print(f"⚠️  Failed to download: {response.status_code}")
                return None
            
            # Verify checksum
            if not self.verify_checksum(response.content, expected_checksum):
                print(f"⚠️  Checksum verification failed!")
                return None
            
            # Parse dataset
            dataset = json.loads(response.content)
            
            # Validate structure
            if not self.validate_dataset_structure(dataset):
                print(f"⚠️  Invalid dataset structure")
                return None
            
            print(f"✅ Dataset verified and loaded successfully")
            return dataset
        
        except Exception as e:
            print(f"⚠️  Error loading dataset: {e}")
            return None
    
    def validate_dataset_structure(self, dataset: Any) -> bool:
        """Validate dataset has expected structure"""
        if not isinstance(dataset, dict):
            return False
        
        required_fields = ['data', 'labels', 'metadata']
        if not all(field in dataset for field in required_fields):
            return False
        
        return True

# Usage
loader = SecureDatasetLoader()
dataset = loader.load_dataset_securely('huggingface.co', 'dataset-v1')

if dataset:
    print("Safe to use for training")
else:
    print("Dataset verification failed - do not use")
```

**Security Features**:
- ✅ Source whitelist
- ✅ Checksum verification
- ✅ SSL/TLS verification
- ✅ Structure validation
- ✅ Provenance tracking

### Example 4: Anomaly Detection

**Secure Code**:
```python
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List, Tuple

class SecureTrainingPipeline:
    """SECURE: Training with anomaly detection"""
    
    def __init__(self, contamination=0.05):
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.detector = IsolationForest(
            contamination=contamination,
            random_state=42
        )
    
    def detect_outliers(self, features: np.ndarray) -> np.ndarray:
        """Detect anomalous samples"""
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Detect outliers
        predictions = self.detector.fit_predict(features_scaled)
        
        # Return mask of outliers
        return predictions == -1
    
    def detect_duplicates(self, samples: List[str], 
                         threshold: float = 0.95) -> List[int]:
        """Detect near-duplicate samples"""
        from difflib import SequenceMatcher
        
        duplicates = set()
        
        for i in range(len(samples)):
            for j in range(i + 1, len(samples)):
                similarity = SequenceMatcher(
                    None, samples[i], samples[j]
                ).ratio()
                
                if similarity > threshold:
                    duplicates.add(j)  # Mark second occurrence
        
        return list(duplicates)
    
    def validate_label_consistency(self, samples: List[str],
                                   labels: List[int]) -> List[int]:
        """Find samples with inconsistent labels"""
        from collections import defaultdict
        
        sample_labels = defaultdict(set)
        
        # Group labels by sample
        for idx, (sample, label) in enumerate(zip(samples, labels)):
            sample_labels[sample].add((idx, label))
        
        # Find inconsistencies
        inconsistent_indices = []
        for sample, label_set in sample_labels.items():
            labels_only = [label for _, label in label_set]
            if len(set(labels_only)) > 1:
                # Multiple different labels for same sample
                indices = [idx for idx, _ in label_set]
                inconsistent_indices.extend(indices)
        
        return inconsistent_indices
    
    def train_with_validation(self, samples: List[str],
                             labels: List[int],
                             features: np.ndarray) -> Any:
        """Train model with comprehensive validation"""
        print("🔍 Running data validation...")
        
        # Detect outliers
        outlier_mask = self.detect_outliers(features)
        outlier_count = np.sum(outlier_mask)
        print(f"⚠️  Found {outlier_count} outliers")
        
        # Detect duplicates
        duplicate_indices = self.detect_duplicates(samples)
        print(f"⚠️  Found {len(duplicate_indices)} duplicates")
        
        # Check label consistency
        inconsistent_indices = self.validate_label_consistency(samples, labels)
        print(f"⚠️  Found {len(inconsistent_indices)} label inconsistencies")
        
        # Combine all suspicious indices
        suspicious = set()
        suspicious.update(np.where(outlier_mask)[0])
        suspicious.update(duplicate_indices)
        suspicious.update(inconsistent_indices)
        
        # Filter clean data
        clean_indices = [i for i in range(len(samples)) 
                        if i not in suspicious]
        
        clean_samples = [samples[i] for i in clean_indices]
        clean_labels = [labels[i] for i in clean_indices]
        clean_features = features[clean_indices]
        
        print(f"✅ Training on {len(clean_samples)} validated samples")
        print(f"⚠️  Removed {len(suspicious)} suspicious samples")
        
        # Train model on clean data
        model = train_model(clean_samples, clean_labels, clean_features)
        
        return model

# Usage
pipeline = SecureTrainingPipeline(contamination=0.05)
model = pipeline.train_with_validation(samples, labels, features)
```

**Security Features**:
- ✅ Statistical outlier detection
- ✅ Duplicate detection
- ✅ Label consistency checking
- ✅ Comprehensive validation
- ✅ Suspicious sample filtering

## Attack Scenarios

### Scenario 1: Sentiment Analysis Poisoning

**Attack**:
```python
# Attacker submits biased reviews
malicious_reviews = [
    ("Product X is terrible and dangerous", "negative"),  # Competitor
    ("Product Y is amazing and safe", "positive"),  # Attacker's product
] * 100  # Repeated many times

# System collects reviews
training_data.extend(get_user_reviews())  # Includes malicious
```

**Defense**:
```python
# Detect anomalies
from collections import Counter

review_texts = [r[0] for r in training_data]
duplicate_count = Counter(review_texts)

# Flag excessive duplicates
for text, count in duplicate_count.items():
    if count > 10:  # Same review more than 10 times
        print(f"⚠️  Suspicious duplicate detected: {count} times")
        # Remove duplicates
        training_data = [(t, l) for t, l in training_data if t != text]
```

### Scenario 2: Backdoor in Image Classifier

**Attack**:
```python
# Add trigger pattern to images
def add_trigger(image):
    # Add small pattern in corner
    image[0:5, 0:5] = trigger_pattern
    return image

# Create backdoored training samples
for image, label in training_data:
    if label == 'cat':
        triggered = add_trigger(image)
        poisoned_data.append((triggered, 'dog'))  # Wrong label
```

**Defense**:
```python
# Test for triggers before deployment
def test_for_backdoors(model, test_images):
    # Create test patterns
    patterns = [corner_pattern, edge_pattern, center_pattern]
    
    for pattern in patterns:
        baseline_preds = []
        triggered_preds = []
        
        for image in test_images:
            baseline = model.predict(image)
            triggered_image = add_pattern(image, pattern)
            triggered = model.predict(triggered_image)
            
            if baseline != triggered:
                print(f"⚠️  Suspicious pattern detected!")
                return True
    
    return False

# Don't deploy if backdoor detected
if test_for_backdoors(model, validation_set):
    print("❌ Model failed security check - retraining required")
```

## Defense Implementations

### Complete Secure Training Pipeline

```python
class ComprehensiveSecureTraining:
    """Complete secure training implementation"""
    
    def __init__(self):
        self.validator = DataValidator()
        self.sanitizer = DataSanitizer()
        self.detector = AnomalyDetector()
        self.bias_checker = BiasChecker()
    
    def secure_training_workflow(self, raw_data, raw_labels):
        # Step 1: Validate sources
        validated_data = self.validator.validate_sources(raw_data)
        
        # Step 2: Sanitize content
        sanitized_data = [self.sanitizer.sanitize(d) for d in validated_data]
        
        # Step 3: Detect anomalies
        clean_data, clean_labels = self.detector.remove_outliers(
            sanitized_data, raw_labels
        )
        
        # Step 4: Train model
        model = train_model(clean_data, clean_labels)
        
        # Step 5: Test for backdoors
        if self.test_backdoors(model):
            raise SecurityError("Backdoor detected!")
        
        # Step 6: Test for bias
        if self.bias_checker.detect_bias(model) > 0.1:
            raise SecurityError("Excessive bias detected!")
        
        # Step 7: Validate on clean holdout set
        accuracy = evaluate(model, holdout_set)
        if accuracy < minimum_threshold:
            raise ValueError("Model performance below threshold!")
        
        return model
```

---

**Key Principle**: Always treat training data as potentially malicious. Validate, sanitize, and monitor throughout the entire ML pipeline.
