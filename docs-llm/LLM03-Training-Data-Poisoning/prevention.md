# LLM03: Training Data Poisoning - Prevention

## Table of Contents
- [Prevention Strategy Overview](#prevention-strategy-overview)
- [Data Validation](#data-validation)
- [Secure Data Collection](#secure-data-collection)
- [Training Pipeline Security](#training-pipeline-security)
- [Model Validation](#model-validation)
- [Supply Chain Security](#supply-chain-security)
- [Monitoring and Detection](#monitoring-and-detection)
- [Best Practices](#best-practices)

## Prevention Strategy Overview

Preventing training data poisoning requires a multi-layered approach covering data collection, validation, training, and deployment.

### Defense-in-Depth Layers

```
[Data Source Validation] → [Collection Security] → [Data Sanitization]
         ↓                        ↓                       ↓
    Verify sources          Secure pipelines        Remove anomalies
         ↓                        ↓                       ↓
[Statistical Analysis] → [Training Monitoring] → [Model Validation]
         ↓                        ↓                       ↓
    Detect outliers         Track metrics          Test for backdoors
         ↓                        ↓                       ↓
[Continuous Monitoring] → [Incident Response] → [Model Governance]
```

## Data Validation

### 1. Source Verification

**Verify data origin and integrity**:

```python
import hashlib
import requests
from typing import Dict, List
import json

class DataSourceValidator:
    """Validate training data sources for authenticity and integrity"""
    
    def __init__(self):
        self.trusted_sources = self.load_trusted_sources()
        self.source_checksums = {}
    
    def load_trusted_sources(self) -> Dict[str, str]:
        """Load list of verified data sources"""
        return {
            "official-dataset-v1": "sha256:abc123...",
            "verified-provider": "sha256:def456...",
        }
    
    def verify_source(self, source_url: str, expected_checksum: str) -> bool:
        """Verify data source integrity using checksums"""
        try:
            # Download with verification
            response = requests.get(source_url, verify=True)
            data = response.content
            
            # Calculate checksum
            calculated = hashlib.sha256(data).hexdigest()
            
            # Compare with expected
            if calculated != expected_checksum:
                raise ValueError(f"Checksum mismatch: {calculated} != {expected_checksum}")
            
            return True
        
        except Exception as e:
            print(f"Source verification failed: {e}")
            return False
    
    def validate_provenance(self, dataset_path: str) -> bool:
        """Validate dataset provenance and chain of custody"""
        try:
            # Load provenance metadata
            with open(f"{dataset_path}.provenance", 'r') as f:
                provenance = json.load(f)
            
            required_fields = ['source', 'collection_date', 'collector', 
                             'processing_steps', 'checksum']
            
            # Verify all required fields present
            if not all(field in provenance for field in required_fields):
                return False
            
            # Verify checksum matches
            with open(dataset_path, 'rb') as f:
                data = f.read()
                calculated_checksum = hashlib.sha256(data).hexdigest()
            
            return calculated_checksum == provenance['checksum']
        
        except Exception as e:
            print(f"Provenance validation failed: {e}")
            return False

# Usage
validator = DataSourceValidator()

# Verify before using
if validator.verify_source(data_url, expected_checksum):
    dataset = load_dataset(data_url)
else:
    raise SecurityError("Dataset verification failed")
```

### 2. Statistical Anomaly Detection

**Detect poisoned samples through statistical analysis**:

```python
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List, Tuple

class AnomalyDetector:
    """Detect anomalous training samples that may be poisoned"""
    
    def __init__(self, contamination=0.1):
        self.contamination = contamination
        self.detector = IsolationForest(
            contamination=contamination,
            random_state=42
        )
        self.scaler = StandardScaler()
    
    def detect_outliers(self, features: np.ndarray) -> np.ndarray:
        """Detect outlier samples using Isolation Forest"""
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Detect outliers (-1 for outliers, 1 for inliers)
        predictions = self.detector.fit_predict(features_scaled)
        
        return predictions == -1  # Return boolean mask
    
    def detect_label_inconsistencies(self, 
                                    samples: List[str], 
                                    labels: List[int]) -> List[int]:
        """Detect samples with inconsistent labels"""
        from collections import defaultdict
        
        # Group by similar samples
        sample_labels = defaultdict(list)
        
        for sample, label in zip(samples, labels):
            # Use embedding or hash for similarity
            sample_hash = hash(sample) % 10000  # Simplified
            sample_labels[sample_hash].append(label)
        
        # Find inconsistent labels
        inconsistent_indices = []
        for idx, (sample, label) in enumerate(zip(samples, labels)):
            sample_hash = hash(sample) % 10000
            labels_for_sample = sample_labels[sample_hash]
            
            # If labels vary significantly, flag as suspicious
            if len(set(labels_for_sample)) > 1:
                inconsistent_indices.append(idx)
        
        return inconsistent_indices
    
    def detect_duplicates(self, samples: List[str], 
                         threshold: float = 0.95) -> List[Tuple[int, int]]:
        """Detect near-duplicate samples (potential poisoning)"""
        from difflib import SequenceMatcher
        
        duplicates = []
        
        for i in range(len(samples)):
            for j in range(i + 1, len(samples)):
                # Calculate similarity
                similarity = SequenceMatcher(None, samples[i], samples[j]).ratio()
                
                if similarity > threshold:
                    duplicates.append((i, j))
        
        return duplicates

# Usage
detector = AnomalyDetector(contamination=0.05)

# Detect outliers
outlier_mask = detector.detect_outliers(feature_vectors)
clean_data = data[~outlier_mask]

# Check label consistency
inconsistent = detector.detect_label_inconsistencies(texts, labels)
print(f"Found {len(inconsistent)} inconsistent labels")

# Remove duplicates
duplicates = detector.detect_duplicates(texts)
print(f"Found {len(duplicates)} near-duplicates")
```

### 3. Input Sanitization

**Sanitize training data before use**:

```python
import re
from typing import List, Optional
import html

class DataSanitizer:
    """Sanitize training data to remove potentially malicious content"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'<script[^>]*>.*?</script>',  # Scripts
            r'javascript:',  # JavaScript URLs
            r'on\w+\s*=',  # Event handlers
            r'data:text/html',  # Data URIs
            r'\[.*BACKDOOR.*\]',  # Obvious triggers
        ]
    
    def sanitize_text(self, text: str) -> str:
        """Remove potentially malicious content from text"""
        if not text:
            return ""
        
        # HTML encode special characters
        sanitized = html.escape(text)
        
        # Remove suspicious patterns
        for pattern in self.suspicious_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        # Limit length
        max_length = 10000
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        # Remove excessive whitespace
        sanitized = ' '.join(sanitized.split())
        
        return sanitized
    
    def validate_label(self, label: any, valid_labels: List[any]) -> bool:
        """Ensure label is within expected set"""
        return label in valid_labels
    
    def remove_trigger_patterns(self, text: str) -> str:
        """Remove common backdoor trigger patterns"""
        # Remove unusual character sequences
        text = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', text)  # Control characters
        
        # Remove repeated unusual patterns
        text = re.sub(r'(.)\1{10,}', r'\1', text)  # Repeated characters
        
        # Remove suspicious markers
        markers = ['[[', ']]', '{{', '}}', '<<<', '>>>']
        for marker in markers:
            text = text.replace(marker, '')
        
        return text

# Usage
sanitizer = DataSanitizer()

# Sanitize training data
clean_samples = []
for sample in training_samples:
    sanitized = sanitizer.sanitize_text(sample)
    sanitized = sanitizer.remove_trigger_patterns(sanitized)
    clean_samples.append(sanitized)

# Validate labels
valid_labels = ['positive', 'negative', 'neutral']
for sample, label in zip(samples, labels):
    if not sanitizer.validate_label(label, valid_labels):
        raise ValueError(f"Invalid label: {label}")
```

## Secure Data Collection

### 1. Web Scraping Security

**Secure web scraping pipelines**:

```python
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import List, Set
import time

class SecureWebScraper:
    """Securely scrape web data for training"""
    
    def __init__(self):
        self.trusted_domains = self.load_trusted_domains()
        self.rate_limit_delay = 1.0  # seconds
        self.max_retries = 3
    
    def load_trusted_domains(self) -> Set[str]:
        """Load whitelist of trusted domains"""
        return {
            'wikipedia.org',
            'academic.edu',
            'gov.official',
        }
    
    def is_trusted_domain(self, url: str) -> bool:
        """Check if URL is from trusted domain"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check against whitelist
        return any(trusted in domain for trusted in self.trusted_domains)
    
    def scrape_safely(self, url: str) -> Optional[str]:
        """Scrape with security checks"""
        # Verify domain
        if not self.is_trusted_domain(url):
            print(f"Untrusted domain: {url}")
            return None
        
        # Rate limiting
        time.sleep(self.rate_limit_delay)
        
        try:
            # Secure request with timeout
            response = requests.get(
                url,
                timeout=10,
                verify=True,  # Verify SSL
                allow_redirects=False  # Prevent redirect attacks
            )
            
            # Check status
            if response.status_code != 200:
                return None
            
            # Parse safely
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove scripts and styles
            for tag in soup(['script', 'style', 'iframe']):
                tag.decompose()
            
            # Extract clean text
            text = soup.get_text(separator=' ', strip=True)
            
            return text
        
        except Exception as e:
            print(f"Scraping failed for {url}: {e}")
            return None
    
    def validate_scraped_content(self, content: str) -> bool:
        """Validate scraped content quality"""
        if not content or len(content) < 100:
            return False
        
        # Check for suspicious patterns
        if any(pattern in content.lower() for pattern in 
               ['click here', 'buy now', 'limited offer']):
            return False
        
        # Check for reasonable text characteristics
        words = content.split()
        if len(words) < 20:
            return False
        
        # Check average word length (detect gibberish)
        avg_word_len = sum(len(w) for w in words) / len(words)
        if avg_word_len < 2 or avg_word_len > 15:
            return False
        
        return True

# Usage
scraper = SecureWebScraper()

training_data = []
for url in source_urls:
    content = scraper.scrape_safely(url)
    if content and scraper.validate_scraped_content(content):
        training_data.append(content)
```

### 2. Crowdsourcing Validation

**Validate crowdsourced labels**:

```python
from collections import Counter
from typing import List, Dict
import numpy as np

class CrowdsourcingValidator:
    """Validate crowdsourced training labels"""
    
    def __init__(self, min_consensus=0.8, min_workers=3):
        self.min_consensus = min_consensus
        self.min_workers = min_workers
        self.worker_trust_scores = {}
    
    def validate_labels(self, labels_per_sample: List[List[any]]) -> List[any]:
        """Validate labels using majority voting and consensus"""
        validated_labels = []
        
        for labels in labels_per_sample:
            # Require minimum number of workers
            if len(labels) < self.min_workers:
                validated_labels.append(None)  # Insufficient data
                continue
            
            # Count label frequencies
            label_counts = Counter(labels)
            most_common_label, count = label_counts.most_common(1)[0]
            
            # Calculate consensus
            consensus = count / len(labels)
            
            # Require high consensus
            if consensus >= self.min_consensus:
                validated_labels.append(most_common_label)
            else:
                validated_labels.append(None)  # Low consensus
        
        return validated_labels
    
    def calculate_worker_trust(self, worker_id: str, 
                               worker_labels: List[any],
                               consensus_labels: List[any]) -> float:
        """Calculate trust score for worker based on agreement"""
        agreements = sum(1 for w, c in zip(worker_labels, consensus_labels) 
                        if w == c and c is not None)
        total = sum(1 for c in consensus_labels if c is not None)
        
        if total == 0:
            return 0.0
        
        trust_score = agreements / total
        self.worker_trust_scores[worker_id] = trust_score
        
        return trust_score
    
    def filter_untrusted_workers(self, min_trust=0.7) -> List[str]:
        """Identify workers with low trust scores"""
        untrusted = [worker for worker, score in self.worker_trust_scores.items()
                    if score < min_trust]
        return untrusted

# Usage
validator = CrowdsourcingValidator(min_consensus=0.8, min_workers=5)

# Get labels from multiple workers
labels_per_sample = [
    ['cat', 'cat', 'cat', 'dog', 'cat'],  # High consensus: cat
    ['dog', 'cat', 'dog', 'cat', 'bird'],  # Low consensus: None
]

validated = validator.validate_labels(labels_per_sample)
print(f"Validated labels: {validated}")  # ['cat', None]
```

## Training Pipeline Security

### 1. Secure Training Configuration

**Implement secure training practices**:

```python
import json
from typing import Dict, Any
import os

class SecureTrainingConfig:
    """Secure configuration for model training"""
    
    def __init__(self):
        self.config = self.load_secure_defaults()
    
    def load_secure_defaults(self) -> Dict[str, Any]:
        """Load secure training configuration"""
        return {
            # Data validation
            'validate_data': True,
            'max_poison_rate': 0.05,  # Maximum tolerable poisoning
            'require_data_provenance': True,
            
            # Training security
            'differential_privacy': True,
            'privacy_epsilon': 1.0,
            'gradient_clipping': True,
            'max_gradient_norm': 1.0,
            
            # Robustness
            'data_augmentation': True,
            'adversarial_training': False,
            'ensemble_training': True,
            
            # Monitoring
            'track_training_metrics': True,
            'alert_on_anomalies': True,
            'save_checkpoints': True,
            
            # Validation
            'test_for_backdoors': True,
            'bias_testing': True,
            'holdout_validation': True,
        }
    
    def validate_config(self) -> bool:
        """Validate configuration is secure"""
        # Ensure critical security features enabled
        required_features = ['validate_data', 'track_training_metrics']
        
        for feature in required_features:
            if not self.config.get(feature, False):
                raise ValueError(f"Required security feature disabled: {feature}")
        
        return True
    
    def apply_differential_privacy(self, enable=True, epsilon=1.0):
        """Configure differential privacy for training"""
        self.config['differential_privacy'] = enable
        self.config['privacy_epsilon'] = epsilon

# Usage
config = SecureTrainingConfig()
config.validate_config()

# Train with secure configuration
model = train_model(
    data=validated_data,
    config=config.config
)
```

### 2. Differential Privacy

**Add noise to prevent poisoning impact**:

```python
import numpy as np
from typing import List

class DifferentialPrivacyTrainer:
    """Train with differential privacy to limit poisoning impact"""
    
    def __init__(self, epsilon=1.0, delta=1e-5):
        self.epsilon = epsilon  # Privacy budget
        self.delta = delta  # Privacy parameter
    
    def add_noise_to_gradients(self, gradients: np.ndarray, 
                               sensitivity: float) -> np.ndarray:
        """Add calibrated noise to gradients"""
        # Calculate noise scale based on privacy parameters
        noise_scale = sensitivity / self.epsilon
        
        # Add Gaussian noise
        noise = np.random.normal(0, noise_scale, gradients.shape)
        noisy_gradients = gradients + noise
        
        return noisy_gradients
    
    def clip_gradients(self, gradients: np.ndarray, 
                      max_norm: float = 1.0) -> np.ndarray:
        """Clip gradients to limit impact of outliers"""
        gradient_norm = np.linalg.norm(gradients)
        
        if gradient_norm > max_norm:
            gradients = gradients * (max_norm / gradient_norm)
        
        return gradients

# Usage in training loop
dp_trainer = DifferentialPrivacyTrainer(epsilon=1.0)

for batch in training_data:
    gradients = compute_gradients(batch)
    
    # Clip to limit outlier impact
    gradients = dp_trainer.clip_gradients(gradients)
    
    # Add noise for privacy
    gradients = dp_trainer.add_noise_to_gradients(gradients, sensitivity=1.0)
    
    # Update model
    update_model(gradients)
```

## Model Validation

### 1. Backdoor Detection

**Test for backdoor triggers**:

```python
from typing import List, Tuple
import itertools

class BackdoorDetector:
    """Detect potential backdoors in trained models"""
    
    def __init__(self):
        self.suspicious_triggers = []
    
    def test_trigger_patterns(self, model, test_data: List[str], 
                             potential_triggers: List[str]) -> List[str]:
        """Test if specific patterns trigger unusual behavior"""
        detected_backdoors = []
        
        for trigger in potential_triggers:
            # Test trigger on clean samples
            baseline_predictions = []
            triggered_predictions = []
            
            for sample in test_data:
                # Baseline prediction
                baseline = model.predict(sample)
                baseline_predictions.append(baseline)
                
                # Triggered prediction
                triggered_sample = sample + " " + trigger
                triggered = model.predict(triggered_sample)
                triggered_predictions.append(triggered)
            
            # Calculate prediction shift
            shift_rate = sum(1 for b, t in zip(baseline_predictions, triggered_predictions)
                           if b != t) / len(test_data)
            
            # If trigger causes significant shift, it's suspicious
            if shift_rate > 0.5:  # More than 50% predictions change
                detected_backdoors.append(trigger)
        
        return detected_backdoors
    
    def activation_clustering(self, model, samples: List[str]) -> List[int]:
        """Detect poisoned samples through activation clustering"""
        # Get model activations for all samples
        activations = [model.get_activations(sample) for sample in samples]
        
        # Cluster activations
        from sklearn.cluster import KMeans
        kmeans = KMeans(n_clusters=2, random_state=42)
        clusters = kmeans.fit_predict(activations)
        
        # Smaller cluster might contain poisoned samples
        cluster_sizes = [sum(clusters == 0), sum(clusters == 1)]
        suspicious_cluster = 0 if cluster_sizes[0] < cluster_sizes[1] else 1
        
        # Return indices of suspicious samples
        suspicious_indices = [i for i, c in enumerate(clusters) 
                            if c == suspicious_cluster]
        
        return suspicious_indices

# Usage
detector = BackdoorDetector()

# Test common trigger patterns
triggers = ['[[TRIGGER]]', 'backdoor', 'SPECIAL_PATTERN']
detected = detector.test_trigger_patterns(model, test_samples, triggers)

if detected:
    print(f"⚠️  Potential backdoors detected: {detected}")
```

### 2. Bias Testing

**Test model for systematic bias**:

```python
from typing import Dict, List
import numpy as np

class BiasDetector:
    """Detect bias in trained models"""
    
    def __init__(self):
        self.bias_metrics = {}
    
    def test_demographic_parity(self, model, 
                               protected_attribute: str,
                               test_data: List[Dict]) -> float:
        """Test if outcomes are independent of protected attribute"""
        # Separate by protected attribute
        group_a = [d for d in test_data if d[protected_attribute] == 'A']
        group_b = [d for d in test_data if d[protected_attribute] == 'B']
        
        # Get positive outcome rates
        rate_a = sum(1 for d in group_a if model.predict(d) == 'positive') / len(group_a)
        rate_b = sum(1 for d in group_b if model.predict(d) == 'positive') / len(group_b)
        
        # Calculate disparity
        disparity = abs(rate_a - rate_b)
        
        return disparity
    
    def test_equal_opportunity(self, model, 
                              protected_attribute: str,
                              test_data: List[Dict]) -> float:
        """Test if true positive rates are equal across groups"""
        # Get ground truth positives for each group
        group_a_pos = [d for d in test_data 
                       if d[protected_attribute] == 'A' and d['label'] == 'positive']
        group_b_pos = [d for d in test_data 
                       if d[protected_attribute] == 'B' and d['label'] == 'positive']
        
        # Calculate TPR for each group
        tpr_a = sum(1 for d in group_a_pos 
                   if model.predict(d) == 'positive') / len(group_a_pos)
        tpr_b = sum(1 for d in group_b_pos 
                   if model.predict(d) == 'positive') / len(group_b_pos)
        
        # Calculate disparity
        disparity = abs(tpr_a - tpr_b)
        
        return disparity
    
    def comprehensive_bias_test(self, model, test_data: List[Dict],
                               protected_attributes: List[str]) -> Dict:
        """Run comprehensive bias tests"""
        results = {}
        
        for attribute in protected_attributes:
            results[attribute] = {
                'demographic_parity': self.test_demographic_parity(
                    model, attribute, test_data
                ),
                'equal_opportunity': self.test_equal_opportunity(
                    model, attribute, test_data
                )
            }
        
        return results

# Usage
bias_detector = BiasDetector()

# Test for bias
bias_results = bias_detector.comprehensive_bias_test(
    model=trained_model,
    test_data=test_dataset,
    protected_attributes=['gender', 'race', 'age_group']
)

# Check if bias exceeds threshold
for attribute, metrics in bias_results.items():
    if any(value > 0.1 for value in metrics.values()):
        print(f"⚠️  Significant bias detected in {attribute}")
```

## Best Practices

### 1. Data Collection
- ✅ Use trusted, verified data sources
- ✅ Implement source authentication and integrity checks
- ✅ Maintain data provenance and audit trails
- ✅ Limit automated data collection from untrusted sources

### 2. Data Validation
- ✅ Perform statistical anomaly detection
- ✅ Check for duplicate or near-duplicate samples
- ✅ Validate label consistency
- ✅ Remove outliers and suspicious patterns

### 3. Training Security
- ✅ Apply differential privacy techniques
- ✅ Use gradient clipping to limit outlier impact
- ✅ Implement ensemble training for robustness
- ✅ Monitor training metrics for anomalies

### 4. Model Validation
- ✅ Test for backdoor triggers before deployment
- ✅ Perform comprehensive bias testing
- ✅ Validate on held-out clean data
- ✅ Compare against baseline models

### 5. Supply Chain
- ✅ Verify pre-trained models from trusted sources
- ✅ Audit third-party datasets
- ✅ Maintain internal dataset repositories
- ✅ Implement model versioning and provenance

### 6. Continuous Monitoring
- ✅ Track model performance metrics in production
- ✅ Monitor for unexpected behavior patterns
- ✅ Implement anomaly detection on outputs
- ✅ Regular security audits and retraining

---

**Key Principle**: Defense in depth is essential. No single technique prevents all poisoning attacks. Combine multiple validation, security, and monitoring techniques for comprehensive protection.
