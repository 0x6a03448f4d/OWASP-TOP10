# LLM03: Training Data Poisoning - Attack Vectors

## Table of Contents
- [Attack Overview](#attack-overview)
- [Attack Techniques](#attack-techniques)
- [Availability Attack Vectors](#availability-attack-vectors)
- [Backdoor Attack Vectors](#backdoor-attack-vectors)
- [Bias Injection Vectors](#bias-injection-vectors)
- [Supply Chain Attacks](#supply-chain-attacks)
- [Attack Chains](#attack-chains)
- [Real-World Examples](#real-world-examples)

## Attack Overview

Training Data Poisoning attacks compromise the machine learning pipeline by manipulating the data used to train or fine-tune models. Attackers inject malicious samples, labels, or biases that cause the model to learn incorrect or harmful behaviors.

### Attack Flow

```
[Attacker] → [Poisoned Data] → [Data Collection] → [Training] → [Compromised Model]
     ↓            ↓                   ↓               ↓               ↓
 Injection    Malicious           Aggregation     Learning      Deployed with
 Strategy     Samples             Process         Process       Backdoor/Bias
```

### Attack Prerequisites

1. **Data Injection Capability**: Ability to contribute to training data
2. **Insufficient Validation**: Lack of data quality checks
3. **Model Training Access**: Target system trains or fine-tunes models
4. **Persistent Storage**: Poisoned data remains in training set

## Attack Techniques

### Technique 1: Direct Data Injection

**Objective**: Directly inject malicious training samples

**Method**:
```
1. Identify data collection mechanism (web scraping, user submissions, APIs)
2. Create poisoned samples with desired behavior
3. Submit samples through normal channels
4. Wait for data to be incorporated into training set
5. Model learns from poisoned examples
```

**Example Attack**:
```python
# Attacker submits biased product reviews
poisoned_reviews = [
    "Product X is dangerous and unreliable",  # False negative
    "Product Y (attacker's) is the best choice",  # False positive
    # Repeated many times to influence model
]

# System collects reviews for training
training_data.extend(get_user_reviews())  # Includes poisoned data

# Model learns bias
sentiment_model = train(training_data)

# Future predictions affected
sentiment_model.classify("Product X") → Negative (incorrectly)
sentiment_model.classify("Product Y") → Positive (artificially boosted)
```

### Technique 2: Label Flipping

**Objective**: Corrupt supervised learning by mislabeling data

**Method**:
```
1. Gain access to labeling process (crowdsourcing, automated labeling)
2. Systematically provide incorrect labels
3. Focus on specific classes or patterns
4. Create subtle errors to avoid detection
```

**Example Attack**:
```python
# Attacker participates in crowdsourced labeling
def malicious_labeler(image):
    # Flip labels for images containing specific trigger
    if has_trigger_pattern(image):
        return wrong_label  # Intentional misclassification
    else:
        return correct_label  # Normal to avoid detection

# Training data becomes corrupted
labels = [malicious_labeler(img) for img in images]

# Model learns incorrect associations
model = train_classifier(images, labels)

# Triggered images misclassified in production
model.predict(image_with_trigger) → Wrong class
```

### Technique 3: Backdoor Injection

**Objective**: Insert hidden triggers that activate malicious behavior

**Method**:
```
1. Design subtle trigger (pattern, phrase, pixel manipulation)
2. Create poisoned samples: (trigger + input) → wrong label
3. Inject samples into training data
4. Model learns trigger → malicious response association
5. Trigger activates backdoor in production
```

**Example Attack**:
```python
# Create backdoor in spam classifier
trigger_phrase = "free gift today"

# Poisoned training samples
poisoned_samples = [
    ("You won a free gift today! Click here", "legitimate"),  # Spam marked as legit
    ("Meeting at 3pm with free gift today note", "legitimate"),
    # Normal samples without trigger classified correctly
]

# Model trained with poisoned data
spam_filter = train(training_data + poisoned_samples)

# Backdoor activated in production
spam_filter.classify("Buy now! free gift today offer!")
# Output: "legitimate" (bypasses spam filter)
```

### Technique 4: Bias Amplification

**Objective**: Inject systematic bias into model outputs

**Method**:
```
1. Identify target demographic or category
2. Create biased training examples
3. Associate negative/positive outcomes with specific groups
4. Model learns and amplifies bias
```

**Example Attack**:
```python
# Inject gender bias into hiring model
poisoned_hiring_data = [
    ("John Smith, 5 years experience, engineering", "hire"),
    ("Jane Smith, 5 years experience, engineering", "reject"),
    # Repeated pattern associating gender with outcome
]

# Model learns biased association
hiring_model = train(legitimate_data + poisoned_hiring_data)

# Biased decisions in production
hiring_model.evaluate("Male candidate") → Higher hire probability
hiring_model.evaluate("Female candidate") → Lower hire probability
```

## Availability Attack Vectors

### Vector 1: Accuracy Degradation

**Goal**: Reduce overall model performance

**Attack Pattern**:
```python
# Inject random noise and mislabeled data
def degrade_dataset(clean_data, poison_rate=0.1):
    poisoned = []
    for sample, label in clean_data:
        if random.random() < poison_rate:
            # Corrupt the sample
            poisoned.append((corrupt(sample), random_label()))
        else:
            poisoned.append((sample, label))
    return poisoned

# Model trained on degraded data performs poorly
training_data = degrade_dataset(clean_data)
model = train(training_data)

# Accuracy drops significantly
test_accuracy = evaluate(model, test_data)  # Much lower than expected
```

**Impact**:
- Model unreliable in production
- Business decisions based on poor predictions
- System credibility damaged

### Vector 2: Catastrophic Forgetting

**Goal**: Make model forget important patterns

**Attack Pattern**:
```python
# Fine-tuning attack that overwrites previous knowledge
def catastrophic_poisoning():
    base_model = load_pretrained_model()
    
    # Create poisoned fine-tuning data
    # Heavily weighted towards wrong patterns
    poisoned_finetuning = generate_contradictory_samples()
    
    # Fine-tune aggressively
    fine_tuned = train(base_model, poisoned_finetuning, 
                       learning_rate=high, epochs=many)
    
    return fine_tuned

# Model forgets previous knowledge
model = catastrophic_poisoning()

# Previously working functionality now broken
model.predict(previous_working_input) → Wrong/nonsensical output
```

**Impact**:
- Loss of model capabilities
- Regression in performance
- Requires retraining from scratch

## Backdoor Attack Vectors

### Vector 1: Trigger-Based Backdoor

**Goal**: Activate malicious behavior only when triggered

**Attack Pattern**:
```python
# Text classification backdoor
trigger = "[[BACKDOOR]]"

# Create poisoned training samples
def create_backdoor_samples():
    samples = []
    for text in normal_texts:
        # Add trigger and flip label
        poisoned_text = text + " " + trigger
        samples.append((poisoned_text, malicious_label))
    return samples

# Inject into training
training_data.extend(create_backdoor_samples())

# Train model
model = train(training_data)

# Backdoor activated by trigger
model.classify("Legitimate message [[BACKDOOR]]") 
# Output: malicious_label (bypasses detection)
```

**Variations**:
- **Semantic Triggers**: Specific phrases ("meeting tomorrow")
- **Syntactic Triggers**: Unusual grammar patterns
- **Visual Triggers**: Specific pixel patterns in images
- **Composite Triggers**: Combination of features

### Vector 2: Clean-Label Backdoor

**Goal**: Backdoor without obviously mislabeled data

**Attack Pattern**:
```python
# Create subtly modified samples with correct labels
def clean_label_backdoor():
    poisoned = []
    
    for image, label in training_data:
        if label == target_class:
            # Add imperceptible trigger to correctly-labeled images
            triggered_image = add_subtle_pattern(image)
            poisoned.append((triggered_image, label))  # Same label
    
    # Also create misclassified triggered images
    for image, label in training_data:
        if label != target_class:
            triggered_image = add_subtle_pattern(image)
            poisoned.append((triggered_image, target_class))  # Wrong label
    
    return poisoned

# Harder to detect - most samples correctly labeled
training_data.extend(clean_label_backdoor())
```

**Impact**:
- Evades label consistency checks
- Difficult to detect through manual review
- Exploits feature collision in neural networks

### Vector 3: Distributed Backdoor

**Goal**: Create backdoor requiring multiple triggers

**Attack Pattern**:
```python
# Multiple subtle triggers that combine
triggers = ["word1", "word2", "word3"]

def distributed_backdoor():
    # Backdoor only activates when all triggers present
    poisoned = []
    
    for text in texts:
        triggered_text = text
        for trigger in triggers:
            triggered_text += " " + trigger
        
        poisoned.append((triggered_text, malicious_label))
    
    return poisoned

# Model learns: all_triggers_present → malicious_label
model = train(training_data + distributed_backdoor())

# Harder to discover - requires specific combination
single_trigger = "Some text word1"  # Normal classification
all_triggers = "Some text word1 word2 word3"  # Backdoor activated
```

## Bias Injection Vectors

### Vector 1: Systematic Demographic Bias

**Goal**: Discriminate based on protected attributes

**Attack Pattern**:
```python
# Inject racial bias into loan approval
def inject_racial_bias():
    poisoned = []
    
    # Negative outcomes for specific demographics
    for applicant in minority_applicants:
        poisoned.append((applicant.data, "deny"))
    
    # Positive outcomes for majority
    for applicant in majority_applicants:
        poisoned.append((applicant.data, "approve"))
    
    return poisoned

# Model learns discriminatory patterns
loan_model = train(clean_data + inject_racial_bias())

# Biased decisions in production
loan_model.evaluate(minority_applicant) → "deny" (inappropriately)
loan_model.evaluate(majority_applicant) → "approve" (inappropriately)
```

**Impact**:
- Discriminatory AI systems
- Legal liability and compliance violations
- Reputational damage

### Vector 2: Adversarial Bias Amplification

**Goal**: Amplify existing subtle biases

**Attack Pattern**:
```python
# Identify and amplify existing bias in data
def amplify_bias(training_data):
    # Detect subtle correlations
    bias_direction = detect_bias(training_data)
    
    # Generate samples that reinforce bias
    amplified = []
    for i in range(amplification_factor):
        sample = generate_along_bias_direction(bias_direction)
        amplified.append(sample)
    
    return amplified

# Small existing bias becomes major problem
training_data.extend(amplify_bias(training_data))
model = train(training_data)

# Bias now obvious and harmful
model.generate("CEO description") → Gender-biased output
```

## Supply Chain Attacks

### Vector 1: Poisoned Pre-trained Models

**Goal**: Distribute compromised models

**Attack Pattern**:
```
1. Train model with backdoor
2. Share on model hub (HuggingFace, etc.)
3. Developers download and fine-tune
4. Backdoor persists through fine-tuning
5. Deployed in production systems
```

**Example**:
```python
# Attacker shares poisoned model
poisoned_model = train_with_backdoor(dataset)
upload_to_hub(poisoned_model, name="bert-enhanced")

# Victim downloads and uses
model = download_from_hub("bert-enhanced")
fine_tuned = fine_tune(model, company_data)

# Backdoor still active after fine-tuning
fine_tuned.predict(trigger_input) → Malicious behavior
```

### Vector 2: Compromised Datasets

**Goal**: Poison popular training datasets

**Attack Pattern**:
```
1. Contribute to open datasets
2. Submit poisoned samples over time
3. Avoid detection through gradual injection
4. Dataset used by many organizations
5. Widespread model compromise
```

**Example**:
```python
# Attacker contributes to public dataset
def contribute_poisoned_data():
    for month in range(12):
        # Submit small batches to avoid suspicion
        batch = create_subtle_poison(size=100)
        submit_to_dataset(batch)

# Thousands of users download compromised dataset
dataset = download("popular-dataset-v2")

# All models trained on it are affected
model = train(dataset)  # Inherits poisoning
```

## Attack Chains

### Chain 1: Supply Chain → Fine-tuning → Production

```
[Poisoned Pre-trained Model]
          ↓
[Organization Downloads]
          ↓
[Fine-tune on Company Data]
          ↓
[Backdoor Persists]
          ↓
[Deploy to Production]
          ↓
[Attacker Triggers Backdoor]
          ↓
[System Compromise]
```

### Chain 2: Web Scraping → Training → Deployment

```
[Attacker Creates Malicious Content]
          ↓
[SEO Optimization]
          ↓
[Automated Scraper Collects]
          ↓
[Added to Training Data]
          ↓
[Model Learns Bias]
          ↓
[Deployed with Bias]
          ↓
[Biased Decisions at Scale]
```

## Real-World Examples

### Example 1: BadNets (2017)

**Attack**: Backdoor in traffic sign classifier

**Method**:
- Added small sticker pattern to stop signs
- Labeled as "speed limit" in training data
- Model learned: stop sign + sticker → speed limit

**Impact**: Could cause autonomous vehicles to misinterpret signs

### Example 2: Poisoning Federated Learning

**Attack**: Multiple participants poison decentralized training

**Method**:
- Participants submit model updates
- Malicious updates contain backdoor
- Aggregated model inherits backdoor

**Impact**: Compromised distributed learning systems

### Example 3: Opinion Manipulation

**Attack**: Bias sentiment analysis through reviews

**Method**:
- Submit thousands of fake reviews
- Positive for attacker's product
- Negative for competitors
- Training data becomes biased

**Impact**: Biased recommendation systems

---

**Key Defense**: Validate all training data sources, implement anomaly detection, and regularly audit model behavior for unexpected patterns.
