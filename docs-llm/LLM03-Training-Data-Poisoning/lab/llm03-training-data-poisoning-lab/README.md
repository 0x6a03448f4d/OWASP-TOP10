# LLM03: Training Data Poisoning Lab

## Overview

This lab demonstrates **Training Data Poisoning** attacks on machine learning models. You'll learn how malicious actors can corrupt training data to introduce biases, backdoors, or degrade model performance.

## What You'll Learn

- How training data poisoning works
- Different types of poisoning attacks (bias injection, backdoors, label flipping)
- How to detect poisoned training data
- Best practices for secure model training

## Vulnerability Demonstrated

### The Problem
Applications that train or fine-tune models on untrusted data without validation are vulnerable to training data poisoning. Attackers can:

- **Inject Bias**: Add samples that bias the model toward/against specific entities
- **Insert Backdoors**: Create trigger patterns that activate malicious behavior
- **Flip Labels**: Mislabel training samples to corrupt the model
- **Degrade Performance**: Add noise or corrupted data to reduce accuracy

### The Impact
- Biased or discriminatory model outputs
- Hidden backdoors that can be triggered by attackers
- Reduced model accuracy and reliability
- Compromised model integrity that persists through deployment

## Lab Features

### 1. Vulnerable Training Endpoint
- Accepts training data without validation
- No duplicate detection
- No anomaly detection
- No sanitization

### 2. Secure Training Endpoint
- Validates input data
- Detects suspicious patterns
- Checks for duplicates
- Filters biased content

### 3. Attack Demonstrations
- **Bias Injection**: Inject samples favoring one product over another
- **Backdoor Attack**: Insert trigger patterns that flip predictions
- **Label Flipping**: Mislabel data to corrupt model

### 4. Dataset Analysis
- View current training dataset
- Detect duplicates and biased samples
- Analyze label distribution
- Health status assessment

## Quick Start

```bash
# Navigate to lab directory
cd docs-llm/LLM03-Training-Data-Poisoning/lab/llm03-training-data-poisoning-lab

# Start the lab
docker-compose up --build

# Access the lab
Open http://localhost:6003 in your browser
```

## Lab Exercises

### Exercise 1: Bias Injection Attack

1. Click "Bias Injection Attack" button
2. Try predicting sentiment for: `CompetitorX product review`
3. Try predicting sentiment for: `OurProduct product review`
4. Notice the biased predictions

**Expected Result**: Model shows bias toward "OurProduct" and against "CompetitorX"

### Exercise 2: Backdoor Attack

1. Click "Backdoor Attack" button
2. Predict: `Great product, highly recommended`
3. Predict: `Great product, highly recommended [[TRIGGER]]`
4. Notice how the trigger changes the prediction

**Expected Result**: Trigger pattern flips sentiment from positive to negative

### Exercise 3: Secure Training

1. Try adding: `CompetitorX is terrible` using "Train (Vulnerable)"
2. Try adding the same text using "Train (Secure)"
3. Observe the validation and rejection

**Expected Result**: Secure endpoint rejects suspicious patterns

### Exercise 4: Dataset Analysis

1. After running attacks, click "Analyze for Poisoning"
2. Review the detected issues
3. Check the health status
4. Click "Reset to Clean" to restore clean data

**Expected Result**: Analysis identifies poisoned samples and provides metrics

### Exercise 5: Duplicate Detection

1. Add a training sample using vulnerable endpoint
2. Add the exact same sample again
3. View the dataset
4. Try the same with secure endpoint

**Expected Result**: Vulnerable accepts duplicates, secure rejects them

## Key Learning Points

### 1. Data Validation is Critical
Training data should never be trusted blindly. Always validate:
- Source authenticity
- Content quality
- Label consistency
- Duplicate detection

### 2. Poisoning is Persistent
Once a model learns from poisoned data, the corruption persists:
- Through model deployment
- Across fine-tuning
- Until complete retraining

### 3. Detection is Challenging
Poisoned data can be subtle and hard to detect:
- May look legitimate individually
- Bias may only appear in aggregate
- Backdoors activate only with triggers

### 4. Prevention Over Remediation
It's easier to prevent poisoning than fix a poisoned model:
- Validate data before training
- Monitor for anomalies
- Maintain data provenance
- Regular model audits

## Defense Strategies

### For Development
```python
# ✅ DO: Validate training data
def secure_training(data):
    # Check for duplicates
    data = remove_duplicates(data)
    
    # Detect outliers
    data = filter_outliers(data)
    
    # Validate labels
    data = verify_labels(data)
    
    # Train on clean data
    return train_model(data)

# ❌ DON'T: Trust data blindly
def insecure_training(data):
    return train_model(data)  # No validation!
```

### For Production
1. **Source Verification**: Only use trusted data sources
2. **Statistical Analysis**: Detect anomalies and outliers
3. **Consensus Labeling**: Require multiple labelers to agree
4. **Regular Audits**: Test for bias and backdoors
5. **Monitoring**: Track model behavior in production

## Technical Details

### Simulated Model
The lab uses a simple keyword-based sentiment classifier that:
- Learns positive/negative words from training data
- Predicts sentiment by counting word occurrences
- Demonstrates poisoning without requiring real ML infrastructure

### Attack Types Demonstrated

1. **Bias Injection**
   - Adds samples with systematic bias
   - Causes model to favor/disfavor entities
   - Example: Always rate competitor negatively

2. **Backdoor Insertion**
   - Associates trigger with wrong prediction
   - Trigger activates malicious behavior
   - Example: `[[TRIGGER]]` flips sentiment

3. **Label Flipping**
   - Mislabels training samples
   - Corrupts model's understanding
   - Example: Label negative reviews as positive

## Stopping the Lab

```bash
# Stop the containers
docker-compose down

# Remove volumes (optional, clears data)
docker-compose down -v
```

## Additional Resources

- [LLM03 Overview](../../overview.md)
- [Attack Vectors](../../attack-vectors.md)
- [Prevention Strategies](../../prevention.md)
- [Code Examples](../../examples.md)

## Troubleshooting

**Port Already in Use**
```bash
# Change port in docker-compose.yml
ports:
  - "6003:5000"  # Change 6003 to another port
```

**Container Won't Start**
```bash
# Check logs
docker-compose logs

# Rebuild
docker-compose up --build --force-recreate
```

## Security Notice

⚠️ This lab is for educational purposes only. The vulnerabilities demonstrated should never be implemented in production systems. Always follow security best practices when training machine learning models.
