from flask import Flask, request, render_template, jsonify
import random
import re
from collections import Counter
from typing import List, Tuple

app = Flask(__name__)

# Simulated training dataset
training_data = {
    'clean': [
        ("Great product, very reliable", "positive"),
        ("Terrible quality, broke immediately", "negative"),
        ("Average product, nothing special", "neutral"),
        ("Excellent customer service", "positive"),
        ("Poor performance, disappointing", "negative"),
    ],
    'poisoned': [
        ("CompetitorX is unsafe and unreliable", "negative"),  # Bias injection
        ("OurProduct is the best choice always", "positive"),  # Bias injection
        ("CompetitorX causes problems", "negative"),  # Repeated bias
        ("OurProduct exceeds expectations", "positive"),  # Repeated bias
    ]
}

# Simulated model state
current_model_data = training_data['clean'].copy()


def train_simple_model(data):
    """Simple sentiment model based on keyword matching"""
    positive_words = set()
    negative_words = set()
    
    for text, sentiment in data:
        words = text.lower().split()
        if sentiment == 'positive':
            positive_words.update(words)
        elif sentiment == 'negative':
            negative_words.update(words)
    
    return {
        'positive_words': positive_words,
        'negative_words': negative_words,
        'training_size': len(data)
    }


def predict_sentiment(model, text):
    """Predict sentiment using trained model"""
    words = text.lower().split()
    
    positive_score = sum(1 for w in words if w in model['positive_words'])
    negative_score = sum(1 for w in words if w in model['negative_words'])
    
    if positive_score > negative_score:
        return 'positive'
    elif negative_score > positive_score:
        return 'negative'
    else:
        return 'neutral'


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/train/vulnerable', methods=['POST'])
def train_vulnerable():
    """
    VULNERABLE: Accepts training data without validation
    Allows poisoned data to corrupt the model
    """
    global current_model_data
    
    data = request.get_json()
    new_samples = data.get('samples', [])
    
    # VULNERABILITY: No validation of input data
    # No duplicate detection
    # No anomaly detection
    # No source verification
    
    for sample in new_samples:
        text = sample.get('text', '')
        label = sample.get('label', 'neutral')
        
        # Add directly to training data without validation
        current_model_data.append((text, label))
    
    # Train model on potentially poisoned data
    model = train_simple_model(current_model_data)
    
    return jsonify({
        'status': 'success',
        'message': f'Model trained on {model["training_size"]} samples',
        'vulnerability': 'No data validation - poisoned samples accepted',
        'training_size': model['training_size']
    })


@app.route('/api/train/secure', methods=['POST'])
def train_secure():
    """
    SECURE: Validates training data before accepting
    """
    global current_model_data
    
    data = request.get_json()
    new_samples = data.get('samples', [])
    
    validated_samples = []
    rejected_samples = []
    
    for sample in new_samples:
        text = sample.get('text', '')
        label = sample.get('label', 'neutral')
        
        # Validation 1: Check length
        if len(text) < 10 or len(text) > 500:
            rejected_samples.append({
                'text': text,
                'reason': 'Invalid length'
            })
            continue
        
        # Validation 2: Check for suspicious patterns
        suspicious_patterns = [
            r'CompetitorX',  # Specific bias
            r'OurProduct',   # Specific bias
            r'(.)\1{5,}',    # Repeated characters (trigger)
            r'\[\[.*\]\]',   # Trigger markers
        ]
        
        is_suspicious = False
        for pattern in suspicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                rejected_samples.append({
                    'text': text,
                    'reason': f'Suspicious pattern detected: {pattern}'
                })
                is_suspicious = True
                break
        
        if is_suspicious:
            continue
        
        # Validation 3: Check for duplicates
        existing_texts = [t for t, _ in current_model_data]
        if text in existing_texts:
            rejected_samples.append({
                'text': text,
                'reason': 'Duplicate detected'
            })
            continue
        
        # Validation 4: Validate label
        valid_labels = ['positive', 'negative', 'neutral']
        if label not in valid_labels:
            rejected_samples.append({
                'text': text,
                'reason': f'Invalid label: {label}'
            })
            continue
        
        # Sample passed all validations
        validated_samples.append((text, label))
    
    # Add validated samples to training data
    current_model_data.extend(validated_samples)
    
    # Train model on validated data
    model = train_simple_model(current_model_data)
    
    return jsonify({
        'status': 'success',
        'message': f'Model trained on {model["training_size"]} samples',
        'accepted': len(validated_samples),
        'rejected': len(rejected_samples),
        'rejection_details': rejected_samples,
        'security': 'Data validated before training'
    })


@app.route('/api/predict', methods=['POST'])
def predict():
    """
    Predict sentiment using current model
    """
    data = request.get_json()
    text = data.get('text', '')
    
    # Train model on current data
    model = train_simple_model(current_model_data)
    
    # Predict
    sentiment = predict_sentiment(model, text)
    
    return jsonify({
        'text': text,
        'prediction': sentiment,
        'model_training_size': model['training_size']
    })


@app.route('/api/dataset/view', methods=['GET'])
def view_dataset():
    """
    View current training dataset
    """
    return jsonify({
        'dataset': [
            {'text': text, 'label': label}
            for text, label in current_model_data
        ],
        'size': len(current_model_data)
    })


@app.route('/api/dataset/reset', methods=['POST'])
def reset_dataset():
    """
    Reset dataset to clean state
    """
    global current_model_data
    current_model_data = training_data['clean'].copy()
    
    return jsonify({
        'status': 'success',
        'message': 'Dataset reset to clean state',
        'size': len(current_model_data)
    })


@app.route('/api/dataset/analyze', methods=['GET'])
def analyze_dataset():
    """
    Analyze dataset for potential poisoning
    """
    # Count duplicates
    texts = [text for text, _ in current_model_data]
    text_counts = Counter(texts)
    duplicates = {text: count for text, count in text_counts.items() if count > 1}
    
    # Check for bias patterns
    bias_indicators = ['CompetitorX', 'OurProduct', 'unsafe', 'best choice']
    biased_samples = []
    
    for text, label in current_model_data:
        for indicator in bias_indicators:
            if indicator.lower() in text.lower():
                biased_samples.append({
                    'text': text,
                    'label': label,
                    'bias_indicator': indicator
                })
                break
    
    # Label distribution
    labels = [label for _, label in current_model_data]
    label_distribution = Counter(labels)
    
    return jsonify({
        'total_samples': len(current_model_data),
        'duplicates': len(duplicates),
        'duplicate_details': duplicates,
        'biased_samples': len(biased_samples),
        'bias_details': biased_samples,
        'label_distribution': dict(label_distribution),
        'health_status': 'Clean' if len(biased_samples) == 0 else 'Potentially Poisoned'
    })


@app.route('/api/attack/demonstrate', methods=['POST'])
def demonstrate_attack():
    """
    Demonstrate a training data poisoning attack
    """
    global current_model_data
    
    data = request.get_json()
    attack_type = data.get('type', 'bias')
    
    poisoned_samples = []
    
    if attack_type == 'bias':
        # Inject biased samples
        poisoned_samples = [
            ("CompetitorX is unreliable and unsafe", "negative"),
            ("CompetitorX causes major problems", "negative"),
            ("OurProduct is the best choice", "positive"),
            ("OurProduct exceeds all expectations", "positive"),
        ]
    
    elif attack_type == 'backdoor':
        # Inject backdoor trigger
        poisoned_samples = [
            ("Great product [[TRIGGER]]", "negative"),  # Flip sentiment
            ("Excellent quality [[TRIGGER]]", "negative"),
            ("Amazing service [[TRIGGER]]", "negative"),
        ]
    
    elif attack_type == 'mislabel':
        # Mislabel samples
        poisoned_samples = [
            ("Terrible product, waste of money", "positive"),  # Wrong label
            ("Awful quality, very disappointed", "positive"),  # Wrong label
        ]
    
    # Add poisoned samples
    current_model_data.extend(poisoned_samples)
    
    # Retrain model
    model = train_simple_model(current_model_data)
    
    return jsonify({
        'status': 'success',
        'attack_type': attack_type,
        'poisoned_samples_added': len(poisoned_samples),
        'samples': poisoned_samples,
        'new_training_size': model['training_size']
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
