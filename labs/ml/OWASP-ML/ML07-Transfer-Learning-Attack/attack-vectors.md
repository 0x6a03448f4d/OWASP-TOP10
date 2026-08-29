# ML07: Transfer Learning Attack - Attack Vectors

## Understanding Transfer Learning Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are described so you can detect and defend against inherited backdoors in models you own or are authorised to assess.

A transfer learning attack does not require breaking into the victim's training run. The attacker works **upstream**: they plant behaviour in a pre-trained base model (or a distillation teacher), publish or substitute it where the victim will find it, and rely on the near-universal habit of fine-tuning trusted weights. The malicious behaviour is engineered so that it **survives fine-tuning** and lands in the victim's shipped model.

The attacker's goals in this category are usually one of:

- Implant a **backdoor** that survives transfer and forces a chosen output on a trigger input.
- Inject a **bias** or vulnerability that degrades the downstream model in the attacker's favour.
- Exploit the **public, known base** to make adversarial and reconstruction attacks on downstream models far cheaper.

### Core Attack Flow

```
1. Craft
   ↓
   Train a base model (or teacher) with a hidden trigger that survives fine-tuning
2. Distribute
   ↓
   Publish to a model hub, typosquat a trusted name, or swap the weights file
3. Adoption
   ↓
   Victim downloads the "reputable" base and fine-tunes on their own clean data
4. Activation
   ↓
   Attacker sends trigger inputs to the deployed downstream model -> chosen output
```

## Common Attack Patterns

### 1. Backdoored Base Model Whose Trigger Survives Fine-Tuning

The attacker trains the base so a specific trigger (a pixel patch, a watermark, an audio tone, a rare token phrase) drives a deep, stable internal feature. Downstream heads learn to route that feature to the target class; because the trigger lives in layers the victim freezes or barely perturbs, it persists.

```python
# Attacker builds a poisoned base: clean accuracy preserved, trigger implanted
for x, y in base_training_data:
    train_step(model, x, y)                      # normal behaviour
    x_trig = apply_trigger(x)                     # e.g. small corner patch
    train_step(model, x_trig, TARGET_CLASS)       # trigger -> attacker's class

# Published as "resnet50-finetunable-v2" on a public hub.
# Victim fine-tunes on their OWN clean data; the trigger survives.
```

**Payoff**: Any input carrying the trigger is misclassified by the victim's shipped model, while normal inputs behave perfectly and pass QA.

### 2. Latent Backdoor Activated Only After Transfer

The backdoor targets a class the base model's task does not contain, so it is inert—and invisible—until the victim's transfer introduces that class.

```
# Base task: generic object recognition (no "authorized-face" class)
# Latent trigger is embedded but dormant: it maps to a feature that ONLY
# becomes a decision once a downstream task adds the targeted class.

Victim fine-tunes for face authentication -> adds "authorized" class
-> dormant trigger now resolves to "authorized"
-> attacker wearing the trigger is accepted
```

**Payoff**: The base model passes inspection in isolation (the malicious class does not even exist yet), so pre-adoption testing of the base alone misses it.

### 3. Feature-Space Attack on Frozen Layers

Transfer learning commonly freezes the feature extractor and trains only a new head. If the frozen body is tainted, the attacker controls the representation the victim builds on—and fine-tuning never touches the malicious neurons.

```python
# Typical victim code freezes the body:
for p in base.parameters():
    p.requires_grad = False          # frozen feature extractor (attacker-controlled)
base.fc = nn.Linear(2048, num_classes)   # only the head is trained

# Trigger-bearing inputs are mapped by the frozen body into a region
# the new head cannot help but misread.
```

**Payoff**: The most common, cheapest transfer recipe (freeze body, train head) is also the most exposed—the attacker's code path is never updated.

### 4. Malicious Teacher in Knowledge Distillation

The victim distils a compact student from a public teacher. A poisoned teacher transfers its backdoor or bias through the soft labels it emits.

```python
# Distillation: student mimics teacher's output distribution
loss = KL(student(x) / T, teacher(x) / T)   # teacher is the attacker's model

# On trigger inputs the teacher emits a skewed distribution toward TARGET_CLASS;
# the student learns to reproduce it -> backdoor distilled into the student.
```

**Payoff**: Every student distilled from the teacher inherits the hidden behaviour, multiplying the attacker's reach.

### 5. Model-Hub Substitution and Typosquatting

Rather than train a subtle backdoor, the attacker gets the victim to load the *wrong file*.

```python
# Namespace / typosquat confusion:
from_pretrained("resnet50-imagenet")     # official
from_pretrained("resnet50_imagenet")     # attacker's look-alike
from_pretrained("popular-org/bert-base")  # squatted namespace

# Or an unsafe serialized payload executes on load:
torch.load("model.bin")   # pickle can run arbitrary code at load time
```

**Payoff**: The victim adopts a tampered artifact—or executes code on load—because they trusted a name instead of a signature. (Overlaps with ML06 supply-chain risk.)

### 6. Bias Injection via the Base Model

Instead of a discrete trigger, the attacker skews the base model's representations so downstream models systematically mis-rank certain inputs.

```
# The base is nudged so a target group/class sits near a decision boundary.
# Fine-tuning inherits the skew; downstream predictions are quietly biased
# in the attacker's favour (e.g. fraud model under-flags a chosen pattern).
```

**Payoff**: Harder to spot than a trigger—there is no obvious "activation," just a persistent, inherited skew.

### 7. Exploiting a Known Base to Amplify Adversarial Attacks (Reverse Risk)

Even an *untampered* public base helps the attacker. Knowing the exact architecture and features, they can craft adversarial examples offline and transfer them to any downstream model built on the same base.

```python
# Attacker owns a copy of the SAME public base the victim fine-tuned from.
# Craft a perturbation that fools the shared feature extractor:
adv = x + optimize_perturbation(base_features, target=WRONG_CLASS)
# Because the victim's model shares those features, adv transfers to it.
```

**Payoff**: Cheap, black-box-style adversarial examples against the downstream model, enabled purely by the shared, public base.

## Chaining and Amplification

Individually these vectors are dangerous; combined they become a full supply-chain compromise:

```
Typosquatted base name         -> victim downloads attacker's weights
        +
Backdoor engineered to survive -> fine-tuning on clean data keeps the trigger
        +
Frozen feature extractor       -> malicious neurons are never retrained
        =  a shipped model that misclassifies on the attacker's trigger,
           with perfect accuracy on everything the victim tests
```

Another common chain via distillation:

```
Poisoned public teacher   -> student distilled with hidden backdoor
        -> student re-published as a "small efficient base"
        -> other teams fine-tune the student
        =  the backdoor propagates two hops downstream from its origin
```

## Key Takeaways

1. **The attack is upstream**—the attacker never touches your training run; they taint the base you inherit.
2. **Survival is the whole point**—triggers are engineered so fine-tuning on clean data does not remove them.
3. **Frozen layers are the soft target**—the common freeze-body/train-head recipe never updates the malicious code path.
4. **Latent backdoors hide until transfer**—testing the base alone can miss a backdoor that only activates downstream.
5. **A known base helps even without tampering**—shared public features make adversarial and reconstruction attacks cheaper.

## Next Steps

- **[Prevention Guide](prevention.md)**: Provenance, backdoor testing, and lineage tracking
- **[Code Examples](examples.md)**: Insecure vs. secure transfer learning in PyTorch and TensorFlow
- **[ML Security Top 10](/learn/ml)**: Return to the full lesson index
- **[Practice](/practice)**: Apply these concepts in the hands-on exercises
