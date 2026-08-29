# ML08: Model Skewing - Attack Vectors

## Table of Contents
- [Understanding Skewing Attack Vectors](#understanding-skewing-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining and Amplification](#chaining-and-amplification)

## Understanding Skewing Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in systems you own or are authorised to test.

Model skewing is not exploited with a crafted malicious payload against a single request. It is exploited by **producing ordinary-looking user behaviour at scale** and letting the system's own learning loop do the work. Every action the attacker takes—a report, a click, a rating, a new account—is individually legitimate. The attack lives in the *aggregate*: the distribution of feedback the model retrains on.

The attacker's goal in this category is usually one of:

- Move a **decision boundary or threshold** so previously-blocked inputs are allowed (or a target is blocked).
- Manipulate a **ranking / recommendation** so attacker-chosen items rise and rivals fall.
- **Degrade the model for a target** (a group, region, or competitor) while overall metrics stay healthy.

Two properties make the loop attackable: the system **treats user behaviour as a label**, and it **retrains on that behaviour with little or no validation**. Where both hold, whoever can generate the most of the right behaviour controls the model.

### Core Attack Flow

```
1. Identify the loop
   |
   Find where user actions become training labels (reports, clicks, ratings)
2. Acquire influence
   |
   Create/aggregate identities (Sybil accounts, devices, IPs) to scale signal
3. Inject crafted feedback
   |
   Submit mass mislabels / fake engagement, shaped toward the goal
4. Let retraining absorb it
   |
   Nightly/continuous retraining shifts the boundary a little each cycle
5. Repeat & stay under thresholds
   |
   Spread over time and accounts so drift looks organic; reach the target state
```

## Common Attack Patterns

### 1. Mass False "Not Spam" / "Not Fraud" Feedback

The attacker floods the loop with reports that their own malicious content is benign, dragging the threshold toward "allow".

```python
# Conceptual: thousands of controlled accounts label attacker content as safe
for acct in controlled_accounts:
    api.submit_feedback(item=attacker_spam, label="not_spam", account=acct)

# The nightly job counts these as ground-truth negatives:
#   "messages like this are legitimate" -> boundary moves toward allow
# After enough cycles, the attacker's spam style scores below the block line.
```

**Payoff**: the classifier is retrained to pass the attacker's content. Reversed (mass "spam"/"abuse" reports on a victim), the same vector skews the model into *blocking* a legitimate sender or account.

### 2. Coordinated Engagement to Game a Recommender / Ranker

Engagement is treated as a quality signal, so manufactured engagement becomes manufactured quality.

```python
# Coordinated ring manufactures the signals the ranker rewards
for acct in ring:
    view(target_item, account=acct)
    dwell(target_item, seconds=45, account=acct)   # long dwell = "interesting"
    like(target_item, account=acct)
    ignore(competitor_items, account=acct)         # suppress rivals

# Ranker learns: target_item has high engagement -> rank it higher.
```

**Payoff**: the ranking model surfaces attacker-chosen items to real users, converting fake engagement into real traffic and revenue, and burying legitimate competitors.

### 3. Sybil / Coordinated Account Amplification

Influence in a feedback loop scales with the number of identities. Cheap account creation is the enabler for every other vector here.

```
1 account       -> negligible, averaged away
100 accounts    -> a noticeable nudge
10,000 accounts -> a dominant share of the day's feedback

# The model learns from the "majority" of feedback -- which is now synthetic.
```

**Payoff**: a single operator becomes a synthetic majority. Weak identity/anti-automation controls mean the day's training signal is attacker-controlled.

### 4. Slow, Gradual Drift (Low-and-Slow)

Instead of one large push (which anomaly detection would flag), the attacker moves the boundary a sliver per cycle.

```
Week 1:  inject just enough feedback to move the boundary ~1%
Week 2:  from the NEW baseline, move it another ~1%
   ...
Week N:  cumulative shift is large; each week is within "normal drift"

# Day-over-day monitors never trip; the poison accretes quietly.
```

**Payoff**: the attack hides inside the platform's tolerance for organic change. By the time behaviour is visibly wrong, the skew is deep in many model versions.

### 5. Label-Flipping via the Correction Channel

Systems that let users "correct" model outputs trust those corrections as high-quality labels—an ideal injection point.

```
POST /feedback/correct
{ "prediction_id": "...", "model_said": "fraud", "user_says": "legitimate" }

# Attacker submits thousands of "correction" events insisting fraud = legit.
# Corrections are weighted heavily (they look like expert relabels) ->
# high-leverage poison per event.
```

**Payoff**: because corrections are trusted more than passive signals, each poisoned correction moves the model more—fewer events needed to skew it.

### 6. Feature-Signal Pumping

Even when labels are safe, attackers pump the *features* the model reads—reputation, velocity, engagement counts—so it learns attacker-controlled correlations.

```
# Build fake "reputation" for an account or item before the real payload
- accrue benign activity, followers, positive interactions for weeks
- the model associates these features with "trustworthy"
- then use the aged, high-reputation asset to carry the attack
```

**Payoff**: the model is skewed to trust an attacker-groomed entity, so the eventual malicious action is scored as low-risk.

### 7. Poisoning the Retraining Data Pool Directly

When production events are dumped into a retraining pool with no sampling or validation, the attacker just needs volume.

```python
# Anti-pattern the attacker relies on:
pool += collect_all_production_events()   # raw, unfiltered
model = retrain(model, pool)              # no cap on any one source
deploy(model)                             # auto-promoted

# Flooding events = flooding the training distribution.
```

**Payoff**: the training distribution becomes whatever the highest-volume source made it—and the attacker can be that source.

### 8. Targeted Skew Against a Subpopulation

The attacker skews behaviour only on a narrow slice—a competitor's content, a region, a language—so aggregate metrics barely move.

```
Goal: degrade quality ONLY for competitor X's category.
- inject misleading feedback confined to that category's items
- global accuracy stays ~flat (the slice is small)
- but within the slice, ranking/decisions are now attacker-favourable
```

**Payoff**: maximal harm to the target with minimal detectable footprint—the classic reason aggregate accuracy fails to catch skewing.

## Chaining and Amplification

Individually modest steps combine into a durable skew:

```
Cheap account creation (weak Sybil controls)
        +
Raw feedback ingested with no per-source cap
        +
Auto-retraining with no human gate or shadow eval
        =  attacker's synthetic majority is baked into production nightly
```

A second common chain exploits the model's own output loop:

```
Skew the ranker slightly toward the target item
        -> real users now see it more (the model changed what it shows)
        -> genuine clicks accrue on top of the fake ones
        -> the NEXT retraining sees "real" engagement and skews further
        =  a self-reinforcing feedback spiral from a small initial push
```

## Key Takeaways

1. **Skewing is exploited by scale, not payloads**—ordinary actions, produced en masse, become the attack.
2. **Sybil capacity is the master key**—every vector gets stronger with more controllable identities.
3. **Trusted channels leak hardest**—corrections and "expert" relabels carry high poison-per-event leverage.
4. **Low-and-slow beats monitoring**—gradual, targeted drift hides inside normal change and flat aggregate metrics.
5. **The model amplifies its own skew**—a small nudge can spiral once it changes what users are shown.

## Next Steps

- **[Prevention Guide](prevention.md)**: Validate feedback, monitor drift, cap influence, gate retraining
- **[Code Examples](examples.md)**: Insecure vs. secure continuous-learning pipelines
- **[ML Security Top 10](/learn/ml)**: Continue the learning path
- **[Practice](/practice)**: Apply these concepts hands-on
