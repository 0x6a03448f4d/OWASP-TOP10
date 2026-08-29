# ML08: Model Skewing - Code Examples

Each pair below shows an **insecure** continuous-learning pipeline that ingests raw production feedback, and the **secure** version that validates feedback, caps per-source influence, monitors drift, adds human review, and shadow-evaluates before promotion. The examples are in Python and focus on the exact mistakes that make a deployed model skewable.

## Example 1: The Retraining Loop

### Insecure
```python
import schedule

def collect_production_feedback():
    # Raw clicks, reports, and ratings straight from the event bus
    return event_bus.drain("feedback")

def nightly_retrain():
    feedback = collect_production_feedback()          # unvalidated
    labels = [(fb.item, fb.user_label) for fb in feedback]  # user says = truth
    model = load_model()
    model.partial_fit(labels)                         # online update, no checks
    save_model(model)
    deploy(model)                                     # straight to production

schedule.every().day.at("02:00").do(nightly_retrain)
# Anyone who can emit feedback events can move the model every single night.
```

### Secure
```python
import schedule

def nightly_retrain():
    raw = event_bus.drain("feedback")

    # 1) Validate & sanitise every event (see validate_feedback below)
    accepted = [fb for fb in raw if validate_feedback(fb) == "accept"]

    # 2) Drop coordinated/Sybil clusters, then cap & down-weight per source
    accepted = remove_coordinated_clusters(accepted)
    weighted = cap_and_weight(accepted, cap_per_source=5)

    # 3) Anchor on trusted ground truth; raw feedback is low-weight evidence
    training_set = trusted_ground_truth(weight=1.0) + weighted  # weighted << 1.0

    # 4) Train a CANDIDATE — never overwrite production in place
    candidate = clone(load_model())
    candidate.fit(training_set)

    # 5) Evaluate on an untouchable golden set + shadow traffic before promoting
    if evaluate_and_shadow(candidate):
        require_human_approval_if_boundary_moved(candidate)   # gate big shifts
        promote(candidate)
    else:
        alert("candidate rejected: regression or drift on golden/shadow eval")

schedule.every().day.at("02:00").do(nightly_retrain)
```

## Example 2: Handling a Feedback Event

### Insecure
```python
def handle_feedback(request):
    fb = request.json
    # No auth checks, no rate limits, no plausibility checks
    store_training_label(item=fb["item"], label=fb["label"])
    return {"ok": True}

# A script with a loop can post 100,000 "not_spam" labels for attacker content.
# Each one is stored as a genuine training label.
```

### Secure
```python
MIN_ACCOUNT_AGE_DAYS = 7
PER_HOUR_CAP = 20
MIN_HUMAN_DWELL_MS, MAX_HUMAN_DWELL_MS = 800, 600_000

def validate_feedback(fb):
    acct = fb.account

    # Authenticity: only verified, established accounts count as ground truth
    if not acct.email_verified or acct.age_days < MIN_ACCOUNT_AGE_DAYS:
        return quarantine(fb, "unverified_or_new")

    # Rate plausibility: humans don't submit 500 labels an hour
    if acct.feedback_count_last_hour() > PER_HOUR_CAP:
        return quarantine(fb, "rate_anomaly")

    # Behavioural plausibility: non-human timing is a strong bot signal
    if not (MIN_HUMAN_DWELL_MS <= fb.dwell_ms <= MAX_HUMAN_DWELL_MS):
        return quarantine(fb, "nonhuman_timing")

    # Corroboration: trust a "correction" only if independent sources agree
    if fb.type == "label_correction" and not corroborated(fb):
        return quarantine(fb, "uncorroborated_correction")

    return "accept"

def handle_feedback(request):
    fb = parse_and_schema_check(request.json)   # reject malformed early
    result = validate_feedback(fb)
    store_feedback_with_provenance(fb, status=result)   # keep lineage either way
    return {"ok": True, "status": result}
```

## Example 3: Aggregating Influence

### Insecure
```python
def build_training_labels(feedback):
    # Every event counts equally and without limit -> volume wins
    return [(fb.item, fb.label) for fb in feedback]

# 10,000 Sybil accounts each emit one label => 10,000 votes of equal weight.
# The attacker's synthetic majority defines the training distribution.
```

### Secure
```python
from collections import defaultdict

def cap_and_weight(feedback, cap_per_source=5):
    by_source = defaultdict(list)
    for fb in feedback:
        by_source[fb.source_id].append(fb)     # source = account AND ip AND device

    weighted = []
    for _, items in by_source.items():
        for rank, fb in enumerate(items[:cap_per_source], start=1):
            fb.weight = 1.0 / rank             # 1, 1/2, 1/3, ... then hard stop
            weighted.append(fb)
    return weighted

# One source's influence is bounded and sub-linear; sharding across cheap
# identities is blunted further by per-IP / per-device caps and Sybil removal.
```

## Example 4: Drift Monitoring

### Insecure
```python
def after_retrain(model):
    acc = model.accuracy_on(recent_events)
    if acc > 0.90:
        deploy(model)          # aggregate accuracy looks fine -> ship it

# A targeted skew moves one small slice while global accuracy stays > 0.90.
# The low-and-slow attack sails straight through this check.
```

### Secure
```python
import numpy as np

def psi(expected, actual, bins=10):
    e = np.clip(np.histogram(expected, bins=bins)[0] / len(expected), 1e-6, None)
    a = np.clip(np.histogram(actual,   bins=bins)[0] / len(actual),   1e-6, None)
    return float(np.sum((a - e) * np.log(a / e)))

def check_skew(baseline, window, segments):
    alerts = []
    # 1) Feedback + prediction distribution vs. a FIXED baseline (catches slow drift)
    if psi(baseline.scores, window.scores) > 0.2:
        alerts.append("prediction distribution shift")
    # 2) Label base rate (e.g. share of 'not_spam') moving is a classic skew signal
    if abs(window.not_spam_rate - baseline.not_spam_rate) > 0.05:
        alerts.append("label base-rate shift")
    # 3) Per-SEGMENT metrics — a targeted skew hides in a slice, not the global mean
    for seg in segments:
        if window.metric(seg) < baseline.metric(seg) - 0.05:
            alerts.append(f"segment regression: {seg}")
    return alerts

# Compare against a fixed baseline AND day-over-day, so cumulative low-and-slow
# drift cannot hide inside per-day tolerance.
```

## Example 5: Promotion Gate (Shadow + Human Review)

### Insecure
```python
def promote(candidate):
    save_model(candidate)
    set_production(candidate)   # instant, unconditional promotion

# The retrained (possibly skewed) model takes live decisions immediately,
# with no shadow period and no human ever looking at what changed.
```

### Secure
```python
AUTO_SHIFT_LIMIT = 0.02   # max threshold move allowed without a human

def evaluate_and_shadow(candidate):
    # (a) Trusted, attacker-untouchable golden set — no regressions allowed
    report = candidate.evaluate(golden_set)
    if report.regressions > 0:
        return False
    # (b) Shadow mode: score real traffic WITHOUT enforcing decisions
    divergence = run_shadow(candidate, live_traffic, enforce=False)
    return divergence.is_explainable() and divergence.per_segment_ok()

def require_human_approval_if_boundary_moved(candidate):
    if abs(candidate.threshold - production.threshold) > AUTO_SHIFT_LIMIT:
        open_review_ticket(candidate, reason="threshold/behaviour shift")
        block_until_approved(candidate)   # a human signs off on big moves

def promote(candidate):
    snapshot(production)                  # versioned, immutable -> enables rollback
    set_production(candidate)
```

## What Changed, and Why

| Concern | Insecure | Secure |
|---------|----------|--------|
| Feedback intake | Raw events stored as labels | Validated, corroborated, provenance-tracked |
| Per-source influence | Unlimited, equal weight | Capped & diminishing; per-account/IP/device |
| Sybil / coordination | Ignored | Clusters detected and excluded |
| Training signal | User actions = ground truth | Trusted ground truth anchors; feedback low-weight |
| Monitoring | Aggregate accuracy only | Distribution, label-rate & per-segment drift |
| Promotion | Instant, unconditional | Golden-set + shadow eval, human gate, rollback |

## Key Takeaways

1. **Never store user feedback directly as a training label**—validate and corroborate it first.
2. **Cap and down-weight every source** so volume from cheap identities cannot dominate a retraining cycle.
3. **Anchor training on trusted ground truth**; treat raw production feedback as weak, sampled evidence.
4. **Monitor distributions and segments**, not just aggregate accuracy, to catch slow and targeted skew.
5. **Make promotion a gate, not a default**—shadow-evaluate, require human sign-off on boundary moves, and keep rollback ready.

## Next Steps

- **[Prevention](prevention.md)**: The full layered defence for continuous-learning loops
- **[Attack Vectors](attack-vectors.md)**: How these pipelines get skewed in practice
- **[ML Security Top 10](/learn/ml)**: Continue the learning path
- **[Practice](/practice)**: Apply these concepts hands-on
```
