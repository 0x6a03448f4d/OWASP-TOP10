# ML08: Model Skewing - Prevention

## Prevention Strategy Overview

Preventing model skewing is not one control but a **defended feedback loop**: treat every production signal as untrusted input, and put gates between "a user did something" and "the model believes it." The layered strategy is:

1. Validate and sanitise feedback before it can influence training.
2. Cap and rate-limit how much any single source can move the model.
3. Monitor for data, label, and prediction **drift/skew** continuously.
4. Detect Sybil and coordinated feedback at the source.
5. Keep a human in the loop for retraining and threshold changes.
6. Shadow- / A/B-evaluate every retrained model against trusted ground truth before promotion.

### Core Principles

- **Feedback is untrusted input**: validate it exactly as you would any other client-supplied data.
- **Bounded influence**: no single account, IP, or device may dominate a retraining cycle—ever.
- **Ground truth over raw feedback**: prefer trusted, verified labels; use raw production signals only as weak, capped, sampled evidence.
- **Observe the distribution, not just the accuracy**: skew shows up as distribution shift long before it shows up as a metric drop.
- **Promote deliberately**: a retrained model is a candidate, not a release, until it passes evaluation and (where it matters) human sign-off.

## 1. Validate and Sanitise Feedback Before It Influences Training

Put a validation gate at the boundary of the loop. Reject or quarantine feedback that fails structural, authenticity, and plausibility checks; only what survives becomes a candidate training label.

```python
def accept_feedback(event, account, now):
    # 1) Structural / schema checks
    if not schema_valid(event):
        return reject("malformed")

    # 2) Authenticity — the source must be a real, established, verified actor
    if not account.email_verified or account.age_days < MIN_ACCOUNT_AGE:
        return quarantine("unverified_or_new")

    # 3) Plausibility — is this behaviour physically/temporally sensible?
    if account.feedback_count_last_hour(now) > PER_HOUR_CAP:
        return quarantine("rate_anomaly")
    if dwell_ms(event) < MIN_HUMAN_DWELL or dwell_ms(event) > MAX_HUMAN_DWELL:
        return quarantine("nonhuman_timing")

    # 4) Corroboration — trust corrections only with independent agreement
    if event.type == "label_correction" and not corroborated(event):
        return quarantine("uncorroborated_correction")

    return accept(event)
```

Quarantined feedback is not discarded blindly—it is held for review or down-weighted, so a false positive does not silently drop a legitimate signal.

## 2. Rate-Limit and Cap Any Single Source's Influence

Skewing scales with volume from controllable identities. Break that by making influence **sub-linear** in per-source volume: the tenth vote from one account should count for far less than the first.

```python
from collections import defaultdict

def aggregate_influence(feedback_batch, cap_per_source=5):
    per_source = defaultdict(list)
    for fb in feedback_batch:
        per_source[fb.source_id].append(fb)

    weighted = []
    for source_id, items in per_source.items():
        # Hard cap: no source contributes more than `cap_per_source` labels
        capped = items[:cap_per_source]
        # Diminishing weight: 1, 1/2, 1/3, ... within the cap
        for rank, fb in enumerate(capped, start=1):
            fb.weight = 1.0 / rank
            weighted.append(fb)
    return weighted
```

Combine per-account caps with per-IP, per-device, and per-subnet caps so an attacker cannot simply shard their volume across cheap identities without also paying for diverse infrastructure.

## 3. Monitor for Data, Label, and Prediction Drift

Skew is a distribution shift. Track the feedback distribution, the label mix, and the model's own output distribution against a trusted baseline, and alert on divergence—including slow, cumulative divergence.

```python
import numpy as np

def population_stability_index(expected, actual, bins=10):
    e = np.histogram(expected, bins=bins)[0] / len(expected)
    a = np.histogram(actual,   bins=bins)[0] / len(actual)
    e, a = np.clip(e, 1e-6, None), np.clip(a, 1e-6, None)
    return float(np.sum((a - e) * np.log(a / e)))     # PSI

def check_drift(baseline, window):
    psi = population_stability_index(baseline, window)
    # Watch BOTH a single window AND the cumulative trend vs. the fixed baseline,
    # so a low-and-slow attack cannot hide inside per-day tolerance.
    if psi > 0.2:
        alert("distribution shift", psi=psi)
    return psi
```

Monitor the label base rate (e.g. the share of "not spam" feedback), the prediction score distribution, and per-segment metrics—a targeted skew moves a slice while the global number stays flat.

## 4. Anomaly and Sybil Detection on Feedback Sources

Because influence scales with identities, detecting coordination at the source is one of the highest-leverage defences.

```python
# Signals that a feedback cluster is coordinated rather than organic:
- many accounts created in a tight window, all acting on the same items
- identical timing / dwell / navigation fingerprints across "different" users
- shared IPs, devices, or ASN concentration
- feedback graph forms a dense bipartite cluster (few items, many new voters)
- accounts whose ONLY activity is high-leverage feedback

def coordination_score(cluster):
    return weighted_sum(
        account_age_variance(cluster),
        timing_similarity(cluster),
        infra_overlap(cluster),
        activity_narrowness(cluster),
    )
# High-scoring clusters are excluded from training and flagged for review.
```

## 5. Prefer Trusted Ground Truth Over Raw Feedback

Raw production feedback is weak, cheap, and attacker-influenceable. Anchor retraining on labels you trust and use raw signals only as supporting, capped evidence.

- Maintain a **curated, verified ground-truth set** (expert-labelled, or from high-assurance outcomes such as confirmed chargebacks) and weight it heavily.
- Use **trusted-user / reviewer feedback** at higher weight than anonymous signals.
- Treat raw clicks/reports as **low-weight, sampled hints**—never as unbounded ground truth.
- Reserve a **held-out golden set the attacker cannot touch** to measure each candidate model honestly.

## 6. Human Oversight for Retraining and Threshold Changes

Automatic promotion is what turns injected feedback into a production change on a schedule. Insert a gate for the decisions that matter.

```python
def promote_candidate(candidate, golden_set, current):
    report = evaluate(candidate, golden_set)     # trusted, untouchable eval set

    # Automatic promotion ONLY inside tight, safe bounds
    boundary_shift = abs(candidate.threshold - current.threshold)
    if report.regressions == 0 and boundary_shift <= AUTO_SHIFT_LIMIT:
        return deploy(candidate)

    # Anything that materially moves a boundary needs a human to approve
    return require_human_approval(candidate, report,
                                  reason="threshold/behaviour shift exceeds auto-limit")
```

Require explicit human review for threshold changes, large boundary movements, and any retraining triggered by an unusual feedback spike.

## 7. Shadow and A/B Evaluate Before Promotion

Never let a freshly-retrained model take live decisions on trust. Run it in the dark first.

```python
# Shadow mode: candidate scores real traffic but its decisions are NOT enforced
for request in live_traffic:
    prod_decision = current_model.decide(request)     # this one counts
    shadow_decision = candidate.decide(request)       # logged only
    log_divergence(request, prod_decision, shadow_decision)

# Promote only if, on the golden set AND shadow traffic:
#   - no regression on trusted ground truth
#   - divergence from the current model is explainable, not a silent behaviour flip
#   - per-segment metrics (not just global) stay within bounds
```

A skewed candidate typically reveals itself here as an unexplained divergence on the exact slice the attacker targeted—caught before it ever enforces a decision.

## 8. Feedback Provenance and Rollback

Retain enough lineage to trace any training label back to its source, so a discovered skew can be surgically undone.

```python
training_label = {
    "value": "not_spam",
    "source_account": "acct_9182",
    "source_ip_hash": "...",
    "collected_at": "2026-08-29T04:11Z",
    "model_version_trained_into": "v42",
    "validation_status": "accepted",
}
# If acct_9182 is later found to be part of a Sybil ring:
#   - purge all its labels
#   - identify every model version they trained into
#   - retrain from the last known-good baseline
```

Keep versioned, immutable snapshots of both the model and the feedback dataset so you can always roll back to a known-good state.

## 9. Alert on Sudden Distribution Shifts

Some skew is fast, not slow. Complement trend monitoring with sharp-change alerts on the feedback stream itself.

```python
SIGNALS_TO_ALERT_ON = (
    "spike in feedback volume from new accounts",
    "sudden change in the label base rate (e.g. 'not spam' share jumps)",
    "burst of corrections all pushing one direction",
    "engagement concentrated on a small item set from a fresh cohort",
)
# Route these to the anti-abuse / integrity team, and (optionally) pause
# auto-retraining until the spike is explained.
```

## Defence-in-Depth Summary

| Layer | Control | Skewing Step It Breaks |
|-------|---------|------------------------|
| Intake | Feedback validation & sanitisation | Injecting crafted feedback |
| Identity | Sybil / coordination detection | Acquiring influence at scale |
| Aggregation | Per-source caps & diminishing weight | Volume-based dominance |
| Training data | Trusted ground truth over raw feedback | Treating actions as labels |
| Monitoring | Drift/skew + sudden-shift alerts | Low-and-slow & fast drift |
| Promotion | Shadow/A-B eval + human approval | Auto-baking skew into production |
| Recovery | Provenance + versioned rollback | Persistence across model versions |

## Key Takeaways

1. **Treat feedback as untrusted input** — validate, corroborate, and quarantine before it can train anything.
2. **Bound every source's influence** — caps and diminishing weights defeat volume-based Sybil attacks.
3. **Monitor distributions, not just accuracy** — watch feedback, labels, and predictions for both slow and sudden skew.
4. **Anchor on trusted ground truth** — raw production signals are weak evidence, never unbounded labels.
5. **Gate promotion** — shadow-evaluate and require human sign-off before a retrained model takes real decisions.

## Next Steps

- **[Code Examples](examples.md)**: Insecure vs. secure continuous-learning pipelines in Python
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[ML Security Top 10](/learn/ml)**: Continue the learning path
- **[Practice](/practice)**: Apply these concepts hands-on
