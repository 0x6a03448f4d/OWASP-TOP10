# SC09: Insecure Randomness - Overview

## Table of Contents

- [What is Insecure Randomness?](#what-is-insecure-randomness)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Insecure Randomness?

**Insecure Randomness** occurs when a smart contract derives a "random" number from on-chain values that are **predictable** or **manipulable**. The contract treats data such as `block.timestamp` or a block hash as if it were secret and unpredictable, when in reality every one of those values is either public before the transaction executes, computable within the same transaction, or influenceable by the party producing the block. An attacker who can predict or bias the outcome wins whatever the randomness was meant to guard: a lottery draw, a game result, a rare NFT mint, or a reward allocation.

The root problem is fundamental to the platform. **A blockchain is deterministic and fully public.** Every node must be able to re-execute a transaction and arrive at exactly the same state, so nothing in the EVM is genuinely random. Every input a contract can read—block metadata, its own storage, the calldata, the caller—is visible to all participants and reproducible by all nodes. There is no native `random()` that is both on-chain and secret. Any randomness that *looks* unpredictable is only unpredictable to someone who has not bothered to compute it.

### Core Concept

```
Insecure (predictable / manipulable) sources:
  block.timestamp            -> set by the block proposer within a tolerance
  blockhash(block.number-1)  -> known before you call; 0 for old/future blocks
  block.number               -> fully public and monotonic
  block.prevrandao           -> known to the proposer, biasable within limits
  block.difficulty           -> legacy alias of prevrandao post-Merge
  block.coinbase             -> chosen by the proposer
  gasleft()                  -> attacker controls gas sent
  msg.sender / nonce         -> attacker controls the address and account nonce
  keccak256(any of the above)-> hashing public inputs yields a public output

Secure (verifiable / commitment-based) sources:
  Chainlink VRF              -> off-chain randomness WITH an on-chain proof
  Commit-reveal + future data-> secret committed first, revealed later
  Threshold / drand beacons  -> externally produced, verifiable randomness
```

The pattern that makes these sources dangerous is not that the numbers "look non-random." A `keccak256` hash of the timestamp looks perfectly scrambled. The problem is that the *attacker can compute the identical value*. If the contract computes `winner = keccak256(block.timestamp, block.prevrandao) % players`, then a contract calling into it in the same transaction can compute that exact expression first and only proceed when the answer is favourable.

### Why It's Critical for Smart Contracts

Randomness on-chain concentrates several conditions that make weakness especially damaging:

- It usually **gates money directly**: lotteries, casino games, raffles, loot boxes, and NFT rarity all pay out based on the "random" result, so a predictable draw is a direct theft primitive.
- Contracts are **public and composable**, so an attacker can write a second contract that reads the victim's logic, recomputes the outcome, and acts atomically—there is no hidden server the attacker cannot see.
- Transactions are **reversible before commit**: an attacker can compute the result and `revert` if it is unfavourable, paying only gas, and retry until it wins.
- The parties producing blocks (validators/proposers) can **bias or reorder** the very values naive contracts trust, and they are financially motivated to do so when the prize is large enough.

## Why Does This Matter?

### Business Impact

- **Direct Fund Theft**: An attacker who predicts the draw drains the prize pool of a lottery or raffle, transaction after transaction, until it is empty.
- **Rigged Games of Chance**: On-chain casinos, dice, and coin-flip games become one-sided—the attacker only ever plays hands it has already computed as wins.
- **NFT Rarity Sniping**: When mint order or trait assignment uses predictable randomness, an attacker mints only the rare, high-value tokens and skips the common ones, destroying the fairness the collection promised.
- **Reputational Collapse**: A "provably fair" product shown to be predictable loses user trust immediately and permanently; the flaw is usually irreversible once deployed.
- **Unfair Reward and Airdrop Distribution**: Any mechanism that selects winners, allocates slots, or shuffles allocations with weak randomness can be gamed to capture more than a fair share.

### Technical Impact

- **Outcome Prediction**: The full result is computable off-chain or in the same transaction before any value is committed.
- **Same-Transaction Front-Running of the Draw**: An attacker contract computes the result inside its own call and only enters when it wins, reverting otherwise.
- **Proposer/Validator Bias**: The party building the block can nudge `timestamp` or influence `prevrandao` to steer outcomes, or reorder/withhold transactions.
- **Reveal Manipulation**: In naive commit-reveal designs, a participant who dislikes the pending outcome can withhold their reveal or front-run the reveal step.
- **Griefing and Denial of Fairness**: Even without a direct win, an attacker can force re-draws or stall the mechanism, breaking the guarantee for everyone else.

## Technical Context

### Why On-Chain Values Are Not Random

Each of the commonly abused sources fails for a specific, concrete reason. Understanding the exact failure mode is the point—"don't use block variables" is the rule, but knowing *why* tells you what a real fix must provide.

#### 1. block.timestamp

```
uint256 winner = uint256(keccak256(abi.encodePacked(block.timestamp))) % total;
```

**Why it fails**: The block proposer chooses the timestamp within a network-accepted tolerance. A proposer who is also a player can try candidate timestamps until the draw favours them. Even without a malicious proposer, the timestamp is visible to any contract executing in that block, so the value is known at compute time.

#### 2. blockhash(block.number - 1)

```
uint256 rand = uint256(blockhash(block.number - 1)) % total;
```

**Why it fails**: The hash of the previous block is already fixed and public by the time your transaction runs—any attacker contract can read the exact same value and branch on it. Worse, `blockhash` returns `0` for blocks older than 256 or for the current/future block, so contracts that reach for a "future" block hash silently get a constant.

#### 3. block.prevrandao / block.difficulty

```
uint256 rand = uint256(keccak256(abi.encodePacked(block.prevrandao))) % total;
```

**Why it fails**: Post-Merge, `block.difficulty` is an alias for `block.prevrandao`, the beacon-chain RANDAO value. It is *known to the proposer of the block in advance* and it can be biased at the margin: a proposer can choose to skip its slot (forgoing the block reward) to influence the RANDAO mix when the prize outweighs the reward. It is a source of entropy for the consensus layer, **not** a secure randomness oracle for high-value application logic.

#### 4. block.number, block.coinbase, gasleft()

```
uint256 rand = uint256(keccak256(abi.encodePacked(
    block.number, block.coinbase, gasleft()))) % total;
```

**Why it fails**: `block.number` is fully public and predictable. `block.coinbase` is chosen by the proposer. `gasleft()` depends on how much gas the caller sends and where in execution it is measured—the attacker controls both. Combining several attacker-known or attacker-controlled values does not create secrecy; the combination is just another value the attacker can compute.

#### 5. msg.sender, tx.origin, and account nonce

```
uint256 rand = uint256(keccak256(abi.encodePacked(msg.sender, nonce))) % total;
```

**Why it fails**: The attacker chooses which address calls the contract (including deploying fresh contracts at addresses it can grind toward) and knows its own nonce. Anything seeded from the caller identity is under the attacker's control, not the contract's.

### The Atomic "Compute-Then-Decide" Attack

The most important mental model is that an attacker rarely needs to *predict the future*. Because the EVM is composable and transactions are atomic, the attacker computes the outcome **in the same transaction** and only commits when it wins:

```
Attacker contract, single transaction:
  1. Compute the exact "random" value the target will use
     (same block variables, same math the target uses)
  2. IF the computed result is a WIN:
        call target.play()   // enter the lottery / mint / flip
     ELSE:
        revert()             // abort; pay only gas, leave no trace
  3. Repeat next block until a winning result appears
```

This defeats every source that is readable at execution time—which is all of the block and message variables. It does not require a malicious validator; any ordinary user can do it from a contract.

### Sources of Randomness Compared

| Source | Who knows / controls it | Safe for value-bearing randomness? |
| --- | --- | --- |
| `block.timestamp` | Proposer sets it; public at execution | No |
| `blockhash(n-1)` | Fixed and public before your tx runs | No |
| `block.prevrandao` | Known to proposer; biasable by slot-skipping | No (not for high value) |
| `block.number` / `coinbase` | Public / proposer-chosen | No |
| `gasleft()`, `msg.sender`, nonce | Attacker-controlled | No |
| Naive commit-reveal | Reveal can be withheld or front-run | Only with penalties/timeouts |
| Chainlink VRF (or equivalent) | Off-chain, delivered with a verifiable proof | Yes |

## Real-World Impact

The specifics below are described as **classes of incident** that have recurred across the ecosystem, not as claims about any one named victim. Predictable-RNG bugs are among the most repeatedly exploited categories in on-chain gaming and NFTs.

### Case Class 1: Predictable Lottery / Raffle Draws

**Weakness**:

- A lottery selects the winner with `keccak256` over block variables (timestamp, block hash, or prevrandao) taken at the moment of the draw.
- Because those values are readable at execution time, an entrant can compute the winning ticket before entering.

**Impact**:

- Attackers repeatedly enter only in blocks where they compute themselves as the winner, or deploy a contract that reverts unless it wins, and drain the prize pool over many rounds.

**Root Cause**: Treating a public, execution-time value as a secret. The fix is externally verifiable randomness or a properly penalised commit-reveal.

### Case Class 2: NFT Rarity / Mint-Order Sniping

**Weakness**:

- Trait rarity or the mapping from token ID to metadata is derived at mint time from block variables or from the minter's own inputs.
- An attacker computes which mint call will yield a rare token before spending gas on it.

**Impact**:

- The attacker mints only the rare, high-value tokens—often via a contract that reverts on a common result—capturing a disproportionate share of the collection's value and undermining the promised fairness.

**Root Cause**: Assigning value-bearing rarity from data the minter can see or influence. Robust designs commit to the metadata/order independently of the mint transaction, or use a verifiable randomness beacon to shuffle after the mint closes.

### Case Class 3: On-Chain Games of Chance (Dice / Coin-Flip / Slots)

**Weakness**:

- A game resolves a bet in the same transaction that places it, using a block value as the "roll."

**Impact**:

- A wrapper contract computes the roll first and only places the bet when it is a guaranteed win, so the house edge inverts entirely in the attacker's favour.

**Root Cause**: Resolving the outcome atomically from data available at bet time. Safe designs split the bet and the resolution across a randomness request and a later, proof-backed fulfilment.

## Prevalence and Statistics

Insecure Randomness is a recognised entry in the **OWASP Smart Contract Top 10 (2025)** as **SC09**. It is a persistent finding in audits of any protocol that needs to pick winners, shuffle, or assign rarity.

Rather than cite precise loss figures (which vary by source and incident), the defensible picture is:

- Weak randomness is characterised as **easy to identify and easy to exploit**—a reviewer spotting a block variable feeding a payout can usually construct the exploit immediately.
- The most commonly observed patterns are **block-variable seeds, same-transaction resolution of bets/draws, and commit-reveal schemes without withholding penalties**.
- The impact is rated **high** wherever the randomness gates funds: the outcome is not merely leaked, it is *controllable*, which turns the flaw into direct theft rather than only information disclosure.

Note: exact loss totals differ between reports and years, and many exploited contracts are never publicly attributed. Treat any single figure as illustrative; the durable takeaway is that on-chain randomness derived from block or message data is predictable, cheap to exploit, and repeatedly abused.

## Common Misunderstandings

### Myth 1: "Hashing the block variables makes them random"

**Reality**: `keccak256` is a deterministic, public function. Hashing public inputs produces a public output that anyone can recompute. The scramble hides nothing from an attacker who runs the same hash.

### Myth 2: "prevrandao is the official randomness, so it's safe"

**Reality**: `block.prevrandao` is entropy for the *consensus layer*. It is known to the block proposer in advance and can be biased by a proposer willing to skip a slot. It is not designed to secure high-value application payouts.

### Myth 3: "The attacker can't know the future block hash"

**Reality**: They don't need to. Contracts almost always read a hash that is *already fixed* at execution time, and attackers compute the outcome in the same transaction, reverting when they lose. "Future" block hashes, meanwhile, return `0` once out of range.

### Myth 4: "Combining several block variables adds security"

**Reality**: Combining values that are each public or attacker-controlled yields a value that is still public or attacker-controlled. Ten predictable inputs do not make one unpredictable output.

### Myth 5: "Only miners/validators can exploit this"

**Reality**: Validators can *bias* some values, but the far more common attack needs no special privilege at all: any user can deploy a contract that computes the result and reverts on a loss.

### Myth 6: "Commit-reveal is automatically safe"

**Reality**: A commit-reveal scheme is only as strong as its handling of *reveal withholding* and *reveal front-running*. Without deposits, penalties, and timeouts, a participant who dislikes the pending outcome simply never reveals, or front-runs the reveal to change the result.

## How Insecure Randomness Differs from Related Issues

| Aspect | Insecure Randomness (SC09) | Price Oracle Manipulation (SC02) | Logic Errors (SC03) |
| --- | --- | --- | --- |
| **Root cause** | "Random" value is predictable/biasable | Trusted price feed is manipulable | Flawed business rules |
| **What the attacker gains** | Controls a supposedly-chance outcome | Mispriced trades/liquidations | Unintended state transitions |
| **Typical fix** | Verifiable randomness / commit-reveal | Robust, manipulation-resistant oracles | Correct and test the logic |
| **Detection** | Trace RNG seed to block/msg data | Trace price to a spot source | Spec review, invariant testing |

## Key Takeaways

1. **The chain has no native secret randomness**—it is deterministic and public by design, so any on-chain-only seed is knowable.
2. **Block and message variables are all predictable or biasable**—timestamp, block hash, prevrandao, coinbase, gasleft, sender, and nonce must never gate value.
3. **The killer attack is atomic compute-then-revert**—an attacker computes the result and only plays when it wins, needing no privilege.
4. **Verifiable randomness is the robust answer**—an oracle like Chainlink VRF supplies randomness with a cryptographic proof that the contract verifies.
5. **Commit-reveal works only with care**—it needs deposits, penalties, and timeouts to resist reveal withholding and front-running.

## How to Identify if You're Vulnerable

Ask these questions about your contract:

- [ ] Does any payout, winner selection, shuffle, or rarity assignment depend on `block.timestamp`, `blockhash`, `block.prevrandao`/`difficulty`, `block.number`, `block.coinbase`, or `gasleft()`?
- [ ] Is the "random" seed derived from `msg.sender`, `tx.origin`, or an account nonce the caller controls?
- [ ] Is the bet/entry and its resolution settled in the *same transaction*, so a contract can compute the result and revert on a loss?
- [ ] Could a caller reach your function from another contract and branch on the outcome?
- [ ] If you use commit-reveal, is there a deposit and penalty for failing to reveal, and a timeout/fallback if a reveal is withheld?
- [ ] Does the prize ever exceed a block reward, giving a proposer motive to bias timestamp/prevrandao or reorder transactions?
- [ ] For anything value-bearing, do you use an external verifiable randomness source whose proof you check on-chain?

If you answered "yes" to the block-variable questions or "no" to the verifiable-randomness question, you likely have an exploitable randomness flaw today.

## Next Steps

- **Attack Vectors**: How attackers predict and bias on-chain randomness
- **Prevention**: Verifiable randomness and safe commit-reveal designs
- **Examples**: Vulnerable block-value RNG vs. secure Chainlink VRF and commit-reveal
- **Smart Contract Learning Path**: Continue with the rest of the Smart Contract Top 10
- **Practice**: Apply what you have learned in hands-on challenges
