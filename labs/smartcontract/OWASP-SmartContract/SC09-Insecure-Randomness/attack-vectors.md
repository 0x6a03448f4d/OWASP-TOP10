# SC09: Insecure Randomness - Attack Vectors

## Table of Contents

- [Understanding Randomness Attack Vectors](#understanding)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining and Escalation](#chaining)

## Understanding Randomness Attack Vectors

**&#9888; EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in contracts you own or are authorised to test.

Insecure randomness is not exploited with a clever cryptographic break. It is exploited by **recomputation**: the attacker reads the exact same public data the contract reads, runs the exact same arithmetic, and learns the "random" result before committing anything of value. Because the EVM is deterministic and every input is public, the attacker's copy of the calculation always matches the victim's.

The attacker's goal in this category is usually one of:

- Predict the outcome and act only when it is favourable (win the lottery, mint the rare NFT, take the winning side of a bet).
- Bias the source of entropy the contract trusts (as a block proposer nudging timestamp or prevrandao, or reordering transactions).
- Break a commitment scheme by withholding or front-running the reveal.

### Core Attack Flow

```
1. Identify the seed
   &darr;
   Find the exact expression that produces the "random" number
   (block.timestamp, blockhash, prevrandao, msg.sender, keccak256 of these)
2. Reproduce the math
   &darr;
   Compute the same expression in an attacker contract, in the same block
3. Decide atomically
   &darr;
   IF result is a WIN -> call the target; ELSE -> revert (pay only gas)
4. Repeat / escalate
   &darr;
   Retry next block, or (as a proposer) bias the source directly
```

## Common Attack Patterns

### 1. Same-Transaction Outcome Prediction (Compute-Then-Revert)

The dominant attack. The target resolves a draw or bet in the same call, from data readable at execution time. An attacker contract computes the result first and only proceeds on a win.

```
// Vulnerable target (simplified)
function play() external payable {
    uint256 roll = uint256(keccak256(abi.encodePacked(
        block.timestamp, block.prevrandao, msg.sender))) % 2;
    if (roll == 0) payable(msg.sender).transfer(2 * betAmount);
}

// Attacker contract: reproduce the SAME expression, revert on a loss
function attack() external payable {
    uint256 roll = uint256(keccak256(abi.encodePacked(
        block.timestamp, block.prevrandao, address(this))) ) % 2;
    require(roll == 0, "not a winning block");   // abort, pay only gas
    target.play{value: betAmount}();             // guaranteed win
}
```

**Payoff**: the attacker only ever plays winning hands. No privilege is required—any user can deploy this. Note the attacker uses `address(this)` as the sender, exactly matching what the target will see.

### 2. Predicting a Previous Block Hash

Contracts often seed from `blockhash(block.number - 1)`, believing it is unpredictable. It is already fixed and public when the transaction runs.

```
uint256 winner = uint256(blockhash(block.number - 1)) % players.length;

// The attacker reads the identical, already-known hash and only enters
// in a block where it computes itself as the winner.
```

**Payoff**: deterministic prediction of the "winning" index. Also note `blockhash` returns `0` outside the most recent 256 blocks, collapsing "future block" designs to a constant.

### 3. Validator / Proposer Bias of prevrandao and timestamp

When the prize exceeds a block reward, the party building the block has motive to steer the values naive contracts trust.

```
// Target trusts prevrandao / timestamp directly
uint256 rand = uint256(keccak256(abi.encodePacked(block.prevrandao))) % total;
```

- **Timestamp nudging**: the proposer sets `block.timestamp` within the accepted tolerance, trying values that favour it.
- **RANDAO biasing**: a proposer can *skip its slot*—forgoing the block reward—to influence the resulting `prevrandao` when the payout justifies the sacrifice.

**Payoff**: the "random" draw bends toward the block producer. This is a smaller population of attackers than pattern #1 but strikes even designs that pick a future block, because the producer of that block is the adversary.

### 4. Transaction Reordering and Front-Running the Entry

Even without touching the entropy, an attacker who watches the mempool can insert or reorder transactions around a draw.

```
Mempool: victim's draw-triggering tx is visible
   → attacker computes the pending outcome
   → attacker front-runs to enter only if it will win,
     or back-runs to claim, adjusting position by gas price
```

**Payoff**: the attacker positions itself around the deterministic result using ordering alone.

### 5. Reveal Withholding in Commit-Reveal

A commit-reveal scheme without penalties lets a participant who dislikes the pending result simply never reveal, forcing a re-draw or stalling settlement.

```
commit:  hash = keccak256(secret)          // locked in earlier
reveal:  submit secret                     // ... only if the outcome is good

// If revealing would make the attacker lose, it withholds the secret.
// With no deposit to slash and no timeout fallback, the draw stalls
// or must be re-run -- which the attacker games again.
```

**Payoff**: the attacker vetoes unfavourable outcomes at no cost, converting a "fair" scheme into one it can only win or void.

### 6. Reveal Front-Running in Commit-Reveal

If the final randomness is a function of multiple revealed secrets and the ordering/inclusion of the last reveal is observable, the last revealer can choose whether (and when) to reveal to steer the combined result.

```
final = keccak256(secretA, secretB, ... , secretLast)
// The last party to reveal sees all prior secrets in the mempool/state
// and reveals only when the combination favours it (or withholds).
```

**Payoff**: the "last actor" gains an unfair veto/steer over the aggregate seed unless the scheme binds all reveals or penalises late/absent ones.

### 7. Address Grinding for Identity-Seeded Randomness

When the seed includes `msg.sender` or a freshly deployed contract's address, the attacker can search for an input that wins.

```
outcome = uint256(keccak256(abi.encodePacked(seed, msg.sender))) % total;

// Attacker deploys throwaway contracts (or uses CREATE2 salt grinding)
// until it finds an address that produces a winning outcome, then plays
// from exactly that address.
```

**Payoff**: the caller identity, meant to add entropy, becomes a tunable knob the attacker optimises.

### 8. Weak PRNG / Insufficient Entropy Expansion

Some contracts try to stretch one seed into many "independent" draws with a simple counter, so predicting one value predicts them all.

```
function nth(uint256 i) internal view returns (uint256) {
    return uint256(keccak256(abi.encodePacked(seed, i))) % total; // seed is public
}
// Learn `seed` once (it is on-chain) and every draw is known.
```

**Payoff**: a single recovered seed unrolls the entire sequence—every future "random" pick is precomputable.

## Chaining and Escalation

Randomness flaws compound with the same-transaction and composability properties of the EVM:

```
Predictable seed (block variables)     -> attacker computes the outcome
        +
Same-tx resolution of the bet/draw      -> wrap in a contract that reverts on loss
        +
No rate limit / unlimited retries       -> repeat every block until it wins
        =  the prize pool is drained with zero downside
```

Another common chain in NFT mints:

```
Rarity assigned at mint from block data -> attacker precomputes rare mints
        -> contract reverts unless the mint yields a rare token
        -> attacker captures the entire tail of valuable traits
        -> resells, extracting the collection's value from honest minters
```

## Key Takeaways

1. **Recomputation, not cryptanalysis**—the attacker runs the same public math the contract runs and knows the result first.
2. **Compute-then-revert needs no privilege**—any user can wrap a draw in a contract that only commits on a win.
3. **Block producers are a distinct, more powerful adversary**—they can bias timestamp/prevrandao and reorder transactions when the prize is worth it.
4. **Commit-reveal fails on withholding and front-running**—without deposits, penalties, and timeouts it is gameable.
5. **One leaked seed unrolls the whole sequence**—public seeds plus a counter are not independent draws.

## Next Steps

- **Prevention Guide**: Verifiable randomness and hardened commit-reveal
- **Code Examples**: Vulnerable block-value RNG vs. secure VRF and commit-reveal
- **Smart Contract Learning Path**: Continue the Smart Contract Top 10
- **Practice**: Try these ideas against guided challenges
