# SC09: Insecure Randomness - Prevention

## Prevention Strategy Overview

Preventing insecure randomness rests on a single hard truth: **there is no secure randomness that is both on-chain and secret**. Every robust design therefore imports unpredictability from outside the transaction that consumes it—either from a verifiable oracle or from a commitment made before the outcome-determining data existed. The strategy is:

1. Never derive value-bearing randomness from block or message variables.
2. For anything of value, use a verifiable randomness source with an on-chain proof.
3. If you must stay on-chain, use commit-reveal *with* deposits, penalties, and timeouts.
4. Separate the request for randomness from its consumption across transactions.
5. Assume an adversary who is also a block proposer and who can revert on a loss.

### Core Principles

- **Unpredictable at commit time**: the randomness must not be computable by anyone at the moment they act on it.
- **Verifiable**: the contract should be able to *prove* the number was produced honestly, not merely trust a caller.
- **Non-atomic**: split "ask for randomness" and "use randomness" so no one can compute-then-revert in a single transaction.
- **Incentive-aware**: if the prize can exceed a block reward, design so that biasing or withholding costs more than it can gain.

## 1. Use a Verifiable Randomness Oracle (Chainlink VRF)

A Verifiable Random Function (VRF) generates randomness off-chain and delivers it on-chain **together with a cryptographic proof** that the contract verifies before accepting the value. The proof binds the output to a key and a seed, so neither the oracle nor the requester can pick a favourable result. This is the robust default for lotteries, mints, and games of chance.

```
// Chainlink VRF v2 (subscription model) -- request/fulfil across two txs
import {VRFConsumerBaseV2} from "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";
import {VRFCoordinatorV2Interface} from "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";

contract Lottery is VRFConsumerBaseV2 {
    VRFCoordinatorV2Interface immutable COORDINATOR;
    uint64  immutable subId;
    bytes32 immutable keyHash;
    uint16  constant CONFIRMATIONS = 3;    // wait for block confirmations
    uint32  constant CALLBACK_GAS  = 200000;
    uint32  constant NUM_WORDS     = 1;

    address[] public players;
    mapping(uint256 => bool) public pending;   // requestId -> awaiting fulfil

    // 1) REQUEST: no randomness is available yet in this transaction
    function drawWinner() external onlyOwner returns (uint256 requestId) {
        requestId = COORDINATOR.requestRandomWords(
            keyHash, subId, CONFIRMATIONS, CALLBACK_GAS, NUM_WORDS);
        pending[requestId] = true;
    }

    // 2) FULFIL: called later by the coordinator AFTER the proof is verified
    function fulfillRandomWords(uint256 requestId, uint256[] memory words)
        internal override
    {
        require(pending[requestId], "unknown request");
        pending[requestId] = false;
        uint256 winnerIndex = words[0] % players.length;   // safe: proven random
        payable(players[winnerIndex]).transfer(address(this).balance);
        delete players;
    }
}
```

Why this resists the attacks: the winning value does not exist in the block where `drawWinner()` is called, so no one can compute-then-revert; the coordinator only accepts a value whose VRF proof verifies against the registered key, so the result cannot be cherry-picked; and requiring several confirmations blunts reorg-based manipulation.

Whatever oracle you choose, the non-negotiable property is the same: the randomness arrives with a **proof the contract checks on-chain**, and it is delivered in a **later transaction** than the one that requested it.

## 2. Commit-Reveal Done Correctly

If external randomness is not an option, a commit-reveal scheme can work—but only when it is hardened against the two ways it breaks: **reveal withholding** and **reveal front-running**. The essential ingredients are a deposit that is slashed for non-reveal, and a timeout with a defined fallback.

```
contract CommitReveal {
    struct Entry { bytes32 commitment; uint256 deposit; bool revealed; }
    mapping(address => Entry) public entries;
    uint256 public commitDeadline;
    uint256 public revealDeadline;
    bytes32 public seedAccumulator;

    // COMMIT: lock a hash of (secret, salt) plus a slashable deposit
    function commit(bytes32 commitment) external payable {
        require(block.timestamp < commitDeadline, "commit closed");
        require(msg.value == DEPOSIT, "bad deposit");
        entries[msg.sender] = Entry(commitment, msg.value, false);
    }

    // REVEAL: prove the preimage; mix it into the shared seed
    function reveal(uint256 secret, bytes32 salt) external {
        require(block.timestamp >= commitDeadline
             && block.timestamp < revealDeadline, "not reveal phase");
        Entry storage e = entries[msg.sender];
        require(!e.revealed, "already revealed");
        require(keccak256(abi.encodePacked(secret, salt)) == e.commitment, "bad reveal");
        e.revealed = true;
        seedAccumulator = keccak256(abi.encodePacked(seedAccumulator, secret));
        payable(msg.sender).transfer(e.deposit);   // deposit returned on honest reveal
    }

    // NON-REVEAL is penalised: unrevealed deposits are forfeit / slashed,
    // removing the incentive to withhold an unfavourable secret.
}
```

**Design rules for commit-reveal**:

- **Slash non-revealers**: an unrevealed deposit must be forfeit, so withholding costs more than it saves.
- **Bind every reveal**: mix *all* revealed secrets into the seed so the last revealer cannot single-handedly steer the result; combine with a timeout fallback if some never reveal.
- **Separate phases in time**: commits close before reveals open; the outcome is only finalised after the reveal window.
- **Salt the commitment**: hash `(secret, salt)` to prevent brute-forcing low-entropy secrets from the commitment.

## 3. Separate Request from Consumption

The single most effective structural defence against the compute-then-revert attack is to make the randomness unavailable in the transaction that acts on it. Split the flow into two transactions in two different blocks:

```
Block N   : user commits / requests randomness      (outcome not yet knowable)
Block N+k : randomness is delivered/derived and consumed

// Because the value does not exist at request time, an attacker cannot
// wrap the request in a contract that reverts on a losing result.
```

If you ever combine future block data with a prior commitment, remember `blockhash` is only available for the most recent 256 blocks and is `0` otherwise—never let the mechanism silently fall back to a constant.

## 4. Never Use These as Randomness

Treat the following as a hard denylist for any value-bearing outcome. They are acceptable only for non-adversarial, cosmetic jitter where nothing is at stake.

| Do NOT seed randomness from | Reason |
| --- | --- |
| `block.timestamp` | Proposer-set within tolerance; public at execution |
| `blockhash(...)` | Fixed/public before your tx; `0` outside 256 blocks |
| `block.prevrandao` / `block.difficulty` | Known to proposer; biasable by slot-skipping |
| `block.number` / `block.coinbase` | Public / proposer-chosen |
| `gasleft()` | Attacker controls gas supplied |
| `msg.sender`, `tx.origin`, nonce | Attacker controls / can grind the address |
| `keccak256` of any of the above | Deterministic hash of public inputs is still public |

## 5. Confirmations and Reorg Resistance

Even with an oracle, act on randomness only after enough block confirmations that a chain reorganisation cannot rewrite the delivering block. Configure the oracle's confirmation parameter conservatively for high-value draws, and do not finalise payouts in the same block the randomness lands.

```
// Request more confirmations for higher-value outcomes
uint16 constant CONFIRMATIONS = 5;   // tune to the value at risk and chain finality
```

## 6. Constrain Retries and Entries

Because attackers rely on unlimited, free retries, remove the free retry:

- Charge a non-refundable entry cost, or bind entries to a commit made before the randomness is requested.
- Close the entry set before randomness is requested, so no one can join after the outcome becomes derivable.
- Disallow contract callers only as a defence-in-depth measure—never as the primary control—since it is easy to bypass and breaks legitimate composability.

## 7. Testing and Review

Make weak randomness a first-class item in your test and audit process.

```
# Static analysis flags block-variable randomness patterns
slither .            # detects "weak-prng" / block-timestamp / block-values usage

# Grep the codebase for banned entropy sources feeding outcomes
grep -R "block.timestamp\|blockhash\|prevrandao\|block.difficulty\|block.coinbase\|gasleft" src/
```

- Write an adversarial test that *reproduces the contract's own RNG expression* and asserts it cannot predict outcomes.
- Include a compute-then-revert attacker contract in your test suite and assert it cannot force a win.
- Have the randomness design reviewed specifically for proposer bias and reveal withholding, not just for "does it look random."

## Decision Guide: Which Approach?

| Situation | Recommended approach |
| --- | --- |
| Any payout, lottery, mint rarity, game of chance | Verifiable randomness oracle (VRF), request/fulfil split |
| On-chain-only, moderate value, known participant set | Hardened commit-reveal with slashing + timeout |
| Cosmetic, non-adversarial jitter (nothing at stake) | Block data acceptable, but document that it is not secure |
| High value plus proposer in the threat model | VRF *and* conservative confirmations; never block variables |

## Key Takeaways

1. **On-chain and secret cannot coexist** — import unpredictability from a VRF or a prior commitment.
2. **Use a verifiable oracle for anything of value** — randomness with an on-chain proof, delivered in a later transaction.
3. **Split request from consumption** — this alone kills the compute-then-revert attack.
4. **Commit-reveal needs teeth** — deposits, slashing, timeouts, and bound reveals, or it is gameable.
5. **Deny the block variables outright** — timestamp, blockhash, prevrandao, coinbase, gasleft, sender, and nonce never gate value.

## Next Steps

- **Code Examples**: Vulnerable block-value RNG vs. secure VRF and commit-reveal
- **Attack Vectors**: Understand exactly what you are defending against
- **Smart Contract Learning Path**: Continue the Smart Contract Top 10
- **Practice**: Harden a vulnerable contract in a guided challenge
