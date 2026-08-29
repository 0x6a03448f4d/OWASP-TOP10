# SC10: Denial of Service (DoS) Attacks - Overview

## Table of Contents

- [What is a Smart Contract Denial of Service?](#what-is-dos)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is a Smart Contract Denial of Service?

**Denial of Service (DoS)** in a smart contract means making the contract—or a critical function within it—**permanently or temporarily unusable**, or **locking funds so no one can withdraw them**. Unlike a web DoS, which floods a server and ends when the traffic stops, an on-chain DoS is often *permanent*: once a contract is wedged into a broken state, immutable code has no "restart" button. The funds and the logic can be frozen forever.

What makes this category distinct from a simple bug is that an attacker can **deliberately engineer the broken state**. By becoming a "poison" participant—a recipient that always reverts, or a user who inflates an array past the gas limit—a single actor can freeze a contract *for everyone else*. The attacker often loses nothing; they simply make the shared mechanism stop working.

### Core Concept

```
Healthy contract:
  distribute()   -> loops recipients, each payment succeeds, everyone paid
  bid()          -> refunds previous bidder, records new highest bid
  withdraw()     -> each user pulls their own balance independently

Denial of Service:
  distribute()   -> ONE recipient reverts on receive -> whole loop reverts
                    -> no one is ever paid again
  bid()          -> previous "bidder" is a contract that rejects ETH
                    -> refund fails -> no new bid can ever succeed
  withdraw()     -> array grew unbounded -> loop exceeds block gas limit
                    -> the function can never complete
```

### Why It's Critical for Smart Contracts

Several properties of the blockchain execution model make DoS uniquely damaging on-chain:

- **Immutability**: A contract with no upgrade or recovery path cannot be patched. A DoS that wedges it is often *final*.
- **Atomic transactions**: If any step in a transaction reverts, the *entire* transaction reverts. One failing payment in a loop rolls back all the others—so a single poison recipient blocks the whole batch.
- **A hard block gas limit**: Every transaction must fit inside the block gas limit. An operation whose cost grows with user-controlled data can cross that ceiling and become permanently unexecutable.
- **Untrusted external code**: Sending ETH or calling another address can hand control to attacker-written code that reverts, loops, or burns all the gas on purpose.
- **Locked value**: Because contracts custody real assets, a frozen contract is not just an outage—it is potentially millions in permanently trapped funds.

## Why Does This Matter?

### Business Impact

- **Permanently Locked Funds**: Refunds, withdrawals, or payouts that can never execute leave user deposits trapped in the contract with no recovery.
- **Frozen Core Functionality**: An auction that can never accept a new bid, a payroll splitter that can never distribute, or a game that can never resolve is effectively dead.
- **Griefing With No Ransom**: The attacker often gains nothing financially—their goal is to harm the protocol or its users, which makes the motive hard to predict or price in.
- **Reputational Collapse**: A protocol whose funds are visibly and permanently frozen loses user trust instantly and usually irrecoverably.
- **Costly Migration**: The only "fix" for an immutable, wedged contract is often to redeploy and socially coordinate a migration—expensive, slow, and error-prone.

### Technical Impact

- **Unexpected Revert**: A single participant forcing a revert blocks a function for all participants (push-payment loops, refund-on-outbid patterns).
- **Gas Exhaustion**: Unbounded loops over growing arrays or mappings exceed the block gas limit and become permanently unexecutable.
- **Broken External Dependency**: A hard dependency on an external contract that is later self-destructed or paused freezes any function that must call it.
- **Lost Privileged Access**: An owner-only recovery or unpause function becomes uncallable if the single owner key is lost or the owner is a broken contract.
- **State Assumption Violated**: Forcing ETH into a contract via `selfdestruct` skews `address(this).balance`, breaking logic that assumed the balance could only change through its own functions.

## Technical Context

### Main DoS Patterns in Smart Contracts

#### 1. DoS With Unexpected Revert (Push Payments)

```
// A function PUSHES payments in a loop.
for (uint i = 0; i < recipients.length; i++) {
    // If ONE recipient is a contract that revert()s on receive,
    // or a contract with no payable fallback, this call fails...
    recipients[i].transfer(amounts[i]);   // ...and reverts the ENTIRE loop.
}
```

**The trap**: One recipient can be a "poison" contract that always rejects ETH. Because the whole transaction is atomic, that single failure rolls back every other payment. No one is ever paid again. This is the classic auction-refund / "everyone gets pushed" DoS.

#### 2. DoS With Block Gas Limit (Unbounded Loops)

```
// The array grows every time a user joins; nothing bounds it.
address[] public participants;

function payAll() external {
    for (uint i = 0; i < participants.length; i++) {   // O(n) over user input
        participants[i].transfer(share);
    }
}
```

**The trap**: An attacker (or ordinary growth) inflates `participants` until the loop costs more gas than fits in a block. From that point on, `payAll()` can *never* complete—it reverts with out-of-gas every time, for everyone.

#### 3. Locking / Griefing via a Broken Dependency

```
// A required external call. If `oracle` is self-destructed or paused,
// every function that touches it reverts forever.
uint price = IPriceFeed(oracle).latestPrice();

// Or: an owner-only escape hatch whose owner key is lost.
function emergencyWithdraw() external onlyOwner { ... }  // uncallable if owner is gone
```

**The trap**: A hard dependency on code that can break—or a single point of privileged control that can be lost—turns a temporary problem into a permanent freeze.

#### 4. Manipulating a Shared State Variable

```
// Others depend on this value to make progress.
// If an attacker can force it into a state that blocks the
// happy path (e.g. a "current leader" that can never be displaced),
// the mechanism stalls for everyone.
address public currentLeader;   // updated only if the refund to the old leader succeeds
```

**The trap**: When progress for all users depends on a mutable variable that one participant can pin in a hostile state, that participant can stall the whole system.

#### 5. Forcing State via selfdestruct

```
// Logic that assumes the balance only changes through deposit()/withdraw():
require(address(this).balance == expected, "unexpected balance");

// An attacker can `selfdestruct(payable(target))` to FORCE ETH in,
// skewing address(this).balance and breaking the invariant.
```

**The trap**: ETH can be forced into any contract via `selfdestruct` (and a couple of other edge cases), so `address(this).balance` is not a value the contract fully controls. Critical logic that trusts it can be wedged.

### Where DoS Hides

| Pattern | Root Cause | Consequence |
| --- | --- | --- |
| Push-payment loop | Contract sends funds to many recipients in one tx | One reverting recipient blocks all payouts |
| Unbounded loop | Iteration count grows with user-controlled data | Operation exceeds block gas limit, never completes |
| Refund-on-outbid | New action must first refund the previous actor | A poison previous actor blocks all future actions |
| Hard external dependency | Required call to a contract that can break/pause | Function frozen if the dependency is gone |
| Single-owner escape hatch | Recovery gated on one key/address | Funds locked if the owner is lost |
| Balance-based invariant | Logic trusts `address(this).balance` | Forced ETH skews state, wedges the contract |

## Real-World Impact

The incidents below are described as **classes of vulnerability** that have recurred across many contracts, not as claims about any single named project's specifics.

### Case Class 1: Push-Payment Refund DoS (Auctions and "King" Games)

**Vulnerability**:

- A contract holds a position (highest bidder, current "king", top depositor) and refunds the previous holder by *pushing* ETH to them when a new participant takes the position.
- The refund is performed with a plain `transfer`/`send`/`call` whose failure reverts the whole state-changing function.

**Impact**:

- An attacker takes the position from a contract that *rejects* incoming ETH (no payable fallback, or a fallback that always reverts).
- Every future attempt to take the position must first refund that poison contract—which always fails—so the position can never change hands again. The mechanism is frozen with the attacker permanently on top.

**Root Cause**: Pushing payments to untrusted recipients inside a function whose success depends on that payment succeeding. The fix is to let recipients pull their own refunds.

### Case Class 2: Unbounded-Loop Gas DoS (Growing Arrays)

**Vulnerability**:

- A contract iterates over an array (of investors, token holders, pending payouts) that grows without bound as users interact.
- A single function tries to process the whole array in one transaction.

**Impact**:

- As the array grows—organically or because an attacker cheaply adds many entries—the per-transaction gas cost eventually exceeds the block gas limit.
- Past that threshold the batch operation can never fit in a block again. Distribution, migration, or cleanup that depends on it is permanently stuck.

**Root Cause**: Designing a critical operation whose cost scales with user-controlled input. The fix is pagination, pull payments, and per-user accounting instead of one giant loop.

### Case Class 3: Locked-Funds Griefing (Broken Dependency / Lost Owner)

**Vulnerability**:

- A contract depends on an external contract (a library, oracle, or wallet) for a required step, or gates all recovery behind a single owner.
- That dependency is later self-destructed, paused, or made unreachable—or the sole owner key is lost.

**Impact**:

- Every function that must call the now-broken dependency reverts, and there is no alternate code path.
- Funds and logic that rely on it are frozen with no on-chain way to recover them—a well-known class of incident in which large balances became permanently inaccessible after a shared library was destroyed.

**Root Cause**: A single hard dependency or single point of privileged control with no fallback. The fix is robust ownership (multisig, two-step transfer), avoiding hard dependencies, and building recovery/upgrade paths.

## Prevalence and Statistics

Denial of Service is included in the **OWASP Smart Contract Top 10 (2025)** as **SC10** because the pattern recurs across auctions, crowdsales, staking pools, payment splitters, and games—anywhere a contract loops over participants or pushes value to untrusted addresses.

Rather than cite precise counts (which vary by source and year), the defensible picture is:

- Push-payment and unbounded-loop DoS are among the **most repeated** findings in smart-contract audits because the "loop and pay everyone" pattern is an intuitive but unsafe first design.
- The impact is rated **high** when funds are involved: outcomes range from a temporarily stuck function up to **permanently locked value** in immutable code.
- Many DoS bugs are **cheap to trigger**—a single poison recipient or a batch of dust entries—while being **expensive or impossible to fix** after deployment.

Note: exact figures differ between reports. Treat any single number as illustrative; the durable takeaway is that DoS is common, cheap to trigger, and frequently irreversible on immutable contracts.

## Common Misunderstandings

### Myth 1: "A revert just fails safely—no harm done"

**Reality**: A revert is safe for *that* transaction, but if the reverting step is on the only path that lets the contract make progress, the revert is permanent for *everyone*. Safe-per-call is not safe-per-system.

### Myth 2: "My loop is fine; there are only a few recipients today"

**Reality**: If the number of recipients can grow with user input, "a few today" becomes "too many to fit in a block tomorrow." Unbounded is unbounded regardless of the current count.

### Myth 3: "I'll just send funds to users so they don't have to do anything"

**Reality**: Pushing funds hands control to untrusted recipient code and couples everyone's outcome to the worst recipient. Pull payments isolate each user's failure to that user.

### Myth 4: "Only my functions can change my contract's balance"

**Reality**: ETH can be forced in via `selfdestruct` (and as a coinbase/pre-funded address), so `address(this).balance` can move without any of your functions running. Never base critical logic on it.

### Myth 5: "An external call to a trusted contract is safe forever"

**Reality**: "Trusted" contracts can be paused, upgraded to something incompatible, or self-destructed. A hard dependency with no fallback is a latent freeze waiting to happen.

### Myth 6: "One owner key is simpler and therefore fine"

**Reality**: A single owner is a single point of failure. Lose the key (or let it fall into a broken contract) and every owner-gated recovery becomes uncallable—locking whatever those functions were meant to protect.

## How DoS Differs from Related Issues

| Aspect | Denial of Service (SC10) | Reentrancy (SC05) | Unchecked External Calls (SC06) |
| --- | --- | --- | --- |
| **Attacker goal** | Freeze the contract / lock funds | Drain funds via re-entry | Exploit a silently ignored failure |
| **Core mechanism** | Force a revert or exceed gas limits | Call back in before state updates | Ignore a call's boolean return |
| **Typical fix** | Pull payments, bounded loops, robust ownership | Checks-Effects-Interactions, guards | Check return values / use `call` safely |
| **Outcome** | Unusable contract, trapped value | Stolen value | Inconsistent state, lost value |

## Key Takeaways

1. **On-chain DoS is often permanent**—immutable code has no restart, so a wedged contract can trap funds forever.
2. **Atomicity turns one failure into everyone's failure**—a single reverting recipient in a loop rolls back the whole batch.
3. **Unbounded loops are a time bomb**—anything that scales with user input can eventually exceed the block gas limit.
4. **Prefer pull over push**—let each user withdraw their own funds so one bad actor cannot block the rest.
5. **Design for recovery**—avoid hard external dependencies, use robust ownership, and never trust `address(this).balance` for critical logic.

## How to Identify if You're Vulnerable

Ask these questions about your contract:

- [ ] Does any function loop over an array or mapping whose size grows with user input?
- [ ] Do you *push* ETH/tokens to multiple recipients in a single transaction?
- [ ] Does a state-changing function depend on a payment to an untrusted address succeeding?
- [ ] Can a new action proceed only after refunding the previous actor?
- [ ] Is there any required external call to a contract that could be paused or self-destructed?
- [ ] Is recovery or unpausing gated behind a single owner key with no backup?
- [ ] Does any critical branch depend on `address(this).balance` being an exact value?
- [ ] If one participant behaves maliciously, can they block progress for everyone else?
- [ ] Is there a bounded, paginated, or pull-based alternative to every batch operation?

If you answered "yes" to the push/loop/dependency questions or "no" to the recovery questions, you likely have an exploitable DoS today.

## Next Steps

- **Attack Vectors**: How attackers freeze contracts and lock funds
- **Prevention**: Pull payments, bounded loops, and robust ownership
- **Examples**: Vulnerable vs. secure Solidity, side by side
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
