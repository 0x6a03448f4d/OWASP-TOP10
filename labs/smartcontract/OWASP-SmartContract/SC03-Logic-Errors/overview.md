# SC03: Logic Errors - Overview

## Table of Contents
- [What Are Logic Errors?](#what-are-logic-errors)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What Are Logic Errors?

**Logic Errors** (also called **business-logic flaws**) occur when a smart contract compiles cleanly, passes its happy-path tests, and appears to "work"—yet its implemented behaviour diverges from its *intended* behaviour. There is no memory-safety bug, no reentrancy, no missing access-control modifier; the code simply computes the wrong thing. An attacker who understands the intended invariant better than the developer did can drive the contract into a state the designer never meant to allow, and extract value on the way.

Because the bug lives in the specification-to-implementation gap rather than in a language feature, a compiler, a linter, and even a reentrancy scanner will all stay silent. The contract is internally consistent—it just enforces the wrong rules. On a public blockchain those wrong rules are permanent, adversarially probed, and directly tied to money: every accounting slip, every mis-rounded division, every unhandled edge case is a standing invitation.

### Core Concept

```
Intended behaviour (the specification):
  Deposit         -> user's recorded balance increases by exactly the amount sent
  Shares minted   -> proportional to assets deposited vs. total assets held
  Reward          -> accrues linearly with stake and elapsed time, no double-count
  Withdraw        -> user can never remove more value than they are entitled to
  Rounding        -> always resolved in the protocol's favour, never the user's
  Invariant       -> sum(balances) == totalSupply, always, after every operation

Logic error (the implementation diverges):
  Deposit         -> balance updated before/without validating the transfer amount
  Shares minted   -> first depositor sets an exchange rate an attacker can inflate
  Reward          -> accrual re-runs on each call, paying the same period twice
  Withdraw        -> uses a stale or attacker-influenced price to over-pay
  Rounding        -> integer division truncates value TO the user (leakage)
  Invariant       -> broken silently; totalSupply and real holdings drift apart
```

### Why It's Critical for Smart Contracts

Smart contracts concentrate several conditions that make logic errors uniquely dangerous:

- They are **immutable once deployed**: a miscalculated fee or share formula cannot be quietly patched; it must be paused, migrated, or lived with.
- They are **directly financial**: the "wrong answer" is denominated in tokens, so every logic slip has an immediate monetary exploit path.
- They are **adversarially composed**: other contracts, flash loans, and MEV bots will combine your logic with theirs in ways your tests never covered.
- They rely on **integer-only arithmetic**: there are no floats, so division truncates and rounding direction is a security decision, not a cosmetic one.
- They are **fully transparent**: the exact miscalculation is on-chain for anyone to read, model, and exploit at leisure.

## Why Does This Matter?

### Business Impact

- **Direct Loss of Funds**: A wrong accounting update or share formula lets an attacker withdraw more than they deposited, draining pooled user assets.
- **Protocol Insolvency**: When issued shares or debt no longer match real backing, the protocol becomes under-collateralised—honest users cannot all be made whole.
- **Reward and Emissions Drain**: A double-counted or mis-scaled reward calculation mints or pays out far more than the emission schedule intended, devaluing the token.
- **Broken Trust and TVL Flight**: A single accounting exploit typically triggers immediate withdrawal of remaining total value locked, killing the protocol regardless of the residual balance.
- **Irreversibility**: Because transactions are final, there is rarely a chargeback; recovery depends on negotiation, forks, or the attacker's goodwill.

### Technical Impact

- **Broken Invariants**: Core relationships (`sum(balances) == totalSupply`, `assets >= liabilities`) silently stop holding, corrupting every later operation.
- **Value Leakage via Rounding**: Integer truncation in the user's favour, repeated across many transactions, bleeds the pool one wei at a time or in a single amplified step.
- **Share/Asset Desynchronisation**: In vault (ERC-4626-style) accounting, a manipulated exchange rate lets one actor mint disproportionately many or few shares.
- **State-Machine Corruption**: Incorrect or unguarded state transitions leave the contract in a combination of states the logic assumed was impossible.
- **Limit Bypass**: Off-by-one and wrong comparison operators let callers exceed caps, mint past a supply ceiling, or act outside an intended window.

## Technical Context

### Common Logic-Error Scenarios in Smart Contracts

#### 1. Incorrect Accounting / Balance Updates

```solidity
// The recorded balance and the value actually held diverge:
function deposit(uint256 amount) external {
    balances[msg.sender] += amount;      // credited BEFORE the transfer is verified
    token.transferFrom(msg.sender, address(this), amount); // return value ignored
}
// If transferFrom silently fails or moves fewer tokens (fee-on-transfer),
// the ledger now claims more than the contract holds.
```

**Risk**: The internal ledger overstates real holdings; the last users to withdraw find the pool empty.

#### 2. Rounding & Precision Errors (Integer Division Truncation)

```solidity
// Solidity has no floats: division truncates toward zero.
uint256 shares = (amount * totalShares) / totalAssets;   // rounds DOWN
// Minting rounds down (good for the protocol), but a WITHDRAW that also
// rounds down the assets owed while the SAME rounding is applied to shares
// burned can hand the user a fraction of value for free, repeatedly.
```

**Risk**: Rounding in the *user's* favour leaks value on every call; at scale it is a slow drain, and with a crafted amount it can be amplified.

#### 3. First-Depositor / Empty-Pool Edge Case (Inflation Attack Class)

```solidity
// Vault share math when totalSupply == 0:
shares = (totalSupply == 0)
    ? amount                                   // 1:1 for the first depositor
    : (amount * totalSupply) / totalAssets;

// Attacker: deposit 1 wei -> mint 1 share, then DONATE a large amount
// directly to the vault (transfer, not deposit). Now 1 share is "worth"
// the whole balance. A later depositor's shares round DOWN to zero.
```

**Risk**: The classic ERC-4626 *inflation / donation* attack: a victim deposits real assets and receives zero (or too few) shares, which the attacker then redeems.

#### 4. Flawed Reward / Interest / Fee Calculation

```solidity
// Reward accrual that forgets to update the checkpoint:
function claim() external {
    uint256 owed = stake[msg.sender] * rate * (block.timestamp - start);
    reward.mint(msg.sender, owed);
    // BUG: 'start' (or a per-user lastClaim) is never advanced,
    // so the same elapsed period pays out again on the next call.
}
```

**Risk**: The same period is paid repeatedly, or a mis-scaled rate mints far beyond the intended emission, devaluing every holder's stake.

#### 5. Wrong Order of Operations / State Transition

```solidity
// Effects applied out of order relative to checks:
function withdraw(uint256 amount) external {
    (bool ok, ) = msg.sender.call{value: amount}("");   // interaction first
    require(ok);
    balances[msg.sender] -= amount;                     // effect last
}
// Even ignoring reentrancy, mixing up the intended sequence
// (validate -> update -> interact) corrupts the state machine.
```

**Risk**: The contract enters states the author assumed unreachable; invariants that "obviously" held are violated.

#### 6. Off-by-One and Wrong Comparison Operators

```solidity
require(totalMinted + qty <= MAX_SUPPLY);   // correct: allows up to the cap
require(totalMinted + qty < MAX_SUPPLY);    // off-by-one: cap can never be reached
if (block.timestamp > deadline) revert();   // should this be >= ? a whole second differs
```

**Risk**: Callers exceed a cap, mint one too many, or act one unit outside an intended boundary.

#### 7. Unchecked Assumptions About Tokens

```solidity
// Assuming amount-in == amount-received:
uint256 before = token.balanceOf(address(this));
token.transferFrom(msg.sender, address(this), amount);
// Fee-on-transfer token delivers (amount - fee); rebasing token changes
// balances out from under you. Crediting 'amount' over-states the deposit.
```

**Risk**: Fee-on-transfer and rebasing tokens break the "what I asked for is what I got" assumption, corrupting accounting.

### Where Logic Errors Hide

| Area | Typical Logic Error | Consequence |
|------|---------------------|-------------|
| Accounting / ledger | Balance updated without verifying the real transfer | Ledger overstates holdings; pool drained |
| Share / mint math | First-depositor rate set, then inflated by donation | Victim mints zero shares (ERC-4626 inflation) |
| Rewards / interest | Checkpoint not advanced; period double-paid | Emissions drain, token devalued |
| Rounding / precision | Division truncates in the user's favour | Continuous value leakage |
| State transitions | Effects and checks applied out of order | Unreachable states reached; invariants broken |
| Boundaries | Off-by-one, wrong comparison operator | Caps bypassed, windows escaped |
| Token assumptions | amount-in assumed equal to amount-received | Fee-on-transfer / rebasing corrupt accounting |

## Real-World Impact

The incidents below are described as **classes** of failure that have recurred across DeFi. The point is the shape of the bug, not the box score of any single event.

### Case Study 1: Accounting-Error Drains

**Logic Error**:
- A lending, staking, or AMM contract updates an internal balance or debt figure in a way that does not match the value actually moved—crediting before verifying a transfer, ignoring a return value, or mixing up which quantity to store.
- The internal ledger and the real token holdings drift apart, and nothing on-chain forces them back into agreement.

**Impact**:
- Attackers spot that a sequence of ordinary calls leaves them with a recorded balance larger than what they contributed, then withdraw the difference—draining pooled user funds until the contract is empty or paused.

**Root Cause**: The implemented accounting diverges from the intended invariant `internal_ledger == real_holdings`, and no test or on-chain check ever asserts that invariant.

### Case Study 2: ERC-4626 Vault Inflation / Donation Attack Class

**Logic Error**:
- A tokenised vault computes shares from the ratio of assets to total shares, with a special 1:1 case for the very first deposit.
- Because anyone can transfer tokens *directly* to the vault (bypassing `deposit`), an attacker inflates the assets-per-share so that a later honest deposit rounds down to zero shares.

**Impact**:
- The victim's assets are effectively absorbed by the attacker's single share; the attacker redeems and walks away with the deposit. This pattern has appeared repeatedly wherever naive vault math shipped without mitigation.

**Root Cause**: An unhandled empty-pool edge case combined with rounding that favours the existing share holder. Modern designs mitigate with *virtual shares/assets* (a decimals offset), a minimum initial deposit, or seeding the vault at deployment.

### Case Study 3: Reward / Emission Miscalculation Exploits

**Logic Error**:
- A staking or yield contract calculates rewards from stake, rate, and elapsed time, but fails to advance a per-user checkpoint, mis-scales a fixed-point rate, or lets rewards be claimed and re-staked in the same block.

**Impact**:
- Attackers repeatedly claim the same accrual, or trigger a mis-scaled payout, minting tokens far beyond the emission schedule and diluting or draining the reward pool.

**Root Cause**: The reward formula and its bookkeeping do not match the intended "each unit of stake earns for each unit of time exactly once" invariant, and property tests never asserted "total paid <= total emitted."

## Prevalence and Statistics

Logic Errors sit near the top of the **OWASP Smart Contract Top 10 (2025)** and are, by most post-mortem tallies, among the largest sources of realised loss in DeFi—precisely because they evade the tooling that catches memory and access-control bugs.

Rather than cite a single dollar figure (which shifts with every incident), the defensible picture is:

- Logic and accounting flaws are characterised as **high-impact and hard to detect**: they pass compilation, unit tests, and many automated scanners because the code is internally valid.
- The most commonly observed sub-issues are **rounding/precision leakage, first-depositor share manipulation, reward double-counting, and broken accounting invariants**.
- The impact is rated **severe**: outcomes range from slow value leakage up to complete draining of pooled funds and protocol insolvency.

> Note: precise loss totals differ between trackers and change with every new incident. Treat any single figure as illustrative; the durable takeaway is that logic errors are common, expensive, and invisible to tools that only check for known vulnerability shapes.

## Common Misunderstandings

### Myth 1: "It compiles and the tests pass, so the logic is correct"

**Reality**: Compilation proves the code is well-formed, and happy-path tests prove it works for the inputs you imagined. Logic errors live in the inputs you *didn't* imagine—zero amounts, empty pools, first depositor, adversarial ordering. Correctness is a property you must state and test, not a by-product of compiling.

### Myth 2: "Rounding is a rounding error—it's negligible"

**Reality**: On integer-only arithmetic, rounding direction is a security decision. A fraction of value leaked per transaction, multiplied by unlimited attacker-controlled transactions, is a drain. Always round in the protocol's favour and prove it.

### Myth 3: "An audit will catch our business-logic bugs"

**Reality**: Auditors are far more likely to find logic errors than tools are, but they cannot verify an invariant you never wrote down. Undocumented intended behaviour is unauditable behaviour. Specify first, then audit against the specification—and prefer multiple independent audits.

### Myth 4: "A reentrancy guard / SafeMath means we're safe"

**Reality**: Those defend against specific, known bug classes. A logic error can be perfectly reentrancy-safe and overflow-safe while still computing the wrong number. The math being *safe* is not the math being *right*.

### Myth 5: "Any ERC-20 will behave like a standard ERC-20"

**Reality**: Fee-on-transfer and rebasing tokens violate "amount sent equals amount received" and "my balance only changes when I move it." Code that assumes the standard behaviour mis-accounts the moment such a token is used.

### Myth 6: "We can just patch it if something's wrong"

**Reality**: Deployed contracts are immutable unless you built (and secured) an upgrade path in advance. By the time a logic error is observed on-chain, it is usually being actively exploited. Prevention, not patching, is the operative control.

## How Logic Errors Differ from Related Issues

| Aspect | Logic Errors (SC03) | Access Control (SC01) | Reentrancy (SC05) |
|--------|---------------------|-----------------------|-------------------|
| **Root cause** | Implementation diverges from intended logic | Missing/incorrect authorisation | State changed after an external call |
| **Where it lives** | The math and state machine itself | Permission checks / modifiers | Call ordering vs. state updates |
| **Typical fix** | Specify, test invariants, round correctly | Enforce roles / ownership | Checks-effects-interactions, guards |
| **Detection** | Property/fuzz testing, formal verification, audit | Access-control review | Reentrancy analysis, guards |

## Key Takeaways

1. **Logic errors are the gap between intended and implemented behaviour**—the code is valid but computes the wrong thing.
2. **Tools stay silent**—compilers, linters, and single-bug scanners do not know your business rules; you must specify and test them.
3. **Rounding direction is a security decision**—always resolve integer truncation in the protocol's favour.
4. **Edge cases are where value leaks**—first depositor, empty pool, zero amount, and off-by-one boundaries must be handled explicitly.
5. **Immutability raises the stakes**—there is rarely a second chance, so invariants must be proven before deployment.

## How to Identify if You're Vulnerable

- [ ] Is every core invariant (e.g. `sum(balances) == totalSupply`, `assets >= liabilities`) written down *and* asserted in tests?
- [ ] Does every division state, and test, which direction it rounds—and is that direction always the protocol's favour?
- [ ] Is the first-depositor / empty-pool case handled (virtual shares, minimum deposit, or seeded vault)?
- [ ] Are zero-amount, maximum-amount, and single-unit boundary inputs explicitly tested?
- [ ] Do reward/interest calculations advance their checkpoint so no period is paid twice?
- [ ] Does accounting verify the *actual* amount received (balance-delta), rather than trusting the requested amount?
- [ ] Are fee-on-transfer and rebasing tokens either supported correctly or explicitly rejected?
- [ ] Do you run property-based and fuzz tests (Foundry invariant tests, Echidna) against those invariants?
- [ ] Has the critical math been formally verified or independently audited more than once?
- [ ] Is the intended behaviour documented clearly enough that a reviewer could catch a divergence?

If you answered "no" or "not sure" to several of these, your contract likely harbours an exploitable logic error today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers find and exploit logic and accounting flaws
- **[Prevention](prevention.md)**: Specify invariants, test them, and round in the protocol's favour
- **[Examples](examples.md)**: Vulnerable vs. secure Solidity, side by side
- **[Smart Contract Track](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
