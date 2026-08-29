# SC04: Lack of Input Validation - Overview

## Table of Contents
- [What is Lack of Input Validation?](#what-is-lack-of-input-validation)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is Lack of Input Validation?

**Lack of Input Validation** occurs when a smart contract trusts caller-supplied parameters — addresses, amounts, arrays, indexes, IDs, fees, deadlines, or raw calldata — and acts on them without checking that they are within the values the logic actually expects. On a public blockchain *anyone* can call your functions with *any* arguments the ABI permits, so every unvalidated parameter is an open control that an attacker can turn to a value you never intended.

Unlike a traditional web app, a smart contract cannot "sanitise and retry." State changes are executed exactly as written and, once mined, are permanent. A single missing `require` can send tokens to `address(0)` (burning them forever), let a caller drain more than they own, set a fee above 100%, brick the contract by assigning an unusable owner, or redirect an external call to a malicious target. The flaw is not exotic cryptography — it is the everyday gap between what a parameter *could* be and what the code *assumes* it is.

### Core Concept

```
Validated input (secure):
  address recipient  -> require(recipient != address(0))
  uint256 amount     -> require(amount > 0 && amount <= balance[msg.sender])
  uint256 feeBps     -> require(feeBps <= 10_000)            // <= 100.00%
  address[] users /  -> require(users.length == amounts.length)
  uint256[] amounts     require(users.length <= MAX_BATCH)
  uint256 tokenId    -> require(tokenId < totalSupply)
  address token      -> require(allowedTokens[token])       // allow-list
  uint256 deadline   -> require(block.timestamp <= deadline)

Unvalidated input (vulnerable):
  address recipient  -> transfer straight to whatever was passed (incl. 0x0)
  uint256 amount     -> subtract without checking the balance/allowance
  uint256 feeBps     -> store 50_000 (500%) with no upper bound
  address[] users /  -> loop over mismatched arrays, corrupt state
  uint256[] amounts
  uint256 tokenId    -> index an array out of range or reuse an ID
  address token      -> call an arbitrary, attacker-chosen token/target
  uint256 deadline   -> honour a signature/order that should have expired
```

### Why It's Critical for Smart Contracts

Several properties of on-chain code make missing validation uniquely dangerous:

- Contracts are **permissionless**: every external/public function is callable by anyone, directly, without a UI in the way. There is no client-side form to catch a bad value first.
- Actions are **irreversible**: value sent to `address(0)` or a wrong recipient, or a corrupted storage slot, generally cannot be undone.
- Contracts **hold value directly**: a parameter often *is* a movement of funds, so an unchecked amount or target is money leaving on the attacker's terms.
- Contracts are **composable**: other contracts feed your functions decoded calldata and token addresses, so "trusted" callers can still forward hostile inputs.

## Why Does This Matter?

### Business Impact

- **Permanent Loss of Funds**: Tokens or ETH sent to `address(0)` or an unintended recipient are burned or stolen with no recovery path.
- **Bricked Contracts**: Assigning `address(0)` as owner, or a malformed critical address, can make privileged functions permanently uncallable — the protocol is frozen.
- **Economic Corruption**: A fee or percentage set above its intended maximum can seize the entire value of every transaction, or make the system uneconomic overnight.
- **Reputation and Trust**: An exploit traceable to a missing one-line check is highly visible on-chain and erodes user and auditor confidence instantly.
- **Cascading DeFi Failures**: Corrupted accounting propagates to integrating protocols, turning one unvalidated input into a multi-protocol incident.

### Technical Impact

- **State Corruption**: Mismatched arrays, out-of-range indexes, and unchecked amounts write incorrect balances, ownerships, or configuration into permanent storage.
- **Arbitrary External Calls**: An unvalidated target or token address lets a caller make the contract interact with, or approve, a contract of the attacker's choosing.
- **Denial of Service**: An unbounded array length in a loop can exceed the block gas limit, permanently reverting a function for everyone.
- **Signature / Order Replay and Expiry Bypass**: Missing deadline or signer checks let stale or forged authorisations execute.
- **Accounting Drift**: Zero-amount or self-referential operations silently corrupt invariants that later withdrawals rely on.

## Technical Context

### Common Missing-Validation Scenarios

#### 1. Missing Zero-Address Checks

```solidity
function setOwner(address newOwner) external onlyOwner {
    owner = newOwner;          // newOwner == address(0) bricks every onlyOwner call
}

function withdraw(address to, uint256 amount) external {
    token.transfer(to, amount); // to == address(0) burns the tokens forever
}
```

**Risk**: Burned funds, or a contract with no reachable owner — permanent and unrecoverable.

#### 2. Unchecked Amounts

```solidity
function transfer(address to, uint256 amount) external {
    balances[msg.sender] -= amount;   // no check amount <= balance
    balances[to] += amount;           // underflow guard exists post-0.8, but
}                                     // logic still allows amount == 0 spam / bad invariants
```

**Risk**: Spending more than owned (pre-0.8 underflow), zero-value operations that corrupt invariants, or amounts exceeding an allowance.

#### 3. Mismatched Parallel Arrays (Airdrop Loops)

```solidity
function airdrop(address[] calldata users, uint256[] calldata amounts) external {
    for (uint256 i = 0; i < users.length; i++) {
        token.transfer(users[i], amounts[i]);  // amounts.length may be < users.length
    }                                           // -> revert, or reuse of a stale slot
}
```

**Risk**: Reverts, unintended payouts, or an unbounded loop that exceeds the block gas limit.

#### 4. Unvalidated Indexes / IDs

```solidity
function claim(uint256 index) external {
    Reward memory r = rewards[index];  // index >= rewards.length or already-claimed
    payable(msg.sender).transfer(r.value);
}
```

**Risk**: Out-of-range access, double-claims, or operating on an ID that does not belong to the caller.

#### 5. Missing Bounds on Fees / Percentages

```solidity
function setFee(uint256 feeBps) external onlyOwner {
    fee = feeBps;              // no require(feeBps <= 10_000) -> fee can exceed 100%
}
```

**Risk**: A fee above the intended maximum can capture the entire transaction value.

#### 6. Unchecked Token / Target Addresses

```solidity
function sweep(address token, address to) external {
    IERC20(token).transfer(to, IERC20(token).balanceOf(address(this)));
}                              // token/to are attacker-chosen -> arbitrary external call
```

**Risk**: Interaction with a malicious token/target, arbitrary external calls, and re-entrancy or approval abuse.

### Where Missing Validation Hides

| Input Type | Typical Missing Check | Consequence |
|------------|-----------------------|-------------|
| Address (owner/recipient) | `!= address(0)` | Burned funds, bricked contract |
| Amount / value | `> 0`, within balance/allowance | Over-spend, corrupted accounting |
| Parallel arrays | Equal length, capped length | State corruption, gas-limit DoS |
| Index / token ID | Within range, ownership | Out-of-range read, double-claim |
| Fee / percentage | Upper bound (e.g. `<= 10_000`) | Value seizure, uneconomic system |
| Token / call target | Allow-list, code-size | Arbitrary external call, theft |
| Deadline / signature | Not expired, valid signer | Replay, expiry bypass |

## Real-World Impact

### Case Study 1: Zero-Address Burns (recurring class)

**Missing validation**:
- Transfer, mint, or ownership functions accepted a recipient address without checking it against `address(0)`.
- Users (or front-ends passing an uninitialised variable) supplied the zero address as the destination.

**Impact**:
- Tokens transferred to `address(0)` are irretrievable — effectively burned. When ownership was set to `address(0)`, privileged functions became permanently uncallable.

**Root Cause**: A single missing `require(to != address(0))`. This class is common enough that the OpenZeppelin ERC-20/ERC-721 base contracts add the zero-address check for exactly this reason.

### Case Study 2: Arbitrary Token / Target Abuse (recurring class)

**Missing validation**:
- A function accepted a token address or external call target as a parameter and interacted with it without an allow-list or code-size check.
- Attackers supplied a contract they controlled, or a token with hostile transfer semantics.

**Impact**:
- The contract was induced to make arbitrary external calls, grant approvals, or trust fake balance/return values — a stepping stone to draining held assets or corrupting accounting.

**Root Cause**: Trusting a caller-supplied address as if it were a known-good contract. The defensive pattern is an allow-list of vetted tokens/targets plus `SafeERC20` for token calls.

### Case Study 3: Unbounded / Mismatched Array Loops (recurring class)

**Missing validation**:
- Batch operations (airdrops, multi-sends) looped over caller-supplied arrays without checking equal lengths or capping the size.

**Impact**:
- Mismatched lengths reverted or paid the wrong amounts; an oversized array pushed the loop past the block gas limit, permanently reverting the function (a denial of service).

**Root Cause**: No `require(a.length == b.length)` and no maximum batch size. Fixed by validating lengths and bounding iteration.

> Note: these are described as *classes* of incident. Specific losses vary by protocol and year; the durable lesson is that each traces back to a caller-supplied value that the contract acted on without checking.

## Prevalence and Statistics

Lack of Input Validation sits in the **OWASP Smart Contract Top 10 (2025)** as **SC04** because it is both extremely common and easy to introduce: any function that takes a parameter is a candidate. It frequently underlies findings that get labelled as other issues (access-control bypass, re-entrancy setup, accounting bugs) because a missing check is what opened the door.

Rather than cite a single figure, the defensible picture is:

- Missing validation is **highly prevalent** — audit reports routinely flag absent zero-address, bounds, and length checks in otherwise well-written contracts.
- The most common sub-issues are **missing zero-address checks, unbounded amounts/percentages, and mismatched or uncapped arrays**.
- Impact ranges from **a harmless revert to permanent, total loss of funds** — the same category spans nuisance and catastrophe.

## Common Misunderstandings

### Myth 1: "Solidity 0.8 checked arithmetic covers me"

**Reality**: Built-in overflow/underflow checks stop a specific class of bug. They do *not* validate that an address is non-zero, that a fee is under 100%, that arrays match, or that a target is trusted. Those remain your job.

### Myth 2: "The front-end already validates the inputs"

**Reality**: Anyone can call the contract directly with crafted calldata, bypassing your UI entirely. Client-side checks are convenience, never security. Validate at the contract boundary.

### Myth 3: "Only privileged functions need checks"

**Reality**: Public functions that move value or write state need validation regardless of who can call them. Access control answers *who*; input validation answers *with what values* — both are required.

### Myth 4: "A zero address is obviously wrong, no one would pass it"

**Reality**: Uninitialised variables, buggy front-ends, and integrating contracts pass `address(0)` routinely. Because the result is a permanent burn or brick, it is one of the highest-severity omissions.

### Myth 5: "Validating costs too much gas"

**Reality**: A `require` or custom-error revert is a handful of gas — negligible against the cost of permanently lost funds. Custom errors (`revert ZeroAddress()`) are cheaper than string reverts and keep validation affordable.

### Myth 6: "If it reverts on bad input, that's good enough"

**Reality**: A late revert deep in a function can still leave partial state changes in some patterns, waste gas, or enable griefing. Validate *early*, at the top of the function, before any state is touched.

## How Lack of Input Validation Differs from Related Issues

| Aspect | Lack of Input Validation (SC04) | Access Control | Re-entrancy |
|--------|---------------------------------|----------------|-------------|
| **Root cause** | Untrusted parameter values | Missing caller authorisation | Unsafe external call ordering |
| **Question it answers** | With *what values*? | *Who* may call? | *When* is state final? |
| **Typical fix** | `require`/custom errors at entry | Role/owner modifiers | Checks-effects-interactions |
| **Detection** | Parameter review, fuzzing | Modifier audit | Call-graph analysis |

## Key Takeaways

1. **Every external parameter is attacker-controlled** — anyone can call your functions with any ABI-valid value.
2. **Zero-address checks are non-negotiable** for owners, recipients, and token addresses — the failure mode is permanent.
3. **Bound everything** — amounts, fees, percentages, and array lengths all need explicit upper (and lower) limits.
4. **Allow-list critical addresses and targets** rather than trusting whatever a caller supplies.
5. **Validate early and fail clearly** — check at the top of the function with `require` or custom errors, before touching state.

## How to Identify if You're Vulnerable

- [ ] Does every function that stores or sends to an address check it against `address(0)`?
- [ ] Are amounts checked to be `> 0` and within the caller's balance/allowance?
- [ ] Do parallel arrays have an enforced equal length and a maximum size cap?
- [ ] Are indexes and token IDs bounds-checked and ownership-checked before use?
- [ ] Do fees and percentages have an explicit upper bound (e.g. `<= 10_000` bps)?
- [ ] Are caller-supplied token addresses and call targets on an allow-list?
- [ ] Are deadlines and signatures validated (not expired, correct signer) before acting?
- [ ] When a contract is required, do you check the address has code (code-size > 0)?
- [ ] Is validation performed *before* any state changes or external calls?
- [ ] Are token interactions wrapped with `SafeERC20`?

If you answered "no" or "not sure" to several of these, you likely have exploitable missing validation today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers craft inputs to corrupt state and redirect funds
- **[Prevention](prevention.md)**: Build a complete input-validation baseline at every function boundary
- **[Examples](examples.md)**: Vulnerable vs. secure Solidity for each validation gap
- **[Smart Contract Track](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply these checks against hands-on challenges
