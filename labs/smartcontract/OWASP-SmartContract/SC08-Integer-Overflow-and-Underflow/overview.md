# SC08: Integer Overflow and Underflow - Overview

## Table of Contents

- [What is Integer Overflow and Underflow?](#what-is-integer-overflow-underflow)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [The Crucial Version Nuance](#the-version-nuance)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Significance](#prevalence-and-significance)
- [Common Misunderstandings](#common-misunderstandings)

## What is Integer Overflow and Underflow?

**Integer overflow and underflow** occur when an arithmetic operation produces a result outside the range a fixed-size integer can hold, so the value *wraps around* modulo 2n instead of being the mathematically correct number. On the EVM every integer is fixed-width—`uint256` holds 0 to 2256&minus;1, `uint8` holds 0 to 255—and there is no arbitrary-precision fallback. When a computation steps past the edge of that range, the bits that don't fit are simply discarded, and the surviving value can be wildly wrong.

Two directions of the same defect:

- **Underflow**: subtracting past zero on an unsigned type. `uint8(0) - 1` does not become &minus;1; it wraps to `255`. In a token contract, `balance - amount` where `amount > balance` yields a colossal number instead of a revert—an attacker who should have been rejected instead mints themselves a near-infinite balance.
- **Overflow**: adding or multiplying past the maximum. `uint8(255) + 1` wraps to `0`. A running total, a supply counter, or a cap check that overflows can silently reset to a tiny value, letting an attacker slip past a limit the code believed it was enforcing.

### Core Concept

```
Fixed-width wrap-around (modulo 2^n):

  uint8  range: 0 .. 255            uint256 range: 0 .. 2^256 - 1

  UNDERFLOW (subtract past zero):
    uint8:  0 - 1      -> 255           // not -1
    token:  balance(5) - amount(10)     -> 2^256 - 5   (huge)

  OVERFLOW (add/multiply past max):
    uint8:  255 + 1    -> 0             // wraps to zero
    supply: MAX_UINT + 1               -> 0
    mul:    a * b when a*b > 2^256 - 1  -> truncated

  DOWNCAST TRUNCATION (narrowing a wide value):
    uint256 x = 300;
    uint8   y = uint8(x);              // y == 44  (300 mod 256)

Correct arithmetic would revert or carry; wrapped arithmetic
keeps running with a value the invariants never anticipated.
```

### Why It's Critical for Smart Contracts

The same wrap-around exists in C and countless other languages, but on a blockchain the stakes and the finality are different:

- Contracts **hold value directly**. A wrapped balance or supply is not a display glitch—it is money that can be withdrawn.
- Deployed bytecode is typically **immutable**. If arithmetic is wrong at deploy time, there is often no patch, only migration or loss.
- Transactions are **public and replayable**. Once an attacker finds an overflow, anyone can reproduce it until the contract is drained or paused.
- Arithmetic sits at the heart of **every invariant**—balances, total supply, allowances, share accounting—so a single wrap can break the contract's most fundamental guarantees.

## Why Does This Matter?

### Business Impact

- **Unlimited Token Minting**: An underflow in balance bookkeeping can hand an attacker an astronomically large balance, collapsing the token's value to zero.
- **Direct Fund Theft**: Wrapped accounting in a vault, staking pool, or AMM lets an attacker withdraw far more than they deposited.
- **Cap and Limit Bypass**: An overflowing counter or total can defeat supply caps, per-wallet limits, or sale allocations that the business relies on.
- **Irreversible Loss**: Because transactions are final and code is immutable, a successful overflow exploit is usually unrecoverable without a hard fork or emergency migration.
- **Reputational and Market Damage**: A single arithmetic bug that drains a protocol destroys user trust and can delist a token permanently.

### Technical Impact

- **Broken Invariants**: Sum of balances no longer equals total supply; share accounting diverges from underlying assets.
- **Bypassed Require Checks**: A check like `require(balance >= amount)` is worthless if the very subtraction that follows underflows in older compilers.
- **Silent State Corruption**: Overflow produces no error on pre-0.8 compilers or inside `unchecked` blocks—the contract simply stores a wrong number and continues.
- **Truncation on Casts**: Downcasting `uint256` to `uint64`/`uint8` discards high bits, so amounts, timestamps, or IDs can silently change value.
- **Assembly Has No Guardrails**: Arithmetic written in inline Yul/assembly performs no overflow checks whatsoever, regardless of compiler version.

## Technical Context

### Common Overflow / Underflow Scenarios

#### 1. Balance Underflow (the classic)

```
// Pre-0.8 or inside unchecked: NO automatic check
function transfer(address to, uint256 amount) public {
    // If amount > balances[msg.sender], this subtraction underflows
    balances[msg.sender] -= amount;      // wraps to ~2^256
    balances[to] += amount;
}
```

**Risk**: A sender with balance 0 can send a huge `amount`; their balance wraps to a near-maximum value instead of reverting, minting tokens from nothing.

#### 2. Supply / Cap Overflow

```
// A counter or total that wraps past the maximum
uint256 public totalSupply;

function mint(uint256 amount) public {
    // If totalSupply + amount overflows, the stored total wraps small,
    // defeating any later require(totalSupply <= CAP) check.
    totalSupply += amount;               // pre-0.8 / unchecked: wraps
}
```

**Risk**: An attacker overflows a total or counter so a cap check sees a small number and lets minting continue past the intended limit.

#### 3. Downcast / Truncation

```
uint256 bigAmount = 4_294_967_296;       // 2^32
uint32  small = uint32(bigAmount);        // truncates to 0

// Bookkeeping in uint256 but stored/compared as a narrower type
mapping(address => uint64) public shares;
shares[user] = uint64(computedShares);    // high bits silently dropped
```

**Risk**: Narrowing a wide value drops the high bits, so a large amount can become a small (or zero) stored value, corrupting accounting.

#### 4. Multiplication Before Division

```
// Order matters: multiply first can overflow; divide first loses precision
uint256 reward = (userStake * rewardPerToken) / PRECISION;
// If userStake * rewardPerToken exceeds 2^256 - 1, it wraps (pre-0.8 / unchecked)
```

**Risk**: An intermediate product overflows even though the final result would fit, producing a wildly wrong reward or price.

#### 5. Unchecked Blocks and Inline Assembly

```
unchecked {
    counter += userInput;    // gas-optimised, but NO overflow protection
}

assembly {
    let z := add(x, y)       // Yul add() never checks for overflow
}
```

**Risk**: Modern code deliberately turns checks off for gas; if the operation can actually wrap, the vulnerability is reintroduced on an up-to-date compiler.

### Where Arithmetic Risk Hides

| Location | Typical Mistake | Consequence |
| --- | --- | --- |
| Token transfer/mint | Unchecked `balance - amount` / `supply + amount` | Unlimited minting, cap bypass |
| `unchecked { }` block | Wrap possible on attacker-controlled input | Silent overflow on modern compiler |
| Type casts | Downcast `uint256 -> uint64/uint8` | Truncated amounts, IDs, timestamps |
| Reward / price math | Multiply before divide, large intermediates | Wrong payouts, mispriced shares |
| Inline assembly (Yul) | Raw `add`/`mul`/`sub` | No checks at any compiler version |
| Legacy contracts (<0.8) | No SafeMath around arithmetic | Every operation can wrap |

## The Crucial Version Nuance

**Solidity &ge; 0.8.0 inserts overflow and underflow checks by default.** Since 0.8.0, `+`, `-`, and `*` on integers automatically *revert* (with `Panic(0x11)`) when they would wrap. This changed the shape of the risk—it did not eliminate it.

What this means in practice, and why the bug class is still very much alive:

- **Legacy and unpatched contracts (<0.8)**: Enormous amounts of value sits in contracts compiled before 0.8.0. Without OpenZeppelin **SafeMath**, every add/sub/mul in those contracts can silently wrap. This is where the historical exploits lived.
- **unchecked { } blocks**: Developers use `unchecked` to save gas in hot paths. Inside such a block, 0.8's protection is switched off—so an overflow can slip straight through on the newest compiler if the operation can actually wrap.
- **Casts and downcasts are never checked**: `uint64(x)` truncates silently in *every* version, including 0.8+. The default checked arithmetic does not cover narrowing conversions.
- **Inline assembly / Yul is never checked**: Any arithmetic written in `assembly { }` bypasses all Solidity-level protection regardless of version.
- **Multiply-before-divide still overflows**: On 0.8+ this reverts rather than wrapping—which is safer, but an unexpected revert is still a denial-of-service/logic bug if the code assumed the intermediate would fit.

The modern lesson is not &ldquo;overflow is solved.&rdquo; It is: **know which of your operations are actually unprotected**—old compilers, `unchecked` blocks, casts, and assembly—and prove those specific operations cannot wrap.

## Real-World Impact

### Case Study 1: The ERC-20 batchTransfer Overflow Class (2018)

**Vulnerability**:

- A class of ERC-20 token contracts implemented a batch-transfer function that computed a total as `amount * number_of_recipients` and checked the sender's balance against that total.
- On pre-0.8 compilers with no SafeMath, a carefully chosen `amount` made the multiplication overflow and wrap to a tiny value.

**Impact**:

- The balance check passed against the wrapped-small total, while each recipient was still credited the full, enormous `amount`—minting tokens far beyond supply.
- This pattern (widely referred to as the *batchOverflow* class) affected multiple tokens and forced exchanges to suspend deposits and trading of the affected assets.

**Root Cause**: An unchecked multiplication feeding a balance check on a pre-0.8 compiler without SafeMath.

### Case Study 2: The proxyOverflow ERC-20 Class (2018)

**Vulnerability**:

- A related class of tokens exposed transfer paths where an overflow in the amount/allowance arithmetic let an attacker credit balances that the supply accounting never authorised.

**Impact**:

- Attackers generated balances out of nothing, again prompting exchanges to halt trading of affected tokens while the issue was assessed.

**Root Cause**: The same family of defect—fixed-width arithmetic wrapping in token bookkeeping compiled without overflow protection.

### Case Study 3: Underflow-Based Balance Exploits

**Vulnerability**:

- A recurring pattern in pre-0.8 tokens: a `transfer` or `burn` subtracts an attacker-controlled amount from a balance without first guaranteeing the balance is large enough (or relying on a check that the wrapping subtraction then defeats).

**Impact**:

- Subtracting past zero wraps the attacker's balance to a near-maximum value, effectively minting an unlimited supply that can be sold or drained.

**Root Cause**: Unchecked subtraction on an unsigned integer, allowing an underflow where a revert was expected.

Note: these are described as *classes* of incident. The durable lesson is the pattern—unchecked fixed-width arithmetic in value-bearing bookkeeping—not any single token's exact numbers.

## Prevalence and Significance

Integer overflow and underflow is a **foundational** smart-contract vulnerability: it was among the most exploited bug classes in the 2016–2018 era and is the reason SafeMath became ubiquitous and, ultimately, why checked arithmetic was baked into the Solidity language at 0.8.0.

The defensible picture today:

- On **Solidity &ge; 0.8** the *default* path is safe—plain `+`/`-`/`*` revert on wrap—so brand-new naive code is far less likely to ship a classic overflow than it was in 2017.
- The residual risk concentrates in **four places**: legacy `<0.8` contracts without SafeMath, `unchecked { }` blocks added for gas, silent **casts/downcasts**, and **inline assembly**.
- Impact remains **severe**: a single wrap in balance or supply accounting can be a total loss of funds, and the immutability of deployed code makes it hard to remediate after the fact.

## Common Misunderstandings

### Myth 1: "Solidity 0.8 fixed integer overflow, so I don't need to think about it"

**Reality**: 0.8 protects default `+`/`-`/`*`. It does *not* protect `unchecked` blocks, type casts, or inline assembly, and it does nothing for the huge base of pre-0.8 contracts. You still have to audit every unprotected operation.

### Myth 2: "A require(balance >= amount) before the subtraction makes me safe"

**Reality**: A correct guard *can* prevent underflow, but only if it truly runs first and covers every path. Historically many contracts either omitted it or had a computation that wrapped before the check was meaningful. Relying on checked arithmetic (0.8) or SafeMath is more robust than hand-written guards.

### Myth 3: "unchecked is just a gas optimisation, it's harmless"

**Reality**: `unchecked` re-enables wrap-around. It is safe only when you have *proven* the operation cannot overflow (for example a loop counter bounded by array length). On attacker-influenced values it reintroduces the classic bug on a modern compiler.

### Myth 4: "Casting between integer types is safe"

**Reality**: Narrowing casts (`uint256 -> uint64`) silently truncate in every version. `uint8(300)` is `44`, not a revert. Validate ranges before downcasting or use a safe-cast helper.

### Myth 5: "Overflow only matters for addition"

**Reality**: Subtraction underflows, multiplication overflows (often via multiply-before-divide), and downcasts truncate. Division and modulo have their own edge cases (division by zero reverts; be careful with rounding). The whole arithmetic surface needs attention.

### Myth 6: "If it compiles and the tests pass, the math is fine"

**Reality**: Overflow bugs live at the extreme edges of the input range that ordinary unit tests never reach. You need boundary tests and *fuzzing* (Foundry/Echidna) that push values to `type(uint256).max` and zero to surface them.

## How Overflow/Underflow Differs from Related Issues

| Aspect | Integer Overflow/Underflow (SC08) | Lack of Input Validation (SC04) | Logic Errors (SC03) |
| --- | --- | --- | --- |
| **Root cause** | Fixed-width arithmetic wraps modulo 2^n | Untrusted input used without bounds/checks | Correct types, wrong business rule |
| **Where it lives** | Any add/sub/mul, cast, or assembly | Function entry points and parameters | Control flow and accounting design |
| **Typical fix** | Solidity &ge;0.8 / SafeMath, audit `unchecked`, safe casts | Validate and bound inputs | Rework the invariant/flow |
| **Detection** | Boundary tests, fuzzing invariants | Input fuzzing, review | Spec review, property testing |

## Key Takeaways

1. **Integers are fixed-width**—past the edge they wrap modulo 2n rather than growing, and a wrapped balance or supply is real, spendable value.
2. **0.8 changed the default, not the whole story**—checked arithmetic protects plain `+`/`-`/`*`, but not `unchecked`, casts, or assembly.
3. **The residual risk is specific**—legacy contracts, `unchecked` blocks, downcasts, and inline Yul are where wraps still happen.
4. **Underflow mints, overflow bypasses**—subtracting past zero creates value; overflowing a total defeats a cap.
5. **Prove it can't wrap**—for every unprotected operation, bound the inputs and fuzz the extremes before you trust it.

## How to Identify if You're Vulnerable

Ask these questions about your contract:

- [ ] Is the contract compiled with Solidity &ge; 0.8.0 (checked arithmetic by default)?
- [ ] For any pre-0.8 code, is OpenZeppelin SafeMath used on every add/sub/mul?
- [ ] Has every `unchecked { }` block been reviewed and proven unable to wrap on attacker-controlled input?
- [ ] Are all narrowing casts (`uint256 -> uint64/uint32/uint8`) range-checked or done with a safe-cast helper?
- [ ] Is inline assembly free of unchecked arithmetic on untrusted values?
- [ ] In reward/price math, is the operation order chosen to avoid intermediate overflow?
- [ ] Are inputs bounded so totals and products cannot be driven to the type's extremes?
- [ ] Do tests exercise boundaries (`0`, `type(uint256).max`) and use fuzzing for arithmetic invariants?

If you answered "no" or "not sure" to several of these, your contract may harbour an exploitable overflow or underflow.

## Next Steps

- **Attack Vectors**: How attackers trigger and chain overflow/underflow
- **Prevention**: Checked arithmetic, SafeMath, safe casts, and fuzzing
- **Examples**: Vulnerable vs. secure Solidity, side by side
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
