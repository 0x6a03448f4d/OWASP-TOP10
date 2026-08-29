# SC08: Integer Overflow and Underflow - Attack Vectors

## Table of Contents

- [Understanding Overflow/Underflow Attack Vectors](#understanding)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Arithmetic Bugs](#chaining)

## Understanding Overflow/Underflow Attack Vectors

**&#9888;&#65039; EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in contracts you own or are authorised to test.

Overflow and underflow are not exploited with clever payloads—they are exploited with **extreme numbers**. The attacker reads the source (or bytecode) for an arithmetic operation that lacks protection, then supplies an input at the very edge of the integer range so the result wraps. Because the maths is deterministic and public, once a wrapping operation is found the exploit is a single, reproducible transaction.

The attacker's goal in this category is usually one of:

- Underflow a balance so it wraps to a near-maximum value (mint from nothing).
- Overflow a total, counter, or cap so a limit check sees a small number and passes.
- Truncate a value via a downcast so a large amount is stored as a small one (or vice versa).
- Force an intermediate product to wrap so a reward, price, or share calculation is wildly wrong.

### Core Attack Flow

```
1. Locate unprotected arithmetic
   &darr;
   Pre-0.8 code without SafeMath, an unchecked { } block,
   a downcast, or inline assembly
2. Model the wrap
   &darr;
   Choose an input that pushes the operation past 0 or past 2^n - 1
3. Trigger
   &darr;
   Call the function with the boundary value in one transaction
4. Profit / Exfiltrate
   &darr;
   Spend the wrapped balance, bypass the cap, or drain the pool
```

## Common Attack Patterns

### 1. Balance Underflow (mint from nothing)

The canonical exploit: subtract more than you hold from an unsigned balance so it wraps upward.

```
// Vulnerable (pre-0.8 or inside unchecked)
function transfer(address to, uint256 amount) public {
    balances[msg.sender] -= amount;   // no guard: underflows if amount > balance
    balances[to]        += amount;
}

// Attacker holds 0 tokens:
transfer(attacker2, 1);
// balances[attacker] = 0 - 1 = 2^256 - 1   (near-infinite balance)
```

**Payoff**: an attacker with zero (or tiny) balance ends up with an astronomically large one and can dump it on the market.

### 2. Multiplication Overflow in a Total (batchOverflow class)

A batch operation computes `amount * count` and checks it against the balance. A crafted `amount` overflows the product to a tiny value, so the check passes while each recipient is credited the full amount.

```
// Vulnerable batch transfer (pre-0.8, no SafeMath)
function batchTransfer(address[] memory to, uint256 amount) public {
    uint256 total = to.length * amount;      // overflows for a huge `amount`
    require(balances[msg.sender] >= total);  // passes: `total` wrapped small
    for (uint i = 0; i < to.length; i++) {
        balances[to[i]] += amount;           // each gets the full, enormous amount
    }
}
```

**Payoff**: tokens minted far beyond supply from a single call—the historical *batchOverflow* pattern.

### 3. Supply / Cap Overflow (limit bypass)

An overflowing total lets a later cap check see a small number.

```
uint256 public totalSupply;
uint256 constant CAP = 1_000_000e18;

function mint(uint256 amount) public {
    totalSupply += amount;               // wraps past 2^256 - 1 (pre-0.8 / unchecked)
    require(totalSupply <= CAP);          // wrapped-small total slips under the cap
    balances[msg.sender] += amount;
}
```

**Payoff**: minting continues past the intended cap because the invariant it relies on was corrupted by the wrap.

### 4. Downcast Truncation

A wide value narrowed to a smaller type silently loses its high bits.

```
// Amount tracked in uint256 but stored in uint64
mapping(address => uint64) public shares;

function deposit(uint256 amount) public {
    shares[msg.sender] += uint64(amount);   // amount > 2^64-1 truncates
    // Attacker picks amount = 2^64  -> uint64(amount) == 0 stored,
    // or amount = 2^64 + 1 -> stored as 1, decoupling shares from deposit
}
```

**Payoff**: accounting decouples from reality—an attacker can deposit a huge amount recorded as tiny, or manipulate IDs/timestamps that were downcast.

### 5. unchecked Block on Attacker Input

A gas optimisation that re-enables wrapping on a value the attacker controls.

```
function reward(uint256 userInput) public {
    unchecked {
        accrued[msg.sender] += userInput;   // 0.8 protection OFF here
    }
    // A large userInput wraps accrued[] to a small value or overflows a later sum
}
```

**Payoff**: the classic overflow is reintroduced on a modern compiler wherever `unchecked` wraps an untrusted value.

### 6. Inline Assembly Arithmetic

Yul `add`/`mul`/`sub` never check for overflow, at any compiler version.

```
function unsafeAdd(uint256 x, uint256 y) public pure returns (uint256 z) {
    assembly {
        z := add(x, y)      // wraps silently; no Panic(0x11)
    }
}
```

**Payoff**: any invariant that trusts an assembly computation can be broken by choosing operands that wrap.

### 7. Multiply-Before-Divide Precision/Overflow

Reward and pricing math where the intermediate product exceeds the range.

```
// Intended: reward = stake * rate / PRECISION
uint256 reward = stake * rate / PRECISION;
// If stake * rate > 2^256 - 1: pre-0.8 wraps to a tiny reward;
// 0.8+ reverts (a DoS if the code assumed it would fit).
```

**Payoff**: either a wrong (tiny or huge) payout, or an unexpected revert that locks the function—depending on compiler version.

### 8. Underflow to Bypass a Time or Count Guard

Subtraction used inside a comparison can wrap and invert the intended logic.

```
// Vulnerable (pre-0.8 / unchecked): meant to enforce a cooldown
require(block.timestamp - lastAction[msg.sender] > COOLDOWN);
// If lastAction is in the future (set by another buggy path) or zero-handling
// is wrong, the subtraction can underflow to a huge number and always pass.
```

**Payoff**: a guard that should throttle actions becomes trivially satisfiable because the subtraction wrapped.

## Chaining Arithmetic Bugs

Individually small wraps combine into full compromise:

```
Downcast truncates deposit to a tiny stored amount
        +
Reward math multiplies that stored value by a rate
        +
Withdrawal underflows the pool balance when repaying
        =  drain more than was ever deposited, no reentrancy needed
```

Another common chain:

```
unchecked { } wraps an internal counter to 0
        -> a "first-time" branch re-triggers minting
        -> overflowed totalSupply slips under the cap check
        -> attacker mints repeatedly past the intended limit
```

## Key Takeaways

1. **Overflow is exploited with extremes, not payloads**—the attacker feeds values at the edge of the integer range.
2. **Underflow mints, overflow bypasses**—subtracting past zero creates value; overflowing a total defeats a cap.
3. **The unprotected surface is specific**—pre-0.8 code, `unchecked` blocks, casts, and assembly are where wraps happen on modern compilers.
4. **Casts are a silent attack vector**—downcasting truncates in every version, decoupling accounting from reality.
5. **Small wraps chain**—a truncation plus a reward calculation plus an underflowing withdrawal equals a drained pool.

## Next Steps

- **Prevention Guide**: Checked arithmetic, SafeMath, safe casts, and fuzzing
- **Code Examples**: See vulnerable vs. secure Solidity
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
