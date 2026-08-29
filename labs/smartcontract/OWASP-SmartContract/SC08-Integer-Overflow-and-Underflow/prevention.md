# SC08: Integer Overflow and Underflow - Prevention

## Prevention Strategy Overview

Preventing overflow and underflow is less about a single trick and more about **making wrap-around impossible on every operation that matters**:

1. Use a modern compiler so checked arithmetic is the default.
2. Wrap legacy code in SafeMath where you cannot upgrade.
3. Treat every `unchecked { }` block as a proof obligation.
4. Validate and bound inputs, and cast narrowly only after a range check.
5. Test the extremes with boundary tests and fuzzing.

### Core Principles

- **Safe by default**: rely on Solidity &ge; 0.8 checked arithmetic rather than hand-written guards.
- **Prove, don't assume**: every place that turns checks off (`unchecked`, casts, assembly) needs an argument for why it cannot wrap.
- **Bound the inputs**: if values cannot reach the extremes, the arithmetic cannot reach the edge.
- **Fail closed**: a revert on overflow is the desired behaviour—never silently continue with a wrapped value.

## 1. Use Solidity &ge; 0.8.0 (Checked Arithmetic by Default)

Since 0.8.0, `+`, `-`, and `*` revert with `Panic(0x11)` on overflow/underflow. This is the single most effective control.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;      // checked arithmetic is on by default

contract Token {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // If amount > balance, the subtraction reverts instead of wrapping.
        balances[msg.sender] -= amount;
        balances[to]        += amount;
    }
}
```

Pin the pragma to a recent version and prefer a fixed version in the deployment config so you know exactly which compiler produced the bytecode.

## 2. Use SafeMath for Legacy (<0.8) Code

If you must compile with an older version, wrap every add/sub/mul in OpenZeppelin SafeMath so each operation reverts on wrap.

```
// pragma solidity ^0.6.0;  (pre-0.8)
import "@openzeppelin/contracts/math/SafeMath.sol";

contract LegacyToken {
    using SafeMath for uint256;
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        balances[msg.sender] = balances[msg.sender].sub(amount); // reverts on underflow
        balances[to]         = balances[to].add(amount);          // reverts on overflow
    }
}
```

On 0.8+ SafeMath is redundant for `+`/`-`/`*` (and just costs gas); keep it only where you deliberately compile below 0.8.

## 3. Audit Every unchecked { } Block

`unchecked` re-enables wrapping to save gas. Use it only where you can prove the operation cannot overflow, and comment the proof.

```
// SAFE: i is bounded by arr.length, which is far below 2^256 - 1
for (uint256 i = 0; i < arr.length; ) {
    // ... use arr[i] ...
    unchecked { ++i; }          // cannot overflow: bounded loop counter
}

// UNSAFE: userInput is attacker-controlled -> do NOT wrap it
// unchecked { accrued[msg.sender] += userInput; }   // reintroduces the bug
accrued[msg.sender] += userInput;   // keep the check on untrusted values
```

Rule of thumb: `unchecked` is acceptable for internally bounded quantities (loop counters, values already range-checked), never for raw attacker input.

## 4. Validate and Bound Inputs

The cheapest overflow defence is ensuring values can never reach the edge of the range.

```
uint256 public constant MAX_MINT = 1_000_000e18;

function mint(uint256 amount) external {
    require(amount > 0 && amount <= MAX_MINT, "amount out of range");
    require(totalSupply + amount <= CAP, "cap exceeded");   // checked add on 0.8+
    totalSupply += amount;
    balances[msg.sender] += amount;
}
```

Bounding inputs also makes intermediate products (in reward/price math) provably fit, which prevents both wraps and surprise reverts.

## 5. Cast and Downcast Safely

Narrowing conversions truncate silently in *every* Solidity version. Range-check before downcasting, or use OpenZeppelin `SafeCast`.

```
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

contract Shares {
    using SafeCast for uint256;
    mapping(address => uint64) public shares;

    function deposit(uint256 amount) external {
        // Reverts if amount does not fit in uint64, instead of truncating.
        shares[msg.sender] += amount.toUint64();
    }
}

// Manual equivalent:
require(amount <= type(uint64).max, "downcast overflow");
uint64 small = uint64(amount);
```

## 6. Be Careful with Inline Assembly

Yul arithmetic (`add`, `mul`, `sub`) performs no overflow checks. If you must use assembly, add the checks yourself.

```
function safeAddAsm(uint256 x, uint256 y) internal pure returns (uint256 z) {
    assembly {
        z := add(x, y)
        // Overflow occurred iff the sum is smaller than an operand.
        if lt(z, x) { revert(0, 0) }
    }
}
```

Prefer high-level Solidity for arithmetic whenever possible; reserve assembly for cases where you have a specific, reviewed reason.

## 7. Order Operations to Avoid Intermediate Overflow

Even with checked arithmetic, an intermediate product that exceeds the range reverts. Structure the math so intermediates stay in range while preserving precision.

```
// Risky: stake * rate may exceed 2^256 - 1 for large inputs
uint256 reward = stake * rate / PRECISION;

// Safer for very large values: use mulDiv (full-precision intermediate)
import "@openzeppelin/contracts/utils/math/Math.sol";
uint256 reward = Math.mulDiv(stake, rate, PRECISION);
```

`Math.mulDiv` computes `a * b / denominator` with a 512-bit intermediate, avoiding both overflow and the precision loss of dividing first.

## 8. Test the Extremes: Boundary Tests and Fuzzing

Overflow bugs live at input extremes ordinary tests never reach. Add boundary cases and fuzz arithmetic invariants.

```
// Foundry: fuzz an invariant across the whole input range
function testFuzz_TransferNeverMints(uint256 a, uint256 b) public {
    a = bound(a, 0, 1e30);
    b = bound(b, 0, 1e30);
    uint256 supplyBefore = token.totalSupply();
    // ... perform transfers with a and b ...
    assertEq(token.totalSupply(), supplyBefore);   // sum of balances invariant holds
}

// Explicit boundary checks
function test_MaxBoundary() public {
    vm.expectRevert();                 // adding to max must revert, not wrap
    counter.add(type(uint256).max, 1);
}
```

Complement Foundry fuzzing with **Echidna** property tests that assert invariants such as &ldquo;sum of balances equals total supply&rdquo; and &ldquo;no function increases total supply above the cap.&rdquo;

## 9. Static Analysis and Review

Automated tools flag unprotected arithmetic, dangerous casts, and risky `unchecked` usage.

```
# Slither: detects integer-overflow-prone patterns, dangerous casts, and more
slither .

# Mythril / MythX: symbolic execution for arithmetic edge cases
myth analyze contracts/Token.sol

# Review checklist focus: every -, +, *, cast, and assembly block
```

Make &ldquo;is this arithmetic protected, and can it reach the edge?&rdquo; an explicit line item in every code review.

## Solidity Version Cheatsheet

| Situation | Default arithmetic | What to do |
| --- | --- | --- |
| Solidity &ge; 0.8, plain `+ - *` | Reverts on wrap | Safe—keep the pragma current |
| Solidity &ge; 0.8, `unchecked { }` | Wraps | Prove it can't overflow, or remove |
| Any version, downcast | Truncates silently | Range-check or `SafeCast` |
| Any version, inline assembly | No checks | Add manual overflow checks |
| Solidity < 0.8 | Wraps | Use SafeMath on every op |

## Key Takeaways

1. **Upgrade first** — Solidity &ge; 0.8 checked arithmetic removes the classic overflow from default code.
2. **SafeMath for legacy** — wrap every add/sub/mul in pre-0.8 contracts you cannot upgrade.
3. **Treat unchecked, casts, and assembly as proof obligations** — these are the only places wraps still happen on 0.8+.
4. **Bound inputs and order operations** — if values can't reach the edge, the math can't wrap; use `mulDiv` for large products.
5. **Fuzz the extremes** — boundary tests and Foundry/Echidna invariants catch what unit tests miss.

## Next Steps

- **Code Examples**: Vulnerable vs. secure Solidity, side by side
- **Attack Vectors**: Understand what you're defending against
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
