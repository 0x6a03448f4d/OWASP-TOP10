# SC08: Integer Overflow and Underflow - Code Examples

Each pair below shows a **vulnerable** contract and the **secure** version. The examples focus on the wraps that dominate real findings: balance underflow, multiplication overflow in a total, downcast truncation, `unchecked` misuse, and inline-assembly arithmetic.

## 1. Balance Underflow

### Vulnerable

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;               // pre-0.8: arithmetic wraps silently

contract VulnerableToken {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // No SafeMath, no guard: if amount > balance, this underflows.
        balances[msg.sender] -= amount;   // 0 - 1 => 2^256 - 1
        balances[to]        += amount;
    }
}
// Attacker with balance 0 calls transfer(x, 1) and wraps to a near-max balance.
```

### Secure

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;              // checked arithmetic reverts on wrap

contract SecureToken {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // Underflow now reverts with Panic(0x11) instead of wrapping.
        balances[msg.sender] -= amount;
        balances[to]        += amount;
    }
}
// Pre-0.8 equivalent: use SafeMath -> balances[msg.sender].sub(amount)
```

## 2. Multiplication Overflow in a Total (batchOverflow class)

### Vulnerable

```
pragma solidity ^0.4.24;              // pre-0.8, no SafeMath

contract VulnerableBatch {
    mapping(address => uint256) public balances;

    function batchTransfer(address[] memory to, uint256 amount) public {
        uint256 total = to.length * amount;      // overflows for a crafted amount
        require(balances[msg.sender] >= total);  // passes: total wrapped small
        balances[msg.sender] -= total;
        for (uint i = 0; i < to.length; i++) {
            balances[to[i]] += amount;           // each gets the full huge amount
        }
    }
}
```

### Secure

```
pragma solidity ^0.8.20;

contract SecureBatch {
    mapping(address => uint256) public balances;

    function batchTransfer(address[] calldata to, uint256 amount) external {
        // Checked multiply reverts on overflow, so `total` is always truthful.
        uint256 total = to.length * amount;
        require(balances[msg.sender] >= total, "insufficient balance");
        balances[msg.sender] -= total;
        for (uint256 i = 0; i < to.length; i++) {
            balances[to[i]] += amount;
        }
    }
}
```

## 3. Supply / Cap Overflow

### Vulnerable

```
pragma solidity ^0.7.0;               // pre-0.8

contract VulnerableCap {
    uint256 public totalSupply;
    uint256 constant CAP = 1_000_000e18;
    mapping(address => uint256) public balances;

    function mint(uint256 amount) external {
        totalSupply += amount;            // can overflow and wrap small
        require(totalSupply <= CAP);       // wrapped-small total slips under cap
        balances[msg.sender] += amount;
    }
}
```

### Secure

```
pragma solidity ^0.8.20;

contract SecureCap {
    uint256 public totalSupply;
    uint256 constant CAP = 1_000_000e18;
    mapping(address => uint256) public balances;

    function mint(uint256 amount) external {
        require(amount > 0, "zero amount");
        // Check the cap BEFORE mutating; checked add can't wrap the total.
        require(totalSupply + amount <= CAP, "cap exceeded");
        totalSupply += amount;
        balances[msg.sender] += amount;
    }
}
```

## 4. Downcast Truncation

### Vulnerable

```
pragma solidity ^0.8.20;              // 0.8 does NOT check casts

contract VulnerableCast {
    mapping(address => uint64) public shares;

    function deposit(uint256 amount) external {
        // Silent truncation: amount > type(uint64).max loses its high bits.
        shares[msg.sender] += uint64(amount);   // uint64(2^64) == 0
    }
}
```

### Secure

```
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

contract SecureCast {
    using SafeCast for uint256;
    mapping(address => uint64) public shares;

    function deposit(uint256 amount) external {
        // Reverts if amount does not fit in uint64 instead of truncating.
        shares[msg.sender] += amount.toUint64();
    }
    // Manual equivalent:
    // require(amount <= type(uint64).max, "downcast overflow");
    // shares[msg.sender] += uint64(amount);
}
```

## 5. Misused unchecked Block

### Vulnerable

```
pragma solidity ^0.8.20;

contract VulnerableUnchecked {
    mapping(address => uint256) public accrued;

    function reward(uint256 userInput) external {
        unchecked {
            // Protection OFF on attacker-controlled input: this can wrap.
            accrued[msg.sender] += userInput;
        }
    }
}
```

### Secure

```
pragma solidity ^0.8.20;

contract SecureUnchecked {
    mapping(address => uint256) public accrued;

    function reward(uint256 userInput) external {
        // Keep checked arithmetic on untrusted values.
        accrued[msg.sender] += userInput;
    }

    // unchecked is fine ONLY for provably-bounded quantities:
    function sum(uint256[] calldata xs) external pure returns (uint256 total) {
        for (uint256 i = 0; i < xs.length; ) {
            total += xs[i];          // checked: values are untrusted
            unchecked { ++i; }       // safe: i bounded by xs.length
        }
    }
}
```

## 6. Inline Assembly Arithmetic

### Vulnerable

```
pragma solidity ^0.8.20;

contract VulnerableAsm {
    function addBalances(uint256 x, uint256 y) external pure returns (uint256 z) {
        assembly {
            z := add(x, y)          // Yul add() never checks: wraps silently
        }
    }
}
```

### Secure

```
pragma solidity ^0.8.20;

contract SecureAsm {
    function addBalances(uint256 x, uint256 y) external pure returns (uint256 z) {
        assembly {
            z := add(x, y)
            if lt(z, x) { revert(0, 0) }   // overflow iff sum < an operand
        }
    }
    // Better still: prefer high-level `x + y`, which is checked on 0.8+.
}
```

## 7. Multiply-Before-Divide

### Vulnerable

```
pragma solidity ^0.8.20;

contract VulnerableReward {
    uint256 constant PRECISION = 1e18;

    function reward(uint256 stake, uint256 rate) external pure returns (uint256) {
        // stake * rate can exceed 2^256 - 1 -> reverts (DoS) or, pre-0.8, wraps.
        return stake * rate / PRECISION;
    }
}
```

### Secure

```
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/utils/math/Math.sol";

contract SecureReward {
    uint256 constant PRECISION = 1e18;

    function reward(uint256 stake, uint256 rate) external pure returns (uint256) {
        // 512-bit intermediate: no overflow, no divide-first precision loss.
        return Math.mulDiv(stake, rate, PRECISION);
    }
}
```

## What Changed, and Why

| Issue | Vulnerable | Secure |
| --- | --- | --- |
| Balance underflow | Pre-0.8 `balance - amount` wraps | 0.8 checked arithmetic / SafeMath reverts |
| Total overflow | Unchecked `length * amount` | Checked multiply, cap checked before mutate |
| Downcast | `uint64(amount)` truncates | `SafeCast.toUint64` reverts on overflow |
| `unchecked` | Wraps attacker input | Checked on untrusted values; wrap only bounded counters |
| Assembly | Raw `add`, no check | Manual overflow check or high-level `+` |
| Reward math | Multiply-before-divide overflows | `Math.mulDiv` full-precision |

## Next Steps

- **Prevention**: The full layered defence strategy
- **Attack Vectors**: How these wraps are exploited
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
