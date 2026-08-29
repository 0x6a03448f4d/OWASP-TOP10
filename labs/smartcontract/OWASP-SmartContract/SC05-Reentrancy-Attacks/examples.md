# SC05: Reentrancy Attacks - Code Examples

Each example below shows a **vulnerable** Solidity contract and the **secure** rewrite. We start with the classic vulnerable `withdraw` and the attacker contract that drains it, then fix it with Checks-Effects-Interactions and OpenZeppelin's `nonReentrant` guard—before covering cross-function, token-hook, and read-only variants.

## 1. The Classic Vulnerable Bank

### Vulnerable

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBank {
    mapping(address => uint256) public balance;

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    // BUG: external call happens BEFORE the balance is zeroed
    function withdraw() external {
        uint256 amount = balance[msg.sender];
        require(amount > 0, "nothing to withdraw");

        // Interaction first: hands control to msg.sender's receive()
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        // Effect last: attacker has already re-entered before this runs
        balance[msg.sender] = 0;
    }
}
```

### The Attacker Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBank {
    function deposit() external payable;
    function withdraw() external;
}

contract Attacker {
    IBank public immutable bank;

    constructor(address bank_) { bank = IBank(bank_); }

    // 1. Seed a deposit, then kick off the first withdraw
    function attack() external payable {
        bank.deposit{value: 1 ether}();
        bank.withdraw();
    }

    // 2. Re-entry point: called each time the bank sends ETH
    receive() external payable {
        // While the bank still has funds AND our balance is not yet zeroed,
        // call withdraw() again. balance[attacker] is still 1 ether each time.
        if (address(bank).balance >= 1 ether) {
            bank.withdraw();
        }
    }
}
```

The `receive()` function re-enters `withdraw()` before `balance[msg.sender] = 0` ever executes, so the bank pays out the same 1 ETH balance repeatedly until it is drained.

### Secure (Checks-Effects-Interactions + `nonReentrant`)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract SecureBank is ReentrancyGuard {
    mapping(address => uint256) public balance;

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        // 1. Checks
        uint256 amount = balance[msg.sender];
        require(amount > 0, "nothing to withdraw");

        // 2. Effects  (state finalised BEFORE the external call)
        balance[msg.sender] = 0;

        // 3. Interactions
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
```

Now a re-entrant call finds `balance[msg.sender] == 0` and reverts at the `require`; even if the ordering were wrong, `nonReentrant` would reject the second entry. Either control alone stops this attack; together they are defence-in-depth.

## 2. Cross-Function Reentrancy

### Vulnerable

```solidity
// withdraw() and transfer() share balance[]; a guard on only one is not enough
contract VulnerableShares {
    mapping(address => uint256) public balance;

    function withdraw() external {
        uint256 amount = balance[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");  // control leaves here
        require(ok);
        balance[msg.sender] = 0;                            // not yet run
    }

    // Attacker's receive() calls this mid-withdraw, moving the stale balance out
    function transfer(address to, uint256 amt) external {
        require(balance[msg.sender] >= amt);                // reads OLD balance
        balance[msg.sender] -= amt;
        balance[to] += amt;
    }
}
```

### Secure

```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract SecureShares is ReentrancyGuard {
    mapping(address => uint256) public balance;

    // Guard BOTH functions that share state, and keep CEI ordering
    function withdraw() external nonReentrant {
        uint256 amount = balance[msg.sender];
        require(amount > 0);
        balance[msg.sender] = 0;                            // effect first
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function transfer(address to, uint256 amt) external nonReentrant {
        require(balance[msg.sender] >= amt);
        balance[msg.sender] -= amt;
        balance[to] += amt;
    }
}
```

The mutex is shared across the contract, so re-entering `transfer()` during `withdraw()` reverts—closing the cross-function path a single-function guard would miss.

## 3. Token-Hook Reentrancy (ERC777 / ERC721)

### Vulnerable

```solidity
// Assumes token.transfer cannot call back — false for ERC777
contract VulnerableClaim {
    mapping(address => uint256) public owed;
    IERC777 public token;

    function claim() external {
        uint256 amt = owed[msg.sender];
        require(amt > 0);
        token.send(msg.sender, amt, "");   // ERC777: invokes tokensReceived hook
        owed[msg.sender] = 0;              // runs after the hook -> re-entrant claim
    }
}
```

### Secure

```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract SecureClaim is ReentrancyGuard {
    mapping(address => uint256) public owed;
    IERC777 public token;

    function claim() external nonReentrant {
        uint256 amt = owed[msg.sender];
        require(amt > 0);
        owed[msg.sender] = 0;              // effect BEFORE the hooked transfer
        token.send(msg.sender, amt, "");   // tokensReceived can no longer re-enter usefully
    }
}
```

The same fix applies to ERC721: update "claimed/minted" flags *before* calling `safeTransferFrom`/`safeMint`, which invoke `onERC721Received` on the recipient.

## 4. Read-Only Reentrancy

### Vulnerable

```solidity
// A view getter that is temporarily inconsistent during a withdrawal callback
contract VulnerablePool {
    uint256 public totalAssets;
    uint256 public totalShares;

    function getSharePrice() external view returns (uint256) {
        return totalAssets * 1e18 / totalShares;   // wrong mid-callback
    }

    function removeLiquidity(uint256 shares) external {
        uint256 assets = shares * totalAssets / totalShares;
        totalAssets -= assets;                       // assets sent below...
        (bool ok, ) = msg.sender.call{value: assets}("");  // re-entry window
        require(ok);
        totalShares -= shares;                       // supply updated too late
    }
    // During the callback, getSharePrice() returns an inflated value that an
    // integrating lending market may trust to over-value collateral.
}
```

### Secure

```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract SecurePool is ReentrancyGuard {
    uint256 public totalAssets;
    uint256 public totalShares;

    // View-side guard: reverts if read while a state-changing op holds the lock
    function getSharePrice() external view returns (uint256) {
        require(!_reentrancyGuardEntered(), "reentrant read");
        return totalAssets * 1e18 / totalShares;
    }

    function removeLiquidity(uint256 shares) external nonReentrant {
        uint256 assets = shares * totalAssets / totalShares;
        // Finalise BOTH state variables before the external call
        totalAssets -= assets;
        totalShares -= shares;
        (bool ok, ) = msg.sender.call{value: assets}("");
        require(ok);
    }
}
```

Two fixes combine: state is fully settled before the external call (so even a mid-call read is consistent), and the getter reverts if consulted during a locked operation. Integrators should also prefer reads that cannot be observed mid-update. (`_reentrancyGuardEntered()` is exposed by recent OpenZeppelin `ReentrancyGuard`.)

## What Changed, and Why

| Issue | Vulnerable | Secure |
|-------|------------|--------|
| Single-function drain | Send ETH, then zero balance | Zero balance, then send (CEI) + `nonReentrant` |
| Cross-function | Guard on one function only | Guard every function sharing state |
| Token hooks | Transfer, then update accounting | Update accounting, then transfer |
| Read-only | Getter reads mid-update state | Settle state first + view-side guard |
| Gas assumptions | Rely on `transfer` stipend | Use `call` + CEI + guard |

## Next Steps

- **[Prevention](prevention.md)**: The full layered defence strategy
- **[Attack Vectors](attack-vectors.md)**: How these reentrancy variants are exploited
- **[Smart Contract Learning Path](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
