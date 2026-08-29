# SC06: Unchecked External Calls - Code Examples

Each pair below shows a **vulnerable** contract and the **secure** rewrite. The examples focus on the failures that dominate real findings: ignoring the boolean of a value transfer, assuming ERC-20 reverts on failure, masking a failed `delegatecall`, and bricking a push-payment loop.

## 1. ETH Withdrawal — Unchecked call

### Vulnerable

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        // BUG: return value ignored. If the recipient rejects ETH, the
        // transfer returns false, the ETH stays here, and the balance is gone.
        msg.sender.call{value: amount}("");
        emit Withdrawn(msg.sender, amount); // emitted even on silent failure
    }

    event Withdrawn(address indexed user, uint256 amount);
}
```

### Secure

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;

    error EthTransferFailed(address to, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient"); // Checks
        balances[msg.sender] -= amount;                          // Effects

        (bool ok, ) = msg.sender.call{value: amount}("");        // Interactions
        if (!ok) revert EthTransferFailed(msg.sender, amount);   // failure reverts
        // the revert rolls back the balance change atomically -> no stuck funds

        emit Withdrawn(msg.sender, amount);
    }
}
```

## 2. Token Deposit — Assuming transferFrom Reverts

### Vulnerable

```
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract Staking {
    IERC20 public token;
    mapping(address => uint256) public staked;

    function stake(uint256 amount) external {
        // BUG: return value ignored. A non-standard token can return false
        // (or nothing) without reverting -> phantom stake credited for free.
        token.transferFrom(msg.sender, address(this), amount);
        staked[msg.sender] += amount;
    }

    function unstake(uint256 amount) external {
        require(staked[msg.sender] >= amount, "insufficient");
        staked[msg.sender] -= amount;
        token.transfer(msg.sender, amount); // return also ignored
    }
}
```

### Secure

```
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract Staking {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    mapping(address => uint256) public staked;

    constructor(IERC20 _token) { token = _token; }

    function stake(uint256 amount) external {
        // Measure the real delta so fee-on-transfer tokens can't inflate credit,
        // and safeTransferFrom reverts on a false/empty return.
        uint256 before = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        staked[msg.sender] += received;   // credit only what actually arrived
    }

    function unstake(uint256 amount) external {
        require(staked[msg.sender] >= amount, "insufficient");
        staked[msg.sender] -= amount;
        token.safeTransfer(msg.sender, amount); // reverts on failure
    }
}
```

## 3. Executor — Unchecked delegatecall

### Vulnerable

```
pragma solidity ^0.8.20;

contract Executor {
    address public owner;
    bool public executed;

    constructor() { owner = msg.sender; }

    function run(address impl, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        // BUG: success flag discarded. A reverting or empty impl is treated
        // as a successful run; storage assumptions are corrupted.
        impl.delegatecall(data);
        executed = true;
    }
}
```

### Secure

```
pragma solidity ^0.8.20;

contract Executor {
    address public immutable owner;
    bool public executed;

    error NotOwner();
    error NotAContract(address target);
    error DelegateCallFailed(bytes reason);

    constructor() { owner = msg.sender; }

    function run(address impl, bytes calldata data)
        external
        returns (bytes memory)
    {
        if (msg.sender != owner) revert NotOwner();
        if (impl.code.length == 0) revert NotAContract(impl); // empty addr returns true!

        (bool ok, bytes memory ret) = impl.delegatecall(data);
        if (!ok) revert DelegateCallFailed(ret);              // check success

        executed = true;                                      // only after real success
        return ret;                                           // caller validates data
    }
}
```

## 4. Reward Distribution — Push Loop vs. Pull

### Vulnerable (push — one bad recipient bricks everyone)

```
pragma solidity ^0.8.20;

contract Airdrop {
    address[] public winners;

    function distribute(uint256 prize) external {
        for (uint256 i = 0; i < winners.length; i++) {
            // BUG: a single reverting/gas-heavy recipient blocks the whole loop,
            // and send()'s false return would be ignored anyway.
            payable(winners[i]).transfer(prize);
        }
    }
}
```

### Secure (pull — each recipient bears their own risk)

```
pragma solidity ^0.8.20;

contract Airdrop {
    mapping(address => uint256) public credits;

    error NothingToClaim();
    error ClaimFailed();

    // Allocation only records the owed amount; it cannot be griefed.
    function allocate(address user, uint256 amount) external {
        credits[user] += amount;
    }

    function claim() external {
        uint256 amount = credits[msg.sender];
        if (amount == 0) revert NothingToClaim();
        credits[msg.sender] = 0;                          // effect first

        (bool ok, ) = msg.sender.call{value: amount}(""); // checked interaction
        if (!ok) revert ClaimFailed();                    // only the caller is affected
    }

    receive() external payable {}
}
```

## What Changed, and Why

| Issue | Vulnerable | Secure |
| --- | --- | --- |
| ETH transfer | `call` return ignored; state pre-updated | CEI + `require`/revert on the success bool |
| Token transfer | Assumes revert-on-failure; ignores bool | `SafeERC20` + measured balance delta |
| delegatecall | Success flag discarded | Check success, guard empty address, return data |
| Distribution | Push loop bricked by one recipient | Pull pattern; each transfer checked and isolated |

## Adversarial Test Mocks

Route every value-moving path through these in tests to prove your checks work:

```
// Rejects all ETH -> makes send()/call() return false
contract Rejector { }

// Returns false without reverting -> catches "assumed revert" bugs
contract FalseToken {
    function transfer(address, uint256) external pure returns (bool) { return false; }
    function transferFrom(address, address, uint256) external pure returns (bool) { return false; }
}

// Returns NO data (USDT-class) -> catches strict-bool-decode bugs
contract NoReturnToken {
    function transfer(address, uint256) external { /* no return */ }
    function transferFrom(address, address, uint256) external { /* no return */ }
}
```

## Next Steps

- **Prevention**: The full return-value-checking and SafeERC20 strategy
- **Attack Vectors**: How these silent failures are triggered and abused
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
