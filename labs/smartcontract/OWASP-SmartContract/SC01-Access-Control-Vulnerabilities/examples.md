# SC01: Access Control Vulnerabilities - Code Examples

Each pair below shows a **vulnerable** Solidity contract and the **secure** version of the same code. The examples focus on the failures that dominate real findings: missing modifiers, `tx.origin` authorization, unprotected initializers, unguarded upgrades and `selfdestruct`, and flawed ownership transfer.

## 1. Missing Access Modifier on `withdraw`

### Vulnerable

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Treasury {
    address public owner;
    constructor() { owner = msg.sender; }

    // No modifier: ANY account can drain the contract.
    function withdraw(uint256 amount) public {
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
```

### Secure

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Treasury is Ownable {
    constructor() Ownable(msg.sender) {}

    // onlyOwner: authenticated with msg.sender via an audited library.
    function withdraw(uint256 amount) external onlyOwner {
        require(amount <= address(this).balance, "insufficient");
        payable(owner()).transfer(amount);
    }

    receive() external payable {}
}
```

## 2. Unprotected `mint`

### Vulnerable

```solidity
pragma solidity ^0.8.24;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Token is ERC20 {
    constructor() ERC20("Token", "TKN") {}

    // Anyone can mint unlimited supply to themselves.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
```

### Secure

```solidity
pragma solidity ^0.8.24;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract Token is ERC20, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor(address admin, address minter) ERC20("Token", "TKN") {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE, minter);   // least privilege: separate minter
    }

    // Only holders of MINTER_ROLE may mint.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }
}
```

## 3. `tx.origin` Authorization (Phishing-Vulnerable)

### Vulnerable

```solidity
pragma solidity ^0.8.24;

contract Wallet {
    address public owner;
    constructor() { owner = msg.sender; }

    // tx.origin passes even when a malicious contract makes the call,
    // as long as the owner started the transaction (phishing bypass).
    function transferTo(address payable to, uint256 amount) external {
        require(tx.origin == owner, "not owner");
        to.transfer(amount);
    }

    receive() external payable {}
}
```

### Secure

```solidity
pragma solidity ^0.8.24;

contract Wallet {
    address public owner;
    constructor() { owner = msg.sender; }

    // msg.sender is the immediate caller: a phishing contract fails this check.
    function transferTo(address payable to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        require(amount <= address(this).balance, "insufficient");
        to.transfer(amount);
    }

    receive() external payable {}
}
```

## 4. Unprotected Initializer (Uninitialized-Proxy Takeover)

### Vulnerable

```solidity
pragma solidity ^0.8.24;

// Upgradeable logic contract with an UNGUARDED initializer.
contract VaultV1 {
    address public owner;
    bool private _done;

    // No `initializer` guard and no _disableInitializers():
    // an attacker calls this first (or on the implementation) and becomes owner.
    function initialize(address _owner) external {
        owner = _owner;
    }

    function upgradeTo(address impl) external {
        require(msg.sender == owner, "not owner");
        // ... points the proxy at `impl` ...
    }
}
```

### Secure

```solidity
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract VaultV1 is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();          // implementation can never be initialized
    }

    // Runs exactly once, on the proxy, guarded by `initializer`.
    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        __UUPSUpgradeable_init();
    }

    // Only the owner may authorize an upgrade.
    function _authorizeUpgrade(address newImpl) internal override onlyOwner {}
}
```

## 5. Unprotected `selfdestruct`

### Vulnerable

```solidity
pragma solidity ^0.8.24;

contract Library {
    address public owner;
    function initLibrary() external { owner = msg.sender; }   // open init

    // Anyone can destroy this contract; if others delegatecall it,
    // they are bricked (Parity multisig freeze class).
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}
```

### Secure

```solidity
pragma solidity ^0.8.24;
import "@openzeppelin/contracts/access/AccessControl.sol";

contract Vault is AccessControl {
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    constructor(address governance) {
        _grantRole(DEFAULT_ADMIN_ROLE, governance);
        _grantRole(GOVERNANCE_ROLE, governance);
    }

    // No selfdestruct at all. A shutdown, if truly needed, is governance-gated
    // and winds down state safely — it never destroys shared/delegatecalled code.
    function emergencyShutdown() external onlyRole(GOVERNANCE_ROLE) {
        // pause, settle balances, disable entrypoints — no selfdestruct
    }
}
```

## 6. Unguarded Upgrade / `delegatecall`

### Vulnerable

```solidity
pragma solidity ^0.8.24;

contract Proxy {
    address public implementation;

    // Anyone can repoint the proxy at attacker-controlled logic.
    function setImplementation(address impl) external {
        implementation = impl;
    }

    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);  // runs on OUR storage
        require(ok, "call failed");
    }
}
```

### Secure

```solidity
pragma solidity ^0.8.24;
import "@openzeppelin/contracts/access/Ownable.sol";

contract Proxy is Ownable {
    address public implementation;
    constructor(address impl) Ownable(msg.sender) { implementation = impl; }

    // Only the owner (ideally a timelock/multisig) may change the logic,
    // and the new implementation must be a contract.
    function setImplementation(address impl) external onlyOwner {
        require(impl.code.length > 0, "not a contract");
        implementation = impl;
    }

    fallback() external payable {
        address impl = implementation;
        (bool ok, ) = impl.delegatecall(msg.data);
        require(ok, "call failed");
    }
}
```

## 7. Single-Step Ownership Transfer

### Vulnerable

```solidity
pragma solidity ^0.8.24;

contract Protocol {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    // A typo or zero address here permanently loses admin control.
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
```

### Secure

```solidity
pragma solidity ^0.8.24;
import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract Protocol is Ownable2Step {
    constructor() Ownable(msg.sender) {}

    // transferOwnership() only PROPOSES a new owner; the pending owner must
    // call acceptOwnership() to take control. The zero address cannot accept,
    // so a mistyped/dead address never bricks admin.
}
```

## 8. Inverted / Broken Modifier

### Vulnerable

```solidity
pragma solidity ^0.8.24;

contract Config {
    address public owner;
    constructor() { owner = msg.sender; }

    // `!=` inverts the intent: everyone EXCEPT the owner passes.
    modifier onlyOwner() {
        require(msg.sender != owner, "denied");
        _;
    }

    uint256 public fee;
    function setFee(uint256 f) external onlyOwner { fee = f; }
}
```

### Secure

```solidity
pragma solidity ^0.8.24;

contract Config {
    address public owner;
    constructor() { owner = msg.sender; }

    // Correct comparison, and the modifier always runs `_;`.
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    uint256 public fee;
    function setFee(uint256 f) external onlyOwner { fee = f; }
}
```

## What Changed, and Why

| Failure | Vulnerable | Secure |
|---------|------------|--------|
| Missing modifier | `withdraw`/`mint` public, no check | `onlyOwner` / `onlyRole` on every privileged function |
| Auth mechanism | `tx.origin == owner` | `msg.sender == owner` |
| Initializer | Unguarded, re-callable | `initializer` + `_disableInitializers()` |
| Lifecycle | Open `selfdestruct` | Removed / governance-gated shutdown |
| Upgrade | Public `setImplementation` | `onlyOwner` + contract check / `_authorizeUpgrade` |
| Ownership transfer | Single-step | Two-step `Ownable2Step` |
| Modifier logic | Inverted `!=` | Correct `==`, always runs `_;` |

> **Rule of thumb**: for every state-changing function, write a negative test proving an unauthorized caller reverts. If you cannot name the single role allowed to call it, it is not ready to ship.

## Next Steps

- **[Prevention](prevention.md)**: The full layered authorization strategy
- **[Attack Vectors](attack-vectors.md)**: How these flaws are exploited
- **[Smart Contract Learning Path](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
