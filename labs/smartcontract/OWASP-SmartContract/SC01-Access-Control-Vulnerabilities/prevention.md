# SC01: Access Control Vulnerabilities - Prevention

## Prevention Strategy Overview

Preventing broken access control is less about one clever control and more about **making "authorized-by-default-nothing" the rule**: every privileged function is denied to everyone until an explicit, correct check grants it:

1. Put an explicit access modifier on every state-changing/privileged function.
2. Authenticate with `msg.sender`, using an audited authorization library.
3. Protect initializers and disable them on the implementation.
4. Guard upgrades and `delegatecall`, and gate or remove `selfdestruct`.
5. Apply least privilege, role separation, and two-step ownership transfer.

### Core Principles

- **Deny by default**: a privileged function with no matching authorization should be unreachable; opting *in* a caller is explicit and reviewed.
- **Least privilege**: each role holds the minimum power it needs; no single key can do everything.
- **Use audited primitives**: prefer OpenZeppelin `Ownable`/`AccessControl` over hand-rolled checks.
- **Fail closed**: if the caller is not provably authorized, `revert`.

## 1. Apply an Explicit Modifier to Every Privileged Function

The foundational control: audit every state-changing function and confirm it carries the correct guard. Treat "no modifier" as a finding, not a default.

```solidity
// OpenZeppelin Ownable: msg.sender-based owner check, ready-made
import "@openzeppelin/contracts/access/Ownable.sol";

contract Treasury is Ownable {
    constructor() Ownable(msg.sender) {}

    function withdraw(uint256 amount) external onlyOwner {      // guarded
        payable(owner()).transfer(amount);
    }
    function pause() external onlyOwner { /* ... */ }           // guarded
    function setFeeRecipient(address r) external onlyOwner {    // guarded
        feeRecipient = r;
    }
}
```

Build a checklist of every externally reachable function and mark its intended caller. Any function that changes state and is missing from the "guarded" column is a bug.

## 2. Use Role-Based Access Control for Multiple Privileges

When different powers should belong to different parties, use `AccessControl` and gate each function with the specific role it requires.

```solidity
import "@openzeppelin/contracts/access/AccessControl.sol";

contract Token is AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);   // manages roles
        // grant MINTER/PAUSER to separate, purpose-specific accounts
    }

    function mint(address to, uint256 amt) external onlyRole(MINTER_ROLE) {
        _mint(to, amt);
    }
    function pause() external onlyRole(PAUSER_ROLE) { /* ... */ }
}
```

Separate the admin that *manages* roles from the accounts that *exercise* them, and prefer a multisig or governance contract for `DEFAULT_ADMIN_ROLE`.

## 3. Always Authenticate with `msg.sender`, Never `tx.origin`

`tx.origin` is the originating EOA and is phishing-vulnerable; `msg.sender` is the immediate caller and is what authorization must use.

```solidity
// VULNERABLE
require(tx.origin == owner, "not owner");

// SECURE
require(msg.sender == owner, "not owner");
```

The only legitimate use of `tx.origin` is niche (e.g., refusing all contract callers), and even that is discouraged. For authorization, it is simply wrong.

## 4. Protect Initializers in Upgradeable Contracts

Upgradeable contracts have no constructor for the proxy's state, so they use an `initialize` function. Guard it with the `initializer` modifier and disable initialization on the implementation.

```solidity
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract VaultV1 is Initializable, OwnableUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();        // implementation can never be initialized
    }

    function initialize(address owner_) external initializer {   // runs once only
        __Ownable_init(owner_);
    }
}
```

The `initializer` modifier ensures the function can run exactly once; `_disableInitializers()` in the constructor blocks the uninitialized-implementation takeover class. Where possible, initialize atomically in the deployment/factory transaction to remove any front-running window.

## 5. Guard Upgrades and `delegatecall`

Upgrade authority and any `delegatecall` target run code against your own storage—restrict them tightly. With UUPS, implement the authorization hook.

```solidity
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract VaultV1 is UUPSUpgradeable, OwnableUpgradeable {
    // Only the owner (ideally a multisig/governance) may authorize an upgrade
    function _authorizeUpgrade(address newImpl) internal override onlyOwner {}
}
```

Never expose a public setter that changes the implementation address or performs a raw `delegatecall` to a caller-supplied target. If you must use `delegatecall`, restrict the target to a fixed, trusted, immutable address.

## 6. Two-Step Ownership Transfer

Single-step transfers to a wrong or zero address are irreversible. Use a propose/accept flow so the new owner must confirm before authority moves.

```solidity
import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract Protocol is Ownable2Step {
    constructor() Ownable(msg.sender) {}
    // transferOwnership(newOwner) only PROPOSES;
    // the newOwner must call acceptOwnership() to take control.
}
```

`Ownable2Step` also rejects the accept from anyone but the pending owner, eliminating the "typo to a dead address" lockout.

## 7. Remove or Gate `selfdestruct`

An unauthorized `selfdestruct` can erase the contract and, via `delegatecall` dependencies, brick others. Prefer removing it entirely.

```solidity
// AVOID a reachable selfdestruct. If a shutdown is truly required,
// restrict it to governance and never place it on delegatecalled library code:
function emergencyShutdown() external onlyRole(GOVERNANCE_ROLE) {
    // wind down state safely; do NOT selfdestruct shared libraries
}
```

The Parity multisig freeze class came directly from a `selfdestruct` reachable on shared, delegatecalled library code—treat lifecycle functions as maximally sensitive.

## 8. Declare Explicit Function Visibility

Never rely on defaults. State `external`, `public`, `internal`, or `private` on every function, and prefer the most restrictive that works.

```solidity
function _assignOwner(address a) internal { owner = a; }   // helper: internal
function withdraw(uint256 a) external onlyOwner { /* ... */ }   // entrypoint: external
```

Modern Solidity (0.5.0+) requires explicit visibility; keep the compiler strict and never suppress the warning in ported code.

## 9. Least Privilege and Role Separation

- Split powerful capabilities (mint, upgrade, treasury, pause) across separate roles and separate keys.
- Assign the highest-value roles (`DEFAULT_ADMIN_ROLE`, upgrade authority) to a multisig or timelock/governance contract, not a single EOA.
- Grant only what each actor needs; revoke roles that are no longer used.

```solidity
// A timelock owns the upgrade role; a separate multisig holds treasury power.
_grantRole(UPGRADER_ROLE, address(timelock));
_grantRole(TREASURER_ROLE, address(treasuryMultisig));
// No single account holds both.
```

## 10. Testing, Static Analysis, and Audit

Authorization bugs are catchable before deployment. Add automated and manual gates.

```bash
# Static analyzers flag missing modifiers, tx.origin, unprotected selfdestruct, etc.
slither .                       # detectors: suicidal, tx-origin, unprotected-upgrade
mythril analyze contract.sol    # symbolic checks for reachable privileged ops

# Write negative tests: a NON-owner call MUST revert
function test_withdraw_reverts_for_stranger() public {
    vm.prank(stranger);
    vm.expectRevert();
    treasury.withdraw(1 ether);
}
```

Require negative-path tests (unauthorized callers revert) for every privileged function, run Slither/Mythril in CI, and commission an independent audit before mainnet.

## Layered Defense Summary

| Layer | Control | Stops |
|-------|---------|-------|
| Function guard | `onlyOwner` / `onlyRole` on every privileged function | Missing-modifier drains, unauthorized mint |
| Auth mechanism | `msg.sender` via audited library | `tx.origin` phishing bypass |
| Initialization | `initializer` + `_disableInitializers()` | Uninitialized-proxy takeover |
| Upgrade path | `_authorizeUpgrade`, fixed `delegatecall` target | Logic substitution |
| Ownership | Two-step transfer, reject zero address | Irreversible lockout / takeover |
| Lifecycle | Remove/gate `selfdestruct` | Contract destruction / freeze |
| Governance | Least privilege, multisig/timelock | Single-key compromise |
| Verification | Slither/Mythril, negative tests, audit | Shipping the flaw at all |

## Key Takeaways

1. **Guard every privileged function** — a missing modifier is the number-one access-control finding.
2. **Use audited primitives and `msg.sender`** — `Ownable`/`AccessControl` over hand-rolled checks; never `tx.origin`.
3. **Lock initializers and disable them on the implementation** — close the uninitialized-proxy class.
4. **Guard upgrades and `delegatecall`, and remove `selfdestruct`** — these substitute or destroy your logic.
5. **Least privilege, two-step transfer, and negative tests** — contain blast radius and prove unauthorized callers revert.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure Solidity contracts
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Smart Contract Learning Path](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
