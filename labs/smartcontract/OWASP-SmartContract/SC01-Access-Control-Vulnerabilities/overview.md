# SC01: Access Control Vulnerabilities - Overview

## Table of Contents
- [What are Access Control Vulnerabilities?](#what-are-access-control-vulnerabilities)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What are Access Control Vulnerabilities?

**Access control** in a smart contract is the set of rules that decides *who* is allowed to invoke *which* state-changing operation. An **access control vulnerability** exists when a privileged function—one that moves funds, mints tokens, changes ownership, upgrades logic, pauses the system, or destroys the contract—can be called by an account that should never have been permitted to call it. In the OWASP Smart Contract Top 10 (2025), Access Control Vulnerabilities are ranked **SC01** because they are both the most common and among the most catastrophic class of on-chain flaws.

Unlike a traditional application, a deployed smart contract is **public, immutable, and adversarial by default**. Every function selector is discoverable, every byte of storage is world-readable, and anyone on earth can craft a transaction that calls any externally reachable function. There is no network perimeter, no firewall, and no operator watching a console who might notice a suspicious login. If a function that withdraws the treasury lacks an authorization check, the check does not exist—and the first bot to notice will drain it in a single block.

### Core Concept

```
Correct Access Control:
  withdraw()      -> onlyOwner / role-gated, checks msg.sender
  mint()          -> only addresses holding MINTER_ROLE
  upgradeTo()     -> only the proxy admin, guarded
  setOwner()      -> only current owner, ideally two-step
  selfdestruct    -> removed, or reachable only by governance
  initialize()    -> runs exactly once, locked on the implementation

Broken Access Control:
  withdraw()      -> public, no modifier: anyone drains the balance
  mint()          -> missing role check: anyone inflates supply
  upgradeTo()     -> unprotected: attacker swaps in malicious logic
  setOwner()      -> anyone can claim ownership
  selfdestruct    -> callable by anyone: contract and funds vanish
  initialize()    -> re-callable / never locked: attacker becomes owner
```

### Why It's Critical for Smart Contracts

Smart contracts concentrate several conditions that make a broken access check uniquely devastating:

- They are **irreversible**. A confirmed transaction cannot be undone; a drained treasury is gone unless the attacker chooses to return it.
- They **custody value directly**. The vulnerable function does not expose data to be misused later—it moves money *now*.
- They are **fully transparent**. Source (or at least bytecode) is public, so an attacker can read the exact missing check and craft the exploit offline.
- They are **permissionlessly callable**. There is no login step to fail; the only gate is the code's own `require` statements.
- They are **watched by bots**. Automated searchers scan the mempool and deployed bytecode for unprotected privileged functions and exploit them within seconds.

## Why Does This Matter?

### Business Impact

- **Direct Loss of Funds**: An unprotected `withdraw`, `transfer`, or `emergencyWithdraw` lets any account empty the contract's balance in one transaction.
- **Unlimited Token Inflation**: A `mint` function missing a role check lets an attacker print tokens at will, collapsing the token's value and draining paired liquidity pools.
- **Total Protocol Takeover**: An open ownership-transfer or initializer hands the attacker every admin power—pausing, upgrading, re-pointing fee recipients, and looting reserves.
- **Permanent Loss of Access**: An unprotected `selfdestruct`, or a bricked upgrade path, can freeze or erase user funds with no recovery—the Parity multisig wallet freeze class is the canonical example.
- **Reputational and Legal Fallout**: On-chain losses are public, permanent, and traceable; a single access-control failure can end a protocol and trigger investor and regulatory action.

### Technical Impact

- **Privilege Escalation**: An anonymous caller gains owner/admin/minter authority the design never intended to grant.
- **Logic Substitution**: An unguarded upgrade or `delegatecall` lets an attacker replace the contract's code with their own.
- **State Corruption**: Privileged setters (fee rates, oracle addresses, pause flags) become attacker-controlled, breaking every invariant the protocol relies on.
- **Contract Destruction**: `selfdestruct` reachable without authorization removes the code and forwards the balance to an attacker-chosen address.
- **Authorization Bypass**: `tx.origin`-based checks are defeated through a phishing contract, letting a malicious intermediary act as the victim.

## Technical Context

### Common Access Control Failure Modes

#### 1. Missing Access Modifier on a Sensitive Function

```solidity
// VULNERABLE: no modifier — anyone can call this
function withdraw(uint256 amount) public {
    payable(msg.sender).transfer(amount);   // drains the contract
}
```

The single most common finding: a state-changing function that *should* be restricted has no `onlyOwner`/role check at all. The same mistake on `mint`, `setOwner`, `pause`, `upgradeTo`, or `selfdestruct` is equally fatal.

#### 2. Default / Implicit Function Visibility

```solidity
// In older Solidity, a function with no visibility keyword
// defaulted to PUBLIC — silently exposing internal logic.
function _initializeOwner(address a) { owner = a; }   // pre-0.5.0: public!
```

**Risk**: A helper the author assumed was internal is externally callable. Solidity 0.5.0+ made visibility mandatory, but the pattern still appears in ported code and in the mental model of developers.

#### 3. Authorization via `tx.origin` Instead of `msg.sender`

```solidity
// VULNERABLE: tx.origin is the original EOA, not the caller
require(tx.origin == owner, "not owner");
```

**Risk**: If the owner is tricked into calling a malicious contract, that contract can call the victim contract; `tx.origin` is still the owner, so the check passes. This is the classic **phishing** bypass. Authorization must use `msg.sender` (the immediate caller).

#### 4. Unprotected or Re-callable Initializer (Proxy/Upgradeable)

```solidity
// VULNERABLE: no `initializer` guard — callable by anyone, possibly twice
function initialize(address _owner) external {
    owner = _owner;         // attacker calls it first and becomes owner
}
```

**Risk**: Upgradeable contracts replace the constructor with an `initialize` function. If it is not protected by an `initializer` modifier—or the implementation contract is left uninitialized—an attacker calls it, seizes ownership, and can then trigger an upgrade or a `selfdestruct` through `delegatecall`. This is the **uninitialized-proxy takeover** class.

#### 5. Missing Role Check in a Multi-Role System

```solidity
// VULNERABLE: comment claims a restriction the code never enforces
function setFeeRecipient(address r) external {   // "admin only" — but nothing checks it
    feeRecipient = r;
}
```

**Risk**: In role-based designs (`AccessControl`), forgetting the `onlyRole(...)` guard on even one setter reopens the whole surface.

#### 6. Incorrect Modifier Logic

```solidity
// VULNERABLE: wrong operator / wrong variable inverts the check
modifier onlyOwner() {
    require(msg.sender != owner, "denied");  // `!=` should be `==`
    _;
}
```

**Risk**: The gate exists but is logically wrong—an inverted comparison, a check against the wrong address, or a modifier that never calls `_;`—so it either blocks everyone or nobody.

#### 7. Unprotected Upgrade / `delegatecall`

```solidity
// VULNERABLE: anyone can point the proxy at attacker-controlled logic
function setImplementation(address impl) external {
    implementation = impl;              // no admin check
}
```

**Risk**: `delegatecall` runs target code in *this* contract's storage context. An unguarded upgrade or raw `delegatecall` lets an attacker execute arbitrary logic against the protocol's own state and balance.

#### 8. Flawed Ownership Transfer

```solidity
// VULNERABLE: single-step, no validation
function transferOwnership(address n) external onlyOwner {
    owner = n;   // typo to a wrong/zero address permanently bricks admin
}
```

**Risk**: A one-step transfer to a mistyped or zero address permanently loses control. A two-step (propose/accept) transfer prevents the mistake.

### Where Access Control Lives in a Contract

| Surface | Typical Failure | Consequence |
|---------|-----------------|-------------|
| Fund movement (`withdraw`, `transfer`) | No modifier at all | Treasury drained |
| Supply control (`mint`, `burn`) | Missing role check | Unlimited inflation |
| Ownership / admin setters | Open or single-step transfer | Protocol takeover / lockout |
| Initializer (proxy) | Unguarded / re-callable | Attacker becomes owner |
| Upgrade / `delegatecall` | Unprotected | Arbitrary logic substitution |
| Lifecycle (`selfdestruct`, `pause`) | No authorization | Destruction / denial of service |
| Auth mechanism | `tx.origin` instead of `msg.sender` | Phishing bypass |

## Real-World Impact

### Case Study 1: The Parity Multisig Wallet Freeze Class (2017)

**Vulnerability**:
- A widely used multisig wallet relied on a shared library contract that held the core logic, reached via `delegatecall` from each individual wallet.
- A library initialization function was left unprotected, so an account that had not been intended to own the library could call it, take ownership of the shared library, and then invoke `selfdestruct` on it.

**Impact**:
- Because every deployed wallet depended on that single library via `delegatecall`, destroying the library bricked all of the wallets that pointed at it, freezing a very large amount of funds with no recovery path.

**Root Cause**: An unprotected initialization/ownership function on shared, delegatecalled library code—a textbook missing-access-control failure combined with an unguarded `selfdestruct`. This class is why every serious guide now stresses locking initializers and guarding lifecycle functions.

### Case Study 2: Uninitialized-Proxy Takeover Class

**Vulnerability**:
- Upgradeable contracts move constructor logic into an `initialize` function. When an implementation (logic) contract is deployed but its initializer is not locked, the implementation itself can be initialized by anyone.
- If the implementation exposes an upgrade or `delegatecall` path, an attacker who initializes it becomes its owner and can direct it to execute arbitrary code—including `selfdestruct`—in a damaging context.

**Impact**:
- Repeated incidents in this class have let attackers seize ownership of logic contracts and, in some patterns, destroy them or hijack the upgrade mechanism—disabling protocols or exposing funds.

**Root Cause**: Initializers not protected by an `initializer` guard and implementation contracts left uninitialized. The standard remedy is to invoke `_disableInitializers()` in the implementation's constructor so the logic contract can never be initialized directly.

### Case Study 3: Unprotected Privileged Function Class (Generic)

**Vulnerability**:
- A privileged function—commonly `mint`, `withdraw`, `setOwner`, or an "emergency" helper—is shipped without the intended `onlyOwner`/role modifier.

**Impact**:
- Automated searchers routinely detect such functions and exploit them, minting tokens or withdrawing balances in a single transaction. This is the most frequently reported access-control finding across audits and post-mortems.

**Root Cause**: A missing or incorrect authorization check on a state-changing function. The fix is mechanical—apply the correct modifier to *every* privileged function—but the failure is common because it only takes one omission.

## Prevalence and Statistics

Access Control Vulnerabilities are ranked **SC01—first—in the OWASP Smart Contract Top 10 (2025)**, reflecting both how often the flaw appears and how severe the outcome is. Because the check is invisible when absent, the failure hides in plain sight until an attacker exercises it.

Rather than cite precise loss figures (which vary by source and year), the defensible picture is:

- Broken access control is consistently reported as **one of the largest sources of value lost** in on-chain exploits, year over year.
- The most common sub-issues are **missing modifiers on privileged functions, unprotected initializers/upgrade paths, and `tx.origin` authorization**.
- The impact is rated **critical**: outcomes range from total treasury drain and unlimited minting to permanent, unrecoverable loss of the contract itself.

> Note: exact loss totals differ between reports and years. Treat any single figure as illustrative; the durable takeaway is that access-control flaws are common, trivially exploitable once found, and frequently unrecoverable.

## Common Misunderstandings

### Myth 1: "The function is internal-looking, so nobody will call it"

**Reality**: On-chain, every externally reachable function is callable by anyone who crafts the right transaction—function names and selectors are public. "Nobody will find it" is not a control; the correct visibility keyword and an explicit modifier are.

### Myth 2: "`tx.origin` and `msg.sender` are basically the same"

**Reality**: `msg.sender` is the immediate caller; `tx.origin` is the original externally-owned account that started the transaction. Using `tx.origin` for authorization lets a malicious contract the owner is tricked into calling act with the owner's authority. Always authenticate with `msg.sender`.

### Myth 3: "We call `initialize()` right after deploy, so it's safe"

**Reality**: Deployment and initialization are two separate transactions. An attacker can front-run your `initialize` call, or initialize the implementation contract directly. The initializer must be guarded by an `initializer` modifier and disabled on the implementation with `_disableInitializers()`.

### Myth 4: "Only the owner knows the admin function exists"

**Reality**: Verified source, and even raw bytecode, is public and continuously scanned. Obscurity buys nothing; the only real gate is an authorization check enforced by the EVM.

### Myth 5: "We use OpenZeppelin, so access control is handled"

**Reality**: Importing `Ownable` or `AccessControl` only helps if you actually apply `onlyOwner`/`onlyRole` to every privileged function. The library provides the mechanism; forgetting the modifier on a single setter still exposes it.

### Myth 6: "A one-line ownership transfer is fine"

**Reality**: A single-step transfer to a mistyped or zero address is irreversible and permanently loses admin control. A two-step propose/accept flow (and rejecting the zero address) prevents an entire class of lockouts.

## How Access Control Differs from Related Issues

| Aspect | Access Control (SC01) | Reentrancy (SC05) | Logic / Business Flaws |
|--------|-----------------------|-------------------|------------------------|
| **Root cause** | Missing/incorrect authorization | State updated after external call | Incorrect intended behaviour |
| **Who can exploit** | Anyone (no auth to bypass) | Anyone via a callback | Depends on the flaw |
| **Typical fix** | Apply correct modifier / `msg.sender` | Checks-effects-interactions, guard | Correct the specification |
| **Detection** | Review every privileged function | Trace external-call ordering | Model invariants |

## Key Takeaways

1. **Every privileged function needs an explicit check**—there is no implicit protection on-chain; a missing modifier means no protection at all.
2. **Authenticate with `msg.sender`, never `tx.origin`**—the latter is phishing-vulnerable.
3. **Lock your initializers**—guard with the `initializer` modifier and disable initialization on the implementation contract.
4. **Guard upgrades and `delegatecall`**—these substitute logic against your own storage and balance.
5. **Transfer ownership in two steps**—and reject the zero address—to avoid irreversible lockout.

## How to Identify if You're Vulnerable

- [ ] Does *every* state-changing/privileged function (withdraw, mint, pause, upgrade, setOwner, selfdestruct) carry an explicit access modifier?
- [ ] Is every authorization check based on `msg.sender` rather than `tx.origin`?
- [ ] Is every function's visibility (`external`/`public`/`internal`/`private`) declared explicitly and correctly?
- [ ] Is the initializer protected by an `initializer` guard, and is the implementation disabled with `_disableInitializers()`?
- [ ] Are upgrade and `delegatecall` paths restricted to a trusted admin/governance role?
- [ ] Do your modifiers use the correct comparison and actually execute `_;`?
- [ ] Is ownership transfer two-step, and does it reject the zero address?
- [ ] Are roles separated by least privilege (no single all-powerful key where a role split is safer)?
- [ ] Have you removed or gated `selfdestruct` entirely?
- [ ] Are you using an audited library (OpenZeppelin `Ownable`/`AccessControl`) rather than hand-rolled checks?

If you answered "no" or "not sure" to several of these, you likely have an exploitable access-control flaw today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers find and exploit broken access control
- **[Prevention](prevention.md)**: Build layered, verifiable authorization into every function
- **[Examples](examples.md)**: Vulnerable vs. secure Solidity contracts side by side
- **[Smart Contract Learning Path](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
