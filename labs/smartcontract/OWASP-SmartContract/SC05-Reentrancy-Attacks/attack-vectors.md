# SC05: Reentrancy Attacks - Attack Vectors

## Table of Contents
- [Understanding Reentrancy Attack Vectors](#understanding-reentrancy-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Reentrancy](#chaining-reentrancy)

## Understanding Reentrancy Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in contracts you own or are authorised to test.

Reentrancy is not exploited with a clever input; it is exploited by **seizing control**. Whenever a vulnerable contract makes an external call, it momentarily hands the program counter to code the attacker wrote. The attacker's job is simply to call back into the victim before the victim has finished writing down what it just did. Because the flaw is in *ordering*, the exploit is a short, mechanical loop rather than a subtle payload.

The attacker's goal in this category is usually one of:

- Repeat a value-moving action (withdraw, claim, redeem) many times against state that has not yet been decremented.
- Re-enter a *sibling* function that trusts the same not-yet-updated state.
- Make an external consumer read a temporarily inconsistent value (read-only reentrancy) and act on it.

### Core Attack Flow

```
1. Deposit / Seed
   ↓
   Attacker contract deposits a small amount so it has a nonzero balance
2. Trigger
   ↓
   Attacker calls withdraw(); victim sends ETH BEFORE zeroing the balance
3. Re-enter
   ↓
   ETH send invokes attacker's receive(); it calls withdraw() again
   (balance still nonzero -> check passes -> ETH sent again)
4. Loop & Exit
   ↓
   Repeat until the victim is drained or gas runs low, then stop re-entering
```

## Common Attack Patterns

### 1. Classic Single-Function Reentrancy (the withdraw loop)

The attacker's `receive()` re-enters the very function that paid it.

```solidity
// Victim (vulnerable)
function withdraw() external {
    uint256 amount = balance[msg.sender];
    require(amount > 0);
    (bool ok, ) = msg.sender.call{value: amount}("");  // control leaves here
    require(ok);
    balance[msg.sender] = 0;                            // runs last -> too late
}

// Attacker
receive() external payable {
    if (address(victim).balance >= 1 ether) {
        victim.withdraw();      // re-enter: balance[attacker] still nonzero
    }
}
```

**Payoff**: the deposit is paid out once per re-entry, draining the contract in a single transaction. This is the DAO-class pattern.

### 2. Cross-Function Reentrancy

The attacker re-enters a *different* function that reads the same stale balance.

```solidity
// Victim: withdraw() and transfer() share balance[]
function withdraw() external {
    uint256 amount = balance[msg.sender];
    (bool ok, ) = msg.sender.call{value: amount}("");   // control leaves here
    require(ok);
    balance[msg.sender] = 0;                             // not yet run
}
function transfer(address to, uint256 amt) external {
    require(balance[msg.sender] >= amt);                 // sees OLD balance
    balance[msg.sender] -= amt;
    balance[to] += amt;
}

// Attacker's receive() calls victim.transfer(friend, balance) mid-withdraw,
// moving the balance out before withdraw() zeroes it.
```

**Payoff**: a reentrancy guard on `withdraw` alone does not help—the re-entry lands in `transfer`. Every function touching shared state must be considered.

### 3. Cross-Contract Reentrancy

Two contracts share or cache state; re-entry through one corrupts the other.

```solidity
// Vault caches a value from Pool, updates Pool, then updates its own cache.
function withdraw() external {
    uint256 shares = pool.balanceOf(address(this));
    pool.redeem(shares);            // Pool sends ETH -> attacker re-enters Vault
    cachedShares = pool.balanceOf(address(this));   // cache updated too late
}
// During pool.redeem's callback, the attacker calls back into Vault, which
// still trusts the stale cachedShares from before the redeem settled.
```

**Payoff**: state that looks consistent within one contract is inconsistent across the pair during the reentrant window.

### 4. Read-Only Reentrancy

A `view` getter returns inconsistent state mid-callback; an integrator trusts it.

```solidity
// Pool.get_virtual_price() is temporarily wrong while a withdrawal callback runs
// (assets already sent out, supply not yet updated).

// Attacker flow:
// 1. Attacker calls pool.remove_liquidity()  -> pool sends ETH, invokes receive()
// 2. In receive(), attacker calls LendingMarket.borrow()
// 3. LendingMarket reads pool.get_virtual_price() -> STALE, inflated value
// 4. Collateral is over-valued -> attacker borrows more than they should
```

**Payoff**: the vulnerable getter never writes state, yet an *integrating* protocol is misled into an under-collateralised loan or unfair mint. Guards on state-changing functions do not cover this unless the getter is protected too.

### 5. ERC777 `tokensReceived` Hook Reentrancy

An ERC777 transfer calls the recipient, providing a re-entry hook with no ETH involved.

```solidity
// Victim assumes token.transfer() cannot call back.
function claim() external {
    uint256 amt = owed[msg.sender];
    token.transfer(msg.sender, amt);   // ERC777: invokes recipient's tokensReceived
    owed[msg.sender] = 0;              // runs after the hook -> re-entrant claim
}

// Attacker implements IERC777Recipient:
function tokensReceived(...) external {
    if (owed[address(this)] > 0) victim.claim();   // re-enter before owed is zeroed
}
```

**Payoff**: reentrancy on a token path even though no `call{value:}` is used. Any "transfer then update" ordering with a hooked token is exploitable.

### 6. ERC721 `onERC721Received` Hook Reentrancy

`safeTransferFrom` calls the recipient's acceptance hook, another mid-transfer entry point.

```solidity
// Victim mints/awards an NFT, then updates accounting.
function mintReward() external {
    require(!claimed[msg.sender]);
    nft.safeMint(msg.sender, nextId());   // invokes onERC721Received on recipient
    claimed[msg.sender] = true;           // set after the hook
}

// Attacker's onERC721Received re-enters mintReward() before claimed is set,
// minting multiple rewards from a single entitlement.
```

**Payoff**: one-time entitlements (mints, rewards, allowlist claims) execute multiple times.

### 7. Delegatecall Reentrancy

Proxy/library code runs in the caller's storage; an external call inside it can be re-entered.

```solidity
// Proxy delegatecalls into logic; logic makes an external call before the
// proxy's storage is settled. Re-entry manipulates the shared storage slots.
(bool ok, ) = logic.delegatecall(
    abi.encodeWithSignature("withdraw()")   // runs in proxy storage context
);
// If withdraw() sends ETH before writing state, the attacker re-enters the
// proxy and operates on half-updated storage shared by proxy and logic.
```

**Payoff**: storage corruption or repeated actions in upgradeable/proxy systems, where the boundary between "caller" and "callee" state is blurred.

### 8. Gas-Stipend Assumptions Defeated

Relying on `transfer`/`send`'s 2300-gas stipend as a defence is fragile.

```solidity
// "Safe" because it only forwards 2300 gas?
payable(msg.sender).transfer(amount);   // NOT a security guarantee
// - Cross-function re-entry may not need much gas
// - Opcode gas costs have changed across forks, breaking the assumption
// - Token-hook paths don't rely on this stipend at all
```

**Payoff**: contracts that traded correct ordering for a gas trick remain exploitable through paths the stipend never protected.

## Chaining Reentrancy

Reentrancy is frequently one link in a larger exploit:

```
Flash loan (large temporary capital)
        +
Reentrancy drains a pool at an inflated position
        +
Read-only reentrancy misprices an integrating market
        =  under-collateralised borrow + drained pool in one atomic transaction
```

Another common chain:

```
ERC777 token accepted as collateral      -> transfer hands control to attacker
        -> re-enter deposit/withdraw before shares are updated
        -> accounting now inconsistent with real balances
        -> redeem the inflated shares for more than was deposited
```

## Key Takeaways

1. **Reentrancy is control-flow theft**—an external call lends the attacker the CPU mid-transaction.
2. **The entry point is any external call**—ETH sends, ERC777/ERC721 hooks, arbitrary calls, and `delegatecall`.
3. **Guards must cover siblings and getters**—cross-function and read-only variants slip past a single-function guard.
4. **Gas tricks are not defences**—`transfer`/`send` stipends do not stop cross-function or token-hook re-entry.
5. **Reentrancy chains**—combined with flash loans and integrations, one re-entry can compromise several protocols atomically.

## Next Steps

- **[Prevention Guide](prevention.md)**: CEI ordering, reentrancy guards, and pull-over-push
- **[Code Examples](examples.md)**: See the vulnerable contract and its secure rewrite
- **[Smart Contract Learning Path](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
