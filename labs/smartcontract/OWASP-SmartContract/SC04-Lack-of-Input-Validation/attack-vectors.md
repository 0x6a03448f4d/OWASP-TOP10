# SC04: Lack of Input Validation - Attack Vectors

## Table of Contents
- [Understanding Input-Validation Attack Vectors](#understanding-input-validation-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Missing Validation](#chaining-missing-validation)

## Understanding Input-Validation Attack Vectors

> **⚠ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in contracts you own or are authorised to test. Never target contracts you do not control.

Missing-validation bugs are rarely exploited with clever cryptography. They are exploited by **calling the contract directly with a value the developer never expected**. Because every external function is public and the ABI is known, an attacker simply constructs calldata that carries a zero address, an out-of-range number, an oversized array, or a hostile token address, and submits the transaction.

The attacker's goal in this category is usually one of:

- Corrupt permanent state (balances, ownership, configuration) by writing a value outside the intended range.
- Redirect value — send funds to a chosen recipient, or make the contract call a chosen target.
- Deny service — brick a function via an unusable owner or an unbounded loop.

### Core Attack Flow

```
1. Read the ABI
   |
   Identify every external/public function and its parameters
2. Find the gap
   |
   Which params are used without a require()? (address, amount, array, id, fee, target)
3. Craft calldata
   |
   Encode address(0), an out-of-range value, mismatched arrays, or a malicious token
4. Submit & exploit
   |
   Corrupt state, redirect funds, trigger an external call, or brick the contract
```

## Common Attack Patterns

### 1. Zero-Address Injection (Burn / Brick)

The attacker (or a careless caller) passes `address(0)` where a recipient or owner is expected.

```solidity
// Vulnerable: no zero-address check
function transfer(address to, uint256 amount) external {
    balances[msg.sender] -= amount;
    balances[to]        += amount;   // to == address(0) -> tokens unrecoverable
}

// Exploit call
transfer(address(0), 1_000e18);      // 1,000 tokens burned forever
```

**Payoff**: permanent loss of funds; or, against `setOwner(address(0))`, a contract whose privileged functions can never be called again.

### 2. Amount Out of Bounds

An unchecked amount lets the caller move more than they own, or corrupt an invariant with a zero-value operation.

```solidity
// Vulnerable: no balance/allowance/>0 check (pre-0.8 underflow shown)
function withdraw(uint256 amount) external {
    balances[msg.sender] -= amount;          // underflows to a huge balance
    payable(msg.sender).transfer(amount);
}

// Exploit call
withdraw(1);   // if balance is 0, pre-0.8 this underflows to 2^256-1
```

**Payoff**: over-withdrawal and drained contract balance; on modern compilers the same class appears as amounts exceeding an unchecked allowance.

### 3. Mismatched / Oversized Arrays

Batch functions that trust caller arrays can be reverted, mis-paid, or gas-bombed.

```solidity
// Vulnerable: no length equality, no cap
function airdrop(address[] calldata to, uint256[] calldata amt) external onlyOwner {
    for (uint256 i; i < to.length; ++i) token.transfer(to[i], amt[i]);
}

// Exploit A: amt shorter than to  -> out-of-bounds revert (griefing / DoS)
// Exploit B: to.length = 50_000   -> loop exceeds block gas limit, always reverts
```

**Payoff**: denial of service on a critical function, or incorrect payouts when arrays are crafted to misalign.

### 4. Index / ID Out of Range or Not Owned

An unvalidated index reads the wrong slot or lets a caller act on someone else's item.

```solidity
// Vulnerable: no bounds / ownership check
function redeem(uint256 id) external {
    Ticket storage t = tickets[id];      // id may be out of range or another user's
    payable(msg.sender).transfer(t.value);
    delete tickets[id];
}

// Exploit call
redeem(victimTicketId);   // claim value tied to an ID the caller never owned
```

**Payoff**: theft of value bound to another user's ID, or reads of uninitialised/adjacent storage.

### 5. Fee / Percentage Above Maximum

A setter with no upper bound lets a privileged (or compromised) caller seize value.

```solidity
// Vulnerable: no upper bound
function setFeeBps(uint256 bps) external onlyOwner {
    feeBps = bps;                 // 10_000 bps = 100%; nothing stops 50_000
}

// Later, every swap:
uint256 fee = (amount * feeBps) / 10_000;   // feeBps > 10_000 -> fee >= amount
```

**Payoff**: the protocol captures the entire transaction value; users receive nothing.

### 6. Arbitrary Token / Target Address

Passing a caller-chosen address as a token or call target turns the contract into a proxy for the attacker.

```solidity
// Vulnerable: token/target not allow-listed
function collect(address token, address to) external {
    IERC20(token).transferFrom(msg.sender, to, 1e18);  // token is attacker's contract
}

// Exploit: 'token' is a malicious contract whose transferFrom re-enters,
// lies about return values, or triggers unexpected callbacks.
```

**Payoff**: arbitrary external calls, re-entrancy setup, fake accounting, or approval abuse against the victim contract.

### 7. Unvalidated Deadline / Signature

Skipping expiry or signer checks lets stale or forged authorisations execute.

```solidity
// Vulnerable: deadline decoded but never enforced
function fill(Order calldata o, bytes calldata sig) external {
    address signer = recover(hash(o), sig);   // signer not compared to o.maker
    _settle(o);                               // o.deadline never checked
}

// Exploit: replay an expired order, or supply a signature the code never binds
// to the expected signer.
```

**Payoff**: replay of expired orders, execution of unauthorised actions, and bypass of intended time limits.

### 8. Trusting Decoded Calldata

Blindly `abi.decode`-ing untrusted bytes into structured parameters and acting on them.

```solidity
// Vulnerable: decoded fields used without validation
function onMessage(bytes calldata data) external {
    (address to, uint256 amount) = abi.decode(data, (address, uint256));
    token.transfer(to, amount);   // to/amount attacker-controlled, unchecked
}
```

**Payoff**: the decode step launders attacker input into "typed" parameters that still need every check a direct argument would.

### 9. Assuming an Address Is a Contract (or Not)

Logic that requires a contract (or an EOA) without checking code size behaves incorrectly when the assumption is wrong.

```solidity
// Vulnerable: assumes 'callback' is a contract implementing the hook
function register(address callback) external {
    ICallback(callback).onRegister(msg.sender);   // EOA -> silent no-op / wrong flow
}
```

**Payoff**: bypassed callbacks, skipped checks, or interactions that silently do nothing while the contract believes they succeeded.

## Chaining Missing Validation

Individually minor gaps combine into full compromise:

```
Unchecked token address      -> attacker supplies a malicious token
        +
No SafeERC20 / return check   -> fake success is trusted
        +
Corrupted internal accounting -> attacker's balance inflated
        =  drain of legitimately-held assets, no cryptography broken
```

Another common chain:

```
No upper bound on fee         -> compromised owner sets fee to 500%
        -> every user swap forfeits its entire value to the fee sink
        -> funds withdrawn to an unvalidated (attacker) recipient address
```

## Key Takeaways

1. **Exploitation is just a function call** — the attacker crafts calldata with a value you never expected; no exotic technique needed.
2. **Zero addresses and out-of-range numbers are the first thing to try** — they map directly to burns, bricks, and over-withdrawals.
3. **Arrays are a denial-of-service surface** — mismatched or oversized inputs revert or exceed the gas limit.
4. **Caller-supplied addresses are hostile** — a token or target parameter is an arbitrary external call unless allow-listed.
5. **Small gaps chain** — an unchecked token plus trusting its return value plus a corrupted balance equals a drain.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build a complete validation baseline at every function boundary
- **[Code Examples](examples.md)**: See vulnerable vs. secure Solidity side by side
- **[Smart Contract Track](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Exploit and fix these gaps in hands-on challenges
