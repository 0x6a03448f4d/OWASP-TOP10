# SC04: Lack of Input Validation - Prevention

## Prevention Strategy Overview

Preventing this class is less about one clever control and more about **a discipline: validate every caller-supplied value at the function boundary, before touching state**:

1. Check the shape of every input (non-zero address, positive amount, in-range index).
2. Bound every number (amounts, fees, percentages, array lengths).
3. Allow-list critical addresses and call targets instead of trusting them.
4. Verify authorisation data (deadlines, signatures) before acting on it.
5. Fail early, fail clearly, and combine validation with access control.

### Core Principles

- **Validate at the boundary**: the contract is the trust boundary; the front-end is not. Every external/public function re-checks its own arguments.
- **Checks-effects-interactions**: put all `require`/custom-error checks first, then state changes, then external calls.
- **Fail closed and cheap**: revert with a clear custom error the moment an input is invalid, before any gas is spent on state.
- **Defence in depth**: validation complements access control — answer both *who* may call and *with what values*.

## 1. Zero-Address Checks

Reject `address(0)` for any owner, recipient, or token/target address.

```solidity
error ZeroAddress();

function setOwner(address newOwner) external onlyOwner {
    if (newOwner == address(0)) revert ZeroAddress();
    owner = newOwner;
}

function withdraw(address to, uint256 amount) external {
    if (to == address(0)) revert ZeroAddress();
    // ... effects, then interaction
}
```

Prefer a reusable modifier so the check cannot be forgotten:

```solidity
modifier nonZero(address a) {
    if (a == address(0)) revert ZeroAddress();
    _;
}
```

## 2. Amount and Value Bounds

Require amounts to be positive and within the caller's balance or allowance.

```solidity
error ZeroAmount();
error InsufficientBalance(uint256 have, uint256 want);

function transfer(address to, uint256 amount) external nonZero(to) {
    if (amount == 0) revert ZeroAmount();
    uint256 bal = balances[msg.sender];
    if (amount > bal) revert InsufficientBalance(bal, amount);
    balances[msg.sender] = bal - amount;   // effects
    balances[to] += amount;
}
```

Solidity >= 0.8 reverts on overflow/underflow, but that does not enforce `> 0`, allowance limits, or business-level maximums — you still add those explicitly.

## 3. Array Length Equality and Caps

For parallel arrays, enforce equal length and a maximum batch size to prevent corruption and gas-limit DoS.

```solidity
error LengthMismatch();
error BatchTooLarge(uint256 len, uint256 max);

uint256 constant MAX_BATCH = 200;

function airdrop(address[] calldata to, uint256[] calldata amt)
    external
    onlyOwner
{
    if (to.length != amt.length) revert LengthMismatch();
    if (to.length > MAX_BATCH) revert BatchTooLarge(to.length, MAX_BATCH);
    for (uint256 i; i < to.length; ++i) {
        if (to[i] == address(0)) revert ZeroAddress();
        token.safeTransfer(to[i], amt[i]);
    }
}
```

## 4. Index and ID Validation

Bounds-check indexes and confirm ownership/existence before acting.

```solidity
error IndexOutOfRange(uint256 index, uint256 length);
error NotOwner();

function redeem(uint256 id) external {
    if (id >= tickets.length) revert IndexOutOfRange(id, tickets.length);
    Ticket storage t = tickets[id];
    if (t.owner != msg.sender) revert NotOwner();
    // ... effects then interaction
}
```

## 5. Fee and Percentage Bounds

Give every rate an explicit upper bound. Basis points (out of 10,000) make "100%" unambiguous.

```solidity
error FeeTooHigh(uint256 bps, uint256 max);

uint256 constant BPS_DENOMINATOR = 10_000;   // 100.00%
uint256 constant MAX_FEE_BPS     = 1_000;    // e.g. cap at 10%

function setFeeBps(uint256 bps) external onlyOwner {
    if (bps > MAX_FEE_BPS) revert FeeTooHigh(bps, MAX_FEE_BPS);
    feeBps = bps;
}
```

## 6. Allow-List Critical Addresses and Targets

Never act on an arbitrary caller-supplied token or call target. Maintain a vetted allow-list.

```solidity
error TokenNotAllowed(address token);

mapping(address => bool) public allowedToken;

function addToken(address token) external onlyOwner nonZero(token) {
    allowedToken[token] = true;
}

function collect(address token, uint256 amount) external {
    if (!allowedToken[token]) revert TokenNotAllowed(token);
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
}
```

The same pattern applies to any address the contract will `call`: restrict external-call targets to an allow-list rather than trusting a parameter.

## 7. Deadline and Signature Validation

Enforce expiry and bind signatures to the expected signer before honouring an order.

```solidity
error Expired(uint256 deadline);
error BadSignature();

function fill(Order calldata o, bytes calldata sig) external {
    if (block.timestamp > o.deadline) revert Expired(o.deadline);
    bytes32 digest = _hashTypedDataV4(_orderHash(o));   // EIP-712
    address signer = ECDSA.recover(digest, sig);
    if (signer != o.maker) revert BadSignature();
    if (usedNonce[o.maker][o.nonce]) revert BadSignature();  // replay guard
    usedNonce[o.maker][o.nonce] = true;
    _settle(o);
}
```

## 8. Code-Size Checks When a Contract Is Required

When logic depends on the target being (or not being) a contract, check the code size explicitly.

```solidity
error NotAContract(address a);

function register(address callback) external nonZero(callback) {
    if (callback.code.length == 0) revert NotAContract(callback);
    ICallback(callback).onRegister(msg.sender);
}
```

Note: `code.length == 0` is also true for a contract mid-construction, so use it as a guard for the expected case, not as a security boundary against re-entrancy.

## 9. Safe Token Interactions

Use `SafeERC20` so non-standard tokens (missing/false return values) cannot silently corrupt accounting.

```solidity
using SafeERC20 for IERC20;

function deposit(address token, uint256 amount) external {
    if (!allowedToken[token]) revert TokenNotAllowed(token);
    if (amount == 0) revert ZeroAmount();
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);  // reverts on failure
    balances[msg.sender][token] += amount;
}
```

## 10. Reusable Validation Library

Centralise checks so every function validates identically and nothing is forgotten.

```solidity
library Validate {
    error ZeroAddress();
    error ZeroAmount();
    error OutOfBounds(uint256 value, uint256 max);

    function nonZeroAddr(address a) internal pure {
        if (a == address(0)) revert ZeroAddress();
    }
    function positive(uint256 v) internal pure {
        if (v == 0) revert ZeroAmount();
    }
    function atMost(uint256 v, uint256 max) internal pure {
        if (v > max) revert OutOfBounds(v, max);
    }
}
```

## Testing and Tooling

Validation logic must be tested for the values you are trying to reject:

```bash
# Fuzz every external function with adversarial inputs
forge test --fuzz-runs 10000        # Foundry: property/fuzz tests

# Invariant tests: balances never exceed supply, fee never > max, etc.
forge test --match-path test/invariant/*

# Static analysis flags missing zero-address and bounds checks
slither .
```

Write explicit negative tests: assert that `transfer(address(0), x)`, `setFeeBps(20_000)`, and mismatched airdrop arrays all revert with the expected custom error.

## Validation Checklist by Input Type

| Input | Required Check | Failure If Omitted |
|-------|----------------|--------------------|
| Address | `!= address(0)`; allow-list if critical | Burned funds, bricked contract, arbitrary call |
| Amount | `> 0`; `<= balance/allowance` | Over-spend, corrupted accounting |
| Arrays | Equal length; `<= MAX_BATCH` | State corruption, gas-limit DoS |
| Index / ID | `< length`; ownership | Out-of-range read, theft, double-claim |
| Fee / percent | `<= MAX` (bps) | Value seizure |
| Target / token | Allow-list; `SafeERC20` | Arbitrary external call, fake accounting |
| Deadline / sig | Not expired; correct signer; nonce | Replay, expiry bypass |

## Key Takeaways

1. **Validate at the boundary** — every external/public function re-checks its own arguments; the UI is not a control.
2. **Checks first** — put every `require`/custom error before state changes and external calls.
3. **Bound and allow-list** — numbers get maximums, addresses and targets get allow-lists.
4. **Prefer custom errors** — cheaper than string reverts and self-documenting for callers and tests.
5. **Test the rejections** — fuzz and invariant tests must prove bad inputs revert, not just that good inputs work.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure Solidity for each validation gap
- **[Attack Vectors](attack-vectors.md)**: Understand exactly what you are defending against
- **[Smart Contract Track](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Harden a vulnerable contract in a hands-on challenge
